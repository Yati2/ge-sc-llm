#!/usr/bin/env python3

import os
import json
import re
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import time

# Configuration
MARKDOWN_DIR = Path("markdown_files")
OUTPUT_DIR = Path("extracted_contracts")
TIER_1_DIR = OUTPUT_DIR / "tier_1_complete"
TIER_2_DIR = OUTPUT_DIR / "tier_2_code_blocks"
TIER_3_DIR = OUTPUT_DIR / "tier_3_snippets"
STATS_FILE = OUTPUT_DIR / "extraction_stats.json"
FAILED_LOG = OUTPUT_DIR / "failed_extractions.log"
SHARED_FILES_JSON = OUTPUT_DIR / "shared_github_files.json"
FINDINGS_JSON = Path("solodit_sequential_findings.json")

# GitHub API settings
GITHUB_RAW_URL = "https://raw.githubusercontent.com"
REQUEST_DELAY = 1.0  # Increased to avoid rate limits
MAX_RETRIES = 3  # Retry failed downloads  


class ContractExtractor:
    def __init__(self):
        self.stats = {
            "total_processed": 0,
            "successful_extractions": 0,
            "github_attempted": 0,
            "github_successful": 0,
            "by_tier": {
                "tier_1_github_complete": 0,
                "tier_2_code_blocks": 0,
                "tier_3_snippets": 0
            },
            "by_extraction_type": {
                "github_complete": 0,
                "markdown_code_block": 0,
                "content_snippet": 0
            },
            "failed": 0,
            "failure_reasons": {}
        }
        self.failed_files = []
        
        # Track which vulnerabilities reference which GitHub files
        # Key: github_filename (e.g., "CLOB.sol"), Value: list of {id, title, file_key}
        self.github_file_references = {}
        
        # Load solodit findings for metadata access
        self.findings_data = {}
        if FINDINGS_JSON.exists():
            try:
                with open(FINDINGS_JSON, 'r', encoding='utf-8') as f:
                    findings_list = json.load(f)
                    # Create lookup dict by ID
                    self.findings_data = {f['id']: f for f in findings_list}
                print(f"📖 Loaded {len(self.findings_data)} findings from {FINDINGS_JSON}")
            except Exception as e:
                print(f"⚠️  Warning: Could not load {FINDINGS_JSON}: {e}")
        
        # Create output directories
        for dir_path in [TIER_1_DIR, TIER_2_DIR, TIER_3_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def extract_title_from_markdown(self, md_path: Path) -> str:
        """Extract vulnerability title from markdown file (first heading)."""
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('# '):
                        return line[2:].strip()  # Remove '# ' prefix
            return "Untitled Vulnerability"
        except Exception as e:
            print(f"  ⚠️  Error extracting title: {e}")
            return "Untitled Vulnerability"
    
    def determine_failure_reason(self, vulnerability_id: str, content: str, github_urls: List[str]) -> Tuple[str, str]:
        """Determine detailed failure reason based on finding metadata and content analysis."""
        # Get finding metadata from solodit JSON
        finding = self.findings_data.get(vulnerability_id, {})
        
        kind = finding.get('kind', 'UNKNOWN')
        pdf_link = finding.get('pdf_link', '')
        github_link_valid = finding.get('github_link_valid', False)
        has_github_link = bool(finding.get('github_link', '').strip())
        
        # Check if any .sol files were found in URLs
        has_sol_urls = len(github_urls) > 0
        
        # Determine specific failure reason
        if pdf_link and pdf_link.strip():
            reason = "no_code_found_pdf_source"
            details = f"{kind} source with PDF link, no extractable code from content or valid .sol links"
        elif has_github_link and not github_link_valid:
            reason = "no_code_found_github_invalid"
            details = f"{kind} source, GitHub link present but invalid/inaccessible, no code in content"
        elif has_github_link and github_link_valid and not has_sol_urls:
            reason = "no_code_found_github_no_sol"
            details = f"{kind} source, valid GitHub link but no .sol files referenced, no code blocks in content"
        elif has_github_link and github_link_valid and has_sol_urls:
            reason = "no_code_found_github_download_failed"
            details = f"{kind} source, .sol files found but download failed, no fallback code in content"
        elif kind == 'MARKDOWN':
            reason = "no_code_found_markdown_only"
            details = f"MARKDOWN source, no GitHub links, no code blocks in content/summary"
        elif not has_github_link:
            reason = "no_code_found_no_source"
            details = f"{kind} source, no GitHub link provided, no extractable code in content"
        else:
            reason = "no_code_found"
            details = f"{kind} source, no extractable code in any format"
        
        return reason, details
    
    def extract_github_url(self, text: str) -> List[str]:
        """Extract GitHub URLs from text."""
        # Pattern for GitHub URLs - handles both #L123 and # L123 (with space)
        # Matches: https://github.com/.../file.sol#L97-L100 or # L97-L100
        pattern = r'https://github\.com/[\w\-./]+\.sol(?:#\s*L\d+(?:-L\d+)?)?'
        urls = re.findall(pattern, text)
        return urls
    
    def parse_github_url(self, url: str) -> Optional[Dict]:
        """
        Parse GitHub URL to extract components.
        Returns dict with: owner, repo, branch, path, line_start, line_end, is_sol_file
        Handles both #L42-L58 and # L42-L58 (with space)
        """
        # Remove trailing punctuation and angle brackets
        url = url.rstrip('.,;:>').lstrip('<')
        
        # Pattern: https://github.com/owner/repo/blob/branch/path/file.sol#L42-L58 or # L42-L58
        pattern = r'github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+?)(?:#\s*L(\d+)(?:-L(\d+))?)?$'
        match = re.search(pattern, url)
        
        if not match:
            return None
        
        owner, repo, branch, file_path, line_start, line_end = match.groups()
        
        # Check if it's a .sol file
        is_sol_file = file_path.endswith('.sol')
        
        return {
            "owner": owner,
            "repo": repo,
            "branch": branch,
            "path": file_path,
            "line_start": int(line_start) if line_start else None,
            "line_end": int(line_end) if line_end else None,
            "is_sol_file": is_sol_file,
            "original_url": url
        }
    
    def download_github_file(self, github_info: Dict, retry_count: int = 0) -> Optional[str]:
        """Download file content from GitHub with retry logic."""
        raw_url = f"{GITHUB_RAW_URL}/{github_info['owner']}/{github_info['repo']}/{github_info['branch']}/{github_info['path']}"
        
        try:
            time.sleep(REQUEST_DELAY)  # Rate limiting
            response = requests.get(raw_url, timeout=15)
            
            if response.status_code == 200:
                print(f"    ✅ Downloaded {len(response.text)} bytes")
                return response.text
            elif response.status_code == 404:
                print(f"    ❌ File not found (HTTP 404)")
                return None  # Don't retry 404s
            elif response.status_code == 403 and retry_count < MAX_RETRIES:
                print(f"    ⏳ Rate limited (HTTP 403), retry {retry_count+1}/{MAX_RETRIES}...")
                time.sleep(2 ** retry_count)  # Exponential backoff
                return self.download_github_file(github_info, retry_count + 1)
            else:
                print(f"    ❌ GitHub download failed: HTTP {response.status_code}")
                if retry_count < MAX_RETRIES:
                    print(f"    ⏳ Retrying {retry_count+1}/{MAX_RETRIES}...")
                    time.sleep(1)
                    return self.download_github_file(github_info, retry_count + 1)
                return None
        except Exception as e:
            print(f"    ❌ Download error: {e}")
            if retry_count < MAX_RETRIES:
                print(f"    ⏳ Retrying {retry_count+1}/{MAX_RETRIES}...")
                time.sleep(1)
                return self.download_github_file(github_info, retry_count + 1)
            return None
    
    def extract_code_blocks(self, text: str) -> List[str]:
        """Extract Solidity code blocks from markdown."""
        # Pattern for ```solidity code blocks
        pattern = r'```solidity\n(.*?)```'
        code_blocks = re.findall(pattern, text, re.DOTALL)
        
        # Also try ```sol
        pattern2 = r'```sol\n(.*?)```'
        code_blocks.extend(re.findall(pattern2, text, re.DOTALL))
        
        # Also try plain ``` if it looks like Solidity
        pattern3 = r'```\n(.*?)```'
        plain_blocks = re.findall(pattern3, text, re.DOTALL)
        for block in plain_blocks:
            if 'pragma solidity' in block or 'contract ' in block or 'function ' in block:
                code_blocks.append(block)
        
        return code_blocks
    
    def extract_code_blocks_with_language(self, text: str) -> List[Dict[str, str]]:
        """Extract code blocks with their language identifiers."""
        code_blocks = []
        
        # Pattern to match ```language\ncode``` blocks
        pattern = r'```(\w+)?\n(.*?)```'
        matches = re.findall(pattern, text, re.DOTALL)
        
        for language, code in matches:
            if not language:
                language = "unknown"
            code_blocks.append({
                "language": language,
                "code": code.strip()
            })
        
        return code_blocks
    
    def extract_recommendations(self, markdown_text: str) -> Dict:
        """
        Extract recommendation section from markdown.
        
        Looks for headers like:
        - Recommendation
        - Recommendations
        - Recommended mitigation steps
        - Mitigation
        - Suggested Fix
        
        Returns:
        {
            "has_recommendation": bool,
            "recommendation_text": str,
            "fix_code_blocks": [{language: str, code: str}]
        }
        """
        result = {
            "has_recommendation": False,
            "recommendation_text": "",
            "fix_code_blocks": []
        }
        
        # Regex to find recommendation sections (case-insensitive)
        # Matches: ## Recommendation, ## Recommendations, ### Recommended mitigation steps, etc.
        pattern = r'(?:^|\n)(#{1,4})\s*(Recommendation|Recommendations|Recommended\s+mitigation\s+steps?|Mitigation|Suggested\s+Fix)s?\s*\n(.*?)(?=\n#{1,4}\s+\w+|\Z)'
        
        match = re.search(pattern, markdown_text, re.IGNORECASE | re.DOTALL)
        
        if match:
            result["has_recommendation"] = True
            section_content = match.group(3).strip()
            result["recommendation_text"] = section_content
            
            # Extract code blocks from the recommendation section
            result["fix_code_blocks"] = self.extract_code_blocks_with_language(section_content)
        
        return result
    
    def extract_poc(self, markdown_text: str) -> Dict:
        """
        Extract Proof of Concept section from markdown.
        
        Looks for headers like:
        - Proof of Concept
        - PoC
        - Exploit
        - Exploit Scenario
        
        Returns:
        {
            "has_poc": bool,
            "poc_text": str,
            "poc_code_blocks": [{language: str, code: str}]
        }
        """
        result = {
            "has_poc": False,
            "poc_text": "",
            "poc_code_blocks": []
        }
        
        # Regex to find PoC sections (case-insensitive)
        # Matches: ## Proof of Concept, ## PoC, ### Exploit, etc.
        pattern = r'(?:^|\n)(#{1,4})\s*(Proof\s+of\s+Concept|PoC|Exploit\s+Scenario|Exploit)s?\s*\n(.*?)(?=\n#{1,4}\s+\w+|\Z)'
        
        match = re.search(pattern, markdown_text, re.IGNORECASE | re.DOTALL)
        
        if match:
            result["has_poc"] = True
            section_content = match.group(3).strip()
            result["poc_text"] = section_content
            
            # Extract code blocks from the PoC section
            result["poc_code_blocks"] = self.extract_code_blocks_with_language(section_content)
        
        return result
    
    def remove_recommendation_and_poc_sections(self, markdown_text: str) -> str:
        """
        Remove Recommendation and PoC sections from markdown content.
        This ensures we only extract vulnerable code, not fixes or exploits.
        
        Returns: markdown text with recommendation and PoC sections removed
        """
        # Remove Recommendation sections
        rec_pattern = r'(?:^|\n)(#{1,4})\s*(Recommendation|Recommendations|Recommended\s+mitigation\s+steps?|Mitigation|Suggested\s+Fix)s?\s*\n(.*?)(?=\n#{1,4}\s+\w+|\Z)'
        content = re.sub(rec_pattern, '', markdown_text, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove PoC sections
        poc_pattern = r'(?:^|\n)(#{1,4})\s*(Proof\s+of\s+Concept|PoC|Exploit\s+Scenario|Exploit)s?\s*\n(.*?)(?=\n#{1,4}\s+\w+|\Z)'
        content = re.sub(poc_pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
        
        return content
    
    def assess_code_quality(self, code: str) -> Dict:
        """Assess the quality and completeness of extracted code."""
        lines = code.strip().split('\n')
        num_lines = len(lines)
        
        has_pragma = 'pragma solidity' in code
        has_contract = 'contract ' in code or 'interface ' in code or 'library ' in code
        has_function = 'function ' in code
        
        # Check for balanced braces
        balanced_braces = code.count('{') == code.count('}')
        
        # Determine quality tier
        if has_pragma and has_contract and balanced_braces and num_lines > 20:
            tier = "tier_2"
            is_complete = True
        elif has_function and num_lines > 5:
            tier = "tier_3"
            is_complete = False
        elif num_lines > 3:
            tier = "tier_3"
            is_complete = False
        else:
            tier = None  # Too small, skip
            is_complete = False
        
        return {
            "tier": tier,
            "is_complete": is_complete,
            "has_pragma": has_pragma,
            "has_contract": has_contract,
            "has_function": has_function,
            "balanced_braces": balanced_braces,
            "num_lines": num_lines
        }
    
    def save_contract(self, vulnerability_id: str, code: str, metadata: Dict, tier: str, 
                     vulnerability_title: str = None, recommendation_data: Dict = None, poc_data: Dict = None):
        """Save extracted contract and metadata."""
        # Add vulnerability title to metadata
        if vulnerability_title:
            metadata['vulnerability_title'] = vulnerability_title
        
        # Add recommendation data to metadata
        if recommendation_data:
            metadata['recommendation'] = recommendation_data
        
        # Add PoC data to metadata
        if poc_data:
            metadata['poc'] = poc_data
        
        # Determine output directory based on tier
        if tier == "tier_1":
            output_dir = TIER_1_DIR
        elif tier == "tier_2":
            output_dir = TIER_2_DIR
        else:
            output_dir = TIER_3_DIR
        
        # Generate filename
        if tier == "tier_1" and 'filename' in metadata:
            # For Tier 1, use format: {vulnerability_id}_{github_filename}
            github_filename = metadata['filename']
            if github_filename.endswith('.sol'):
                github_filename = github_filename[:-4]  # Remove .sol extension
            base_name = f"{vulnerability_id}_{github_filename}.sol"
        else:
            # For Tier 2 & 3, use vulnerability_id
            base_name = metadata.get('filename', f"{vulnerability_id}_contract")
            if not base_name.endswith('.sol'):
                base_name += '.sol'
        
        sol_path = output_dir / base_name
        json_path = output_dir / base_name.replace('.sol', '.json')
        
        # Handle duplicates with counter suffix
        if sol_path.exists():
            counter = 1
            base_name_no_ext = base_name.replace('.sol', '')
            while sol_path.exists():
                base_name = f"{base_name_no_ext}_{counter}.sol"
                sol_path = output_dir / base_name
                json_path = output_dir / base_name.replace('.sol', '.json')
                counter += 1
        
        # Save Solidity file
        with open(sol_path, 'w', encoding='utf-8') as f:
            f.write(code)
        
        # Save metadata
        metadata['extraction_date'] = datetime.now().isoformat()
        metadata['filename'] = str(sol_path.name)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"  ✅ Saved: {sol_path.name} ({tier})")
    
    def process_markdown_file(self, md_path: Path):
        """Process a single markdown file following the decision tree."""
        vulnerability_id = md_path.stem
        print(f"\n📄 Processing: {vulnerability_id}")
        
        self.stats['total_processed'] += 1
        
        # Extract title from markdown
        vulnerability_title = self.extract_title_from_markdown(md_path)
        
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"  ❌ Error reading file: {e}")
            self.log_failure(vulnerability_id, "file_read_error", str(e))
            return
        
        # Extract recommendations and PoC sections from markdown FIRST
        recommendation_data = self.extract_recommendations(content)
        poc_data = self.extract_poc(content)
        
        if recommendation_data['has_recommendation']:
            print(f"  📋 Found Recommendation section with {len(recommendation_data['fix_code_blocks'])} code block(s)")
        if poc_data['has_poc']:
            print(f"  🔬 Found PoC section with {len(poc_data['poc_code_blocks'])} code block(s)")
        
        # Remove Recommendation and PoC sections from content before extracting vulnerable code
        # This prevents mixing vulnerable code with fixes or exploits
        content_for_vulnerable_code = self.remove_recommendation_and_poc_sections(content)
        
        extracted = False
        github_attempted = False
        
        # PRIORITY 1: GitHub links to .sol files (download complete file, ignore line numbers)
        # For Tier 1: Download each UNIQUE .sol file only ONCE (not per URL)
        github_urls = self.extract_github_url(content)
        
        # Track unique files by their path to avoid duplicate downloads
        seen_github_files = set()
        all_line_refs = []  # Collect all line references for metadata
        
        for url in github_urls:
            github_info = self.parse_github_url(url)
            
            if github_info and github_info['is_sol_file']:
                # Create unique key for this file
                file_key = f"{github_info['owner']}/{github_info['repo']}/{github_info['branch']}/{github_info['path']}"
                
                # Track line references
                if github_info['line_start']:
                    all_line_refs.append([github_info['line_start'], github_info['line_end']])
                
                # Skip only if we already downloaded this exact file within the SAME vulnerability
                if file_key in seen_github_files:
                    print(f"  🔗 Duplicate URL in same vulnerability: {github_info['path']} (skipping)")
                    continue
                
                seen_github_files.add(file_key)
                github_attempted = True
                self.stats['github_attempted'] += 1
                
                lines_info = ""
                if github_info['line_start']:
                    lines_info = f" (ref lines {github_info['line_start']}-{github_info['line_end']})"
                print(f"  🔗 GitHub .sol: {github_info['path']}{lines_info}")
                
                # Download the COMPLETE file (ignore line numbers)
                code = self.download_github_file(github_info)
                
                if code:
                    self.stats['github_successful'] += 1
                    
                    github_filename = Path(github_info['path']).name
                    
                    # Track file references for statistics
                    if github_filename not in self.github_file_references:
                        self.github_file_references[github_filename] = []
                    self.github_file_references[github_filename].append({
                        'id': vulnerability_id,
                        'title': vulnerability_title,
                        'file_key': file_key
                    })
                    
                    metadata = {
                        "id": vulnerability_id,
                        "extraction_type": "github_complete",
                        "source_url": github_info['original_url'],
                        "is_complete": True,
                        "tier": "tier_1",
                        "referenced_lines": all_line_refs if all_line_refs else None,
                        "filename": github_filename
                    }
                    
                    quality = self.assess_code_quality(code)
                    metadata.update(quality)
                    
                    self.save_contract(vulnerability_id, code, metadata, "tier_1", vulnerability_title, 
                                      recommendation_data, poc_data)
                    self.stats['by_tier']['tier_1_github_complete'] += 1
                    self.stats['by_extraction_type']['github_complete'] += 1
                    self.stats['successful_extractions'] += 1
                    extracted = True
                    # Successfully downloaded - stop trying other URLs
                    break
        
        if extracted:
            return
        
        # PRIORITY 2: Extract code blocks from markdown content (excluding Recommendation/PoC sections)
        code_blocks = self.extract_code_blocks(content_for_vulnerable_code)
        
        if code_blocks:
            print(f"  📝 Found {len(code_blocks)} code block(s)")
            
            tier_2_blocks = []
            tier_3_blocks = []
            
            for idx, code in enumerate(code_blocks):
                quality = self.assess_code_quality(code)
                
                if quality['tier'] is None:
                    print(f"    ⚠️  Block {idx+1}: Too short, skipping")
                    continue
                
                if quality['tier'] == 'tier_2':
                    tier_2_blocks.append((idx, code, quality))
                elif quality['tier'] == 'tier_3':
                    tier_3_blocks.append((idx, code, quality))
            
            # Save tier 2 blocks individually (these are more complete)
            for idx, code, quality in tier_2_blocks:
                metadata = {
                    "id": vulnerability_id,
                    "extraction_type": "markdown_code_block",
                    "source": "markdown_content",
                    "block_index": idx,
                    **quality
                }
                
                self.save_contract(vulnerability_id, code, metadata, "tier_2", vulnerability_title,
                                  recommendation_data, poc_data)
                self.stats['by_tier']['tier_2_code_blocks'] += 1
                self.stats['by_extraction_type']['markdown_code_block'] += 1
                self.stats['successful_extractions'] += 1
                extracted = True
            
            # Combine ALL tier 3 blocks from the same finding into ONE file
            if tier_3_blocks:
                if len(tier_3_blocks) == 1:
                    # Single snippet - save normally
                    idx, code, quality = tier_3_blocks[0]
                    metadata = {
                        "id": vulnerability_id,
                        "extraction_type": "markdown_code_block",
                        "source": "markdown_content",
                        "block_index": idx,
                        "is_combined": False,
                        **quality
                    }
                    self.save_contract(vulnerability_id, code, metadata, "tier_3", vulnerability_title,
                                      recommendation_data, poc_data)
                    self.stats['by_tier']['tier_3_snippets'] += 1
                    self.stats['by_extraction_type']['markdown_code_block'] += 1
                    self.stats['successful_extractions'] += 1
                    extracted = True
                else:
                    # Multiple snippets - combine them
                    combined_code = ""
                    snippet_indices = []
                    total_lines = 0
                    
                    for idx, code, quality in tier_3_blocks:
                        snippet_indices.append(idx)
                        combined_code += f"// ========== Snippet {idx+1} ==========\n"
                        combined_code += code.strip() + "\n\n"
                        total_lines += quality['num_lines']
                    
                    print(f"    📦 Combining {len(tier_3_blocks)} tier 3 snippets into one file")
                    
                    # Assess combined quality
                    combined_quality = self.assess_code_quality(combined_code)
                    
                    metadata = {
                        "id": vulnerability_id,
                        "extraction_type": "markdown_code_block",
                        "source": "markdown_content",
                        "is_combined": True,
                        "num_snippets": len(tier_3_blocks),
                        "snippet_indices": snippet_indices,
                        "original_total_lines": total_lines,
                        **combined_quality
                    }
                    
                    self.save_contract(vulnerability_id, combined_code, metadata, "tier_3", vulnerability_title,
                                      recommendation_data, poc_data)
                    self.stats['by_tier']['tier_3_snippets'] += 1
                    self.stats['by_extraction_type']['markdown_code_block'] += 1
                    self.stats['successful_extractions'] += 1
                    extracted = True
        
        if extracted:
            return
        
        # PRIORITY 3: Extract inline code snippets (last resort, excluding Recommendation/PoC sections)
        # Look for function definitions in plain text and combine them
        function_pattern = r'function\s+\w+\s*\([^)]*\)[^{]*\{[^}]*\}'
        functions = re.findall(function_pattern, content_for_vulnerable_code, re.DOTALL)
        
        if functions:
            valid_snippets = []
            
            for idx, snippet in enumerate(functions):
                if len(snippet) >= 50:  # Filter out too short
                    valid_snippets.append((idx, snippet))
            
            if valid_snippets:
                print(f"  🔍 Found {len(valid_snippets)} inline snippet(s)")
                
                if len(valid_snippets) == 1:
                    # Single snippet - save normally
                    idx, snippet = valid_snippets[0]
                    quality = self.assess_code_quality(snippet)
                    
                    metadata = {
                        "id": vulnerability_id,
                        "extraction_type": "content_snippet",
                        "source": "inline_content",
                        "snippet_index": idx,
                        "is_combined": False,
                        **quality
                    }
                    
                    self.save_contract(vulnerability_id, snippet, metadata, "tier_3", vulnerability_title,
                                      recommendation_data, poc_data)
                    self.stats['by_tier']['tier_3_snippets'] += 1
                    self.stats['by_extraction_type']['content_snippet'] += 1
                    self.stats['successful_extractions'] += 1
                    extracted = True
                else:
                    # Multiple snippets - combine them
                    combined_code = ""
                    snippet_indices = []
                    
                    for idx, snippet in valid_snippets:
                        snippet_indices.append(idx)
                        combined_code += f"// ========== Inline Snippet {idx+1} ==========\n"
                        combined_code += snippet.strip() + "\n\n"
                    
                    print(f"    📦 Combining {len(valid_snippets)} inline snippets into one file")
                    
                    quality = self.assess_code_quality(combined_code)
                    
                    metadata = {
                        "id": vulnerability_id,
                        "extraction_type": "content_snippet",
                        "source": "inline_content",
                        "is_combined": True,
                        "num_snippets": len(valid_snippets),
                        "snippet_indices": snippet_indices,
                        **quality
                    }
                    
                    self.save_contract(vulnerability_id, combined_code, metadata, "tier_3", vulnerability_title,
                                      recommendation_data, poc_data)
                    self.stats['by_tier']['tier_3_snippets'] += 1
                    self.stats['by_extraction_type']['content_snippet'] += 1
                    self.stats['successful_extractions'] += 1
                    extracted = True
        
        if not extracted:
            print(f"  ❌ No code found")
            # Use enhanced failure reason determination
            reason, details = self.determine_failure_reason(vulnerability_id, content, github_urls)
            self.log_failure(vulnerability_id, reason, details)
    
    def log_failure(self, vulnerability_id: str, reason: str, details: str):
        """Log failed extraction."""
        self.stats['failed'] += 1
        if reason not in self.stats['failure_reasons']:
            self.stats['failure_reasons'][reason] = 0
        self.stats['failure_reasons'][reason] += 1
        
        self.failed_files.append({
            "id": vulnerability_id,
            "reason": reason,
            "details": details
        })
    
    def save_stats(self):
        """Save extraction statistics."""
        with open(STATS_FILE, 'w') as f:
            json.dump(self.stats, f, indent=2)
        
        with open(FAILED_LOG, 'w') as f:
            for failure in self.failed_files:
                f.write(f"{failure['id']}: {failure['reason']} - {failure['details']}\n")
        
        # Save shared file references
        self.save_shared_file_references()
        
        print(f"\n📊 Statistics saved to: {STATS_FILE}")
        print(f"📋 Failed extractions logged to: {FAILED_LOG}")
        if self.github_file_references:
            print(f"🔗 Shared file references saved to: {SHARED_FILES_JSON}")
    
    def save_shared_file_references(self):
        """Save information about GitHub files referenced by multiple vulnerabilities."""
        if not self.github_file_references:
            return
        
        # Prepare data for JSON export
        shared_files_data = {
            "total_github_files": len(self.github_file_references),
            "files_with_multiple_refs": sum(1 for refs in self.github_file_references.values() if len(refs) > 1),
            "files_with_single_ref": sum(1 for refs in self.github_file_references.values() if len(refs) == 1),
            "files": {}
        }
        
        # Sort files by number of references
        sorted_files = sorted(self.github_file_references.items(), 
                            key=lambda x: len(x[1]), reverse=True)
        
        for filename, refs in sorted_files:
            shared_files_data["files"][filename] = {
                "reference_count": len(refs),
                "vulnerabilities": [
                    {
                        "id": ref['id'],
                        "title": ref['title'],
                        "file_key": ref['file_key']
                    }
                    for ref in refs
                ]
            }
        
        with open(SHARED_FILES_JSON, 'w', encoding='utf-8') as f:
            json.dump(shared_files_data, f, indent=2, ensure_ascii=False)
    
    def print_summary(self):
        """Print extraction summary."""
        print("\n" + "="*60)
        print("📊 EXTRACTION SUMMARY")
        print("="*60)
        print(f"Total processed: {self.stats['total_processed']}")
        print(f"Successful: {self.stats['successful_extractions']}")
        print(f"Failed: {self.stats['failed']}")
        
        if self.stats['github_attempted'] > 0:
            success_rate = (self.stats['github_successful'] / self.stats['github_attempted']) * 100
            print(f"\nGitHub Downloads:")
            print(f"  Attempted: {self.stats['github_attempted']}")
            print(f"  Successful: {self.stats['github_successful']} ({success_rate:.1f}%)")
            print(f"  Failed: {self.stats['github_attempted'] - self.stats['github_successful']}")
        
        print(f"\nBy Tier:")
        for tier, count in self.stats['by_tier'].items():
            print(f"  {tier}: {count}")
        print(f"\nBy Extraction Type:")
        for ext_type, count in self.stats['by_extraction_type'].items():
            print(f"  {ext_type}: {count}")
        if self.stats['failure_reasons']:
            print(f"\nFailure Reasons:")
            for reason, count in self.stats['failure_reasons'].items():
                print(f"  {reason}: {count}")
        
        # Print files referenced by multiple vulnerabilities
        self.print_shared_file_references()
        
        print("="*60)
    
    def print_shared_file_references(self):
        """Print statistics about GitHub files referenced by multiple vulnerabilities."""
        if not self.github_file_references:
            return
        
        # Find files referenced by multiple vulnerabilities
        multi_ref_files = {filename: refs for filename, refs in self.github_file_references.items() 
                          if len(refs) > 1}
        
        if multi_ref_files:
            print(f"\n📊 GitHub Files Referenced by Multiple Vulnerabilities:")
            print(f"   (Total: {len(multi_ref_files)} files shared across vulnerabilities)\n")
            
            # Sort by number of references (descending)
            sorted_files = sorted(multi_ref_files.items(), key=lambda x: len(x[1]), reverse=True)
            
            for filename, refs in sorted_files:
                print(f"  📄 {filename} ({len(refs)} vulnerabilities):")
                for ref in refs:
                    title_preview = ref['title'][:70] + "..." if len(ref['title']) > 70 else ref['title']
                    print(f"     • {ref['id']}: {title_preview}")
                print()  # Empty line between files
        else:
            print(f"\n✅ No GitHub files are shared across multiple vulnerabilities")
    
    def run(self):
        """Run extraction on all markdown files."""
        md_files = sorted(MARKDOWN_DIR.glob("*.md"))
        
        if not md_files:
            print(f"❌ No markdown files found in {MARKDOWN_DIR}")
            return
        
        print(f"🚀 Starting extraction on {len(md_files)} files")
        print(f"📁 Output directory: {OUTPUT_DIR}")
        
        for md_path in md_files:
            self.process_markdown_file(md_path)
        
        self.print_summary()
        self.save_stats()


def main():
    extractor = ContractExtractor()
    extractor.run()


if __name__ == "__main__":
    main()
