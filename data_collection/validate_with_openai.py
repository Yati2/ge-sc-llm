#!/usr/bin/env python3
import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import openai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration (loaded from .env with defaults)
CONFIG = {
    'model': os.getenv('OPENAI_MODEL'),
    'max_code_length': int(os.getenv('OPENAI_MAX_CODE_LENGTH')),
    'max_content_length': int(os.getenv('OPENAI_MAX_CONTENT_LENGTH')),
    'temperature': float(os.getenv('OPENAI_TEMPERATURE')),
    'rate_limit_delay': float(os.getenv('OPENAI_RATE_LIMIT_DELAY')),
    'retry_attempts': int(os.getenv('OPENAI_RETRY_ATTEMPTS')),
    'confidence_thresholds': {
        'high': int(os.getenv('CONFIDENCE_HIGH')),
        'medium': int(os.getenv('CONFIDENCE_MEDIUM')),
        'low': int(os.getenv('CONFIDENCE_LOW'))
    }
}

# Paths
FINDINGS_JSON = Path("solodit_sequential_findings.json")
EXTRACTED_DIR = Path("extracted_contracts")
VALIDATION_DIR = Path("validation_results")

# MANDO category definitions
MANDO_CATEGORIES = {
    "access_control": "G5 - Authorization, permissions, role management issues",
    "arithmetic": "G7 - Mathematical operations, overflow/underflow, precision issues",
    "denial_of_service": "G8 - Resource exhaustion, unbounded loops, gas limit issues",
    "front_running": "G4 - Transaction ordering, MEV, sandwich attacks",
    "reentrancy": "G6 - Cross-contract call vulnerabilities, external calls before state updates",
    "time_manipulation": "G9 - Block timestamp/number dependency issues",
    "unchecked_low_level_calls": "G6/I1 - Unchecked send/call/delegatecall, missing return checks"
}

# SCSVS (Smart Contract Security Verification Standard) Categories
# Source: https://github.com/ComposableSecurity/SCSVS
SCSVS_CATEGORIES = {
    # G: General
    "G1": "Architecture, design and threat modeling",
    "G2": "Policies and procedures",
    "G3": "Upgradeability",
    "G4": "Business logic",
    "G5": "Access control",
    "G6": "Communications",
    "G7": "Arithmetic",
    "G8": "Denial of service",
    "G9": "Blockchain data",
    "G10": "Gas usage & limitations",
    "G11": "Code clarity",
    "G12": "Test coverage",
    # C: Components
    "C1": "Token",
    "C2": "Governance",
    "C3": "Oracle",
    "C4": "Vault",
    "C5": "Bridge",
    "C6": "NFT",
    "C7": "Liquid staking",
    "C8": "Liquidity pool",
    "C9": "Uniswap V4 Hook",
    # I: Integrations
    "I1": "Basic",
    "I2": "Token",
    "I3": "Oracle",
    "I4": "Cross-Chain"
}


class ValidationStats:
    """Track validation statistics."""
    
    def __init__(self):
        self.total = 0
        self.by_tier = {'tier_1': {}, 'tier_2': {}, 'tier_3': {}}
        self.mando_distribution = {}
        self.scsvs_distribution = {}
        self.classification_preference = {'mando_only': 0, 'scsvs_only': 0, 'both': 0, 'scsvs_preferred': 0}
        self.tag_validation = {'correct': 0, 'incorrect': 0, 'missing': 0}
        self.consistency = {'high': 0, 'medium': 0, 'low': 0}
        self.fix_code_stats = {'provided': 0, 'generated': 0, 'none': 0}
        self.issues = {
            'incorrect_tags': [],
            'missing_tags': [],
            'content_mismatches': [],
            'high_confidence': [],
            'fix_code_generated': []
        }


class ContractValidator:
    """Validates extracted contracts using OpenAI API."""
    
    def __init__(self, api_key: str):
        self.client = openai.OpenAI(api_key=api_key)
        self.stats = ValidationStats()
        
        # Load findings data
        with open(FINDINGS_JSON, 'r') as f:
            self.findings = {str(item['id']): item for item in json.load(f)}
        
        # Create output directory
        VALIDATION_DIR.mkdir(exist_ok=True)
    
    def truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to max length."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."
    
    def get_system_prompt(self) -> str:
        """Get system prompt for OpenAI."""
        return """You are an expert smart contract security auditor with deep knowledge of Solidity vulnerabilities and the SCSVS (Smart Contract Security Verification Standard).

Your task is to validate extracted Solidity code against vulnerability reports and classify vulnerabilities using both MANDO categories and SCSVS categories.

IMPORTANT: 
- First try to map to MANDO categories (legacy 7 categories)
- If MANDO categories are not sufficient or relevant, suggest appropriate SCSVS categories
- SCSVS provides more granular classification with General (G), Components (C), and Integrations (I) categories

Respond ONLY with valid JSON. Be precise and concise in your reasoning."""
    
    def get_user_prompt(self, vuln_id: str, title: str, summary: str, content: str, 
                       impact: str, existing_tag: Optional[str], code: str, tier: str) -> str:
        """Generate user prompt for validation."""
        
        content_truncated = self.truncate_text(content, CONFIG['max_content_length'])
        code_truncated = self.truncate_text(code, CONFIG['max_code_length'])
        
        mando_desc = "\n".join([f"  - {k}: {v}" for k, v in MANDO_CATEGORIES.items()])
        scsvs_desc = "\n".join([f"  - {k}: {v}" for k, v in SCSVS_CATEGORIES.items()])
        
        return f"""# Vulnerability Report Analysis

## Report Details
- ID: {vuln_id}
- Title: {title}
- Impact: {impact}
- Summary: {summary}
- Content: {content_truncated}
- Existing Tag: {existing_tag or "None"}

## Extracted Solidity Code ({tier})
```solidity
{code_truncated}
```

# Tasks

## Task 1: Content-Code Consistency Validation
Analyze if the extracted code contains the vulnerability described in the report.
- Does the summary accurately describe issues in this code?
- Does the content mention functions/variables that exist in the code?
- Are the described vulnerable patterns present?

## Task 2: Report Tag Validation
Current tag: "{existing_tag or "None"}"
- If tag exists: Is it correct? Provide detailed reasoning if incorrect.
- If missing: What should the tag be?

## Task 3: Vulnerability Classification

### Option A: MANDO Categories (Legacy - 7 categories)
{mando_desc}

### Option B: SCSVS Categories (Preferred if MANDO isn't sufficient)
{scsvs_desc}

**Instructions:**
- Primary: Try to map to MANDO categories first (for backward compatibility)
- If MANDO categories are not relevant or specific enough, use SCSVS categories
- You can map to both MANDO and SCSVS for comprehensive classification
- SCSVS provides more granular categorization especially for component-specific and integration issues

# Response Format (JSON only)

{{
  "content_code_consistency": {{
    "consistent": true/false,
    "confidence": 0-100,
    "summary_matches": true/false,
    "content_matches": true/false,
    "summary_reasoning": "explanation",
    "content_reasoning": "explanation",
    "functions_found": ["func1", "func2"],
    "variables_found": ["var1", "var2"],
    "patterns_found": ["pattern1", "pattern2"],
    "issues": ["issue1 if any"]
  }},
  "report_tag_validation": {{
    "existing_tag": "{existing_tag or 'null'}",
    "tag_present": true/false,
    "tag_correct": true/false/null,
    "confidence": 0-100,
    "reasoning": "detailed explanation",
    "suggested_tag": "tag_name",
    "alternative_tags": ["tag2"],
    "correction_explanation": "explanation"
  }},
  "mando_classification": {{
    "primary_category": "category_name or null if not applicable",
    "secondary_categories": ["cat2"],
    "confidence": 0-100,
    "mando_applicable": true/false,
    "reasoning": "why MANDO category was chosen or why not applicable"
  }},
  "scsvs_classification": {{
    "primary_category": "category_code (e.g., G1, C3, I2)",
    "primary_category_name": "full category name",
    "secondary_categories": ["G7", "C1"],
    "confidence": 0-100,
    "use_scsvs_instead": true/false,
    "reasoning": "detailed explanation of SCSVS mapping",
    "vulnerability_type": "brief description"
  }},
  "severity_assessment": {{
    "reported_severity": "{impact}",
    "severity_justified": true/false,
    "reasoning": "explanation"
  }}
}}"""
    
    def call_openai(self, system_prompt: str, user_prompt: str) -> Dict:
        """Call OpenAI API with retry logic."""
        
        for attempt in range(CONFIG['retry_attempts']):
            try:
                response = self.client.chat.completions.create(
                    model=CONFIG['model'],
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=CONFIG['temperature'],
                    response_format={"type": "json_object"}
                )
                
                result = json.loads(response.choices[0].message.content)
                return result
                
            except json.JSONDecodeError as e:
                print(f"  Warning: JSON parse error (attempt {attempt+1}/{CONFIG['retry_attempts']}): {e}")
                if attempt == CONFIG['retry_attempts'] - 1:
                    raise
                time.sleep(2)
                
            except Exception as e:
                print(f"  Warning: API error (attempt {attempt+1}/{CONFIG['retry_attempts']}): {e}")
                if attempt == CONFIG['retry_attempts'] - 1:
                    raise
                time.sleep(2)
    
    def generate_fix_code(self, vuln_id: str, title: str, summary: str, 
                         recommendation_text: str, vulnerable_code: str, 
                         vulnerability_type: str) -> Dict:
        """Generate fix code when recommendation doesn't provide it."""
        
        system_prompt = """You are an expert Solidity developer and security auditor.

Your task is to generate secure, fixed code based on a vulnerability report and recommendation.

Provide ONLY valid JSON with the fixed code and explanation."""
        
        code_truncated = self.truncate_text(vulnerable_code, CONFIG['max_code_length'])
        
        user_prompt = f"""# Fix Code Generation

## Vulnerability Details
- ID: {vuln_id}
- Title: {title}
- Summary: {summary}
- Type: {vulnerability_type}

## Vulnerable Code
```solidity
{code_truncated}
```

## Recommendation
{recommendation_text}

# Task

Generate secure fixed code that addresses the vulnerability described above.

**Requirements:**
1. Generate complete, compilable Solidity code
2. Include inline comments explaining the fixes
3. Maintain the original function signatures and logic flow
4. Apply security best practices
5. If the vulnerable code is a snippet, provide the fixed snippet with surrounding context

# Response Format (JSON only)

{{
  "has_fix": true,
  "fix_approach": "brief description of the fix strategy",
  "fix_code": "complete fixed solidity code with inline comments",
  "key_changes": ["change1", "change2", "change3"],
  "security_improvements": ["improvement1", "improvement2"],
  "additional_recommendations": "any additional security advice",
  "confidence": 0-100
}}
"""
        
        try:
            result = self.call_openai(system_prompt, user_prompt)
            result['generated_by'] = 'openai'
            result['generation_date'] = datetime.now().isoformat()
            return result
        except Exception as e:
            print(f"  Warning: Fix code generation failed: {e}")
            return {
                "has_fix": false,
                "error": str(e),
                "generated_by": 'openai',
                "generation_date": datetime.now().isoformat()
            }
    
    def validate_contract(self, json_path: Path) -> Optional[Dict]:
        """Validate a single contract file."""
        
        # Load metadata
        with open(json_path, 'r') as f:
            metadata = json.load(f)
        
        vuln_id = metadata['id']
        tier = metadata['tier']
        
        # Get vulnerability report
        if vuln_id not in self.findings:
            print(f"  Warning: No report found for ID {vuln_id}")
            return None
        
        report = self.findings[vuln_id]
        
        # Load extracted code
        sol_path = json_path.with_suffix('.sol')
        if not sol_path.exists():
            print(f"  Warning: .sol file not found for {vuln_id}")
            return None
        
        with open(sol_path, 'r') as f:
            code = f.read()
        
        # Extract existing tag
        existing_tag = None
        tag_scores = report.get('issues_issuetagscore', [])
        if tag_scores and len(tag_scores) > 0:
            if 'tags_tag' in tag_scores[0] and 'title' in tag_scores[0]['tags_tag']:
                existing_tag = tag_scores[0]['tags_tag']['title']
        
        # Create prompts
        system_prompt = self.get_system_prompt()
        user_prompt = self.get_user_prompt(
            vuln_id=vuln_id,
            title=report['title'],
            summary=report['summary'],
            content=report['content'],
            impact=report['impact'],
            existing_tag=existing_tag,
            code=code,
            tier=tier
        )
        
        # Call OpenAI
        validation_results = self.call_openai(system_prompt, user_prompt)
        
        # Check if fix code needs to be generated
        recommendation_data = metadata.get('recommendation', {})
        has_recommendation = recommendation_data.get('has_recommendation', False)
        has_fix_code = bool(recommendation_data.get('fix_code_blocks', []))
        
        if has_recommendation and not has_fix_code:
            # Generate fix code
            print(f"  🛠️  Generating fix code...")
            vulnerability_type = validation_results.get('scsvs_classification', {}).get('vulnerability_type', '') or \
                               validation_results.get('mando_classification', {}).get('primary_category', '')
            
            fix_code = self.generate_fix_code(
                vuln_id=vuln_id,
                title=report['title'],
                summary=report['summary'],
                recommendation_text=recommendation_data.get('recommendation_text', ''),
                vulnerable_code=code,
                vulnerability_type=vulnerability_type
            )
            
            validation_results['generated_fix'] = fix_code
            validation_results['fix_code_source'] = 'generated'
        elif has_fix_code:
            validation_results['fix_code_source'] = 'provided'
        else:
            validation_results['fix_code_source'] = 'none'
        
        # Add metadata
        validation_results['validated_at'] = datetime.now().isoformat()
        validation_results['model'] = CONFIG['model']
        
        return validation_results
    
    def augment_metadata(self, json_path: Path, validation_results: Dict):
        """Add validation results to metadata JSON."""
        
        with open(json_path, 'r') as f:
            metadata = json.load(f)
        
        metadata['validation'] = validation_results
        
        with open(json_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def update_statistics(self, metadata: Dict, validation: Dict):
        """Update validation statistics."""
        
        self.stats.total += 1
        tier = metadata['tier']
        vuln_id = metadata['id']
        
        # Consistency confidence
        consistency_conf = validation['content_code_consistency']['confidence']
        if consistency_conf >= CONFIG['confidence_thresholds']['high']:
            self.stats.consistency['high'] += 1
        elif consistency_conf >= CONFIG['confidence_thresholds']['medium']:
            self.stats.consistency['medium'] += 1
        else:
            self.stats.consistency['low'] += 1
        
        # MANDO distribution
        mando_cat = validation['mando_classification']
        if mando_cat.get('mando_applicable') and mando_cat.get('primary_category'):
            primary = mando_cat['primary_category']
            self.stats.mando_distribution[primary] = self.stats.mando_distribution.get(primary, 0) + 1
        
        # SCSVS distribution
        scsvs_cat = validation.get('scsvs_classification', {})
        if scsvs_cat.get('primary_category'):
            scsvs_primary = scsvs_cat['primary_category']
            self.stats.scsvs_distribution[scsvs_primary] = self.stats.scsvs_distribution.get(scsvs_primary, 0) + 1
        
        # Track classification preference
        has_mando = mando_cat.get('mando_applicable', False)
        has_scsvs = bool(scsvs_cat.get('primary_category'))
        use_scsvs_instead = scsvs_cat.get('use_scsvs_instead', False)
        
        if has_mando and not has_scsvs:
            self.stats.classification_preference['mando_only'] += 1
        elif has_scsvs and (not has_mando or use_scsvs_instead):
            self.stats.classification_preference['scsvs_preferred'] += 1
        elif has_scsvs and not has_mando:
            self.stats.classification_preference['scsvs_only'] += 1
        elif has_mando and has_scsvs:
            self.stats.classification_preference['both'] += 1
        
        # Track fix code statistics
        fix_source = validation.get('fix_code_source', 'none')
        if fix_source == 'provided':
            self.stats.fix_code_stats['provided'] += 1
        elif fix_source == 'generated':
            self.stats.fix_code_stats['generated'] += 1
            self.stats.issues['fix_code_generated'].append({
                'id': vuln_id,
                'filename': metadata['filename'],
                'tier': tier,
                'confidence': validation.get('generated_fix', {}).get('confidence', 0)
            })
        else:
            self.stats.fix_code_stats['none'] += 1
        
        # Tag validation
        tag_val = validation['report_tag_validation']
        if tag_val['tag_present']:
            if tag_val['tag_correct']:
                self.stats.tag_validation['correct'] += 1
            else:
                self.stats.tag_validation['incorrect'] += 1
                self.stats.issues['incorrect_tags'].append({
                    'id': vuln_id,
                    'filename': metadata['filename'],
                    'tier': tier,
                    'existing_tag': tag_val['existing_tag'],
                    'suggested_tag': tag_val['suggested_tag'],
                    'confidence': tag_val['confidence'],
                    'reasoning': tag_val['reasoning'],
                    'correction_explanation': tag_val['correction_explanation']
                })
        else:
            self.stats.tag_validation['missing'] += 1
            self.stats.issues['missing_tags'].append({
                'id': vuln_id,
                'filename': metadata['filename'],
                'tier': tier,
                'suggested_tag': tag_val['suggested_tag'],
                'confidence': validation['mando_classification']['confidence'],
                'reasoning': tag_val['reasoning'],
                'correction_explanation': tag_val['correction_explanation']
            })
        
        # Content mismatches
        if not validation['content_code_consistency']['consistent']:
            self.stats.issues['content_mismatches'].append({
                'id': vuln_id,
                'filename': metadata['filename'],
                'tier': tier,
                'consistency_confidence': consistency_conf,
                'issues': validation['content_code_consistency']['issues'],
                'summary_reasoning': validation['content_code_consistency']['summary_reasoning'],
                'content_reasoning': validation['content_code_consistency']['content_reasoning'],
                'recommendation': 'Manual review required'
            })
        
        # High confidence validations
        classification_conf = max(
            validation['mando_classification'].get('confidence', 0),
            validation.get('scsvs_classification', {}).get('confidence', 0)
        )
        if consistency_conf >= 80 and classification_conf >= 80:
            self.stats.issues['high_confidence'].append({
                'id': vuln_id,
                'filename': metadata['filename'],
                'tier': tier,
                'consistency_confidence': consistency_conf,
                'classification_confidence': classification_conf,
                'status': 'Validated'
            })
    
    def process_all_contracts(self, test_mode: bool = False, max_files: int = 5):
        """Process all extracted contracts."""
        
        # Gather all metadata JSON files
        all_files = []
        for tier_dir in ['tier_1_complete', 'tier_2_code_blocks', 'tier_3_snippets']:
            tier_path = EXTRACTED_DIR / tier_dir
            if tier_path.exists():
                all_files.extend(tier_path.glob('*.json'))
        
        # Filter out non-contract metadata
        contract_files = [f for f in all_files if not f.stem.endswith('_stats') and f.stem != 'extraction_stats']
        
        if test_mode:
            contract_files = contract_files[:max_files]
            print(f"TEST MODE: Processing {len(contract_files)} files")
        
        print(f"\n{'='*60}")
        print(f"VALIDATING EXTRACTED CONTRACTS")
        print(f"{'='*60}\n")
        
        for idx, json_path in enumerate(contract_files, 1):
            try:
                with open(json_path, 'r') as f:
                    metadata = json.load(f)
                
                vuln_id = metadata['id']
                filename = metadata.get('filename', json_path.stem + '.sol')
                tier = metadata['tier']
                
                print(f"[{idx}/{len(contract_files)}] Processing: {filename} ({tier}, id: {vuln_id})")
                
                # Validate
                validation_results = self.validate_contract(json_path)
                
                if validation_results:
                    # Augment metadata
                    self.augment_metadata(json_path, validation_results)
                    
                    # Update statistics
                    self.update_statistics(metadata, validation_results)
                    
                    # Print summary
                    consistency = validation_results['content_code_consistency']
                    tag_val = validation_results['report_tag_validation']
                    mando = validation_results['mando_classification']
                    
                    status = "CONSISTENT" if consistency['consistent'] else "MISMATCH"
                    print(f"  Content-Code: {status} ({consistency['confidence']}% confidence)")
                    
                    if tag_val['tag_present']:
                        tag_status = "CORRECT" if tag_val['tag_correct'] else "INCORRECT"
                        if not tag_val['tag_correct']:
                            print(f"  Report Tag: {tag_status} - \"{tag_val['existing_tag']}\" -> should be \"{tag_val['suggested_tag']}\"")
                        else:
                            print(f"  Report Tag: {tag_status} - \"{tag_val['existing_tag']}\"")
                    else:
                        print(f"  Report Tag: MISSING -> suggested \"{tag_val['suggested_tag']}\"")
                    
                    # Display classification
                    mando_cat = validation_results['mando_classification']
                    scsvs_cat = validation_results.get('scsvs_classification', {})
                    
                    if mando_cat.get('mando_applicable'):
                        print(f"  MANDO: {mando_cat['primary_category']} ({mando_cat['confidence']}%)")
                    
                    if scsvs_cat.get('primary_category'):
                        scsvs_display = f"{scsvs_cat['primary_category']}: {scsvs_cat.get('primary_category_name', '')}"
                        preferred_marker = " [PREFERRED]" if scsvs_cat.get('use_scsvs_instead') else ""
                        print(f"  SCSVS: {scsvs_display} ({scsvs_cat['confidence']}%){preferred_marker}")
                    
                    # Display fix code generation status
                    fix_source = validation_results.get('fix_code_source', 'none')
                    if fix_source == 'generated':
                        fix_conf = validation_results.get('generated_fix', {}).get('confidence', 0)
                        print(f"  🛠️  Fix code generated ({fix_conf}% confidence)")
                    elif fix_source == 'provided':
                        print(f"  ✅ Fix code provided in recommendation")
                    
                    print(f"  Metadata augmented\n")
                
                # Rate limiting
                time.sleep(CONFIG['rate_limit_delay'])
                
            except Exception as e:
                print(f"  Error processing {json_path.name}: {e}\n")
                continue
        
        # Generate reports
        self.generate_reports()
    
    def generate_reports(self):
        """Generate summary reports."""
        
        print(f"\n{'='*60}")
        print(f"VALIDATION SUMMARY")
        print(f"{'='*60}\n")
        
        print(f"Total Validated: {self.stats.total} files\n")
        
        print(f"Content-Code Consistency:")
        print(f"  High Confidence (>80%): {self.stats.consistency['high']} files")
        print(f"  Medium (50-80%): {self.stats.consistency['medium']} files")
        print(f"  Low (<50%): {self.stats.consistency['low']} files\n")
        
        print(f"Report Tag Validation:")
        print(f"  Correct: {self.stats.tag_validation['correct']} files")
        print(f"  Incorrect: {self.stats.tag_validation['incorrect']} files")
        print(f"  Missing: {self.stats.tag_validation['missing']} files\n")
        
        print(f"MANDO Category Distribution:")
        if self.stats.mando_distribution:
            for cat, count in sorted(self.stats.mando_distribution.items(), key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {count}")
        else:
            print(f"  No MANDO classifications")
        
        print(f"\nSCSVS Category Distribution:")
        if self.stats.scsvs_distribution:
            for cat, count in sorted(self.stats.scsvs_distribution.items(), key=lambda x: x[1], reverse=True):
                cat_name = SCSVS_CATEGORIES.get(cat, "Unknown")
                print(f"  {cat} ({cat_name}): {count}")
        else:
            print(f"  No SCSVS classifications")
        
        print(f"\nClassification Preference:")
        print(f"  MANDO only: {self.stats.classification_preference['mando_only']}")
        print(f"  SCSVS preferred: {self.stats.classification_preference['scsvs_preferred']}")
        print(f"  Both classifications: {self.stats.classification_preference['both']}")
        print(f"  SCSVS only: {self.stats.classification_preference['scsvs_only']}")
        
        print(f"\nFix Code Generation:")
        print(f"  Provided in recommendations: {self.stats.fix_code_stats['provided']}")
        print(f"  AI-generated: {self.stats.fix_code_stats['generated']}")
        print(f"  No fix code: {self.stats.fix_code_stats['none']}")
        
        print(f"\nIssues Found:")
        print(f"  {len(self.stats.issues['incorrect_tags'])} incorrect tags")
        print(f"  {len(self.stats.issues['content_mismatches'])} content mismatches")
        print(f"  {len(self.stats.issues['missing_tags'])} missing tags")
        print(f"  {len(self.stats.issues['fix_code_generated'])} fix codes generated")
        
        # Save reports
        with open(VALIDATION_DIR / 'validation_summary.json', 'w') as f:
            json.dump({
                'total_validated': self.stats.total,
                'consistency': self.stats.consistency,
                'tag_validation': self.stats.tag_validation,
                'mando_distribution': self.stats.mando_distribution,
                'scsvs_distribution': self.stats.scsvs_distribution,
                'classification_preference': self.stats.classification_preference,
                'fix_code_stats': self.stats.fix_code_stats
            }, f, indent=2)
        
        with open(VALIDATION_DIR / 'validation_issues.json', 'w') as f:
            json.dump(self.stats.issues, f, indent=2)
        
        # Category mapping
        category_map = {}
        for item in self.stats.issues['high_confidence']:
            category_map[item['id']] = {
                'filename': item['filename'],
                'tier': item['tier'],
                'confidence': item['confidence']
            }
        
        with open(VALIDATION_DIR / 'category_mapping.json', 'w') as f:
            json.dump(category_map, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"Output Files:")
        print(f"  {VALIDATION_DIR / 'validation_summary.json'}")
        print(f"  {VALIDATION_DIR / 'validation_issues.json'}")
        print(f"  {VALIDATION_DIR / 'category_mapping.json'}")
        print(f"  All .json metadata files augmented")
        print(f"{'='*60}\n")


def main():
    """Main execution."""
    
    # Get API key
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("Error: OPENAI_API_KEY not found in .env file")
        print("Please add your API key to .env file (see .env.example for reference)")
        return
    
    # Create validator
    validator = ContractValidator(api_key)
    
    # Run in test mode or full mode
    import sys
    test_mode = '--test' in sys.argv
    
    if test_mode:
        validator.process_all_contracts(test_mode=True, max_files=5)
    else:
        validator.process_all_contracts(test_mode=False)


if __name__ == "__main__":
    main()
