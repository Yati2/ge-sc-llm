#!/usr/bin/env python3
"""
Data Analysis Script - Survey markdown files before extraction
Helps understand what kind of data you have.
"""

import re
from pathlib import Path
from collections import defaultdict

MARKDOWN_DIR = Path("downloaded_findings")


def analyze_markdown_files():
    """Analyze all markdown files and provide statistics."""
    md_files = sorted(p for p in MARKDOWN_DIR.rglob("*.md") if p.is_file())
    
    if not md_files:
        print(f"❌ No markdown files found in {MARKDOWN_DIR}")
        return
    
    print(f"🔍 Analyzing {len(md_files)} markdown files...")
    print("="*60)
    
    stats = {
        'total_files': len(md_files),
        'has_github_sol_link': 0,
        'has_github_with_lines': 0,
        'has_github_any': 0,
        'has_code_blocks': 0,
        'has_inline_code': 0,
        'no_code_found': 0,
        'code_block_sizes': [],
        'github_urls': [],
        'unique_github_files': set(),
        'total_github_links': 0
    }
    
    samples = {
        'github_sol': [],
        'code_blocks': [],
        'snippets': []
    }
    
    for md_path in md_files:
        try:
            with open(md_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"⚠️  Error reading {md_path.name}: {e}")
            continue
        
        file_id = md_path.stem
        has_code = False
        
        # Check for GitHub links - UPDATED to match extract_contracts.py
        # Handles both #L123 and # L123 (with space)
        github_pattern = r'https://github\.com/[\w\-./]+\.sol(?:#\s*L\d+(?:-L\d+)?)?'
        github_urls = re.findall(github_pattern, content)
        
        if github_urls:
            stats['has_github_any'] += 1
            for url in github_urls:
                stats['total_github_links'] += 1
                stats['github_urls'].append(url)
                
                # Extract unique file path (owner/repo/branch/path)
                file_match = re.search(r'github\.com/([^/]+/[^/]+/blob/[^/]+/[\w\-./]+\.sol)', url)
                if file_match:
                    stats['unique_github_files'].add(file_match.group(1))
                
                if '.sol' in url:
                    stats['has_github_sol_link'] += 1
                    has_code = True
                    if len(samples['github_sol']) < 3:
                        samples['github_sol'].append((file_id, url[:100]))
                if '#' in url and 'L' in url:
                    stats['has_github_with_lines'] += 1
        
        # Check for code blocks
        code_block_pattern = r'```(?:solidity|sol)?\n(.*?)```'
        code_blocks = re.findall(code_block_pattern, content, re.DOTALL)
        
        if code_blocks:
            stats['has_code_blocks'] += 1
            has_code = True
            for block in code_blocks:
                num_lines = len(block.strip().split('\n'))
                stats['code_block_sizes'].append(num_lines)
                if len(samples['code_blocks']) < 3:
                    samples['code_blocks'].append((file_id, num_lines, block[:200]))
        
        # Check for inline function snippets
        function_pattern = r'function\s+\w+\s*\([^)]*\)'
        if re.search(function_pattern, content):
            stats['has_inline_code'] += 1
            has_code = True
            if len(samples['snippets']) < 3:
                match = re.search(function_pattern, content)
                samples['snippets'].append((file_id, match.group()[:100]))
        
        if not has_code:
            stats['no_code_found'] += 1
    
    # Print results
    print(f"\n📊 ANALYSIS RESULTS")
    print("="*60)
    print(f"Total files: {stats['total_files']}")
    print(f"\n🔗 GitHub Links:")
    print(f"  Files with GitHub .sol links: {stats['has_github_sol_link']} ({stats['has_github_sol_link']/stats['total_files']*100:.1f}%)")
    print(f"  Total .sol links found: {stats['total_github_links']}")
    print(f"  Unique .sol files: {len(stats['unique_github_files'])} (Tier 1 will deduplicate)")
    print(f"  Files with GitHub line refs (#L): {stats['has_github_with_lines']} ({stats['has_github_with_lines']/stats['total_files']*100:.1f}%)")
    print(f"  Files with any GitHub link: {stats['has_github_any']} ({stats['has_github_any']/stats['total_files']*100:.1f}%)")
    
    print(f"\n📝 Code Blocks:")
    print(f"  Files with code blocks: {stats['has_code_blocks']} ({stats['has_code_blocks']/stats['total_files']*100:.1f}%)")
    if stats['code_block_sizes']:
        avg_size = sum(stats['code_block_sizes']) / len(stats['code_block_sizes'])
        min_size = min(stats['code_block_sizes'])
        max_size = max(stats['code_block_sizes'])
        print(f"  Code block sizes: avg={avg_size:.1f}, min={min_size}, max={max_size} lines")
    
    print(f"\n🔍 Inline Code:")
    print(f"  Files with function snippets: {stats['has_inline_code']} ({stats['has_inline_code']/stats['total_files']*100:.1f}%)")
    
    print(f"\n❌ No Code:")
    print(f"  Files with no extractable code: {stats['no_code_found']} ({stats['no_code_found']/stats['total_files']*100:.1f}%)")
    
    # Show samples
    print(f"\n📋 SAMPLES")
    print("="*60)
    
    if samples['github_sol']:
        print(f"\n🔗 GitHub .sol Link Examples:")
        for file_id, url in samples['github_sol'][:3]:
            print(f"  [{file_id}] {url[:80]}...")
    
    if samples['code_blocks']:
        print(f"\n📝 Code Block Examples:")
        for file_id, num_lines, preview in samples['code_blocks'][:3]:
            print(f"  [{file_id}] {num_lines} lines")
            print(f"    Preview: {preview[:100]}...")
    
    if samples['snippets']:
        print(f"\n🔍 Inline Snippet Examples:")
        for file_id, snippet in samples['snippets'][:3]:
            print(f"  [{file_id}] {snippet}...")
    
    # Recommendations
    print(f"\n💡 EXTRACTION BEHAVIOR")
    print("="*60)
    print("Tier 1 (Complete GitHub files):")
    print("  - Deduplicates: Each unique .sol file downloaded only once")
    print("  - Stops after first successful download per file")
    print("  - Handles 404s and rate limits with retries")
    
    print("\nTier 2 (Code blocks):")
    print("  - Extracts Solidity code blocks from markdown")
    print("  - Requires: pragma + contract + balanced braces + >20 lines")
    
    print("\nTier 3 (Snippets):")
    print("  - Combines all snippets from same file into ONE .sol")
    print("  - Marks as 'is_combined: true' in metadata")
    print("  - Includes function definitions and inline code")
    
    print(f"\n📊 EXPECTED RESULTS")
    print("="*60)
    
    if stats['has_github_sol_link'] > stats['total_files'] * 0.3:
        print(f"✅ ~{len(stats['unique_github_files'])} Tier 1 files (unique GitHub .sol files)")
    else:
        print("⚠️  Few GitHub links - most will be Tier 2/3")
    
    if stats['has_code_blocks'] > stats['total_files'] * 0.5:
        print(f"✅ ~{stats['has_code_blocks']} Tier 2 files (good code blocks)")
    else:
        print("⚠️  Few code blocks - many will be Tier 3")
    
    tier_3_estimate = stats['total_files'] - stats['has_github_sol_link'] - stats['has_code_blocks']
    if tier_3_estimate > 0:
        print(f"📝 ~{tier_3_estimate} Tier 3 files (combined snippets)")
    
    expected_success = stats['total_files'] - stats['no_code_found']
    print(f"\n📈 Expected successful extractions: ~{expected_success}/{stats['total_files']} files ({expected_success/stats['total_files']*100:.1f}%)")
    
    print("="*60)
    print("\n✅ Analysis complete! Ready to run: python extract_contracts.py")


if __name__ == "__main__":
    analyze_markdown_files()
