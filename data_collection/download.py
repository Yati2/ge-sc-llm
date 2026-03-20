import requests
import json
import os
from dotenv import load_dotenv
import time
import re
from urllib.parse import urlparse

load_dotenv()

API_KEY = os.getenv("SOLODIT_API_KEY")
PAGE_SIZE = int(os.getenv("PAGE_SIZE"))
OUTPUT_FILE = os.getenv("OUTPUT_FILE")
REPORTED_AFTER_DATE = os.getenv("REPORTED_AFTER_DATE")
target_per_run = int(os.getenv("TARGET_RUNS"))



url = "https://solodit.cyfrin.io/api/v1/solodit/findings"

headers = {
    "Content-Type": "application/json",
    "X-Cyfrin-API-Key": API_KEY
}

STATE_FILE = os.getenv("STATE_FILE")
OUTPUT_FILE = os.getenv("OUTPUT_FILE")
REPORTED_AFTER_DATE = os.getenv("REPORTED_AFTER_DATE")


def load_download_state():
    """Load the download state from file, or return initial state."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {
        "page_size": PAGE_SIZE,
        "last_downloaded_page": 0,
        "last_seen_finding_id": None,
        "page_completed": True
    }

def save_download_state(state):
    """Save the download state to file."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def extract_github_link(finding):
    """Extract GitHub link from finding's github_link or source_link field."""
    if "github_link" in finding and finding["github_link"]:
        github_link = finding["github_link"]
        if isinstance(github_link, str) and github_link.strip():
            return github_link.strip()
    
    if "source_link" in finding and finding["source_link"]:
        source_link = finding["source_link"]
        if isinstance(source_link, str) and "github.com" in source_link.lower():
            return source_link.strip()
    
    # Fallback: search in content for GitHub URLs
    content = finding.get("content", "")
    github_pattern = r'https?://github\.com/[^\s\)\]\>"]+' 
    matches = re.findall(github_pattern, content)
    if matches:
        return matches[0]
    
    return None

def is_github_link_valid(github_url, timeout=5):
    if not github_url:
        return False
    
    try:

        github_url = github_url.strip()
  
        response = requests.head(github_url, timeout=timeout, allow_redirects=True)
        
        if response.status_code in [200, 301, 302]:
            return True

        elif response.status_code == 405:  
            response = requests.get(github_url, timeout=timeout, allow_redirects=True)
            return response.status_code == 200
        else:
            return False
    except Exception as e:
        print(f"  ⚠ Error checking GitHub link: {e}")
        return False

def should_keep_finding(finding):
    """
    Determine if a finding should be kept based on summary and GitHub link validity.
    
    Rules:
    - No summary + invalid/absent GitHub link → skip (return False)
    - Summary + invalid/absent GitHub link → keep (return True)
    - No summary + valid GitHub link → keep (return True)
    """
    has_summary = bool(finding.get("summary") and finding["summary"].strip())
    github_link = extract_github_link(finding)
    
    if has_summary:
       
        finding["github_link"] = github_link
        finding["github_link_valid"] = is_github_link_valid(github_link) if github_link else False
        return True
    else:
        if github_link:
            is_valid = is_github_link_valid(github_link)
            finding["github_link"] = github_link
            finding["github_link_valid"] = is_valid
            return is_valid
        else:
            return False


state = load_download_state()
page_size = state["page_size"]

# If previous page was not completed, resume from same page. Otherwise, start from next page.
if state.get("page_completed", True):
    start_page = state["last_downloaded_page"] + 1
else:
    start_page = state["last_downloaded_page"]
    print(f"⚠ Previous page {start_page} was not fully scanned. Resuming from same page...")

print(f"Starting download from page {start_page} with page size {page_size}")

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r") as f:
        all_findings = json.load(f)
    print(f"Loaded {len(all_findings)} existing findings")
    # Create a set of already-processed finding IDs to avoid duplicates
    processed_ids = {f["id"] for f in all_findings}
else:
    all_findings = []
    processed_ids = set()

page = start_page
new_findings_this_run = 0

print(f"\nDownloading up to {target_per_run} findings...")

while new_findings_this_run < target_per_run:
    print(f"\nFetching page {page}... ({new_findings_this_run}/{target_per_run} findings collected)")

    payload = {
    "page": page,
    "pageSize": page_size,
    "filters": {
        "languages": [{"value": "Solidity"}],
        "impact": ["HIGH", "MEDIUM"],

        # "reported": {
        #     "value": "after"
        # },
        # "reportedAfter": "2025-02-28T16:00:00.000Z"
    }
}

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()

        findings = response.json()["findings"]
        
        if not findings:
            print(f"  No findings on page {page}, stopping.")
            break
        
        kept_count = 0
        skipped_count = 0
        duplicate_count = 0
        page_fully_scanned = True
        
        for finding in findings:
            # Skip if already processed
            if finding["id"] in processed_ids:
                duplicate_count += 1
                continue
                
            if should_keep_finding(finding):
                all_findings.append(finding)
                processed_ids.add(finding["id"])
                kept_count += 1
                new_findings_this_run += 1
                
                # Stop if we've reached our target for this run
                if new_findings_this_run >= target_per_run:
                    print(f"  ✓ Reached target of {target_per_run} findings!")
                    page_fully_scanned = False
                    break
            else:
                skipped_count += 1
        
        if duplicate_count > 0:
            print(f"  ⏭ Skipped {duplicate_count} already-processed findings")
        print(f"  ✓ Kept {kept_count} findings, skipped {skipped_count}")
        print(f"  New findings this run: {new_findings_this_run}/{target_per_run}")
        print(f"  Total findings overall: {len(all_findings)}")
        
        state["last_downloaded_page"] = page
        state["page_completed"] = page_fully_scanned
        if findings:
            state["last_seen_finding_id"] = findings[-1].get("id")
        save_download_state(state)
        
        with open(OUTPUT_FILE, "w") as f:
            json.dump(all_findings, f, indent=2)
        
        print(f"  💾 State and findings saved")
        
        # Only move to next page if we fully scanned the current page
        if page_fully_scanned:
            page += 1
        else:
            # Stopped mid-page, will resume from same page next run
            break
        
        # Small delay to respect rate limit
        time.sleep(3.5)
        
    except Exception as e:
        print(f"  ❌ Error on page {page}: {e}")
        print(f"  You can resume from page {page} by running the script again")
        # Mark page as incomplete on error
        state["page_completed"] = False
        save_download_state(state)
        break

print(f"\n✅ Run complete!")
print(f"New findings this run: {new_findings_this_run}")
print(f"Total findings overall: {len(all_findings)}")
print(f"Last downloaded page: {state['last_downloaded_page']}")
if not state.get("page_completed", True):
    print(f"⚠ Page {state['last_downloaded_page']} was not fully scanned. Will resume from this page on next run.")
if new_findings_this_run >= target_per_run:
    print(f"\n▶ Run the script again to download the next {target_per_run} findings.")

# Step 5 — Save markdown files for new findings only
os.makedirs("markdown_files", exist_ok=True)

if new_findings_this_run > 0:
    print(f"\nSaving markdown files for {new_findings_this_run} new findings...")
    new_findings = all_findings[-new_findings_this_run:]  # Get only the new findings
    
    for finding in new_findings:
        fid = finding["id"]
        title = finding.get("title", "Untitled")
        content = finding.get("content", "")
        summary = finding.get("summary", "")
        github_link = finding.get("github_link", "N/A")
        github_valid = finding.get("github_link_valid", False)

        md_text = f"# {title}\n\n"
        md_text += "## Summary\n\n"
        md_text += (summary if summary else "*No summary available*") + "\n\n"
        md_text += "## GitHub Source Code\n\n"
        md_text += f"- **Link**: {github_link}\n"
        md_text += f"- **Valid**: {'✓ Yes' if github_valid else '✗ No/Unknown'}\n\n"
        md_text += "## Content\n\n"
        md_text += content

        with open(f"markdown_files/{fid}.md", "w") as f:
            f.write(md_text)

    print(f"✅ All done! {new_findings_this_run} markdown files saved.")