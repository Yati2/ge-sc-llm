import requests
import json
import os
import random
from dotenv import load_dotenv
import time

load_dotenv()

API_KEY = os.getenv("SOLODIT_API_KEY")

url = "https://solodit.cyfrin.io/api/v1/solodit/findings"

headers = {
    "Content-Type": "application/json",
    "X-Cyfrin-API-Key": API_KEY
}

# Step 1 — Get metadata
initial_payload = {
    "page": 1,
    "pageSize": 1,
    "filters": {
        "languages": [{"value": "Solidity"}],
    }
}

response = requests.post(url, headers=headers, json=initial_payload)
response.raise_for_status()

meta_data = response.json()["metadata"]
total_results = meta_data["totalResults"]
page_size = 100
total_pages = (total_results + page_size - 1) // page_size

print(f"Total pages available: {total_pages}")

# Step 2 — Keep sampling until we have 100 findings with non-empty summaries

filtered_findings = []
visited_pages = set()
target_count = 100
findings_per_page = 10

print(f"Downloading findings until we have {target_count} with non-empty summaries...")

while len(filtered_findings) < target_count:
    # Pick a random unvisited page
    random_page = random.randint(1, total_pages)
    if random_page in visited_pages:
        continue

    visited_pages.add(random_page)
    print(f"Fetching page {random_page} (have {len(filtered_findings)}/{target_count} findings so far)")

    payload = {
        "page": random_page,
        "pageSize": findings_per_page,
        "filters": {
            "languages": [{"value": "Solidity"}],
        }
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()

    findings = response.json()["findings"]
    
    # Filter for non-empty summaries immediately
    valid_findings = [f for f in findings if f.get("summary") and f["summary"].strip()]
    filtered_findings.extend(valid_findings)
    
    print(f"  → Got {len(valid_findings)} findings with summaries from this page")

    # Small delay to respect rate limit (20/min)
    time.sleep(3.5)

# Take exactly 100 random findings if we have more
if len(filtered_findings) > target_count:
    filtered_findings = random.sample(filtered_findings, target_count)

print(f"Final count: {len(filtered_findings)} findings with non-empty summaries.")

# Step 3 — Save full dataset JSON
with open("solodit_100_random.json", "w") as f:
    json.dump(filtered_findings, f, indent=2)

# Step 4 — Save markdown files
os.makedirs("markdown_files", exist_ok=True)

for finding in filtered_findings:
    fid = finding["id"]
    title = finding["title"]
    content = finding["content"]
    summary = finding["summary"] or ""

    md_text = f"# {title}\n\n"
    md_text += "## Summary\n\n"
    md_text += summary + "\n\n"
    md_text += "## Content\n\n"
    md_text += content

    with open(f"markdown_files/{fid}.md", "w") as f:
        f.write(md_text)

print("Done. 100 random vulnerabilities saved.")