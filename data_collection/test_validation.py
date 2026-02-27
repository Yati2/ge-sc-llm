import json
import os
from validate_summary import validate_summary_match

os.makedirs("validation_results", exist_ok=True)

with open("solodit_100_random.json", "r") as f:
    findings = json.load(f)

test_findings = findings

for finding in test_findings:
    finding_id = finding["id"]
    title = finding["title"]
    content = finding["content"]
    summary = finding["summary"]
    
    print(f"\n{'='*60}")
    print(f"Testing Finding ID: {finding_id}")
    print(f"Title: {title}")
    print(f"{'='*60}")
    
    # Validate the summary
    is_valid, reason = validate_summary_match(summary, content, title)
    
    # Prepare result
    result = {
        "id": finding_id,
        "title": title,
        "summary": summary,
        "validation_result": {
            "is_valid": is_valid,
            "reason": reason
        }
    }
    
    # Display result
    if is_valid:
        print("VALID: Summary matches code vulnerability")
    else:
        print(f"INVALID: {reason}")
    
    # Save to JSON file 
    output_file = f"validation_results/validation_{finding_id}.json"
    with open(output_file, "w") as out:
        json.dump(result, out, indent=2)
    
    print(f"Result saved to: {output_file}")

print(f"\n{'='*60}")
print("Testing complete!")
