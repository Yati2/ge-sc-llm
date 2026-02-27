import os
import re
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL")  
client = OpenAI(api_key=OPENAI_API_KEY)

def extract_code_snippets(content):
    """Extract code snippets from markdown code blocks."""
    # Match code blocks with ```solidity or ``` or code between backticks
    code_blocks = re.findall(r'```(?:solidity)?\n?(.*?)```', content, re.DOTALL)
    return '\n\n'.join(code_blocks) if code_blocks else ""

def validate_summary_match(summary, content, title):
    # Extract code snippets from content
    code_snippets = extract_code_snippets(content)
    
    # If no code snippets found, use the first part of content
    if not code_snippets:
        code_snippets = content[:2000]
    
    prompt = f"""You are a smart contract security expert specializing in Solidity vulnerabilities. 

Given a vulnerability title, summary, and the code snippet from the vulnerability report, determine if the summary accurately reflects the vulnerability shown in the code.

Title: {title}

Summary: {summary}

Code Snippet:
{code_snippets[:2500]}

Does the summary accurately describe the vulnerability present in the code snippet? 
Focus on whether the summary correctly identifies the security issue in the provided code.

If they match, respond with ONLY "YES"
If they don't match, respond with "NO: " followed by a one-sentence reason explaining the mismatch."""

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are a Solidity smart contract security expert that validates vulnerability reports by analyzing code. Respond with YES or NO: reason."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=100
        )
        
        answer = response.choices[0].message.content.strip()
        
        if answer.upper().startswith("YES"):
            return True, None
        elif answer.upper().startswith("NO"):
            # Extract reason after "NO:"
            reason = answer.split(":", 1)[1].strip() if ":" in answer else "Summary does not match the vulnerability in the code."
            return False, reason
        else:
            return False, "Unable to validate summary."
    
    except Exception as e:
        print(f"  ⚠️  OpenAI API error: {e}")
        return False, f"API error: {str(e)}"
