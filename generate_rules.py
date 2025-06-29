#!/usr/bin/env python3
import os
import json
import argparse
import logging
import requests

# Set up standard logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_secure_rules_prompt(language: str, assistant: str, framework: str=None) -> str:
    """
    Provides guidance to the AI to generate an effective security rules file.

    Args:
        language: The programming language to apply rules to.
        assistant: The coding assistant to target, defaults to Cline
        framework: The core relevant framework, defaults to None
    """

    ruleformat = 'The rules file must be formatted as a well-formed Markdown file.'

    if 'cursor' in assistant.lower():
       ruleformat = '''The rules file must be formatted as a well-formed MDC (.mdc) file, a lightweight format that supports metadata and content.
MDC requires a YAML frontmatter section at the top with these properties:
```
---
description: Brief description of what the rule does # Description SHOULD BE a single sentence.
globs: **/*.js, **/*.ts # File patterns this rule applies to
alwaysApply: false # Whether this rule should always be applied regardless of file context. alwaysApply MUST BE false
---
```\n'''

    if 'windsurf' in assistant.lower():
       ruleformat = '''The rules file must be formatted as a markdown (.md) file.
The rules file MUST have a YAML frontmatter section at the top with these properties:
```
---
trigger: glob # When this rule should be applied.  MUST BE glob
description: Brief description of what the rule does # Description SHOULD BE a single sentence.
globs: **/*.js, **/*.ts # File patterns this rule applies to
---
```\n'''


    return '''You are an expert software engineer specializing in secure code generation using LLMs. Your task is to generate a comprehensive {0} rules file, specifically designed to enforce security best practices for {1} applications built with {2}.

{3}
Adhere to best practices for effective rules files: they should be specific, actionable, concise, and maintain a consistent format.

## Begin the rules file with the following foundational instructions for the LLM:
- As a security-aware developer, generate secure {1} code using {2} that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Identify and Address Top CWEs for {1} + {2}:
Based on common vulnerabilities impacting {1} and {2} applications, identify the top 5-7 relevant CWEs. For each identified CWE, include the following in the rules file:

1. CWE ID and Name: Clearly state the CWE ID and its official name.
2. Summary: Provide a concise, one-sentence summary of the CWE.
3. Mitigation Rule ({1}/{2} Specific): Formulate a concrete, actionable rule for the LLM to follow, directly addressing the CWE within the context of {1} and {2}. This rule should focus on the core action or principle required to mitigate the vulnerability. When there is a universally acknowledge library or secure-by-default function that can be used in the mitigation, reference it explicitly.

Example format:

    ### CWE-XX: CWE Name
    **Summary:** CWE Description
    **Mitigation Rule:** Prescriptive, language specific guidance


## Specific Requirements for CWE Rules:
* **Memory Safety**: For non memory-safe languages, prioritize memory safety.
* **Hardcoded Secrets and Credentials**: Include a dedicated rule for preventing hardcoded secrets and credentials.

## Formatting and Content Constraints:

* **No Examples**: Do not include any code examples within the rules file. The rules should be purely prescriptive guidance.
* **Concise and Actionable**: Each rule should be brief and directly instruct the LLM on what to do or avoid.
* **Structured**: The rules file should be logically structured, with clear headings or markers for each CWE.
* **Return Only Rules File**: Your response should only be the generated {0} rules file, properly formatted, and nothing else. Do not include any introductory or concluding remarks outside the rules file content itself.
'''.format(assistant,language,framework,ruleformat)


def get_anythingllm_workspace_slug(workspace_name: str, base_url: str, headers: dict) -> str:
    # Ensure base_url is correctly formatted to avoid double '/api'
    # If base_url is 'http://localhost:3001/api', we want to use 'http://localhost:3001' as the base for appending '/api/v1/...'
    cleaned_base_url = base_url.rstrip('/')
    if cleaned_base_url.endswith('/api'):
        cleaned_base_url = cleaned_base_url[:-len('/api')]

    api_url = f"{cleaned_base_url}/api/v1/workspaces"
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        workspaces = response.json().get('workspaces', [])
        for workspace in workspaces:
            if workspace['name'] == workspace_name:
                logging.info(f"Found workspace '{workspace_name}' with slug: {workspace['slug']}")
                return workspace['slug']
        logging.error(f"Workspace '{workspace_name}' not found.")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to retrieve workspaces from {api_url}: {e}")
        return None

def generate_content_with_anythingllm(prompt: str, workspace_slug: str, base_url: str, headers: dict) -> str:
    # Ensure base_url is correctly formatted to avoid double '/api'
    cleaned_base_url = base_url.rstrip('/')
    if cleaned_base_url.endswith('/api'):
        cleaned_base_url = cleaned_base_url[:-len('/api')]

    api_url = f"{cleaned_base_url}/api/v1/workspace/{workspace_slug}/chat"
    payload = {
        "message": prompt,
        "mode": "chat"
    }
    try:
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        logging.info(f"Successfully generated content from AnythingLLM for workspace slug: {workspace_slug}")
        return response.json()['textResponse']
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to generate content from AnythingLLM at {api_url}: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate secure rules files using AnythingLLM.")
    parser.add_argument("--workspace", required=True, help="Name of the AnythingLLM workspace to use.")
    args = parser.parse_args()

    ANYTHINGLLM_API_URL = os.environ.get('ANYTHINGLLM_API_URL')
    ANYTHINGLLM_API_KEY = os.environ.get('ANYTHINGLLM_API_KEY')

    if not ANYTHINGLLM_API_URL:
        logging.error("ANYTHINGLLM_API_URL environment variable not found. Please define it.")
        exit(1)
    if not ANYTHINGLLM_API_KEY:
        logging.error("ANYTHINGLLM_API_KEY environment variable not found. Please define it.")
        exit(1)

    headers = {
        'Authorization': f'Bearer {ANYTHINGLLM_API_KEY}',
        'Content-Type': 'application/json'
    }

    workspace_slug = get_anythingllm_workspace_slug(args.workspace, ANYTHINGLLM_API_URL, headers)
    if not workspace_slug:
        logging.error(f"Could not find workspace '{args.workspace}'. Exiting.")
        exit(1)

    with open('assistants.json', 'r') as f:
        assistant_configs = json.load(f)

    assistants = list(assistant_configs.keys())

    with open('technologies.json', 'r') as f:
        technologies_data = json.load(f)

    prompt_configs = technologies_data.get("prompt_configs", [])

    for lang, framework in prompt_configs:
        for assistant in assistants:
            prompt = generate_secure_rules_prompt(lang, assistant, framework)
            rulesfile = generate_content_with_anythingllm(prompt, workspace_slug, ANYTHINGLLM_API_URL, headers)

            if rulesfile is None:
                logging.error(f"Failed to generate rules for {lang} {framework} with assistant {assistant}. Skipping.")
                continue

            assistant_name = assistant.lower()

            filename_pattern = assistant_configs.get(assistant_name, {}).get("pattern", "rules.md")
            if filename_pattern == "rules.mdc":
                filename_pattern = f"{lang}_{framework}_rules.mdc"

            directory_path = os.path.join(lang.lower().replace(' ', '_'), framework.lower().replace(' ', '_'))
            full_file_path = os.path.join(directory_path, filename_pattern)

            # Fix common formatting issues
            if rulesfile.startswith('```mdc') or rulesfile.startswith('```markdown') or rulesfile.startswith('```'):
                rulesfile = "\n".join(rulesfile.split("\n")[1:])
            if rulesfile.endswith('```'):
                rulesfile = rulesfile.rstrip('```')

            try:
                os.makedirs(directory_path, exist_ok=True)
                with open(full_file_path, 'w') as f:
                    f.write(rulesfile)
                logging.info(f"Successfully wrote {full_file_path}")
            except IOError as e:
                logging.error(f"Error writing to file {full_file_path}: {e}")
