#!/usr/bin/env python3
import os
import json
import argparse
import logging
import requests

# Set up standard logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_secure_rules_prompt(language: str, assistant: str, framework: str=None, raw_prompt_content: str=None) -> str:
    """
    Provides guidance to the AI to generate an effective security rules file.

    Args:
        language: The programming language to apply rules to.
        assistant: The coding assistant to target, defaults to Cline
        framework: The core relevant framework, defaults to None
        raw_prompt_content: The raw content of the prompt template.
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

    # Use the provided raw_prompt_content and format it
    return raw_prompt_content.format(assistant, language, framework, ruleformat)


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
    parser.add_argument("--prompt", required=True, help="Path to the prompt file (e.g., prompts/default.txt).")
    args = parser.parse_args()

    # Extract the prompt subdirectory name from the prompt file path
    prompt_subdirectory_name = os.path.splitext(os.path.basename(args.prompt))[0]
    if not prompt_subdirectory_name:
        logging.error(f"Could not derive a valid subdirectory name from prompt path: {args.prompt}")
        exit(1)

    try:
        with open(args.prompt, 'r') as f:
            raw_prompt_content = f.read()
        logging.info(f"Successfully loaded prompt from {args.prompt}")
    except FileNotFoundError:
        logging.error(f"Prompt file not found: {args.prompt}. Please ensure the path is correct.")
        exit(1)
    except IOError as e:
        logging.error(f"Error reading prompt file {args.prompt}: {e}")
        exit(1)

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
            prompt = generate_secure_rules_prompt(lang, assistant, framework, raw_prompt_content)
            rulesfile = generate_content_with_anythingllm(prompt, workspace_slug, ANYTHINGLLM_API_URL, headers)

            if rulesfile is None:
                logging.error(f"Failed to generate rules for {lang} {framework} with assistant {assistant}. Skipping.")
                continue

            assistant_name = assistant.lower()

            filename_pattern = assistant_configs.get(assistant_name, {}).get("pattern", "rules.md")
            if filename_pattern == "rules.mdc":
                filename_pattern = f"{lang}_{framework}_rules.mdc"

            # Construct the directory path including the prompt-specific subdirectory
            directory_path = os.path.join(lang.lower().replace(' ', '_'), framework.lower().replace(' ', '_'), prompt_subdirectory_name)
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
