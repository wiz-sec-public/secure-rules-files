import os
import json
import google.generativeai as genai

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


if __name__ == "__main__":
    with open('assistants.json', 'r') as f:
        assistant_configs = json.load(f)

    # Define a list of tuples, each containing arguments for generate_secure_rules_prompt
    assistants = list(assistant_configs.keys())

    with open('technologies.json', 'r') as f:
        technologies_data = json.load(f)

    prompt_configs = technologies_data.get("prompt_configs", [])

    model = genai.GenerativeModel('gemini-2.5-flash-preview-05-20')

    for lang, framework in prompt_configs:
        for assistant in assistants:
            prompt = generate_secure_rules_prompt(lang, assistant, framework)
            response = model.generate_content(prompt)


            assistant_name = assistant.lower()

            # Get the filename pattern based on the assistant name, default to rules.md
            filename_pattern = assistant_configs.get(assistant_name, {}).get("pattern", "rules.md")
            if filename_pattern == "rules.mdc": # Special case for cursor, needs lang and framework
                filename_pattern = f"{lang}_{framework}_rules.mdc"

            # Construct the directory path
            directory_path = os.path.join(lang.lower().replace(' ', '_'), framework.lower().replace(' ', '_'))

            # Construct the full file path
            full_file_path = os.path.join(directory_path, filename_pattern)

            rulesfile = response.text

            # Fix common formatting issues
            if rulesfile.startswith('```mdc') or rulesfile.startswith('```markdown') or rulesfile.startswith('```'):
                rulesfile = "\n".join(rulesfile.split("\n")[1:])
            if rulesfile.endswith('```'):
                rulesfile = rulesfile.rstrip('```')

            try:
                # Create the directory if it doesn't exist
                os.makedirs(directory_path, exist_ok=True)
                with open(full_file_path, 'w') as f:
                    # Write the string to the file
                    f.write(rulesfile)
                print(f"Successfully wrote {full_file_path}")
            except IOError as e:
                print(f"Error writing to file {full_file_path}: {e}")