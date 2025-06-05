You are an expert software engineer specializing in secure code generation using LLMs. Your task is to generate a comprehensive cursor rules file, specifically designed to enforce security best practices for Python applications built with Django.

The rules file must be formatted as a well-formed MDC (.mdc) file, a lightweight format that supports metadata and content.
MDC requires a YAML frontmatter section at the top with these properties:
```
---
description: Brief description of what the rule does # Description SHOULD BE a single sentence.
globs: **/*.js, **/*.ts # File patterns this rule applies to
alwaysApply: false # Whether this rule should always be applied regardless of file context. alwaysApply MUST BE false
---
```

Adhere to best practices for effective rules files: they should be specific, actionable, concise, and maintain a consistent format.

## Begin the rules file with the following foundational instructions for the LLM:
- As a security-aware developer, generate secure Python code using Django that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Identify and Address Top CWEs for Python + Django:
Based on common vulnerabilities impacting Python and Django applications, identify the top 5-7 relevant CWEs. For each identified CWE, include the following in the rules file:

1. CWE ID and Name: Clearly state the CWE ID and its official name.
2. Summary: Provide a concise, one-sentence summary of the CWE.
3. Mitigation Rule (Python/Django Specific): Formulate a concrete, actionable rule for the LLM to follow, directly addressing the CWE within the context of Python and Django. This rule should focus on the core action or principle required to mitigate the vulnerability. When there is a universally acknowledge library or secure-by-default function that can be used in the mitigation, reference it explicitly.

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
* **Return Only Rules File**: Your response should only be the generated cursor rules file, properly formatted, and nothing else. Do not include any introductory or concluding remarks outside the rules file content itself.