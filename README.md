**Elevate Your Code Security with AI-Native Baseline Rules**

![(Baseline) Secure Rules Files](./assets/header-art.png)

Rules files offer an AI-native interface for improving the security of generated code.

> [!TIP]
> Rules files are most useful when they're specific to your codebase's stack and best practices.

This repository contains a broadly compatible set of baseline rules, encoding security best practices for common programming language and framework pairings.

**These rules files are themselves AI generated**, according to the best practices and principles described in [Rules Files for Safer Vibe Coding](https://www.wiz.io/blog/safer-vibe-coding-rules-files).

## What's Inside This Repository?

- `generate_rules.py`: The Python script responsible for generating these rules files, leveraging the `gemini-2.5-flash-preview-05-20` model
- `prompt.md`: A transparent look at the core prompt used to guide Gemini in crafting these rules files
- **Rules Directory**: The heart of the repository, organized intuitively by Programming Language/Framework to provide easy access to the relevant security rules.

### Supported Technologies

> [!IMPORTANT]
> While these rules files should increase the security of generated code, they are offered without warantee or guarantee.

Our initial set of baseline rules targets a broad spectrum of widely used languages and frameworks:
- Python: Flask, Django
- Javascript: React, Node.js
- Java: Spring
- .NET: ASP.NET Core
- C

Compatible rules were generated for each of the following popular AI coding assistants and tools:
- Cursor Rules
- Cline Rules
- Claude CLAUDE.md
- Windsurf Rules
- Codex AGENTS.md
- Aider Conventions
- GitHub Copilot Copilot Instructions

## Contributing

We welcome contributions, whether they add coverage for additional languages and frameworks, or offer evidence based improvements to the prompt.

- To add a new language or framework: `technologies.json`
- To add a new assistant: `assistants.json`