# Aider Rules for Secure JavaScript/Node.js Code Generation

## Foundational Instructions for the LLM

*   As a security-aware developer, generate secure JavaScript code using Node.js that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Memory Safety Note

JavaScript (Node.js) is a memory-managed language, abstracting memory safety concerns through garbage collection. Therefore, explicit memory safety considerations, typically relevant for languages like C/C++, are not directly applicable as distinct rules here.

## Top CWEs for JavaScript + Node.js

### CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)
**Summary:** XSS occurs when untrusted data is displayed in a web page without proper sanitization, leading to client-side code execution.
**Mitigation Rule:** Always sanitize or escape user-supplied data before rendering it in HTML, using libraries like `dompurify` for HTML sanitization or template engines that auto-escape by default (e.g., Pug, EJS with proper settings).

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** SQL Injection allows attackers to manipulate database queries by injecting malicious SQL code through user input.
**Mitigation Rule:** Use parameterized queries or prepared statements with ORMs (e.g., Sequelize, TypeORM) or database drivers (e.g., `pg` for PostgreSQL, `mysql2` for MySQL) that support them, never concatenate user input directly into SQL strings.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
**Summary:** Path Traversal vulnerabilities allow attackers to access files and directories outside of an intended root directory.
**Mitigation Rule:** Canonicalize and validate all file paths against a whitelist of allowed paths, and strictly use `path.resolve()` or `path.join()` with a safe base directory to prevent relative path manipulation.

### CWE-20: Improper Input Validation
**Summary:** Failure to validate user input allows attackers to submit malicious data that can exploit various vulnerabilities.
**Mitigation Rule:** Implement strict server-side input validation for all user-supplied data (e.g., query parameters, request bodies, headers) using robust validation libraries like `Joi`, `Yup`, or `express-validator`, ensuring data conforms to expected types, formats, lengths, and ranges.

### CWE-522: Insufficiently Protected Credentials
**Summary:** Credentials and sensitive configuration are stored or transmitted in an insecure manner, leading to their compromise.
**Mitigation Rule:** Never hardcode secrets, API keys, or credentials directly in code; instead, load them from environment variables (e.g., `process.env`) or a secure secrets management service (e.g., AWS Secrets Manager, HashiCorp Vault), and ensure configuration files are excluded from version control.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing untrusted data can lead to arbitrary code execution or denial of service if the data contains malicious objects or constructs.
**Mitigation Rule:** Avoid deserializing untrusted data directly; if absolutely necessary, use secure, constrained deserialization mechanisms or libraries that validate and sanitize the structure of the data before processing, and never use `eval()` on untrusted input.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** SSRF allows an attacker to make the server-side application issue HTTP requests to an arbitrary domain chosen by the attacker.
**Mitigation Rule:** Implement strict validation and whitelisting of target URLs and protocols for any server-side initiated requests, disallowing private IP ranges, loopback addresses, and non-HTTP/HTTPS schemes, and use libraries like `got` or `axios` with careful configuration for external requests.
