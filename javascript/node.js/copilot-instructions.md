# Secure JavaScript/Node.js Copilot Rules

## Foundational Instructions for Secure Code Generation

*   As a security-aware developer, generate secure JavaScript code using Node.js that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

## Top CWEs for JavaScript + Node.js

### Memory Safety Considerations

*   **Note**: JavaScript is a memory-managed language with automatic garbage collection, which largely mitigates common memory safety issues like buffer overflows and use-after-free found in lower-level languages. Therefore, explicit memory safety rules related to low-level memory management are not applicable here.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (XSS)
**Summary:** The application embeds untrusted data into a web page without proper validation or escaping, allowing attackers to execute scripts in the victim's browser.
**Mitigation Rule:** Always perform context-aware output encoding or escaping for all untrusted input before rendering it in HTML, JavaScript, URL parameters, or other contexts. For HTML output, utilize libraries like `DOMPurify` for sanitization, or leverage template engines' built-in auto-escaping mechanisms (e.g., Pug, EJS configured with `escape` or `client` options). For data transferred as JSON, ensure proper `JSON.stringify()` usage.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** Untrusted input is directly incorporated into an SQL query without proper neutralization, allowing attackers to manipulate database queries.
**Mitigation Rule:** Use parameterized queries (prepared statements) for all database interactions involving user-supplied input. Leverage Object-Relational Mappers (ORMs) such as Sequelize or Knex.js, or database drivers that explicitly support parameterized queries, ensuring that user input is never concatenated directly into SQL strings.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** User-controlled input is used to construct file paths without proper validation, enabling access to arbitrary files or directories outside of an intended base directory.
**Mitigation Rule:** Validate and sanitize all user-supplied input used in file system operations. Construct paths using `path.resolve()` and `path.join()` in Node.js, and strictly ensure the final resolved path is contained within a predefined, allowed base directory using checks like `resolvedPath.startsWith(basePath)`.

### CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Summary:** Untrusted input is used to construct or modify operating system commands, allowing attackers to execute arbitrary commands on the server.
**Mitigation Rule:** Avoid direct execution of OS commands with user-supplied input. If external command execution is strictly necessary, use Node.js `child_process` methods like `child_process.execFile` or `child_process.spawn` where arguments are passed as a separate array, preventing shell interpretation of input. Never use `child_process.exec` or `child_process.execSync` with unsanitized user input.

### CWE-400: Uncontrolled Resource Consumption ('Denial of Service')
**Summary:** The application consumes excessive resources (CPU, memory, network) due to unbounded operations or large inputs, leading to service degradation or unavailability.
**Mitigation Rule:** Implement strict input validation for size, length, and complexity of all incoming data. Apply rate limiting (e.g., using `express-rate-limit` middleware) to API endpoints to prevent abuse. Use timeouts for external requests and long-running operations. Limit the number of concurrently active operations or database connections.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** The application makes a request to a remote resource specified by a user-controlled URL, potentially allowing an attacker to interact with internal services or external systems.
**Mitigation Rule:** Rigorously validate and sanitize all user-supplied URLs before making server-side requests. Implement a strict allow-list of permitted domains or IP addresses for outgoing requests. Prevent redirections to untrusted or internal locations and explicitly deny requests to private/reserved IP ranges (e.g., loopback, private networks).

### CWE-522: Insufficiently Protected Credentials (Hardcoded Secrets)
**Summary:** Sensitive information like API keys, database credentials, or encryption keys are embedded directly into source code or configuration files that are committed to version control.
**Mitigation Rule:** Never hardcode sensitive credentials, API keys, or cryptographic secrets directly into the codebase. Store configuration and secrets in environment variables (`process.env`), dedicated secrets management services (e.g., AWS Secrets Manager, HashiCorp Vault), or secure configuration management tools. Utilize libraries like `dotenv` for local development to load environment variables, but ensure `.env` files are excluded from version control.
```
```

```markdown
# Secure JavaScript/Node.js Copilot Rules

## Foundational Instructions for Secure Code Generation

*   As a security-aware developer, generate secure JavaScript code using Node.js that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

## Top CWEs for JavaScript + Node.js

### Memory Safety Considerations

*   **Note**: JavaScript is a memory-managed language with automatic garbage collection, which largely mitigates common memory safety issues like buffer overflows and use-after-free found in lower-level languages. Therefore, explicit memory safety rules related to low-level memory management are not applicable here.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (XSS)
**Summary:** The application embeds untrusted data into a web page without proper validation or escaping, allowing attackers to execute scripts in the victim's browser.
**Mitigation Rule:** Always perform context-aware output encoding or escaping for all untrusted input before rendering it in HTML, JavaScript, URL parameters, or other contexts. For HTML output, utilize libraries like `DOMPurify` for sanitization, or leverage template engines' built-in auto-escaping mechanisms (e.g., Pug, EJS configured with `escape` or `client` options). For data transferred as JSON, ensure proper `JSON.stringify()` usage.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** Untrusted input is directly incorporated into an SQL query without proper neutralization, allowing attackers to manipulate database queries.
**Mitigation Rule:** Use parameterized queries (prepared statements) for all database interactions involving user-supplied input. Leverage Object-Relational Mappers (ORMs) such as Sequelize or Knex.js, or database drivers that explicitly support parameterized queries, ensuring that user input is never concatenated directly into SQL strings.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** User-controlled input is used to construct file paths allowing access to arbitrary files or directories outside of an intended base directory.
**Mitigation Rule:** Validate and sanitize all user-supplied input used in file system operations. Construct paths using `path.resolve()` and `path.join()` in Node.js, and strictly ensure the final resolved path is contained within a predefined, allowed base directory using checks like `resolvedPath.startsWith(basePath)`.

### CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Summary:** Untrusted input is used to construct or modify operating system commands, allowing attackers to execute arbitrary commands on the server.
**Mitigation Rule:** Avoid direct execution of OS commands with user-supplied input. If external command execution is strictly necessary, use Node.js `child_process` methods like `child_process.execFile` or `child_process.spawn` where arguments are passed as a separate array, preventing shell interpretation of input. Never use `child_process.exec` or `child_process.execSync` with unsanitized user input.

### CWE-400: Uncontrolled Resource Consumption ('Denial of Service')
**Summary:** The application consumes excessive resources (CPU, memory, network) due to unbounded operations or large inputs, leading to service degradation or unavailability.
**Mitigation Rule:** Implement strict input validation for size, length, and complexity of all incoming data. Apply rate limiting (e.g., using `express-rate-limit` middleware) to API endpoints to prevent abuse. Use timeouts for external requests and long-running operations. Limit the number of concurrently active operations or database connections.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** The application makes a request to a remote resource specified by a user-controlled URL, potentially allowing an attacker to interact with internal services or external systems.
**Mitigation Rule:** Rigorously validate and sanitize all user-supplied URLs before making server-side requests. Implement a strict allow-list of permitted domains or IP addresses for outgoing requests. Prevent redirections to untrusted or internal locations and explicitly deny requests to private/reserved IP ranges (e.g., loopback, private networks).

### CWE-522: Insufficiently Protected Credentials (Hardcoded Secrets)
**Summary:** Sensitive information like API keys, database credentials, or encryption keys are embedded directly into source code or configuration files that are committed to version control.
**Mitigation Rule:** Never hardcode sensitive credentials, API keys, or cryptographic secrets directly into the codebase. Store configuration and secrets in environment variables (`process.env`), dedicated secrets management services (e.g., AWS Secrets Manager, HashiCorp Vault), or secure configuration management tools. Utilize libraries like `dotenv` for local development to load environment variables, but ensure `.env` files are excluded from version control.
