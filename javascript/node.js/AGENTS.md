# Secure JavaScript/Node.js Codex Rules

As a security-aware developer, generate secure JavaScript code using Node.js that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### Memory Safety Considerations
**Mitigation Rule:** JavaScript is a memory-safe language with automatic garbage collection, therefore direct memory management vulnerabilities (like buffer overflows or use-after-free) are not a primary concern for the application logic itself. Focus on preventing resource exhaustion and Denial of Service (DoS) attacks instead, by implementing rate limiting, input size limits, and proper error handling.

### CWE-522: Insufficiently Protected Credentials
**Summary:** This CWE identifies instances where sensitive authentication information or secrets are stored or transmitted in a manner that makes them vulnerable to unauthorized access.
**Mitigation Rule:** Never hardcode secrets, API keys, database credentials, or sensitive configuration parameters directly into source code or commit them to version control. Utilize environment variables (e.g., `process.env`), secure configuration management systems (e.g., HashiCorp Vault), or dedicated secret management services for production environments. Ensure client-side JavaScript does not contain sensitive API keys or credentials.

### CWE-20: Improper Input Validation
**Summary:** The product does not validate or incorrectly validates input, leading to a variety of downstream vulnerabilities.
**Mitigation Rule:** Rigorously validate all input received from untrusted sources (e.g., user input, API calls, file uploads, environment variables) against an explicit schema or allowed patterns. Use libraries like Joi, Zod, or Yup for schema validation to enforce data types, lengths, formats, and ranges. Reject invalid input at the earliest possible stage.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** The application allows attackers to inject client-side scripts into web pages viewed by other users.
**Mitigation Rule:** Always sanitize and context-encode all untrusted data before rendering it into HTML, JavaScript, CSS, or URL contexts. When rendering user-generated content, use templating engines that offer auto-escaping by default (e.g., EJS with proper configuration, Pug, Handlebars with `SafeString` if needed for trusted content) or dedicated sanitization libraries like `dompurify` (for HTML output) on the server-side to prevent XSS. Avoid directly injecting user input into the DOM using `innerHTML` or `eval()`.

### CWE-89/CWE-94/CWE-502: Injection Flaws (SQL, NoSQL, Command, Code, Deserialization)
**Summary:** The application constructs all or part of a command, query, or object directly from untrusted input, allowing an attacker to alter the intended logic.
**Mitigation Rule:**
*   **Database Queries (SQL/NoSQL):** Use parameterized queries or prepared statements for SQL databases (e.g., with `node-postgres`, `mysql2`). For NoSQL databases, strictly validate and sanitize input; avoid constructing queries by concatenating user input directly into query strings or object structures, especially for sensitive operations. Use ORMs/ODMs like Sequelize or Mongoose which often provide built-in protection against injection.
*   **OS Commands:** Never directly execute OS commands using `child_process.exec` or `child_process.execSync` with unsanitized user input. Prefer `child_process.spawn` or `child_process.execFile` with an array of arguments, ensuring the command and arguments are hardcoded or strictly validated.
*   **Code Injection:** Never use `eval()` or `new Function()` with untrusted or unsanitized input. Avoid dynamic code generation based on user-supplied data.
*   **Deserialization:** Avoid deserializing untrusted data, especially from external sources. If deserialization is unavoidable, use secure, robust serialization formats and ensure strict type checking and validation of deserialized objects, using libraries designed for secure deserialization where available.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** The application uses user-supplied input to construct a file path without sufficiently validating that the path stays within an intended directory.
**Mitigation Rule:** Sanitize all user-supplied input used in file system operations to prevent directory traversal. Use `path.normalize()` and `path.resolve()` to resolve paths, and critically, verify that the resolved path is contained within an allowed base directory using `path.startsWith()` or similar logic. Never use `fs.readFile` or `fs.writeFile` directly with untrusted filenames without strict validation.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** The web application does not sufficiently verify that a request was intentionally generated by a legitimate user.
**Mitigation Rule:** Implement CSRF protection for all state-changing operations (e.g., POST, PUT, DELETE requests) by using anti-CSRF tokens. Ensure these tokens are unique per user session, securely generated, validated on the server, and not readable by JavaScript. The `csurf` middleware for Express.js is a common and recommended solution for implementing CSRF protection. Also, ensure same-site cookie attributes are set appropriately (`SameSite=Lax` or `SameSite=Strict`).

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Summary:** The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
**Mitigation Rule:**
*   **Error Handling:** Implement robust error handling that avoids exposing sensitive system details (e.g., stack traces, database error messages, internal paths) to clients. Use generic, user-friendly error messages and log detailed errors internally for debugging.
*   **Logging:** Be cautious about logging sensitive data (e.g., credentials, PII, session IDs). Censor or redact sensitive information before logging. Use secure logging configurations and ensure log files are properly secured with restricted access.
*   **API Responses:** Only return essential data in API responses. Filter out sensitive data (e.g., hashed passwords, internal IDs not meant for client-side use) before sending responses.
*   **Comments/Metadata:** Do not include sensitive information in source code comments, hidden HTML fields, or publicly accessible metadata.