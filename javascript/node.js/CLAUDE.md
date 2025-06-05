# Secure Node.js Code Generation Rules

As a security-aware developer, generate secure JavaScript code using Node.js that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included, explaining their necessity and security implications.

---

## General Security Best Practices

### Memory Safety
**Mitigation Rule:** As JavaScript/Node.js is a memory-managed language, direct memory safety vulnerabilities (e.g., buffer overflows, use-after-free) are largely prevented by the runtime. Focus on logical vulnerabilities, resource consumption, and business logic flaws to prevent denial of service or data corruption.

### Hardcoded Secrets and Credentials
**Mitigation Rule:** Never hardcode sensitive information such as API keys, database credentials, cryptographic keys, or session secrets directly into the code. Utilize environment variables (e.g., `process.env`), secure configuration management tools, or dedicated secrets management services (e.g., AWS Secrets Manager, HashiCorp Vault) to retrieve sensitive data at runtime.

---

## Top CWEs for JavaScript + Node.js

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') & CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') & CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Summary:** Attackers can manipulate application input to execute arbitrary code or commands by injecting malicious strings into data paths or outputs.
**Mitigation Rule:** Always validate and sanitize all user-supplied input rigorously against an allow-list of expected values or patterns. Use parameterized queries for all database interactions (e.g., `pg` for PostgreSQL, `mysql2` for MySQL, or ORMs like Sequelize/TypeORM) to prevent SQL/NoSQL injection. Perform context-aware output encoding (e.g., using libraries like `sanitize-html` or `dompurify` for HTML, or proper JSON stringification for API responses) for all data rendered to the client or used in system commands to prevent XSS and command injection.

### CWE-284: Improper Access Control
**Summary:** Systems fail to properly restrict access to authorized users or processes, leading to privilege escalation or unauthorized data access.
**Mitigation Rule:** Implement robust access control checks at every point of entry for sensitive operations and data. Use role-based access control (RBAC) or attribute-based access control (ABAC) frameworks. Ensure authorization checks are performed server-side and are tied to the authenticated user's session or token, independent of client-side controls, before executing any logic.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** An attacker tricks a victim's browser into making an unwanted request to a web application in which the victim is currently authenticated.
**Mitigation Rule:** Implement CSRF protection for all state-changing operations by including anti-CSRF tokens (e.g., using the `csurf` middleware for Express.js applications) in all forms and AJAX requests. Verify the origin header for requests, and ensure session cookies are marked `SameSite=Lax` or `Strict` and `Secure`.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** An attacker can trick the server into making arbitrary requests to internal or external resources on their behalf, potentially accessing sensitive internal systems or exfiltrating data.
**Mitigation Rule:** When making server-side HTTP requests based on user-supplied URLs, strictly validate and sanitize the URL. Implement a strong allow-list for allowed protocols (e.g., `http`, `https`), hostnames, and IP ranges. Explicitly block access to internal IP ranges (e.g., `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and special loopback addresses. Never allow arbitrary redirection.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Applications deserialize untrusted data without proper validation, leading to remote code execution, denial of service, or other attacks.
**Mitigation Rule:** Avoid deserializing untrusted or user-controlled data if possible. If deserialization is unavoidable, use secure, dedicated deserialization libraries that are resilient to gadget chains and type confusion, and strictly validate the structure and content of the serialized data against a defined schema before deserialization. Never use generic deserialization functions (e.g., `eval`, `vm.runInNewContext`) on untrusted input.

### CWE-400: Uncontrolled Resource Consumption
**Summary:** An application does not properly limit the amount of resources (CPU, memory, disk I/O, network bandwidth, open connections) that can be consumed, leading to denial of service.
**Mitigation Rule:** Implement explicit resource limits on operations that consume significant resources, such as file uploads (e.g., using `multer` with `limits`), database queries (e.g., limiting results), or complex computations. Employ rate limiting (e.g., `express-rate-limit`) on API endpoints to prevent abuse and brute-force attacks. Ensure asynchronous operations do not block the Node.js event loop by avoiding synchronous I/O or CPU-intensive tasks.

### CWE-311: Missing Encryption of Sensitive Data
**Summary:** Sensitive data is stored or transmitted in plain text, making it vulnerable to eavesdropping, unauthorized access, or compromise.
**Mitigation Rule:** Encrypt all sensitive data both at rest and in transit. Use HTTPS/TLS for all network communication (e.g., enforce `https` redirects, use `HSTS` headers). Encrypt sensitive data stored in databases or file systems using strong, industry-standard cryptographic algorithms (e.g., AES-256 with a secure mode like GCM) and securely manage encryption keys. Never store passwords in plain text; always hash them using a strong, slow, and salting-enabled hashing algorithm like `bcrypt` (e.g., using the `bcrypt` or `argon2` npm packages) or `scrypt`.