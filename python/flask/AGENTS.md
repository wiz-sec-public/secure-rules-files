# Secure Python Flask Application Codex Rules

## Foundational Instructions for Secure Code Generation

*   As a security-aware developer, generate secure Python code using Flask that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included, indicating a need for careful vetting.

## Memory Safety Considerations

Python is a memory-safe language, providing automatic memory management and garbage collection, which inherently mitigates many common memory safety vulnerabilities such as buffer overflows, use-after-free, and double-free errors. Explicit memory safety considerations beyond standard Python practices are generally not required.

## Top CWEs for Python + Flask Applications

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** An attacker can alter SQL query logic by injecting malicious SQL code into input parameters.
**Mitigation Rule:** Always use parameterized queries or prepared statements via an ORM (e.g., SQLAlchemy) or database driver functions (e.g., `sqlite3.connect` with parameter substitution) for all database interactions, never concatenating user input directly into SQL strings.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** An attacker can inject malicious client-side scripts into web pages viewed by other users.
**Mitigation Rule:** Always apply context-aware output encoding using Flask's Jinja2 templating engine, which escapes HTML by default, and explicitly escape any dynamic content rendered outside of Jinja2 that originates from user input or external sources.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing untrusted data can lead to arbitrary code execution, denial of service, or information disclosure by allowing attackers to inject malicious objects.
**Mitigation Rule:** Never deserialize untrusted data using Python's `pickle` module or other unsafe serialization formats. If deserialization is necessary, use secure, well-defined formats like JSON or Protocol Buffers, and rigorously validate the schema and content of the deserialized data.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Storing sensitive authentication information or secrets directly within source code makes them easily discoverable and compromises security.
**Mitigation Rule:** Never hardcode secrets, API keys, database credentials, or sensitive configuration values directly in the source code; instead, manage them securely using environment variables, dedicated secrets management services (e.g., HashiCorp Vault, AWS Secrets Manager), or secure configuration files loaded at runtime.

### CWE-16: Configuration
**Summary:** Insecure default configurations or misconfigurations can expose sensitive information or functionality.
**Mitigation Rule:** Configure Flask applications for production by disabling debug mode, setting a strong `SECRET_KEY` from a secure, non-hardcoded source, properly configuring CORS, CSRF (using Flask-WTF or Flask-CSRF), and secure session management, and ensuring all unnecessary features, default accounts, or insecure HTTP methods are removed or secured.

### CWE-287: Improper Authentication
**Summary:** Flaws in the authentication mechanism allow attackers to bypass security checks and gain unauthorized access.
**Mitigation Rule:** Implement robust authentication using strong, modern, and well-tested libraries (e.g., Flask-Login, Flask-Security-Too) for user management, enforce strong password policies, utilize secure password hashing (e.g., `werkzeug.security.generate_password_hash` with `pbkdf2:sha256`), and handle session management securely with HTTPS-only, HttpOnly cookies and proper session expiry.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** An attacker can induce the server-side application to make requests to an arbitrary domain chosen by the attacker, potentially accessing internal resources or services.
**Mitigation Rule:** When making outbound requests based on user-supplied URLs or parameters, strictly validate and sanitize all input, restrict the target addresses to an allow-list of known safe domains or IP ranges, and prevent requests to private, loopback, or cloud metadata service IP addresses.