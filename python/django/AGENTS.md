# Secure Code Generation Rules for Python/Django Applications

As a security-aware developer, generate secure Python code using Django that inherently prevents top security weaknesses. Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes. Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code. Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines. **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

## General Security Considerations for Python/Django

**Memory Safety:** Python is a memory-safe language, automatically managing memory allocation and deallocation. Therefore, explicit memory safety considerations, such as buffer overflows or use-after-free vulnerabilities, are generally not applicable at the application level; focus instead on logical and data-handling security.

---

## Top CWEs for Python + Django Applications

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** An attacker can alter SQL queries by injecting malicious SQL code, leading to unauthorized data access, modification, or deletion.
**Mitigation Rule:** Always use Django's Object-Relational Mapper (ORM) for database interactions. When raw SQL is absolutely necessary, use parameterized queries with `django.db.connections.cursor().execute(sql_query, params)` to ensure proper escaping and prevent injection. Do not construct SQL queries by concatenating user-supplied input.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** An attacker can inject client-side scripts into web pages viewed by other users, leading to session hijacking, defacement, or redirection.
**Mitigation Rule:** Leverage Django's default auto-escaping for all template outputs. If rendering untrusted user-supplied content, use `django.utils.html.escape` explicitly. Avoid using the `|safe` filter or `mark_safe` unless the content is known to be sanitized and free of malicious scripts from a trusted source, with inline comments justifying its use and detailing sanitization.

### CWE-287: Improper Authentication and CWE-384: Session Fixation
**Summary:** Weak authentication mechanisms or session management allow attackers to impersonate users, hijack sessions, or bypass security controls.
**Mitigation Rule:** Utilize Django's built-in `django.contrib.auth` authentication system for all user authentication and session management. Enforce strong password policies using `AUTH_PASSWORD_VALIDATORS` in settings. Ensure all session cookies are configured with `HttpOnly` and `Secure` flags, and transmitted only over HTTPS. Implement proper session invalidation upon logout and password changes to prevent session fixation.

### CWE-20: Improper Input Validation
**Summary:** Failure to validate user-supplied input before processing can lead to a wide range of vulnerabilities, including injection, buffer overflows, and logic flaws.
**Mitigation Rule:** Implement strict input validation for all user-supplied data, including request parameters, headers, and file uploads, at multiple layers (forms, models, views). Use Django Forms for validation, leverage Django Model fields' built-in validation, and apply custom validators as needed to enforce data types, lengths, formats, and acceptable values. Always assume all incoming data is malicious.

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Summary:** Sensitive data (e.g., credentials, personally identifiable information, internal system details) is not adequately protected and can be disclosed to unauthorized parties.
**Mitigation Rule:** Always encrypt sensitive data at rest and in transit. Use Django's `make_password` for hashing passwords and avoid storing plaintext credentials. Configure SSL/TLS (`SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SECURE_BROWSER_XSS_FILTER`) for all communication. Avoid verbose error messages in production environments by setting `DEBUG = False` and configuring custom error handlers. Log sensitive information securely with restricted access.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Secrets and credentials (e.g., API keys, database passwords) are embedded directly within source code, making them easily discoverable and compromising security.
**Mitigation Rule:** Never hardcode secrets, API keys, database credentials, or sensitive configuration values directly in the source code. Store these in environment variables (e.g., using `python-dotenv` or `django-environ` for development) or dedicated secure secrets management solutions (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) that are accessed at runtime.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** An attacker can coerce the server-side application to make requests to an arbitrary domain of the attacker's choosing, potentially accessing internal resources or conducting port scanning.
**Mitigation Rule:** Before making any server-side requests to user-provided URLs, rigorously validate and whitelist the destination. Implement strict URL parsing, scheme validation (e.g., only `http` or `https`), and hostname/IP address whitelisting. Prevent redirects to unauthorized locations. When using libraries like `requests`, ensure proper timeouts are configured and SSL verification (`verify=True`) is enabled for external endpoints.