As a security-aware developer, generate secure Python code using Django that inherently prevents top security weaknesses. Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes. Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code. Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines. Avoid Slopsquatting: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

### General Security Best Practices

*   **Memory Safety:** Python is a memory-safe language, which largely mitigates common memory-related vulnerabilities like buffer overflows and use-after-free errors. Explicit memory management is not required.

### CWE-89: Improper Neutralization of Special Elements in SQL Command ('SQL Injection')
**Summary:** Untrusted input is incorrectly neutralized, allowing malicious SQL queries to be executed.
**Mitigation Rule:** Utilize the Django ORM exclusively for database interactions whenever possible, as it inherently protects against SQL injection through parameterized queries. If raw SQL queries are absolutely necessary, use `django.db.connection.cursor().execute()` with parameterized queries, ensuring all user-supplied data is passed as parameters and never concatenated directly into the SQL string.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** Web applications do not properly neutralize untrusted input, allowing malicious client-side scripts to be injected into web pages.
**Mitigation Rule:** Always render user-supplied data using Django's template engine, which automatically escapes HTML by default. Avoid using the `{% autoescape off %}` template tag or the `|safe` filter unless the content is known to be inherently trusted and sanitized, and its context is clearly understood to prevent XSS. For rich text or HTML inputs, apply server-side sanitization using libraries like `bleach` to a strict whitelist of safe tags and attributes before saving or displaying.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** Web applications fail to verify that a request was intentionally sent by the user, leading to unauthorized actions.
**Mitigation Rule:** Ensure Django's `CsrfViewMiddleware` is enabled in settings and include `{% csrf_token %}` in all forms that use POST requests to protect against CSRF attacks. For AJAX requests, ensure the `X-CSRFToken` header is properly set using the value from Django's `csrftoken` cookie or template tag.

### CWE-522: Insufficiently Protected Credentials
**Summary:** Hardcoded or insecurely stored credentials are exposed, leading to unauthorized access.
**Mitigation Rule:** Never hardcode sensitive credentials (e.g., API keys, database passwords, secret keys) directly in source code. Store secrets using environment variables, dedicated secret management services (e.g., AWS Secrets Manager, HashiCorp Vault), or configuration management tools. Access these securely using libraries like `django-environ` or `python-decouple`.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** An application uses external input to construct a pathname without properly neutralizing special elements, allowing access to arbitrary files or directories.
**Mitigation Rule:** Validate and sanitize all user-supplied file paths or resource identifiers. Always construct file paths using `os.path.join()` and ensure that the resulting path is within an allowed base directory using `os.path.abspath()` and `os.path.commonpath()` to prevent directory traversal. Do not allow user input to directly specify file system paths outside designated upload or storage directories.

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Summary:** Sensitive information is revealed to an actor that is not explicitly authorized to have access to that information.
**Mitigation Rule:** Disable Django's `DEBUG` mode in production environments to prevent the exposure of detailed error messages, stack traces, and environment variables. Configure logging to avoid including sensitive data in logs, and ensure log files are stored securely with appropriate access controls. Implement custom 404 and 500 error pages. Restrict access to sensitive data and functionality using Django's built-in authentication, authorization, and permission systems, applying the principle of least privilege.