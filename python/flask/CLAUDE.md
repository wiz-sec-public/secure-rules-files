As a security-aware developer, generate secure Python code using Flask that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

### Memory Safety

Python is a memory-safe language due to its automatic memory management (garbage collection) and strong typing, which prevent common vulnerabilities like buffer overflows, use-after-free, and double-free that are prevalent in languages without such built-in protections. Therefore, explicit memory safety considerations, as they apply to non-memory-safe languages, are not required.

---

### CWE-79: Cross-Site Scripting (XSS)
**Summary:** An attacker injects malicious client-side scripts into web pages viewed by other users.
**Mitigation Rule:** Always ensure all user-supplied input rendered in HTML templates is properly escaped; leverage Flask's Jinja2 auto-escaping feature and avoid using `Markup`, `{% raw %}`, or `|safe` filters with untrusted data.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** An attacker can alter SQL queries by injecting malicious SQL commands into user-supplied input.
**Mitigation Rule:** Utilize Object-Relational Mappers (ORMs) like SQLAlchemy or ensure all database queries use parameterized queries or prepared statements, never concatenating user input directly into SQL strings.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** An attacker tricks a victim's browser into sending a forged request to a web application where the victim is authenticated.
**Mitigation Rule:** Implement anti-CSRF tokens for all state-changing requests (e.g., POST, PUT, DELETE); use Flask extensions like `Flask-WTF` which provide built-in CSRF protection.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** An attacker manipulates file paths to access or modify files outside of an intended directory.
**Mitigation Rule:** Sanitize all user-supplied file paths strictly; use `werkzeug.utils.safe_join` for combining path components and never directly use raw user input in file system operations.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing untrusted data can lead to arbitrary code execution or denial of service if the data contains malicious objects or constructs.
**Mitigation Rule:** Never deserialize data from untrusted sources using insecure deserialization libraries like `pickle` or `yaml.load` without explicit, secure configuration (e.g., `yaml.safe_load`); prefer data formats like JSON with strict schema validation.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Secrets like API keys, database credentials, or cryptographic keys are embedded directly into source code, making them easily discoverable.
**Mitigation Rule:** Store all sensitive credentials and configuration parameters outside the source code; retrieve them from environment variables, secure configuration files, or a dedicated secret management service (e.g., HashiCorp Vault, AWS Secrets Manager) at runtime.

### CWE-306: Missing Authentication for Critical Function
**Summary:** An application performs a sensitive operation without verifying the identity of the user or system making the request.
**Mitigation Rule:** Implement robust authentication for all sensitive endpoints and operations using decorators like `@login_required` from `Flask-Login` or similar mechanisms, ensuring all access is authorized before execution.