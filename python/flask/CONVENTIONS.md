As a security-aware developer, generate secure Python code using Flask that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### Memory Safety
Python is a memory-safe language, primarily due to its automatic garbage collection and high-level abstractions that prevent direct memory manipulation. Therefore, explicit memory safety considerations, such as buffer overflows or use-after-free vulnerabilities, are generally not applicable and should not be addressed by the LLM.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** Untrusted input is incorporated into an SQL query without proper sanitization, allowing attackers to manipulate database queries.
**Mitigation Rule:** Always use parameterized queries or an Object-Relational Mapper (ORM) like SQLAlchemy with Flask-SQLAlchemy. Never concatenate user-controlled input directly into SQL strings.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** User-controlled data is rendered directly into web pages without proper encoding, allowing attackers to inject client-side scripts.
**Mitigation Rule:** Ensure all user-supplied data displayed in templates is properly HTML-escaped. Jinja2, the default Flask templating engine, auto-escapes by default; explicitly use `{{ variable | e }}` or `markupsafe.escape()` for clarity or when auto-escaping might be disabled.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** An attacker tricks a victim into submitting a malicious request to a web application in which they are authenticated.
**Mitigation Rule:** Implement CSRF protection for all state-changing HTTP methods (e.g., POST, PUT, DELETE). Use a robust Flask extension like Flask-WTF's `CSRFProtect` to generate and validate anti-CSRF tokens.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing data from untrusted sources can lead to remote code execution, denial-of-service, or other attacks.
**Mitigation Rule:** Avoid deserializing untrusted or attacker-controlled data using formats like Python's `pickle`. For structured data exchange, use safe, non-executable formats like JSON. If YAML is necessary, use `PyYAML.safe_load()` instead of `PyYAML.load()`.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** An attacker can manipulate file paths to access or create files outside of an intended directory.
**Mitigation Rule:** When handling user-provided file paths, always validate them to ensure they resolve within an authorized directory. Use `werkzeug.utils.safe_join` for joining paths in Flask or ensure that `os.path.abspath` combined with `os.path.commonprefix` verifies paths before file system operations.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Sensitive information such as API keys, database passwords, or secret keys are directly embedded within the application's source code.
**Mitigation Rule:** Never hardcode sensitive credentials or secret keys in the codebase. Store them securely in environment variables (accessed via `os.environ`), a dedicated secret management service (e.g., AWS Secrets Manager, HashiCorp Vault), or a secure configuration file (e.g., `.env` for local development managed by `python-dotenv`). Access these configurations dynamically at runtime.

### CWE-732: Incorrect Permission Assignment for Critical Resource
**Summary:** Critical files, directories, or resources have overly permissive access controls, potentially exposing sensitive information or allowing unauthorized modification.
**Mitigation Rule:** Ensure that all application files, especially configuration files, database files, and secret keys, have the minimum necessary file system permissions (e.g., `0600` for private files, `0644` for public configuration). Prevent web server processes from having write access to sensitive areas not explicitly designed for uploads.
