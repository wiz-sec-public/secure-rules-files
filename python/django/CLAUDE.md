As a security-aware developer, generate secure Python code using Django that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### Memory Safety Considerations for Python
Python is a memory-safe language, providing automatic memory management (garbage collection) and preventing common memory errors like buffer overflows or use-after-free vulnerabilities at the language level. Focus on secure coding practices rather than low-level memory management.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** The application allows untrusted input to be rendered directly in a web page without proper escaping, leading to execution of malicious scripts in the user's browser.
**Mitigation Rule:** Always use Django's templating engine for rendering output, which automatically escapes HTML. If raw HTML is absolutely necessary, explicitly mark it as safe using `mark_safe` from `django.utils.safestring` only after rigorous sanitization of the input using a trusted library like `Bleach`.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** The application constructs SQL queries using user-controlled input without proper sanitization, allowing attackers to alter the query's intent.
**Mitigation Rule:** Prefer the Django ORM for all database interactions. If raw SQL is unavoidable, always use Django's `cursor.execute()` with parameterized queries, never concatenate user input directly into SQL strings.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** The application fails to verify that a web request was intentionally sent by the user, allowing attackers to trick users into performing unwanted actions.
**Mitigation Rule:** Enable and use Django's built-in CSRF protection for all POST requests by including `{% csrf_token %}` in forms and ensuring `CsrfViewMiddleware` is active in `MIDDLEWARE`.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** The application uses untrusted input to construct file paths without proper validation, allowing attackers to access or modify files outside of intended directories.
**Mitigation Rule:** Never concatenate user-supplied input directly into file paths. When handling file uploads or accessing server-side files based on user input, validate and sanitize filenames to prevent path components like `../` and restrict operations to specific, isolated directories using `os.path.abspath` and `os.path.commonpath` for validation, or Django's `Storage` API.

### CWE-798: Use of Hard-coded Credentials
**Summary:** The application embeds sensitive credentials directly within the source code, making them easily discoverable and compromising security.
**Mitigation Rule:** Never hardcode sensitive information such as API keys, database credentials, or secret keys in the codebase. Utilize environment variables (e.g., `os.environ`), Django's `settings.py` for configuration loaded from environment, or a secure secrets management solution (e.g., `django-environ`, Vault) for production deployments.

### CWE-287: Improper Authentication
**Summary:** The application fails to properly verify the identity of a user, leading to unauthorized access.
**Mitigation Rule:** Use Django's built-in authentication system (`django.contrib.auth`) for user management, session handling, and password hashing. Always store user passwords using strong, adaptive hashing algorithms provided by Django's `PasswordHasher` (e.g., PBKDF2 with SHA256 or Argon2), never plain text or weak hashes.

### CWE-327: Use of a Broken or Risky Cryptographic Algorithm
**Summary:** The application uses cryptography incorrectly or relies on outdated/weak algorithms, making sensitive data vulnerable to attack.
**Mitigation Rule:** For cryptographic operations (e.g., encryption, digital signatures, secure randomness), use Django's built-in cryptographic functions or standard, peer-reviewed libraries like `cryptography` or `hashlib` with strong, up-to-date algorithms (e.g., AES-256 GCM, SHA256+, PBKDF2, Argon2). Always use a cryptographically secure pseudorandom number generator (CSPRNG) for security-sensitive contexts, such as `secrets.token_hex` or `os.urandom`, never `random`.