## Copilot Rules for Secure Python Flask Applications

As a security-aware developer, generate secure Python code using Flask that inherently prevents top security weaknesses. Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes. Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code. Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines. Avoid Slopsquatting: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

### Security Best Practices for Python + Flask

**Memory Safety Note:** Python is a memory-safe language, automatically managing memory allocation and deallocation, thereby mitigating common C/C++ memory safety vulnerabilities such as buffer overflows and use-after-free. Explicit memory safety considerations are therefore disregarded for this language.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** The application does not properly neutralize user-controllable input before it is placed into an output page, allowing an attacker to execute arbitrary HTML or script code in the user's browser.
**Mitigation Rule:** Always use Flask's default Jinja2 templating engine, which performs automatic HTML escaping for variables, or explicitly escape any user-supplied content rendered in templates using `{{ variable | e }}` or `flask.escape()`.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** The application constructs all or part of an SQL query using externally-influenced input, allowing an attacker to modify the intended SQL statement.
**Mitigation Rule:** Utilize Object-Relational Mappers (ORMs) like SQLAlchemy with proper ORM query methods, or exclusively use parameterized queries/prepared statements (e.g., `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))` for `sqlite3`) for all database interactions to prevent injection.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** The application does not verify that a request was intentionally made by the user, allowing an attacker to force a user to execute unwanted actions.
**Mitigation Rule:** Implement CSRF protection using `Flask-WTF` (which integrates `WTForms`) by including a CSRF token in all state-changing HTML forms and validating it on the server-side for POST, PUT, DELETE, and PATCH requests.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** The application uses externally-controlled input to construct a pathname that references a file or directory outside of an intended restricted directory.
**Mitigation Rule:** When handling file paths or allowing file uploads/downloads, always use `werkzeug.utils.safe_join` or `os.path.abspath` combined with explicit path validation to ensure that paths resolve within an allowed base directory and prevent access to arbitrary file system locations.

### CWE-522: Insufficiently Protected Credentials (Hardcoded Secrets)
**Summary:** The application stores sensitive authentication credentials directly within the source code, making them easily discoverable by attackers.
**Mitigation Rule:** Never hardcode secrets, API keys, database credentials, or sensitive configuration values directly in the code. Load all secrets from environment variables (e.g., using `python-dotenv` or `os.environ`), a dedicated configuration management system (e.g., `Dynaconf`), or a secure secrets management service.

### CWE-20: Improper Input Validation
**Summary:** The application does not validate or incorrectly validates input, allowing malicious data to be processed and potentially leading to various vulnerabilities.
**Mitigation Rule:** Implement strict server-side validation for all incoming user input (e.g., form data, query parameters, JSON body) using libraries such as `Flask-WTF` forms, Pydantic, or explicit type, format, length, and range checks before processing or storing the data.

### CWE-306: Missing Authentication for Critical Function
**Summary:** The application allows access to a critical function without performing any authentication checks, enabling unauthorized users to perform sensitive operations.
**Mitigation Rule:** Apply robust authentication (e.g., `Flask-Login` for session-based, `Flask-JWT-Extended` for token-based) and authorization mechanisms (e.g., role-based access control decorators or `Flask-Principal`) to all API endpoints and routes, ensuring that only authenticated and authorized users can access sensitive functionality.