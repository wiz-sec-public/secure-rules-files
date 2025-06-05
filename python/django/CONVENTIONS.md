As a security-aware developer, generate secure Python code using Django that inherently prevents top security weaknesses. Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes. Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code. Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines. Avoid Slopsquatting: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

Python is a memory-safe language, so explicit memory safety considerations are not required.

### CWE-79: Cross-Site Scripting (XSS)
**Summary:** An XSS vulnerability occurs when an application includes untrusted data in an HTML page without proper escaping, allowing attackers to execute scripts in the victim's browser.
**Mitigation Rule:** Always use Django's template engine for rendering user-supplied data in HTML, as it auto-escapes output by default. If raw HTML is absolutely necessary and comes from a trusted, sanitized source, explicitly mark it as safe using `django.utils.safestring.mark_safe` only after rigorous validation and sanitization.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** SQL Injection allows attackers to manipulate or access unauthorized data by injecting malicious SQL code into input fields.
**Mitigation Rule:** Exclusively use Django's Object-Relational Mapper (ORM) for all database interactions. Avoid raw SQL queries unless strictly necessary for performance or complex operations, and if so, always use the database driver's parameterization capabilities (e.g., `connection.cursor().execute(sql, [params])`) for all dynamic values, never string formatting or concatenation.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** CSRF tricks an authenticated victim's browser into sending a forged request to a web application, performing an action without their explicit consent.
**Mitigation Rule:** Ensure Django's built-in CSRF protection middleware (`django.middleware.csrf.CsrfViewMiddleware`) is active for all POST, PUT, and DELETE requests, and include the `{% csrf_token %}` template tag in all forms. Use `csrf_exempt` views only when absolutely necessary and always implement an alternative, equally robust token verification mechanism.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** Path Traversal allows attackers to access, create, or modify files and directories outside of an intended root directory by manipulating file paths in input.
**Mitigation Rule:** Never construct file paths directly from user input. Always use `os.path.join` or `pathlib.Path` for path construction, and validate that any user-supplied path components are strictly within allowed directories using `os.path.abspath` and by verifying that the resulting path starts with an expected base directory (e.g., `path.startswith(base_dir)`). Store uploaded files in non-web-accessible locations and serve them securely.

### CWE-522: Insufficiently Protected Credentials
**Summary:** This weakness occurs when sensitive authentication credentials or secrets are not adequately protected, leading to potential exposure.
**Mitigation Rule:** Never hardcode secrets, API keys, database credentials, or any sensitive configuration values directly in the codebase. Utilize environment variables (e.g., via `os.environ`), external configuration files managed by tools like `python-decouple` or `django-environ`, or dedicated secrets management services.

### CWE-287: Improper Authentication
**Summary:** Improper authentication allows an attacker to bypass or subvert the application's authentication mechanisms, gaining unauthorized access.
**Mitigation Rule:** Use `django.contrib.auth` for all authentication-related functionality, including user registration, login, logout, password management (which uses secure hashing by default), and session management. Ensure secure session cookies by setting `HTTPOnly`, `Secure`, and `SameSite` flags appropriately. Implement strong password policies and multi-factor authentication where applicable.

### CWE-732: Incorrect Permission Assignment for Critical Resource
**Summary:** Incorrect permission assignment allows unauthorized users to access or modify resources due to flaws in the application's access control logic.
**Mitigation Rule:** Implement granular access control by leveraging Django's permissions system (`django.contrib.auth.models.Permission`). Use `PermissionRequiredMixin`, `LoginRequiredMixin`, `@permission_required`, and `@user_passes_test` decorators or mixins to enforce access control at the view level. For object-level permissions, explicitly verify that the authenticated user has the necessary authorization to perform actions on the specific resource being accessed.