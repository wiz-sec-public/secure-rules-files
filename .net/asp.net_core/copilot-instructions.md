As a security-aware developer, generate secure .NET code using ASP.NET Core that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

### Memory Safety
**Note:** C# is a garbage-collected, memory-safe language, which inherently mitigates many memory safety vulnerabilities (e.g., buffer overflows, use-after-free). Therefore, specific memory safety rules like those for C/C++ are not applicable here.

---

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** Untrusted input is used to construct a SQL query without proper neutralization, leading to arbitrary command execution.
**Mitigation Rule:** Always use parameterized queries or an Object-Relational Mapper (ORM) like Entity Framework Core for all database interactions to ensure that user-supplied input is treated as data, not executable code.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** Web application includes unvalidated or improperly encoded user-supplied input in dynamic content, allowing malicious scripts to execute in a user's browser.
**Mitigation Rule:** Automatically HTML-encode all user-supplied input before rendering it in Razor Pages or MVC views; for JavaScript contexts, use a dedicated encoding library or secure framework features to escape data, avoiding direct insertion of untrusted data into script blocks or HTML attributes.

### CWE-287: Improper Authentication
**Summary:** The application does not correctly verify user identity, leading to bypassable authentication mechanisms.
**Mitigation Rule:** Utilize ASP.NET Core Identity for all authentication management, ensuring robust password hashing (e.g., using ASP.NET Core Identity's default `PasswordHasher`), multi-factor authentication (MFA) support, account lockout policies, and secure session management.

### CWE-285: Improper Authorization
**Summary:** The application fails to properly restrict access to resources or functions based on a user's privileges.
**Mitigation Rule:** Implement granular authorization using ASP.NET Core's Role-based or Policy-based Authorization, applying `[Authorize]` attributes with specific roles or policies to controllers, actions, or Razor Pages, and perform explicit authorization checks within business logic where fine-grained control is required.

### CWE-502: Deserialization of Untrusted Data
**Summary:** The application deserializes untrusted data, which can lead to remote code execution, denial of service, or other attacks.
**Mitigation Rule:** Avoid deserializing untrusted or unvalidated data, especially from external sources; if deserialization is absolutely necessary, use secure, constrained formats (e.g., JSON), validate input rigorously, and consider using a safe deserialization library with strict type whitelisting.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Sensitive information, such as passwords or API keys, is directly embedded in code or configuration files.
**Mitigation Rule:** Store all secrets (e.g., database connection strings, API keys, certificates) outside of source code and sensitive configuration files using ASP.NET Core's `IConfiguration` interface with secure providers such as Environment Variables, Azure Key Vault, AWS Secrets Manager, or the .NET Secret Manager tool for development environments.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** An attacker can induce the server-side application to make arbitrary or controlled requests to internal or external resources.
**Mitigation Rule:** When making server-side requests based on user-supplied URLs, strictly validate and sanitize the URL (scheme, host, port, path) against an explicit allow-list of trusted domains and protocols, and use `HttpClient` with appropriate timeouts and cancellation tokens.