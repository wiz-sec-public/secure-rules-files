# Secure Java Spring Code Generation Rules

As a security-aware developer, generate secure Java code using Spring that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

## CWE-Specific Security Rules

### Memory Safety Considerations
**Summary:** Java is a memory-safe language, providing automatic memory management and bounds checking.
**Mitigation Rule:** Disregard specific memory safety considerations for Java as the JVM handles these aspects. Focus on secure coding practices that prevent logic flaws, data exposure, and other common vulnerabilities.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** Untrusted input is used in an SQL query without proper neutralization, allowing attackers to modify the query's intent.
**Mitigation Rule:** Always use `PreparedStatement` with parameterized queries for all database interactions in Spring applications, and never construct SQL queries directly via string concatenation with user input. Utilize Spring Data JPA or Spring's `JdbcTemplate` with named parameters or indexed parameters.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** Untrusted input is directly incorporated into web page content without proper escaping, allowing attackers to inject client-side scripts.
**Mitigation Rule:** Implement strict output encoding for all untrusted data rendered in HTML, JavaScript, CSS, or URL contexts; utilize templating engines like Thymeleaf or FreeMarker which provide auto-escaping by default, or Spring's `HtmlUtils.htmlEscape()` for manual escaping when necessary.

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Summary:** Sensitive data is exposed to an actor who is not authorized to have access to that information.
**Mitigation Rule:** Design applications to enforce the principle of least privilege, ensuring sensitive data is only accessible to authorized components and users, encrypt sensitive data at rest and in transit using TLS/SSL, and avoid logging sensitive information unless absolutely necessary and masked.

### CWE-502: Deserialization of Untrusted Data
**Summary:** The application deserializes untrusted data, which can lead to remote code execution or denial of service attacks.
**Mitigation Rule:** Never deserialize untrusted or unauthenticated data; use secure alternatives like JSON or XML with schema validation, or specialized libraries (e.g., Jackson, Gson) configured to prevent gadget chain attacks, and consider using Spring's `HttpMessageConverters` for safe data binding.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Credentials or other sensitive secrets are embedded directly within the application's source code or configuration files.
**Mitigation Rule:** Store all secrets (e.g., API keys, database passwords) externally using secure configuration management solutions like Spring Cloud Config, HashiCorp Vault, Kubernetes Secrets, or environment variables, and ensure they are retrieved securely at runtime.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** The application fetches a remote resource without validating the user-supplied URL, allowing an attacker to coerce the server into making arbitrary requests.
**Mitigation Rule:** Always validate and sanitize user-supplied URLs before making server-side requests, using a strict allow-list of allowed domains and protocols, and disallow redirects to untrusted destinations.

### CWE-284: Improper Access Control / CWE-285: Improper Authorization
**Summary:** The application does not properly restrict access to resources or functions, allowing unauthorized users to perform actions.
**Mitigation Rule:** Implement robust authorization checks at every API endpoint and service layer using Spring Security's method-level security (`@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@RolesAllowed`) or URL-based interceptors, ensuring all actions are tied to specific roles or permissions.