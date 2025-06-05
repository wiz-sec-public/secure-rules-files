As a security-aware developer, generate secure Java code using Spring that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
**Summary:** Untrusted input is directly incorporated into an SQL query, allowing an attacker to alter the query's meaning or execute arbitrary SQL commands.
**Mitigation Rule:** Always use parameterized queries or Prepared Statements when interacting with databases, leveraging Spring Data JPA, `JdbcTemplate`, or similar frameworks that abstract and enforce secure query construction. Never concatenate user-supplied input directly into SQL strings.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** User-supplied input is rendered by a web browser without proper context-aware sanitization, allowing malicious scripts to execute in the user's browser.
**Mitigation Rule:** Employ context-aware output encoding for all user-supplied data rendered within HTML, JavaScript, or URL contexts. Utilize templating engines like Thymeleaf or FreeMarker that perform automatic escaping by default, and for manual encoding, use robust libraries such as OWASP ESAPI or Apache Commons Text's `StringEscapeUtils`.

### CWE-306: Missing Authentication for Critical Function
**Summary:** Critical application functions or resources can be accessed without requiring proper user authentication.
**Mitigation Rule:** Implement comprehensive authentication mechanisms using Spring Security. Ensure all sensitive endpoints and critical functionalities are protected by appropriate access controls (e.g., `http.authorizeRequests()`, `@PreAuthorize`, `@Secured`), requiring authenticated users with necessary roles or permissions.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** An attacker tricks a victim's browser into making an unintended, authenticated request to a web application where the victim is logged in.
**Mitigation Rule:** Enable and configure CSRF protection provided by Spring Security for all state-changing operations (e.g., POST, PUT, DELETE requests). Ensure that all non-GET HTTP requests include a valid CSRF token that the server verifies.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing data from untrusted sources can lead to arbitrary code execution, denial of service, or information disclosure due to vulnerabilities in the deserialization process.
**Mitigation Rule:** Avoid deserializing untrusted data whenever possible. If deserialization is unavoidable, use secure, schema-validated data formats (e.g., JSON with `Jackson` configured with `FAIL_ON_UNKNOWN_PROPERTIES` and explicit type handling). Implement strict whitelisting for allowed classes and properties to prevent gadget chain exploitation.

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Summary:** Sensitive data is inadvertently or improperly revealed to individuals or systems that are not authorized to access it.
**Mitigation Rule:** Apply the principle of least privilege to data access and revelation. Prevent sensitive data (e.g., PII, credentials, session IDs) from being logged, appearing in verbose error messages (disable stack traces in production, use Spring's `ErrorController` for graceful error handling), or exposed in API responses. Encrypt sensitive data at rest and in transit using strong cryptographic protocols (e.g., TLS for network communication).

### Memory Safety
**Mitigation Rule:** Java is a memory-safe language, automatically managing memory through garbage collection. No explicit memory safety rules (like C/C++ memory management) are required. Focus on standard Java best practices to avoid performance issues or logical memory leaks (e.g., holding unnecessary references).

### Hardcoded Secrets and Credentials
**Mitigation Rule:** Never hardcode sensitive information such as API keys, database credentials, encryption keys, or sensitive configuration parameters directly into source code, configuration files managed in source control, or environment variables in development. Utilize externalized, secure configuration management systems (e.g., Spring Cloud Config, environment variables, HashiCorp Vault, Kubernetes Secrets) to inject sensitive values at runtime in production environments.