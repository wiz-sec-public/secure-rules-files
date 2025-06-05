## Foundational Instructions for Secure Java/Spring Code Generation

- As a security-aware developer, generate secure Java code using Spring that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.
- **Memory Safety**: Java is a memory-managed language, abstracting memory safety concerns from the developer. Focus on logical and data security vulnerabilities rather than low-level memory errors.

---

## Top CWEs for Java + Spring and Their Mitigations

### CWE-89: SQL Injection
**Summary:** Untrusted input is used to construct a SQL query, allowing an attacker to modify the query's intent or execute arbitrary database commands.
**Mitigation Rule:** Always use parameterized queries, prepared statements, or Spring Data JPA's derived queries and `@Query` annotations with named parameters. Never concatenate user-supplied input directly into SQL strings.

### CWE-79: Cross-Site Scripting (XSS)
**Summary:** An application includes untrusted data in an HTTP response without proper encoding, allowing an attacker to execute arbitrary script in the user's browser.
**Mitigation Rule:** Apply context-aware output encoding to all untrusted data before rendering it in HTML, JavaScript, URL parameters, or CSS. Leverage Spring's templating engines (e.g., Thymeleaf, FreeMarker) which provide auto-escaping by default, or use libraries like OWASP Java Encoder. Implement a strict Content Security Policy (CSP) header.

### CWE-287: Improper Authentication
**Summary:** The application does not correctly verify or establish the identity of a user, allowing unauthorized access.
**Mitigation Rule:** Implement authentication using Spring Security. Ensure strong password hashing with adaptive functions like BCrypt or Argon2 (via `PasswordEncoder`). Enforce secure session management, requiring re-authentication for sensitive operations, and implement multi-factor authentication where appropriate.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing untrusted data can lead to arbitrary code execution, denial of service, or data manipulation vulnerabilities.
**Mitigation Rule:** Never deserialize untrusted or unvalidated data. If deserialization is unavoidable, use serialization filters, allowlist only expected classes, or implement strict validation and integrity checks before and after deserialization. Avoid Java's default serialization and prefer safer formats like JSON or XML with secure parsers (e.g., Jackson or JAXB with security features enabled).

### CWE-611: Improper Restriction of XML External Entity Reference (XXE)
**Summary:** An XML parser processes untrusted input containing references to external entities, which can lead to information disclosure, server-side request forgery, or denial of service.
**Mitigation Rule:** Disable DTDs and external entity processing for all XML parsers (e.g., `SAXParserFactory`, `DocumentBuilderFactory`, `XMLInputFactory`). Explicitly set properties like `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` and disable `ENTITY_RESOLUTION` and `EXTERNAL_GENERAL_ENTITIES`.

### CWE-22: Path Traversal
**Summary:** An application uses user-supplied input to construct a file path without proper validation, allowing access to arbitrary files or directories on the server.
**Mitigation Rule:** Validate and sanitize all user-supplied file paths. Use `java.nio.file.Path.normalize()` and resolve against a strictly controlled, pre-defined base directory. Never allow user input to directly form file paths. Implement strong access control on directories and files.

### Hardcoded Secrets and Credentials
**Summary:** Sensitive information like API keys, database credentials, or cryptographic keys are embedded directly into the application's source code or configuration files.
**Mitigation Rule:** Never hardcode secrets or credentials directly in the codebase or application resource files. Utilize externalized configuration management systems such as Spring Cloud Config, HashiCorp Vault, environment variables, JVM system properties, or secure secrets management services provided by cloud providers. Reference these secrets securely at runtime.