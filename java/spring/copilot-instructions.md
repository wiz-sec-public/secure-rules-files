# Copilot Rules for Secure Java/Spring Code Generation

## Foundational Instructions for the LLM:
- As a security-aware developer, generate secure Java code using Spring that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Top CWEs for Java + Spring:

### CWE-79: Cross-site Scripting (XSS)
**Summary:** An attacker can inject client-side scripts into web pages viewed by other users, leading to data theft or defacement.
**Mitigation Rule:** Always perform context-aware output encoding for all user-supplied data displayed in HTML, JavaScript, CSS, or URL contexts, utilizing libraries like OWASP ESAPI or Spring's built-in escaping mechanisms (e.g., Thymeleaf's `th:text`, JSTL `c:out`).

### CWE-89: SQL Injection
**Summary:** An attacker can alter or execute arbitrary SQL commands by manipulating user-supplied input that is directly concatenated into SQL queries.
**Mitigation Rule:** Always use parameterized queries (e.g., `PreparedStatement` in JDBC, `EntityManager` in JPA/Hibernate, `JdbcTemplate` in Spring JDBC) for all database interactions to ensure user input is treated as data, not executable code.

### CWE-20: Improper Input Validation
**Summary:** The application does not adequately validate, filter, or sanitize user input, allowing malicious data to affect application logic or downstream systems.
**Mitigation Rule:** Implement strict input validation on all untrusted data at the earliest possible point (e.g., at the API entry point) using frameworks like Spring Validation with JSR 303/380 annotations (`@Valid`, `@NotBlank`, `@Size`, etc.) and custom validators, rejecting malformed or malicious input.

### CWE-502: Deserialization of Untrusted Data
**Summary:** Deserializing untrusted or malicious data can lead to arbitrary code execution, denial of service, or other attacks.
**Mitigation Rule:** Avoid deserializing untrusted data, especially from external sources. If deserialization is unavoidable, use serialization formats that are inherently safe (e.g., JSON instead of Java's native serialization) and implement strict type checks or whitelisting of allowed classes during deserialization. Spring's default JSON/XML handling with Jackson/JAXB is generally safer, but ensure proper configuration.

### CWE-798: Use of Hard-coded Credentials
**Summary:** Hard-coding sensitive information like API keys, passwords, or cryptographic keys directly into source code makes them easily discoverable and exploitable.
**Mitigation Rule:** Never hard-code secrets or credentials in the source code. Instead, manage all sensitive configuration externally using secure mechanisms such as Spring Boot's externalized configuration (`application.properties`, `application.yml`), environment variables, Vault, or secure configuration servers.

### CWE-287: Improper Authentication & CWE-306: Missing Authentication for Critical Function
**Summary:** The application fails to correctly verify the identity of a user or system, or sensitive functions lack proper authentication controls.
**Mitigation Rule:** Implement robust authentication using Spring Security, ensuring all critical endpoints and functions are protected by authentication mechanisms, enforcing strong password policies, and utilizing multi-factor authentication where appropriate.

### CWE-918: Server-Side Request Forgery (SSRF)
**Summary:** An attacker can coerce the server to make requests to internal or external resources that are otherwise inaccessible, potentially leading to information disclosure or system compromise.
**Mitigation Rule:** Validate and sanitize all URLs or hostnames provided by user input before allowing the server to make external requests, using a strict allow-list of permitted domains or IP ranges, and preventing redirects to untrusted destinations.

### CWE-327: Use of a Broken or Risky Cryptographic Algorithm
**Summary:** The application uses cryptographic algorithms or modes of operation that are known to be weak, deprecated, or improperly implemented, compromising data confidentiality or integrity.
**Mitigation Rule:** Utilize modern, strong cryptographic algorithms (e.g., AES-256 for symmetric encryption, RSA with OAEP for asymmetric, SHA-256/512 for hashing) and secure modes (e.g., GCM for authenticated encryption) provided by standard Java Cryptography Architecture (JCA) or libraries like Bouncy Castle, avoiding outdated algorithms like MD5, SHA-1, or DES.

### Memory Safety Considerations:
Java is a memory-managed language; therefore, explicit low-level memory safety considerations (like buffer overflows or use-after-free) typically addressed in languages like C/C++ are mitigated by the Java Virtual Machine (JVM) and its garbage collector. Focus instead on logical vulnerabilities arising from incorrect data handling and resource management.
