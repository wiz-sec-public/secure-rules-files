# Copilot Rules for Secure JavaScript/React Code Generation

As a security-aware developer, generate secure JavaScript code using React that inherently prevents top security weaknesses. Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes. Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code. Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines. Avoid Slopsquatting: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

---

## Security Best Practices and CWE Mitigations

### Memory Safety Considerations

JavaScript is a garbage-collected language and is memory-safe by design, meaning direct memory management vulnerabilities like buffer overflows or use-after-free are not applicable at the language level. Therefore, direct memory safety considerations are not required in the generated JavaScript code.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (XSS)
**Summary:** An application incorporates untrusted data into a web page without proper neutralization, allowing malicious client-side scripts to execute in the user's browser.
**Mitigation Rule:** Always sanitize and escape all untrusted user input before rendering it in the DOM, avoiding `dangerouslySetInnerHTML` and instead relying on React's automatic escaping for text nodes, or using a secure library like `dompurify` for HTML content that must be dynamically rendered.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** An application does not verify if a received request was intentionally sent by the user, allowing attackers to trick authenticated users into performing unintended actions.
**Mitigation Rule:** Implement CSRF protection by ensuring all state-changing requests (e.g., POST, PUT, DELETE) include a CSRF token (e.g., using a double-submit cookie or synchronizer token pattern) that is verified by the backend for every request.

### CWE-20: Improper Input Validation
**Summary:** The application does not validate or incorrectly validates user input, leading to various vulnerabilities such as injection, buffer overflows, or unexpected behavior.
**Mitigation Rule:** Perform strict input validation on all user-supplied data both on the client-side (for user experience) and critically on the server-side (for security), enforcing expected data types, formats, lengths, and ranges.

### CWE-798: Use of Hard-coded Credentials
**Summary:** The software contains sensitive credentials or configuration data directly embedded within its source code, increasing the risk of unauthorized access.
**Mitigation Rule:** Never hardcode sensitive secrets, API keys, or credentials directly in the client-side code; instead, fetch them securely from an environment variable (for build time configs) or a backend service at runtime, ensuring they are not exposed to the client.

### CWE-284: Improper Access Control
**Summary:** The application does not correctly enforce authorization rules, allowing authenticated users to access or perform actions they are not permitted to.
**Mitigation Rule:** All authorization decisions must be strictly enforced on the server-side, never relying solely on client-side checks for access control or UI element visibility to prevent unauthorized actions.

### CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes (Prototype Pollution)
**Summary:** An attacker can inject properties into the JavaScript prototype chain, allowing them to modify the behavior of objects throughout the application.
**Mitigation Rule:** Avoid using recursive merge functions or deep object assignments with untrusted input; when parsing JSON or similar data, use `Object.create(null)` for base objects to prevent prototype inheritance, and validate input structure to prevent unexpected property assignments.

### CWE-359: Exposure of Private Information to an Unauthorized Actor
**Summary:** Sensitive information is disclosed to an entity that is not authorized to receive it, often through insecure storage, logging, or network transmission.
**Mitigation Rule:** Do not store sensitive user data (e.g., PII, authentication tokens) directly in `localStorage`, `sessionStorage`, or `cookies` unless absolutely necessary and securely handled; encrypt or hash sensitive data before storage or transmission, and avoid logging sensitive information in client-side logs or developer console.