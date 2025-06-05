As a security-aware developer, generate secure JavaScript code using React that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### Memory Safety Considerations for JavaScript
**Mitigation Rule:** JavaScript is a garbage-collected language and handles memory management automatically. Therefore, direct memory safety concerns like buffer overflows or use-after-free vulnerabilities are not applicable. Focus on logical vulnerabilities and data integrity rather than memory corruption.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** The application allows untrusted data to be embedded into web pages without proper sanitization, leading to client-side code execution.
**Mitigation Rule:** Always sanitize and escape all user-supplied or untrusted data before rendering it in React components. Use React's built-in JSX escaping by default, and for dynamic HTML rendering (`dangerouslySetInnerHTML`), ensure data is rigorously sanitized using a library like `DOMPurify` before assignment. Avoid using `eval()`, `new Function()`, or injecting JavaScript URLs.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** The application does not verify that a request originating from a user's browser was intentionally sent by that user, allowing attackers to trick users into executing unintended actions.
**Mitigation Rule:** Implement and enforce robust CSRF protection for all state-changing operations by ensuring all requests include a unique, server-generated CSRF token (e.g., synchronizer token pattern). The token must be validated on the backend for every sensitive request and not accessible via client-side scripts.

### CWE-522: Insufficiently Protected Credentials
**Summary:** Secrets like API keys, database credentials, or sensitive configuration data are stored or transmitted in an insecure manner, making them susceptible to unauthorized access.
**Mitigation Rule:** Never hardcode secrets, API keys, or sensitive configuration directly into JavaScript code or React components. Store them securely in environment variables (for build time) or fetch them from a secure, authenticated backend service at runtime. Use `.env` files for development and ensure they are excluded from version control (`.gitignore`).

### CWE-20: Improper Input Validation
**Summary:** The application does not properly validate or sanitize user-supplied input, leading to various vulnerabilities such as injection, broken logic, or data corruption.
**Mitigation Rule:** Perform comprehensive input validation on all user-supplied data both on the client-side (for user experience) and, critically, on the server-side (for security). Use strict data type checks, length constraints, format validation (e.g., regex for email), and whitelist validation where possible.

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
**Summary:** The application inadvertently discloses sensitive information (e.g., user data, internal configurations, session tokens) to unauthorized parties.
**Mitigation Rule:** Never store sensitive user data (e.g., personal identifiable information, authentication tokens, payment details) directly in browser `localStorage` or `sessionStorage` without strong justification and encryption. Prefer `HttpOnly` and `Secure` cookies for session tokens. Ensure all network communication transmitting sensitive data uses HTTPS/TLS. Prevent accidental exposure via client-side debugging tools or verbose error messages.

### CWE-287: Improper Authentication
**Summary:** The application's authentication mechanism is flawed, allowing unauthorized users to gain access or bypass security controls.
**Mitigation Rule:** Ensure all sensitive API endpoints are protected by proper authentication and authorization checks on the server-side. On the client-side, manage authentication tokens (e.g., JWTs) securely, store them in `HttpOnly` cookies, and ensure their validity is checked prior to making authenticated requests. Implement secure session management and handle token expiration and refresh securely.

### CWE-601: Open Redirect
**Summary:** The application redirects users to a URL specified by an untrusted input, which can be exploited for phishing or malware distribution.
**Mitigation Rule:** When handling redirects (e.g., after login, external links), always validate the target URL against a predefined whitelist of allowed domains or ensure that the redirect URL is relative to the application's own domain. Never use untrusted input directly for redirection without strict validation.