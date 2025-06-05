# Secure JavaScript/React Code Generation Codex Rules

## Foundational Instructions for LLM:

*   As a security-aware developer, generate secure JavaScript code using React that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Top CWEs for JavaScript + React:

### Memory Safety Consideration:
JavaScript is a memory-managed language with automatic garbage collection. Therefore, direct memory safety vulnerabilities (e.g., buffer overflows, use-after-free) common in languages like C/C++ are not directly applicable. However, uncontrolled resource consumption (CWE-400) related to excessive memory usage from large data structures or infinite loops can still lead to client-side denial of service.

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**Summary:** The application does not properly neutralize or escape user-controllable input before it is rendered to the user's browser, leading to the execution of malicious scripts.
**Mitigation Rule:** Ensure all dynamic content rendered into the DOM is properly sanitized and escaped, primarily relying on React's automatic JSX escaping; avoid `dangerouslySetInnerHTML` unless absolutely necessary and with strict sanitization using a library like `dompurify` for untrusted HTML.

### CWE-20: Improper Input Validation
**Summary:** The application does not validate or incorrectly validates user-controlled input, which can lead to various vulnerabilities including injection, buffer overflows, or logical flaws.
**Mitigation Rule:** All user-supplied input, whether from forms, URLs, or APIs, must be strictly validated on both the client-side (for user experience) and server-side (for security) against expected data types, formats, and ranges using robust validation libraries or custom validation logic.

### CWE-352: Cross-Site Request Forgery (CSRF)
**Summary:** The web application does not sufficiently protect sensitive actions from being performed by an authenticated user without their explicit consent, typically by a malicious third-party site.
**Mitigation Rule:** Implement anti-CSRF tokens for all state-changing operations by ensuring every sensitive request includes a unique, unpredictable, and server-validated token, often managed by the backend and included in the client-side requests.

### CWE-798: Use of Hard-coded Credentials
**Summary:** The application uses hard-coded usernames, passwords, API keys, or other credentials directly within the source code, making them easily discoverable and exploitable.
**Mitigation Rule:** Never hardcode sensitive credentials, API keys, or secrets directly in the client-side code; instead, utilize secure environment variables loaded at build time for non-sensitive public configurations, or obtain sensitive credentials securely from a backend service, avoiding their exposure in the browser.

### CWE-400: Uncontrolled Resource Consumption ('Denial of Service')
**Summary:** The application does not properly limit the amount of resources (CPU, memory, network, etc.) that can be consumed by an attacker, leading to a denial of service.
**Mitigation Rule:** Implement rate limiting for API requests from the client, enforce pagination and size limits on data fetched and processed, and ensure client-side rendering or computation logic cannot be easily triggered into infinite loops or excessive memory consumption by malicious input.

### CWE-287: Improper Authentication
**Summary:** The application does not correctly verify the identity of a user or system, leading to unauthorized access.
**Mitigation Rule:** Implement robust authentication mechanisms using industry-standard protocols (e.g., OAuth 2.0, OpenID Connect); securely store and transmit session tokens (e.g., HttpOnly, Secure cookies or JWTs in `localStorage` with appropriate security considerations); and ensure all authentication flows are resistant to common attacks like brute-force or credential stuffing.