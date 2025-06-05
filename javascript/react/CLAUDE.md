# Claude Security Rules for JavaScript/React Applications

## Foundational Instructions for Secure Code Generation

*   As a security-aware developer, generate secure JavaScript code using React that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Memory Safety Considerations

*   **Note**: JavaScript is a memory-managed language, abstracting away direct memory allocation and deallocation. Therefore, typical C/C++ style memory safety issues (e.g., buffer overflows, use-after-free) are not directly applicable. Focus on secure coding practices relevant to the language's execution model, such as preventing excessive memory consumption leading to denial-of-service, and preventing data leakage through improper object handling or closures.

## Top CWEs for JavaScript + React Applications

### CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Summary:** Insufficient neutralization of untrusted input leads to malicious script execution in a user's browser.
**Mitigation Rule:** Always use React's built-in automatic escaping for all content rendered via JSX. When explicitly setting HTML using `dangerouslySetInnerHTML`, ensure all content is strictly sanitized beforehand using a robust, community-audited library like `dompurify`.

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Summary:** Malicious SQL queries can be executed due to improper handling of user-controlled input in database queries.
**Mitigation Rule:** Frontend JavaScript/React applications should not directly interact with databases. Ensure all database interactions occur via a properly secured backend API. The backend must exclusively use parameterized queries or prepared statements for all database operations, never concatenating user input directly into SQL queries.

### CWE-352: Cross-Site Request Forgery (CSRF)

**Summary:** An attacker can trick a victim into submitting a malicious request to a web application they are authenticated to.
**Mitigation Rule:** Implement anti-CSRF tokens on the backend for all state-changing requests (e.g., POST, PUT, DELETE). The React frontend must fetch this token and include it in all such requests. Configure `SameSite` cookie attributes (e.g., `Lax` or `Strict`) to prevent cross-site delivery of session cookies where applicable.

### CWE-20: Improper Input Validation

**Summary:** The software does not validate or incorrectly validates input, allowing malicious data to affect program execution or data integrity.
**Mitigation Rule:** Perform comprehensive input validation on all user-supplied data on both the client-side (for user experience) and *critically* on the server-side. Validation must cover data type, format, length, and content, and should leverage robust schema validation libraries (e.g., `Yup` or `Zod` for client-side, `Joi` or `Zod` for server-side). Never trust client-side validation alone.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Summary:** Input containing path traversal sequences is not properly neutralized, leading to access to arbitrary files or directories.
**Mitigation Rule:** Avoid constructing file paths or resource identifiers directly from untrusted user input within any server-side logic that the React application communicates with (e.g., server-side rendering, API endpoints handling file operations). If file access is necessary, strictly whitelist allowed paths and use `path.normalize()` followed by rigorous validation to prevent traversal sequences.

### CWE-347: Improper Verification of Signature in Cryptographic Key

**Summary:** A cryptographic signature is not properly verified, leading to acceptance of illegitimate data.
**Mitigation Rule:** Do not attempt to verify cryptographic signatures (e.g., JWT signatures) on the client-side in React. Instead, rely on a secure backend to perform all signature verifications and subsequent authorization decisions based on validated tokens. All communication with the backend should be over HTTPS to ensure integrity and confidentiality.

### Hardcoded Secrets and Credentials

**Summary:** Sensitive information like API keys, database credentials, or private keys are directly embedded in the source code.
**Mitigation Rule:** Never hardcode sensitive API keys, credentials, or any form of secret directly into the React frontend source code or expose them in client-side bundles. Utilize environment variables (e.g., via `.env` files for development, or build-time environment injection for production) or secure secret management services to inject sensitive information into the build or runtime environment. Publicly exposed keys must be treated with extreme caution, and strictly limited to public-facing services with appropriate rate limiting and domain restrictions.