- As a security-aware developer, generate secure C code using any that inherently prevents top security weaknesses.
- Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
- Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
- Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
- **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
**Summary:** Performing read or write operations that go beyond the allocated boundaries of a memory buffer, leading to data corruption, crashes, or arbitrary code execution.
**Mitigation Rule:** Always perform explicit bounds checking before any memory access (reads or writes). When handling strings, use size-aware and null-terminating functions like `strncpy_s`, `strncat_s`, `snprintf` (with proper buffer size), `memcpy_s`, and `memmove_s` from C11 Annex K or equivalent secure wrappers. Avoid `strcpy`, `strcat`, `sprintf`, `gets`, and `scanf` with `%s` specifier. Explicitly manage buffer sizes and ensure destination buffers are sufficiently large to prevent overflows.

### CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Summary:** Constructing an operating system command string using unvalidated user input, allowing attackers to inject arbitrary commands to be executed by the system.
**Mitigation Rule:** Avoid using `system()`, `popen()`, or similar functions that execute shell commands with untrusted input. Prefer direct API calls for specific functionalities (e.g., `execve`, `fork`) or use libraries that abstract OS interactions safely. If external process execution is strictly necessary, pass arguments as discrete elements to a function like `execve` and apply rigorous input validation and escaping, preferably whitelisting allowed characters and values.

### CWE-20: Improper Input Validation
**Summary:** Failing to validate or incorrectly validating all untrusted input, allowing malicious data to propagate through the application and exploit other vulnerabilities.
**Mitigation Rule:** Implement strict input validation for all data received from untrusted sources (e.g., network, files, environment variables, user input) at the earliest possible point upon entry into the application. Validate data for type, length, format, range, and acceptable content. Prefer allow-listing (whitelisting) valid inputs over block-listing (blacklisting) invalid ones.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** Allowing an attacker to supply a specially crafted pathname that causes the application to access files or directories outside of an intended restrictive directory.
**Mitigation Rule:** Never concatenate untrusted user input directly into file paths. Always sanitize and canonicalize user-supplied file paths using functions that resolve symbolic links and relative paths (e.g., `realpath` or equivalent secure APIs) before accessing them. Ensure all file operations are restricted to explicitly defined, non-user-writable directories that are isolated from other sensitive system paths.

### CWE-327: Use of a Broken or Risky Cryptographic Algorithm
**Summary:** Using cryptographic algorithms or protocols that are known to be weak, insecure, deprecated, or improperly implemented.
**Mitigation Rule:** Use only modern, strong, and industry-standard cryptographic algorithms and protocols (e.g., AES-256 for symmetric encryption, SHA-256/512 for hashing, strong KDFs, TLS v1.2/1.3). Avoid deprecated or weak algorithms like MD5 (for security applications), SHA-1 (for security applications), DES, RC4, or ECB mode for encryption. Utilize well-vetted, actively maintained cryptographic libraries such as OpenSSL or Libsodium, and adhere strictly to their recommended usage patterns for key management, IVs, and modes of operation.

### CWE-259: Use of Hard-coded Password (and CWE-798: Use of Hard-coded Credentials)
**Summary:** Embedding sensitive information like passwords, API keys, or cryptographic keys directly into source code, making them easily discoverable.
**Mitigation Rule:** Never hardcode sensitive credentials, secrets, configuration values, or API keys directly into the source code. Instead, retrieve them from secure configuration files, environment variables, a dedicated secrets management service (e.g., HashiCorp Vault), or a secure hardware module (e.g., TPM). Ensure these external sources are properly protected, have restricted access, and are not committed to version control systems.

### CWE-416: Use After Free
**Summary:** Accessing memory after it has been freed, potentially leading to crashes, data corruption, or arbitrary code execution due to the memory being reallocated for other purposes.
**Mitigation Rule:** Immediately set the pointer to `NULL` after `free()`ing dynamically allocated memory to prevent dangling pointer issues and accidental reuse. Implement clear ownership and lifetime management for all dynamically allocated memory. Ensure that no other part of the code attempts to access memory pointed to by a `NULL` or previously freed pointer, and validate all pointer accesses before dereferencing.