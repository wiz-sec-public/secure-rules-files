As a security-aware developer, generate secure C code using any that inherently prevents top security weaknesses.
Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
**Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
**Summary:** The software performs an operation on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.
**Mitigation Rule:** Always validate buffer sizes and perform explicit bounds checking before memory access or string operations. Use `strncpy`, `strncat` (ensuring null termination), `snprintf` with a specified maximum size, or safer alternatives like `strlcpy`/`strlcat` where available, instead of `strcpy`, `strcat`, or `sprintf`.

### CWE-125: Out-of-bounds Read
**Summary:** The software reads data from a memory location that is outside of the bounds of the intended buffer.
**Mitigation Rule:** Before accessing array elements or dereferencing pointers based on an index, ensure the index is within the valid allocated or defined bounds of the memory region. When using `scanf` or similar input functions, always specify maximum lengths in the format string (e.g., `%9s` for a 10-byte buffer).

### CWE-416: Use After Free
**Summary:** The software attempts to access memory after it has been freed.
**Mitigation Rule:** After calling `free()` on a pointer, immediately set the pointer to `NULL` to prevent dangling pointer issues and subsequent use-after-free vulnerabilities. Ensure that memory is freed exactly once and that no references to freed memory remain.

### CWE-798: Use of Hard-coded Credentials
**Summary:** The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for authentication, authorization, or encryption.
**Mitigation Rule:** Never embed secrets (e.g., API keys, passwords, cryptographic keys, connection strings) directly in source code. Retrieve sensitive information from secure external sources such as environment variables, secure configuration files, or dedicated secret management systems (e.g., HashiCorp Vault, AWS Secrets Manager) at runtime.

### CWE-78: OS Command Injection
**Summary:** The software constructs all or part of an OS command using externally-controlled input, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended OS command when it is executed.
**Mitigation Rule:** Avoid executing OS commands directly via functions like `system()` or `popen()`. If external command execution is strictly necessary, use `exec` family functions (e.g., `execlp`, `execvp`) with a fixed command and separate, properly escaped arguments. Thoroughly validate and sanitize all user-controlled input that might be incorporated into a command or its arguments.

### CWE-190: Integer Overflow or Wraparound
**Summary:** A computation performs an addition, multiplication, or subtraction that results in an integer value that is larger or smaller than the maximum or minimum value allowed by the integer type, respectively, which can lead to unexpected behavior.
**Mitigation Rule:** Always check for potential integer overflows or underflows before performing arithmetic operations, especially when calculating sizes for memory allocation (`malloc`, `calloc`) or processing loop counters. Use `size_t` for sizes and counts. Consider using safe integer arithmetic libraries if available and appropriate, or implement explicit checks for overflow/underflow conditions.

### CWE-134: Uncontrolled Format String
**Summary:** The software uses a user-controlled format string in a function like `printf` or `sprintf`, which can lead to information disclosure or arbitrary code execution.
**Mitigation Rule:** Never pass user-controlled input directly as the format string argument to functions like `printf`, `sprintf`, `snprintf`, `fprintf`, or `scanf`. Always use a constant, fixed format string for these functions, separating user-controlled data as distinct arguments.