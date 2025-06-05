# Copilot Rules for Secure C Code Generation

## Foundational Instructions for LLM:

*   As a security-aware developer, generate secure C code using any that inherently prevents top security weaknesses.
*   Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes.
*   Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code.
*   Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines.
*   **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

## Identified Top CWEs for C + any:

### CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
**Summary:** This CWE describes a buffer overflow condition where software performs operations on a memory buffer beyond its allocated boundaries, potentially overwriting adjacent memory.
**Mitigation Rule:** Always perform explicit bounds checking before writing to or reading from buffers. When handling strings, use safe string manipulation functions like `strncpy` (with null termination), `strncat` (with explicit size), `snprintf` for formatting, or `memcpy_s`/`memmove_s` from C11 Annex K for memory copying, ensuring destination buffer size is always respected. Avoid unbounded functions like `strcpy`, `strcat`, `sprintf`, `gets`, and `scanf`.

### CWE-416: Use After Free
**Summary:** This CWE occurs when a program attempts to access memory after it has been freed, leading to unpredictable behavior, crashes, or arbitrary code execution.
**Mitigation Rule:** After freeing dynamically allocated memory using `free()`, immediately set the corresponding pointer to `NULL` to prevent subsequent accidental dereferences of stale pointers. Ensure that memory is only freed once and that all access to freed memory ceases.

### CWE-20: Improper Input Validation
**Summary:** This CWE occurs when the software does not validate or incorrectly validates input from an untrusted source, which can lead to various vulnerabilities like injection, buffer overflows, or unexpected application behavior.
**Mitigation Rule:** Implement strict input validation on all untrusted data, using an allow-list (whitelist) approach for permitted characters, values, or formats rather than a deny-list. Canonicalize input before validation and use `is*()` functions from `<ctype.h>` or custom robust validation routines to check character properties.

### CWE-798: Use of Hard-coded Credentials
**Summary:** This CWE describes the inclusion of credentials or cryptographic keys directly within source code or binaries, making them easily discoverable and compromising security.
**Mitigation Rule:** Never hardcode secrets, credentials, API keys, or cryptographic keys directly into the source code. Instead, retrieve sensitive information securely at runtime from environment variables, secure configuration files (with appropriate permissions and encryption), a dedicated secret management service, or command-line arguments.

### CWE-190: Integer Overflow or Wraparound
**Summary:** This CWE occurs when an arithmetic operation produces a result that is larger than the maximum value that can be stored in the integer type, causing the value to "wrap around" to a small or negative number.
**Mitigation Rule:** Before performing arithmetic operations, especially those involving user-supplied input or calculations that might exceed type limits, explicitly check for potential integer overflows or underflows. Use wider integer types or perform manual checks (e.g., `if (a > MAX_INT - b)`) to ensure the result will fit within the intended data type.

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
**Summary:** This CWE occurs when an application processes user-supplied file paths in a way that allows them to access files or directories outside of an intended restricted directory.
**Mitigation Rule:** When handling file paths provided by untrusted input, canonicalize the path first (e.g., resolve `../` sequences) and then strictly validate it against a list of allowed characters, formats, and most importantly, ensure it falls within a predefined, restricted base directory using functions like `realpath()` if available on the system, or careful string manipulation and prefix checking.

### CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**Summary:** This CWE occurs when the outcome of a program depends on the relative timing or interleaving of multiple concurrent operations accessing shared resources, leading to unpredictable or erroneous behavior.
**Mitigation Rule:** Protect all access to shared resources (e.g., global variables, shared memory regions, files) with proper synchronization mechanisms such as mutexes (e.g., `pthread_mutex_t` and associated functions from `<pthread.h>`), semaphores, or atomic operations (from `<stdatomic.h>` in C11) to ensure mutual exclusion and prevent race conditions.