# Claude Rules for Secure C Code Generation

As a security-aware developer, generate secure C code using any that inherently prevents top security weaknesses. Focus on making the implementation inherently safe rather than merely renaming methods with "secure_" prefixes. Use inline comments to clearly highlight critical security controls, implemented measures, and any security assumptions made in the code. Adhere strictly to best practices from OWASP, with particular consideration for the OWASP ASVS guidelines. **Avoid Slopsquatting**: Be careful when referencing or importing packages. Do not guess if a package exists. Comment on any low reputation or uncommon packages you have included.

### CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
**Summary:** The program performs an operation on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.
**Mitigation Rule:** Always perform explicit bounds checks before any read or write operation to a buffer, and use size-limited string and memory manipulation functions like `snprintf`, `strncpy`, `strncat`, `memcpy`, `memmove`, and `memset` with explicit length arguments, ensuring the destination buffer size is never exceeded. Allocate memory dynamically with `malloc`, `calloc`, or `realloc` and always check the return value for `NULL` to ensure allocation success. When reallocating memory, ensure the new size is carefully validated to prevent arithmetic overflows that could lead to smaller-than-intended allocations.

### CWE-125: Out-of-bounds Read
**Summary:** The program reads data from a memory location that is outside of the bounds of a buffer.
**Mitigation Rule:** Ensure all array indices and pointer arithmetic operations are rigorously validated to fall within the allocated or declared bounds of the respective memory region, particularly when processing external input or loop boundaries. Use standard library functions that perform bounds checking, such as `snprintf` for string formatting, and explicitly manage buffer sizes.

### CWE-416: Use After Free
**Summary:** The program attempts to access memory after it has been freed, which can lead to unpredictable behavior, crashes, or arbitrary code execution.
**Mitigation Rule:** After calling `free()` on a pointer, immediately set the pointer to `NULL` to prevent subsequent dereferencing, and ensure no other pointers or aliases refer to the freed memory block. All memory allocations must have a clear ownership and deallocation strategy to avoid double-free vulnerabilities.

### CWE-476: NULL Pointer Dereference
**Summary:** The program attempts to access a memory location through a pointer that has a `NULL` value, typically leading to a crash or denial of service.
**Mitigation Rule:** Always check pointers for `NULL` before dereferencing them, especially after memory allocation attempts (`malloc`, `calloc`, `realloc`), function calls that might return `NULL` on error, or when handling optional data.

### CWE-190: Integer Overflow or Wraparound
**Summary:** An integer arithmetic operation produces a result that is too large to be stored in the available integer type, leading to a wraparound to a much smaller or negative value.
**Mitigation Rule:** When performing arithmetic operations that could lead to integer overflows (e.g., calculations involving sizes, counts, or large numbers), use appropriately sized integer types (e.g., `size_t`, `long long`) and implement explicit checks to detect and handle potential overflows before they occur, especially when calculating buffer sizes or loop bounds.

### CWE-798: Use of Hard-coded Credentials
**Summary:** The program contains sensitive authentication credentials or other secrets directly embedded in the code.
**Mitigation Rule:** Never embed secrets (e.g., API keys, passwords, cryptographic keys, connection strings) directly in the source code. Instead, retrieve sensitive information securely at runtime from environment variables, secure configuration files (with appropriate access controls), or a dedicated secret management system.

### CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
**Summary:** The program constructs an OS command using external input without properly neutralizing special characters, allowing attackers to execute arbitrary system commands.
**Mitigation Rule:** Avoid using `system()`, `execl()`, `execvp()`, or similar functions with unsanitized or untrusted input. If an external process must be executed, use functions that explicitly separate the command and its arguments (e.g., `fork`/`execve`) and strictly validate and sanitize all user-supplied input intended for command arguments to prevent injection of malicious characters or commands. Prefer specific API calls over shell execution where possible.