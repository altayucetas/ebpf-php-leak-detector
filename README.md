
# eBPF PHP Leak Detector

This project is a debugging tool designed to dynamically detect memory management issues within PHP extensions using eBPF technology. It traces the Zend Engine's memory manager to find common bugs originating from native C code.

The tool detects several types of memory errors:

- ```Memory Leak```: Identifies allocated memory that is never freed by the end of the script's execution.

- ```Double Free```: Catches attempts to free the same memory pointer more than once.

- ```Mismatched Free```: Reports the use of an incorrect deallocation function for a given allocation type (e.g., using efree on a pemalloc pointer).

- ```Use-after-Free```: Detects read or write operations on a memory pointer that has already been freed. 

**Note 1**: The tool automatically discovers all exported functions within a target extension's .so file using _nm_ tool. Tracing is only active when the execution flow is inside one of these discovered functions, which filters out noise from the PHP core.

**Note 2**: To capture the extension, you need to perform routine steps. The extension must be compiled, added to the php.ini file, and copied to the extension folder. Only after these can the program be run properly.

**Note 3**: *calloc functions call *malloc functions internally, so they appear to be normal *malloc calls. To avoid this problem, *malloc calls are ignored inside *calloc calls.

**Note 4**: The repo contains a test folder. This folder contains an extension written for testing the code. It can be compiled with the following command. To use the plugin after compiling, add **extension=php_leak_test.so** to the php.ini file.

```
[PHP Folder Path]/bin/phpize && \
./configure --with-php-config=[PHP Folder Path]/bin/php-config && \
make && \
cp modules/php_leak_test.so $([PHP Folder Path]/bin/php-config --extension-dir)
```

**Note 5**: The program was tested with 8.4.12 version PHP compiled with the following flags.
```
    --prefix=[PHP Location]
    --enable-debug
    --enable-fpm
    --enable-dtrace
    --with-openssl
    --with-zlib
    --enable-mbstring
    --with-curl
```

The flow of the program is as follows.

### 1. Scoping

In this phase, the userspace program inspects the target extension's shared object file with nm to identify all exported zif_* and zm_* functions. _uprobes_ are attached to the entry and exit points of these functions. When execution enters an extension function, a flag is set for the current thread ID, activating the memory tracking. When it exits, the flag is cleared. This ensures that only memory operations performed by the extension are analyzed.

### 2. Real-time Memory Tracking

While the "in-extension" flag is active, uprobes on PHP's memory functions (*_emalloc*, *_efree*, etc.) and various libc functions (e.g., *strtok*, *sprintf*) track activity.  All new allocations are stored as entries in an eBPF map, keyed by their memory address. When a free operation occurs, its pointer is added to *FREED_POINTERS* map and the tool checks the *ALLOCATIONS* map. If the address exists, it is removed. If it doesn't exist, it is flagged as a **Double Free**. A check is also performed to ensure the deallocation function matches the allocation type or is flagged as a **Mismatched Free**. During calls to hooked libc functions, the tool flags a **Use-after-Free** if a pointer argument corresponds to a memory address that has already been in *FREED_POINTERS*. All detected corruptions are immediately sent to a separate map for later reporting.

### 3. Memory Operation Analysis

After the target PHP process has completed its work and the user stops the tool (Ctrl+C), the userspace program performs a final check. It iterates through any remaining entries in the *ALLOCATIONS* map. Since these allocations were never freed, they are flagged as memory leaks. Finally, all collected leak and corruption data is processed, symbolized, and printed to the console in a detailed report.

### How to Run

```
sudo /path/to/your/php-leak-detector \
    --php-path /path/to/your/php \
    --extension-path /path/to/your/php/extensions/**/extension.so \
    --libc-path /path/to/your/libc.so.6

```