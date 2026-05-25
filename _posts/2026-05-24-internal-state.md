---
layout: post
title: Internal State
date: 2026-05-24 20:01 -0400
published: true
categories: ["Reversing Challenge","Pwn College"]
tags: ["CIMG Images", "Static analysis","framebuffer"]
toc: true
---
# Challenge: cIMG — Bigger Framebuffer (Level 3)

## Description
This level keeps the same structure as the previous one, but the framebuffer is **much larger**: instead of 4 pixels, the program now expects **570 pixels** that form a complete ASCII art image.

## Key Changes from the Previous Level

In `main`, the count comparison changed:

### Level 2:
```asm
cmp    r13d, 0x4       ; count == 4
sete   bl
```

### Level 3:
```asm
cmp    r14d, 0x23a     ; count == 570 (0x23a)
sete   bl
```

Everything else (magic number, version, header structure, display algorithm) **remains identical**.

---

## Analysis of the Expected State (`desired_output`)

The `desired_output` now occupies **13,680 bytes** (570 slots × 24 bytes) in the `.data` section @ `0x404020`.

### Determining the dimensions

Since `width × height = 570`, the possible factors are:
- 1×570, 2×285, 3×190, 5×114, 6×95, 10×57, 15×38, 19×30, 30×19, 38×15, etc.

Trying different widths to form a coherent image, **38×15** produces a readable image:

```
.------------------------------------.
|                                    |
|                             ____   |
|                            / ___|  |
|                           | |  _   |
|           ___             | |_| |  |
|    ___   |_ _|  __  __     \____|  |
|   / __|   | |  |  \/  |            |
|  | (__    | |  | |\/| |            |
|   \___|  |___| | |  | |            |
|                |_|  |_|            |
|                                    |
|                                    |
|                                    |
'------------------------------------'
```

### `desired_output` characteristics:

- **Spaces (389 slots)**: The character is `' '` (ASCII 0x20). These skip the `memcmp` comparison according to `main`'s code.
- **Non-space characters (181 slots)**: Form the border and the logo. They require an exact match of all 24 ANSI bytes.
- **Identified colors**:
  - White (255,255,255): border (`|`, `-`, `.`, `'`, `_`)
  - Yellow/Green (129,202,111): letters "c"
  - Blue (60,55,249): letters "o"
  - Orange/Salmon (253,167,136): letters "l"
  - Yellow/Gold (225,193,12): letters "l", "e", "g", "e"

---

## Solution Pipeline

### Step 1: Extract `desired_output` from the binary

```python
with open('cimg_level3', 'rb') as f:
    f.seek(0x3000 + 0x20)  # .data + desired_output offset
    data = f.read(570 * 24)
```

### Step 2: Parse each ANSI slot

```python
for i in range(570):
    slot = data[i*24:(i+1)*24]
    r = int(slot[7:10])   # Red
    g = int(slot[11:14])  # Green
    b = int(slot[15:18])  # Blue
    c = chr(slot[19])     # ASCII character
```

### Step 3: Build the `.cimg` file

```python
import struct

header = b'cIMG' + struct.pack('<H', 2) + struct.pack('BB', 38, 15)

pixels = []
for i in range(570):
    slot = data[i*24:(i+1)*24]
    r = int(slot[7:10])
    g = int(slot[11:14])
    b = int(slot[15:18])
    c = ord(chr(slot[19]))
    pixels.append(bytes([r, g, b, c]))

with open('solve_level3.cimg', 'wb') as f:
    f.write(header + b''.join(pixels))
```

### Step 4: Execute on the server

```bash
/challenge/cimg solve_level3.cimg
```

---

## Key Lesson

When the expected state is very large, **you don't need to semantically understand what the image represents**. The approach is:

1. Identify where the expected state is stored (`.data`)
2. Extract it programmatically
3. Reverse the pixel→ANSI transformation (parse the strings)
4. Rebuild the original pixels
5. Pack them into the correct input format

This pipeline is scalable: it would work the same way if there were 10,000 pixels.
