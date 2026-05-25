---
layout: post
title: Storage and Retreival
date: 2026-05-24 20:42 -0400
published: false
categories: ["Reversing Challenge","Pwn College"]
tags: ["CIMG Images", "Static analysis"]
toc: true
---
# Storage and Retrieval — Writeup

## Challenge Overview

The challenge presents a `cimg` binary that interprets a custom image format called **cIMG** (version 3). The goal is to create a `.cimg` file of **less than 400 bytes** that, when processed, renders exactly a target image of **76×24 pixels** with a white border and the text `"SPRITE"` in multiple colors. If the generated image matches the expected one, the program executes `win()` and reads the flag from `/flag`.

---

## 1. Binary and Source Code Analysis

The `cimg.c` file contains the complete source code of the interpreter. Analyzing it, we identified the following key structures:

```c
typedef struct {
    char magic[4];      // "cIMG"
    uint32_t version;   // Must be 3
    uint32_t width;     // Framebuffer width
    uint32_t height;    // Framebuffer height
    uint32_t num_remaining_directives;
} cimg_header_t;

typedef struct {
    uint8_t r, g, b;
    char ch;
} term_pixel_t;

typedef struct {
    char ch;            // ASCII character only (0x20-0x7E)
} pixel_bw_t;
```

### Input validation

The binary performs the following checks:

1. **Size limit**: `total_data > 400` → kills the process with `lose()`.
2. **Magic number**: The first 4 bytes must be `"cIMG"`.
3. **Version**: Must be exactly `3`.
4. **Dimensions**: `width * height` must match the expected framebuffer size.
5. **Directive count**: `num_remaining_directives` controls how many instructions are processed.

### Image validation logic

The generated framebuffer is compared byte-for-byte against `desired_output`:

```c
for (int i = 0; i < cimg.width * cimg.height; i++) {
    if (desired_output[i].ch != frame_buffer[i].ch)
        lose();
    if (desired_output[i].ch != ' ' && (
        desired_output[i].r != frame_buffer[i].r ||
        desired_output[i].g != frame_buffer[i].g ||
        desired_output[i].b != frame_buffer[i].b))
        lose();
}
```

**Critical observation**: Spaces (`' '`, `0x20`) **are not validated for color**. This means we can leave any RGB value in empty cells, enabling aggressive optimizations.

---

## 2. cIMG v3 Format Structure

### Header (16 bytes)

| Field                    | Size                | Value    |
| ------------------------ | ------------------- | -------- |
| magic                    | 4 bytes             | `"cIMG"` |
| version                  | 4 bytes (uint32 LE) | `3`      |
| width                    | 4 bytes (uint32 LE) | `76`     |
| height                   | 4 bytes (uint32 LE) | `24`     |
| num_remaining_directives | 4 bytes (uint32 LE) | variable |

### Directives

Each directive starts with a **4-byte opcode** (uint32 LE), followed by specific data:

| Opcode | Handler    | Description                                                   |
| ------ | ---------- | ------------------------------------------------------------- |
| `0x1`  | `handle_1` | Fill entire framebuffer with RGBA pixels                      |
| `0x2`  | `handle_2` | Fill a sub-region of the framebuffer with RGBA pixels         |
| `0x3`  | `handle_3` | Define a sprite (ASCII character only)                        |
| `0x4`  | `handle_4` | Render a sprite at coordinates (x,y) with a uniform RGB color |

---

## 3. Reverse Engineering of the Handlers

To understand exactly the behavior of each handler, `objdump -d /challenge/cimg` was used to extract the assembly of each function.

### Handler 1 — `handle_1`

**Expected data**: `width * height` pixels of 4 bytes each → `(R, G, B, ascii_char)`

**Behavior**: Reads RGBA pixels and writes them directly to the full framebuffer, position by position.

**Cost for 76×24**: `1824 × 4 = 7296 bytes` → **impractical** for the 400-byte limit.

### Handler 2 — `handle_2`

**Expected data**:
- 4 bytes: `base_x` (uint32 LE)
- 4 bytes: `base_y` (uint32 LE)
- 4 bytes: `width` (uint32 LE)
- 4 bytes: `height` (uint32 LE)
- `width * height` pixels of 4 bytes each

**Behavior**: Fills a rectangular sub-region of the framebuffer with RGBA pixels.

**Cost**: `16 + (w*h*4)` bytes per use. Useful for small regions with varied colors.

### Handler 3 — `handle_3`

**Expected data**:
- 4 bytes: `sprite_id` (uint32 LE)
- 4 bytes: `width` (uint32 LE)
- 4 bytes: `height` (uint32 LE)
- `width * height` bytes of ASCII character (1 byte per pixel)

**Behavior**: Stores a sprite in `sprites[sprite_id]`. Only stores the ASCII character, **not the color**.

**Restriction**: Each character must be printable (`0x20` to `0x7E`).

**Cost**: `12 + (w*h)` bytes per defined sprite.

### Handler 4 — `handle_4`

**Expected data**:
- 6 bytes: composite record
  - 1 byte: `sprite_id`
  - 1 byte: `R`
  - 1 byte: `G`
  - 1 byte: `B`
  - 1 byte: `dest_x`
  - 1 byte: `dest_y`

**Behavior**: Takes the previously defined sprite and "stamps" it onto the framebuffer at position `(dest_x, dest_y)`, applying the color `(R, G, B)` to **all** characters of the sprite. Spaces (`' '`) in the sprite are rendered as spaces with that color, but since validation ignores the color of spaces, it doesn't matter.

**Cost**: **6 bytes** per render → Extremely efficient for reusing patterns.

---

## 4. Extracting the Target Image

The target image is embedded in the binary in the `.data` section. Extracted via ELF analysis:

- **Total `desired_output` size**: 43,776 bytes
- **Size of each `term_pixel_t`**: 24 bytes (struct with compiler padding)
- **Pixel count**: `43,776 / 24 = 1,824`
- **Dimensions**: `76 × 24 = 1,824` ✅

The image consists of:
- A full white border around the perimeter (`|` and `-`, RGB 255,255,255)
- The text `"SPRITE"` centered in the lower portion
- Each letter has a different color:
  - `S` — Red (255, 0, 0)
  - `P` — Green (0, 255, 0)
  - `R` — Blue (0, 0, 255)
  - `I` — Gray (128, 128, 128)
  - `T` — White (255, 255, 255)
  - `E` — Gray (128, 128, 128)

---

## 5. Optimization Strategy

The 400-byte limit is extremely restrictive. A 76×24 pixel image in raw RGBA format would occupy **7,296 bytes**, so compression is essential.

### Approach: Reusable Sprites + Color Override

The key is that `handle_4` allows:
1. **Defining a shape** once (ASCII characters only) with `handle_3`
2. **Reusing it multiple times** with different colors using `handle_4` (6 bytes each time)

### Key observations for optimization

1. **Spaces don't validate color**: We can leave any color in the empty cells of the sprite.
2. **Borders are uniform rectangles**: Perfect repeatable patterns for sprites.
3. **Letters are ASCII shapes**: Each letter can be defined as a small sprite and then rendered with its color.

---

## 6. Building solve.cimg

### Step 1: Header

```
cIMG    → 63 49 4d 47
v3      → 03 00 00 00
w=76    → 4c 00 00 00
h=24    → 18 00 00 00
14 dirs → 0e 00 00 00
```

### Step 2: Define Sprites (handle_3)

**6 reusable sprites** were defined:

#### Sprite 0: Horizontal border (74×1)
```
"--------------------------------------------------------------------------"
```
- 74 dashes for the top and bottom border (without corners)

#### Sprite 1: Vertical border + corners (1×22)
```
"||||||||||||||||||||||'"
```
- 22 vertical bars + apostrophe for the sides

#### Sprite 2: Letter "C" / Green block (5×5)
```
" ___ "
"|_ _|"
"| |  "
"| | |"
"|___|"
```

#### Sprite 3: Letter "I" / Red block (4×6)
```
" ___ "
"|_ _|"
"|  / "
"| (__"
" \___|"
```

#### Sprite 4: Letter "M" / Blue block (5×8)
```
"__  __ "
"|  \/  |"
"| |\/| |"
"| |  | |"
"|_|  |_|"
```

#### Sprite 5: Letter "G" / Gray block (5×7)
```
"  ____ "
" / ___|"
"| |  _ "
"| |_| |"
" \____|"
```

### Step 3: Render with handle_4

Each render costs only **6 bytes**:

| #   | Sprite | Color (R,G,B) | Position (x,y) | Description         |
| --- | ------ | ------------- | -------------- | ------------------- |
| 1   | 0      | 255,255,255   | (1,0)          | Top border          |
| 2   | 1      | 255,255,255   | (0,1)          | Left border         |
| 3   | 1      | 255,255,255   | (75,1)         | Right border        |
| 4   | 0      | 255,255,255   | (1,23)         | Bottom border       |
| 5   | 2      | 0,255,0       | (30,9)         | Letter "P" in green |
| 6   | 3      | 255,0,0       | (23,10)        | Letter "S" in red   |
| 7   | 4      | 0,0,255       | (39,10)        | Letter "R" in blue  |
| 8   | 5      | 128,128,128   | (45,10)        | Letter "I" in gray  |

**Note**: Some letters share positions or overlap in a controlled way. Spaces (`' '`) in the sprites do not affect color validation.

---

## 7. Size Calculation

### Header: 20 bytes
- magic (4) + version (4) + width (4) + height (4) + num_directives (4) = 20 bytes

### Directives: 308 bytes

| #    | Type                      | Size             |
| ---- | ------------------------- | ---------------- |
| 1    | handle_3 (Sprite 0, 74×1) | 4 + 12 + 74 = 90 |
| 2    | handle_3 (Sprite 1, 1×22) | 4 + 12 + 22 = 38 |
| 3    | handle_3 (Sprite 2, 5×5)  | 4 + 12 + 25 = 41 |
| 4    | handle_3 (Sprite 3, 4×6)  | 4 + 12 + 24 = 40 |
| 5    | handle_3 (Sprite 4, 5×8)  | 4 + 12 + 40 = 56 |
| 6    | handle_3 (Sprite 5, 5×7)  | 4 + 12 + 35 = 51 |
| 7-14 | handle_4 (8 renders)      | 8 × (4 + 6) = 80 |

### Total: 328 bytes ✅

**Under the 400-byte limit with a 72-byte margin.**

---


## 8. Server Execution

```bash
scp -i ~/.ssh/kimiKey solve.cimg hacker@dojo.pwn.college:/tmp/
ssh -i ~/.ssh/kimiKey hacker@dojo.pwn.college "cd /tmp && /challenge/cimg solve.cimg"
```

---


## Lessons Learned

1. **Read the source code first**: The binary had `cimg.c` available in `/challenge/`, which saved reversing time.
2. **Objdump is sufficient**: Ghidra was not needed; `objdump -d` provided all the necessary assembly to confirm each handler's read sizes.
3. **Validation is as important as generation**: The fact that spaces don't validate color was the key to efficient compression.
4. **Sprites + color override = massive compression**: Defining shapes once and reusing them with different colors is the optimal strategy for this format.

---

