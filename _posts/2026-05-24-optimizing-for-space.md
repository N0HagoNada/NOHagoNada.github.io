---
layout: post
title: Optimizing for Space
date: 2026-05-29 20:26 -0400
published: true
categories: ["Reversing Challenge","Pwn College"]
tags: ["CIMG Images", "Static analysis"]
toc: true
---
# Reverse Engineering Analysis — Pwn.College: Optimizing for Space

## 1. General Information

| Property     | Value                                                                                   |
| ------------ | --------------------------------------------------------------------------------------- |
| Binary       | `cimg` / `cimg_optimizing`                                                              |
| Architecture | x86-64 ELF                                                                              |
| Goal         | Generate an ANSI framebuffer matching `desired_output` using ≤ 1337 bytes of input data |

## 2. `.cimg` File Format

The program reads from **stdin** (or redirects a `.cimg` file to stdin via `dup2`).

### Header (12 bytes)

| Offset | Size | Field   | Description                         |
| ------ | ---- | ------- | ----------------------------------- |
| 0x00   | 4    | Magic   | `cIMG` (`0x474d4963` little-endian) |
| 0x04   | 2    | Version | Must be `0x0003`                    |
| 0x06   | 1    | Width   | Framebuffer width in cells          |
| 0x07   | 1    | Height  | Framebuffer height in cells         |
| 0x08   | 4    | Count   | Number of commands/directives       |

### Commands (2 bytes opcode + variable payload)

| Opcode (LE) | Decimal | Handler        | Description                                            |
| ----------- | ------- | -------------- | ------------------------------------------------------ |
| `0xD849`    | 55369   | `handle_55369` | Loads a **full** image of framebuffer size             |
| `0xCEE5`    | 52965   | `handle_52965` | Loads a **partial rectangle** at an arbitrary position |

### `handle_52965` Payload (Opcode 0xCEE5)

1. **4 bytes** of parameters:
   - `base_x` (1 byte)
   - `base_y` (1 byte)
   - `width` (1 byte)
   - `height` (1 byte)
2. **width × height × 4 bytes** of RGBA data:
   - Each pixel is `R G B A`
   - The Alpha channel (`A`) is used as the **ASCII character** to print (must be printable: `0x20`–`0x7E`)

### `handle_55369` Payload (Opcode 0xD849)

- Reads `fb_width × fb_height × 4` bytes of RGBA directly.
- Useful to fill the entire framebuffer at once, but **consumes many bytes**.

## 3. In-Memory Data Structures

The program maintains a struct on the stack (12 initial bytes, later extended by `initialize_framebuffer`):

```c
typedef struct {
    char magic[4];       // "cIMG"
    uint16_t version;    // 3
    uint8_t width;       // fb_width
    uint8_t height;      // fb_height
    uint32_t size;       // width * height (number of cells)
    char *framebuffer;   // malloc(size * 0x18 + 1)
} cimg_ctx;
```

### Framebuffer cell format (24 bytes)

Each cell is formatted with `snprintf` using the template:

```
\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m
```

This generates exactly **24 bytes** (0x18) per cell:
- ANSI TrueColor escape sequence (RGB)
- One ASCII character (`%c`)
- ANSI reset (`\x1b[0m`)

## 4. Key Functions

### `initialize_framebuffer(ctx)`

- Computes `size = width * height`
- Allocates `size * 24 + 1` bytes
- **Initializes ALL cells** with white color (`255,255,255`) and space character (`0x20`)

### `handle_55369(ctx)` — Full Image

- Reads `width * height * 4` bytes of RGBA.
- Validates each Alpha byte is printable (`0x20`–`0x7E`).
- For each pixel `(row, col)`, computes the destination index:
  ```
  idx = (col + row * width) % size
  ```
- Writes the ANSI-formatted cell to `framebuffer[idx * 24]`.

**Bytes read cost:** `width * height * 4`. For 76×24 = **7296 bytes**.

### `handle_52965(ctx)` — Partial Rectangle

- Reads 4 bytes: `base_x`, `base_y`, `width_rect`, `height_rect`
- Reads `width_rect * height_rect * 4` bytes of RGBA
- Validates printable Alpha
- For each pixel `(i, j)` within the rectangle:
  ```
  src_idx = j + i * width_rect
  dest_col = (base_x + j) % fb_width
  dest_row = (base_y + i)
  dest_idx = (dest_row * fb_width + dest_col) % size
  ```
- Writes the formatted cell to `framebuffer[dest_idx * 24]`

**Bytes read cost:** `4 + width_rect * height_rect * 4`.

### `display(ctx)`

- Iterates over each row of the framebuffer.
- Writes `width * 24` bytes of the row to stdout.
- Writes a reset + newline sequence (`\x1b[38;2;000;000;000m\n\x1b[0m`).

### `read_exact(fd, buf, len, errmsg, exitcode)`

- Reads **exactly** `len` bytes from `fd`.
- If it fails, prints error and terminates.
- **Adds `len` to the global variable `total_data`**.

### `main()` — Victory Logic

1. Parses the header and executes the `count` commands in a loop.
2. Calls `display()`.
3. Compares the generated framebuffer against `desired_output`:
   - The number of cells must be exactly `0x720` = **1824** (76×24).
   - For each cell:
     - If the character (offset 0x13 = index 19) is space or newline, colors are not compared (optimization).
     - Otherwise, compares the **exact 24 bytes** with `memcmp`.
4. Finally checks:
   ```c
   if (total_data < 0x53a && all_cells_match) {
       win();
   }
   ```
   That is, the total bytes read must be **≤ 1337** (`0x539`).

### Key optimization in the comparison

The binary has a crucial optimization: **it does not compare colors for cells containing space (`0x20`) or newline (`0x0a`)**. It only verifies the character is correct:

```c
char1 = fb_cell[0x13];        // character from the generated cell
char2 = desired_cell[0x13];   // character from the desired output
if (char1 != char2) fail;

if (char1 != ' ' && char1 != '\n') {
    if (memcmp(fb_cell, desired_cell, 0x18) != 0) fail;
}
```

This allows `handle_52965` commands to use **any RGB color for spaces** (e.g., black `0x000000` instead of white `0xffffff`), since the binary won't verify them. This saves bytes by not having to encode white colors explicitly for the background.

## 5. Solution Analysis (`solution.cimg`)

| Property      | Value                   |
| ------------- | ----------------------- |
| Total size    | **1334 bytes**          |
| Allowed limit | 1337 bytes              |
| FB dimensions | 76 × 24 = 1824 cells    |
| Commands used | 11 (all `handle_52965`) |

### Command breakdown

| #   | Opcode | Position | Size | Characters          | Color                              |
| --- | ------ | -------- | ---- | ------------------- | ---------------------------------- |
| 0   | 52965  | (0, 0)   | 76×1 | `.` + `-`×74 + `.`  | White (`ffffff`)                   |
| 1   | 52965  | (0, 23)  | 76×1 | `'` + `-`×74 + `'`  | White (`ffffff`)                   |
| 2   | 52965  | (0, 1)   | 1×22 | `                   | `×22                               | White (`ffffff`) |
| 3   | 52965  | (75, 1)  | 1×22 | `                   | `×22                               | White (`ffffff`) |
| 4   | 52965  | (23, 11) | 6×3  | `/ __\|(__ \___\|`  | Red (`ff0000`) + Black (`000000`)  |
| 5   | 52965  | (25, 10) | 3×1  | `___`               | Red (`ff0000`)                     |
| 6   | 52965  | (30, 10) | 14×4 | `                   | _ _                                | ...\___\|`       | Green (`00ff00`) + Black (`000000`) + Blue (`0000ff`) |
| 7   | 52965  | (31, 9)  | 3×1  | `___`               | Green (`00ff00`)                   |
| 8   | 52965  | (37, 9)  | 6×1  | `__ __`             | Blue (`0000ff`) + Black (`000000`) |
| 9   | 52965  | (45, 10) | 7×4  | `/ ___\|...\____\|` | Gray (`808080`) + Black (`000000`) |
| 10  | 52965  | (47, 9)  | 4×1  | `____`              | Gray (`808080`)                    |

**Byte consumption calculation:**
- Header: 12 bytes
- Each `handle_52965` command: 2 (opcode) + 4 (params) + pixels×4
- Command 0: 2 + 4 + 76×1×4 = **310 bytes**
- Command 1: 2 + 4 + 76×1×4 = **310 bytes**
- Command 2: 2 + 4 + 1×22×4 = **94 bytes**
- Command 3: 2 + 4 + 1×22×4 = **94 bytes**
- Command 4: 2 + 4 + 6×3×4 = **78 bytes**
- Command 5: 2 + 4 + 3×1×4 = **18 bytes**
- Command 6: 2 + 4 + 14×4×4 = **230 bytes**
- Command 7: 2 + 4 + 3×1×4 = **18 bytes**
- Command 8: 2 + 4 + 6×1×4 = **30 bytes**
- Command 9: 2 + 4 + 7×4×4 = **118 bytes**
- Command 10: 2 + 4 + 4×1×4 = **22 bytes**

**Total:** 12 + 310 + 310 + 94 + 94 + 78 + 18 + 230 + 18 + 30 + 118 + 22 = **1334 bytes** ✓

(This matches exactly the binary's `total_data` counter, which must be **≤ 1337**.)

### Why is `handle_55369` not used?

If we used `handle_55369` for the full framebuffer (76×24), it would cost:
- 2 (opcode) + 76×24×4 = **7298 bytes** → **FAR above** the 1337 limit.

The optimization consists of using **small rectangles** (`handle_52965`) to draw only the necessary parts of the ASCII art, leveraging that the framebuffer is initialized in white with spaces.

## 6. Resulting ASCII Art

Running the binary with `solution.cimg` generates the following output (extracted from `desired_output.bin`):

```
.--------------------------------------------------------------------------.
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                              ___   __  __    ____                        |
|                        ___  |_ _| |  \/  |  / ___|                       |
|                       / __|  | |  | |\/| | | |  _                        |
|                      | (__   | |  | |  | | | |_| |                       |
|                       \___| |___| |_|  |_|  \____|                       |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
'--------------------------------------------------------------------------'
```



