---
layout: post
title: 'PwnCollege: File Formats'
date: 2026-05-24 18:37 -0400
published: true
categories: ["Reversing Challenge","Pwn College"]
tags: ["CIMG Images", "Static analysis"]
toc: true
---
# File Format Directives

## 1. General Information

| Property      | Value                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------- |
| Binary        | `cimg`                                                                                      |
| Architecture  | x86-64 ELF                                                                                  |
| Goal          | Generate an ANSI framebuffer that matches `desired_output` using the only available handler |
| Flag obtained | `pwn.college{ x-x.x}`                                                                       |

## 2. Extracted Source Code

The server provides `cimg.c` (main source code) but does **NOT** provide `cimg-handlers.c`. However, the main source code reveals the complete format structure.

### Data Structures

```c
struct cimg_header
{
    char magic_number[4];       // "cIMG"
    uint16_t version;           // 3
    uint8_t width;
    uint8_t height;
    uint32_t remaining_directives;
} __attribute__((packed));

typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_color_t;

typedef pixel_color_t pixel_t;

typedef struct
{
    union
    {
        char data[24];
        struct term_str_st
        {
            char color_set[7];   // \x1b[38;2;
            char r[3];          // 255
            char s1;            // ;
            char g[3];          // 255
            char s2;            // ;
            char b[3];          // 255
            char m;            // m
            char c;             // X
            char color_reset[4];     // \x1b[0m
        } str;
    };
} term_pixel_t;
```

## 3. `.cimg` File Format

### Header (12 bytes)

| Offset | Size | Field   | Description                   |
| ------ | ---- | ------- | ----------------------------- |
| 0x00   | 4    | Magic   | `cIMG`                        |
| 0x04   | 2    | Version | Must be `3`                   |
| 0x06   | 1    | Width   | Framebuffer width             |
| 0x07   | 1    | Height  | Framebuffer height            |
| 0x08   | 4    | Count   | Number of directives/commands |

### Commands

In this level, there is only **ONE handler**:

| Opcode (LE) | Decimal | Handler        | Description                                           |
| ----------- | ------- | -------------- | ----------------------------------------------------- |
| `0x60A4`    | 24740   | `handle_24740` | Loads a full RGBA image matching the framebuffer size |

### `handle_24740` Payload

- Reads exactly `width * height * 4` bytes of RGBA data
- Each pixel is `R G B A` where:
  - `R`, `G`, `B` are the color components (0-255)
  - `A` is the ASCII character to print (must be printable: `0x20`–`0x7E`)
- Formats each pixel into the ANSI string: `\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m`
- Places each cell in `framebuffer[row * width + col]`

## 4. Key Functions

### `initialize_framebuffer(cimg)`

- Computes `num_pixels = width * height`
- Allocates `num_pixels * 24 + 1` bytes
- Initializes **ALL** cells with white color (`255,255,255`) and space character (`0x20`)

### `display(cimg)`

- Iterates over each row
- Writes `width * 24` bytes of the row to stdout
- Writes `\x1b[38;2;000;000;000m\n\x1b[0m` (24-byte newline with reset)

### `main()` — Victory Logic

```c
// No total_data restriction in this level!

if (cimg.num_pixels != sizeof(desired_output)/sizeof(term_pixel_t))
    won = 0;

for (int i = 0; i < cimg.num_pixels && i < sizeof(desired_output)/sizeof(term_pixel_t); i++)
{
    // Character MUST match
    if (cimg.framebuffer[i].str.c != ((term_pixel_t*)&desired_output)[i].str.c)
        won = 0;

    // For NON-space/NON-newline cells, all 24 bytes MUST match exactly
    if (
        cimg.framebuffer[i].str.c != ' ' &&
        cimg.framebuffer[i].str.c != '\n' &&
        memcmp(cimg.framebuffer[i].data, ((term_pixel_t*)&desired_output)[i].data, sizeof(term_pixel_t))
    )
        won = 0;
}

if (won) win();
```

## 5. The `desired_output`

Extracted from the binary at address `0x404020`:

- **Size:** 22320 bytes = 930 cells × 24 bytes
- **Dimensions:** The framebuffer must have a total of **930 cells**
- The `width × height` dimensions can be any factorization of 930, but using `62 × 15` renders the ASCII art correctly

### ASCII Art

```
.------------------------------------------------------------.
|                                                            |
|                                          __  __            |
|                ___                      |  \/  |    ____   |
|               / __|                     | |\/| |   / ___|  |
|              | (__            ___       | |  | |  | |  _   |
|               \___|          |_ _|      |_|  |_|  | |_| |  |
|                               | |                  \____|  |
|                               | |                          |
|                              |___|                         |
|                                                            |
|                                                            |
|                                                            |
|                                                            |
'------------------------------------------------------------'
```

## 6. Solution Process

### Step 1: Extract `desired_output` from the binary

```python
with open('cimg_current', 'rb') as f:
    data = f.read()

idx = data.find(b'\x1b[38;2;255;255;255m.\x1b[0m\x1b[38;2;255;255;255m-')
desired = data[idx:idx+22320]
```

### Step 2: Extract RGB+Character from each cell

For each 24-byte cell:
- `R = int(cell[7:10])`   (bytes 7,8,9 are ASCII digits for red)
- `G = int(cell[11:14])`  (bytes 11,12,13 are ASCII digits for green)
- `B = int(cell[15:18])`  (bytes 15,16,17 are ASCII digits for blue)
- `C = cell[19]`          (byte 19 is the character)

### Step 3: Build the `.cimg` file

```python
output = b'cIMG'                    # Magic
output += struct.pack('<H', 3)      # Version
output += struct.pack('B', 62)      # Width
output += struct.pack('B', 15)      # Height
output += struct.pack('<I', 1)      # 1 directive
output += struct.pack('<H', 24740)  # Opcode handle_24740

# 930 pixels × 4 bytes = 3720 bytes
for i in range(930):
    cell = desired[i*24:(i+1)*24]
    r = int(cell[7:10])
    g = int(cell[11:14])
    b = int(cell[15:18])
    a = cell[19]
    output += bytes([r, g, b, a])
```

### Step 4: Result

- **Total file size:** 3734 bytes
- **Header:** 12 bytes
- **Opcode:** 2 bytes
- **RGBA data:** 3720 bytes (930 pixels × 4)


