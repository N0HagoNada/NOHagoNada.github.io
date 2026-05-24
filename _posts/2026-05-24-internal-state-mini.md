---
layout: post
title: Internal State Mini
date: 2026-05-24 19:45 -0400
published: true
categories: ["Reversing Challenge","Pwn College"]
tags: ["CIMG Images", "Static analysis","framebuffer"]
toc: true
---
# Reverse Engineering Analysis — Pwn.College: Internal State Mini

## 1. Challenge Description

This level introduces a compiled binary (not a Python script like the previous one) that processes images in cIMG format. The program:

1. Reads a `.cimg` file
2. Validates the magic number, version, dimensions, and ASCII characters
3. Initializes an internal framebuffer
4. Converts each pixel into an ANSI escape sequence
5. **Compares the generated framebuffer against a hardcoded expected state (`desired_output`)**
6. Only prints the flag if they match exactly

The goal is to understand the internal state the program expects, reverse the transformation algorithm, and generate an input file that produces that state.

---

## 2. Binary Reconnaissance

Download the binary from the server:

```bash
scp hacker@dojo.pwn.college:/challenge/cimg ./cimg_level2
```

### Basic identification

```
$ readelf -h cimg_level2
  Class:       ELF64
  Machine:     Advanced Micro Devices X86-64
  Type:        EXEC (Executable file)
```

The binary is a statically compiled **ELF64 x86-64** with symbols.

### Interesting strings

```bash
$ strings cimg_level2 | grep -E "ERROR|flag|magic|cimg"
```

Relevant output:
- `/flag`
- `ERROR: Failed to open the flag -- %s!`
- `Your effective user id is not 0!`
- `cimg`
- `ERROR: Invalid file extension!`
- `ERROR: Invalid magic number!`
- `ERROR: Unsupported version!`
- `ERROR: Failed to allocate memory for the image data!`
- `ERROR: Invalid character 0x%x in the image data!`

### Symbols

```bash
$ nm cimg_level2 | grep " T "
```

Key functions:
- `main` @ `0x4012a4`
- `win` @ `0x401586`
- `display` @ `0x4016cb`
- `read_exact` @ `0x40167b`
- `initialize_framebuffer` @ `0x401816`
- `desired_output` @ `0x404020` (`.data` section)

---

## 3. Static Analysis — `main`

### 3.1 Assembly-level control flow (`objdump -d`)

```asm
4012da:  mov    rbp,QWORD PTR [rsi+0x8]      ; argv[1]
4012f6:  call   4011f0 <strcmp@plt>           ; compare extension with ".cimg"
401341:  call   40167b <read_exact>           ; read 8 bytes from header
401346:  cmp    DWORD PTR [rsp],0x474d4963    ; magic number = "cIMG"
401363:  cmp    WORD PTR [rsp+0x4],0x2        ; version = 2
401375:  call   401816 <initialize_framebuffer>
401391:  call   401200 <malloc@plt>           ; malloc(width * height * 4)
4013b7:  call   40167b <read_exact>           ; read width*height*4 bytes
4013cf:  movzx  ecx,BYTE PTR [rbp+rax*4+0x3] ; ASCII byte of pixel
4013d7:  lea    esi,[rcx-0x20]
4013da:  cmp    sil,0x5e                      ; 0x20 <= char <= 0x7E
40140e:  call   4016cb <display>              ; generate ANSI framebuffer
401413:  mov    r13d,DWORD PTR [rsp+0x8]      ; r13 = count = width * height
40141d:  cmp    r13d,0x4                      ; count == 4?
401421:  sete   bl                            ; ebx = 1 if count == 4
401437:  mov    al,BYTE PTR [r14+rdi+0x13]    ; al = framebuffer[i].char
40143c:  cmp    al,BYTE PTR [r12+0x13]        ; compare with desired_output[i].char
401458:  call   4011e0 <memcmp@plt>           ; compare exactly 24 bytes
40146c:  test   ebx,ebx
40146e:  je     401477                        ; if ebx == 0, no flag
401472:  call   401586 <win>                  ; FLAG!
```

### 3.2 Ghidra decompilation

```c
undefined8 main(int param_1,long param_2)
{
  char cVar1;
  uint uVar2;
  int iVar3;
  void *pvVar4;
  long lVar5;
  ulong uVar6;
  size_t __size;
  long lVar7;
  char *pcVar8;
  char *pcVar9;
  undefined1 *__s2;
  long in_FS_OFFSET;
  bool bVar10;
  undefined8 local_58;
  undefined8 uStack_50;
  long local_48;
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  local_58 = 0;
  uStack_50 = 0;
  local_48 = 0;
  if (1 < param_1) {
    pcVar9 = *(char **)(param_2 + 8);
    uVar6 = 0xffffffffffffffff;
    pcVar8 = pcVar9;
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar1 = *pcVar8;
      pcVar8 = pcVar8 + 1;
    } while (cVar1 != '\0');
    iVar3 = strcmp(pcVar9 + (~uVar6 - 6),".cimg");
    if (iVar3 != 0) {
      __printf_chk(1,"ERROR: Invalid file extension!");
      goto LAB_0040135b;
    }
    iVar3 = open(pcVar9,0);
    dup2(iVar3,0);
  }
  read_exact(0,&local_58,8,"ERROR: Failed to read header!",0xffffffff);
  if ((int)local_58 == 0x474d4963) {
    pcVar9 = "ERROR: Unsupported version!";
    if (local_58._4_2_ == 2) {
      initialize_framebuffer(&local_58);
      __size = (long)(int)((uint)local_58._6_1_ * (uint)local_58._7_1_) << 2;
      pvVar4 = malloc(__size);
      pcVar9 = "ERROR: Failed to allocate memory for the image data!";
      if (pvVar4 != (void *)0x0) {
        read_exact(0,pvVar4,__size,"ERROR: Failed to read data!",0xffffffff);
        lVar5 = 0;
        do {
          if ((int)((uint)local_58._6_1_ * (uint)local_58._7_1_) <= (int)lVar5) {
            __s2 = desired_output;
            display(&local_58,pvVar4);
            lVar5 = local_48;
            uVar2 = (uint)uStack_50;
            bVar10 = (uint)uStack_50 == 4;
            for (lVar7 = 0; ((uint)lVar7 != 4 && ((uint)lVar7 < uVar2)); lVar7 = lVar7 + 1) {
              cVar1 = *(char *)(lVar5 + 0x13 + lVar7 * 0x18);
              if (cVar1 != __s2[0x13]) {
                bVar10 = false;
              }
              if ((cVar1 != ' ') && (cVar1 != '\n')) {
                iVar3 = memcmp((void *)(lVar7 * 0x18 + lVar5),__s2,0x18);
                if (iVar3 != 0) {
                  bVar10 = false;
                }
              }
              __s2 = __s2 + 0x18;
            }
            if (bVar10) {
              win();
            }
            return 0;
          }
          lVar7 = lVar5 * 4;
          lVar5 = lVar5 + 1;
        } while ((byte)(*(char *)((long)pvVar4 + lVar7 + 3) - 0x20U) < 0x5f);
        __fprintf_chk(stderr,1,"ERROR: Invalid character 0x%x in the image data!\n");
        goto LAB_0040135b;
      }
    }
  }
  else {
    pcVar9 = "ERROR: Invalid magic number!";
  }
  puts(pcVar9);
LAB_0040135b:
  exit(-1);
}
```

### 3.3 `main` flow summary

| Step | Condition / Call                    | Description                           |
| ---- | ----------------------------------- | ------------------------------------- |
| 1    | `strcmp(...,".cimg")`               | Validates file extension              |
| 2    | `read_exact(0,&local_58,8,...)`     | Reads 8 bytes from header             |
| 3    | `(int)local_58 == 0x474d4963`       | Compares magic number with `"cIMG"`   |
| 4    | `local_58._4_2_ == 2`               | Validates version == 2                |
| 5    | `initialize_framebuffer(&local_58)` | Initializes internal framebuffer      |
| 6    | `malloc(width * height * 4)`        | Allocates memory for pixel data       |
| 7    | `read_exact(0,pvVar4,__size,...)`   | Reads pixel data                      |
| 8    | ASCII validation loop               | Each `pixel[3]` must be `0x20`–`0x7E` |
| 9    | `display(&local_58,pvVar4)`         | Converts pixels to ANSI sequences     |
| 10   | `bVar10 = (uint)uStack_50 == 4`     | Is the total count 4?                 |
| 11   | Comparison loop vs `desired_output` | Character + full 24-byte `memcmp`     |
| 12   | `if (bVar10) { win(); }`            | Calls `win()` if everything matches!  |

### 3.4 Header structure (8 bytes)

Seen in Ghidra as `local_58`:

```
+0x00: DWORD  magic   = "cIMG" = 0x474d4963
+0x04: WORD   version = 0x0002
+0x06: BYTE   width
+0x07: BYTE   height
```

| Offset | Size | Field             |
| ------ | ---- | ----------------- |
| 0x00   | 4    | Magic: `"cIMG"`   |
| 0x04   | 2    | Version: `0x0002` |
| 0x06   | 1    | Width             |
| 0x07   | 1    | Height            |

Each pixel in the payload is **4 bytes**: `R G B A` (Red, Green, Blue, ASCII character).

### 3.5 Victory conditions

Extracted from both the assembly and decompiled code:

1. `width * height == 4`
2. For each pixel `i` from 0 to 3:
   - The ASCII character must match `desired_output[i]` (byte at offset `0x13` in each 24-byte slot)
   - For non-space and non-newline characters, all 24 bytes must match exactly via `memcmp`

---

## 4. Static Analysis — `display` and `initialize_framebuffer`

### 4.1 `initialize_framebuffer` (0x401816)

Ghidra decompilation:

```c
long initialize_framebuffer(long param_1)
{
  undefined4 *puVar1;
  long lVar2;
  int iVar3;
  long in_FS_OFFSET;
  undefined4 local_39;
  undefined4 uStack_35;
  undefined4 uStack_31;
  undefined4 uStack_2d;
  undefined8 local_29;
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  iVar3 = (uint)*(byte *)(param_1 + 6) * (uint)*(byte *)(param_1 + 7);
  *(int *)(param_1 + 8) = iVar3;
  puVar1 = (undefined4 *)malloc((long)iVar3 * 0x18 + 1);
  *(undefined4 **)(param_1 + 0x10) = puVar1;
  if (puVar1 == (undefined4 *)0x0) {
    puts("ERROR: Failed to allocate memory for the framebuffer!");
    exit(-1);
  }
  for (lVar2 = 0; (uint)lVar2 < *(uint *)(param_1 + 8); lVar2 = lVar2 + 1) {
    __snprintf_chk(&local_39,0x19,1,0x19,&DAT_004020d3,0xff,0xff,0xff,0x20,puVar1);
    puVar1 = (undefined4 *)(lVar2 * 0x18 + *(long *)(param_1 + 0x10));
    *puVar1 = local_39;
    puVar1[1] = uStack_35;
    puVar1[2] = uStack_31;
    puVar1[3] = uStack_2d;
    *(undefined8 *)(puVar1 + 4) = local_29;
  }
  return param_1;
}
```

Key points:
- `*(int *)(param_1 + 8) = width * height` → stores the pixel count
- `malloc(count * 0x18 + 1)` → each pixel produces 24 bytes of ANSI output
- Initializes **all** slots with white (`255,255,255`) and space character (`0x20`):
  ```
  "\x1b[38;2;255;255;255m \x1b[0m"
  ```

### 4.2 `display` (0x4016cb)

Ghidra decompilation:

```c
void display(long param_1,long param_2,undefined4 *param_3)
{
  undefined1 *puVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  long in_FS_OFFSET;
  undefined4 local_59;
  undefined4 uStack_55;
  undefined4 uStack_51;
  undefined4 uStack_4d;
  undefined8 local_49;
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_1 + 7); iVar5 = iVar5 + 1) {
    iVar3 = 0;
    while( true ) {
      bVar2 = *(byte *)(param_1 + 6);
      if ((int)(uint)bVar2 <= iVar3) break;
      iVar4 = (uint)bVar2 * iVar5;
      puVar1 = (undefined1 *)(param_2 + (long)(iVar4 + iVar3) * 4);
      __snprintf_chk(&local_59,0x19,1,0x19,&DAT_004020d3,*puVar1,puVar1[1],puVar1[2],puVar1[3],
                     param_3);
      param_3 = (undefined4 *)
                (((ulong)(uint)(iVar3 % (int)(uint)bVar2 + iVar4) % (ulong)*(uint *)(param_1 + 8)) *
                 0x18 + *(long *)(param_1 + 0x10));
      *param_3 = local_59;
      param_3[1] = uStack_55;
      param_3[2] = uStack_51;
      param_3[3] = uStack_4d;
      *(undefined8 *)(param_3 + 4) = local_49;
      iVar3 = iVar3 + 1;
    }
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_1 + 7); iVar5 = iVar5 + 1) {
    write(1,(void *)((long)(int)((uint)*(byte *)(param_1 + 6) * iVar5) * 0x18 +
                    *(long *)(param_1 + 0x10)),(ulong)*(byte *)(param_1 + 6) * 0x18);
    write(1,&DAT_004020f0,0x18);
  }
}
```

### 4.3 The transformation algorithm

This is the **key algorithm** — it transforms each RGBA pixel into an exact 24-byte ANSI sequence:

```
For each row (0 to height-1):
  For each column (0 to width-1):
    idx = row * width + col
    pixel = param_2[idx * 4]
    snprintf(buffer, 25, "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m",
             pixel[0],   // Red
             pixel[1],   // Green
             pixel[2],   // Blue
             pixel[3])   // ASCII character
    framebuffer[idx * 0x18] = buffer (24 bytes)
```

**Format string** at `DAT_004020d3`: `"\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"`

**Reset string** at `DAT_004020f0`: `"\x1b[38;2;000;000;000m\n\x1b[0m"`

---

## 5. Extracting the "Known-Good State" (`desired_output`)

The program compares against a hardcoded buffer in the `.data` section at `0x404020`.

### Via `objdump`

```bash
$ objdump -s -j .data cimg_level2
```

### Via Ghidra

Navigate to `desired_output` @ `0x404020` in the `.data` section.

### Raw hex dump

```
404020: 1b 5b 33 38 3b 32 3b 31 37 30 3b 30 35 34 3b 31  .[38;2;170;054;1
404030: 31 32 6d 63 1b 5b 30 6d 1b 5b 33 38 3b 32 3b 31  12mc.[0m.[38;2;1
404040: 36 31 3b 31 32 39 3b 32 30 34 6d 49 1b 5b 30 6d  61;129;204mI.[0m
404050: 1b 5b 33 38 3b 32 3b 30 30 31 3b 31 39 35 3b 30  .[38;2;001;195;0
404060: 35 33 6d 4d 1b 5b 30 6d 1b 5b 33 38 3b 32 3b 30  53mM.[0m.[38;2;0
404070: 36 34 3b 30 34 36 3b 32 32 34 6d 47 1b 5b 30 6d  64;046;224mG.[0m
```

Each slot occupies exactly **24 bytes (0x18)**. Parsing the 4 slots:

| Slot | Offset   | ANSI Bytes (24 bytes)            | R   | G   | B   | Char |
| ---- | -------- | -------------------------------- | --- | --- | --- | ---- |
| 0    | 0x404020 | `\x1b[38;2;170;054;112mc\x1b[0m` | 170 | 54  | 112 | `c`  |
| 1    | 0x404038 | `\x1b[38;2;161;129;204mI\x1b[0m` | 161 | 129 | 204 | `I`  |
| 2    | 0x404050 | `\x1b[38;2;001;195;053mM\x1b[0m` | 1   | 195 | 53  | `M`  |
| 3    | 0x404068 | `\x1b[38;2;064;046;224mG\x1b[0m` | 64  | 46  | 224 | `G`  |

**Conclusion:** The program expects the image to produce the word **"cIMG"** with those exact colors.

---

## 6. Reversing the Algorithm

### Forward (program)
```
Pixel [R,G,B,A] → snprintf → "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m" → framebuffer
```

### Reverse (our job)
```
desired_output → parse R,G,B,character → rebuild Pixel [R,G,B,A]
```

For each 24-byte slot in `desired_output`:
- `R = int(slot[7:10])`   — bytes 7,8,9 are ASCII digits for red
- `G = int(slot[11:14])`  — bytes 11,12,13 are ASCII digits for green
- `B = int(slot[15:18])`  — bytes 15,16,17 are ASCII digits for blue
- `C = slot[19]`          — byte 19 is the ASCII character

### Required pixels (row-major order)

| Pixel | R   | G   | B   | ASCII | Hex           |
| ----- | --- | --- | --- | ----- | ------------- |
| 0     | 170 | 54  | 112 | `c`   | `AA 36 70 63` |
| 1     | 161 | 129 | 204 | `I`   | `A1 81 CC 49` |
| 2     | 1   | 195 | 53  | `M`   | `01 C3 35 4D` |
| 3     | 64  | 46  | 224 | `G`   | `40 2E E0 47` |

---

## 7. Payload Construction

### Header (8 bytes)

```
63 49 4d 47   - "cIMG" (magic)
02 00         - Version 2 (little-endian WORD)
04            - Width = 4
01            - Height = 1
```

*(Width × Height must be exactly 4)*

### Pixel Data (16 bytes = 4 pixels × 4)

```
AA 36 70 63   - Pixel 0: (170, 54, 112, 'c')
A1 81 CC 49   - Pixel 1: (161, 129, 204, 'I')
01 C3 35 4D   - Pixel 2: (1, 195, 53, 'M')
40 2E E0 47   - Pixel 3: (64, 46, 224, 'G')
```

### Complete file (hex)

```
63494d47 02000401 aa367063 a181cc49 01c3354d 402ee047
```

### Python script

```python
import struct

header = b'cIMG' + struct.pack('<H', 2) + struct.pack('BB', 4, 1)

pixels = bytes([
    170, 54, 112, ord('c'),
    161, 129, 204, ord('I'),
    1, 195, 53, ord('M'),
    64, 46, 224, ord('G'),
])

with open('solve_level2.cimg', 'wb') as f:
    f.write(header + pixels)
```

**Total file size:** 24 bytes (8 header + 16 pixel data).

---

## 8. Runtime Verification with GDB

To confirm our hypotheses, we used **gdb** on the server with a breakpoint at the decision point (`0x40146c`):

```bash
$ gdb -ex "file /challenge/cimg" \
      -ex "break *0x40146c" \
      -ex "run /tmp/solve_level2.cimg" \
      -ex "x/4s \$r14" \
      -ex "x/96bx 0x404020" \
      -ex "info registers ebx r13"
```

### Results

**Breakpoint hit:**
```
Breakpoint 1, 0x000000000040146c in main ()
```

**Generated framebuffer (`$r14`):**
```
0x247e62a0: "\033[38;2;170;054;112mc\033[0m\033[38;2;161;129;204mI\033[0m
              \033[38;2;001;195;053mM\033[0m\033[38;2;064;046;224mG\033[0m"
```

**`desired_output` (0x404020):**
```
0x404020 <desired_output>:       0x1b 0x5b 0x33 0x38 0x3b 0x32 0x3b 0x31
0x404028 <desired_output+8>:     0x37 0x30 0x3b 0x30 0x35 0x34 0x3b 0x31
0x404030 <desired_output+16>:    0x31 0x32 0x6d 0x63 0x1b 0x5b 0x30 0x6d
0x404038 <desired_output+24>:    0x1b 0x5b 0x33 0x38 0x3b 0x32 0x3b 0x31
...
```

**Decision registers:**
```
ebx            0x1                 1    ← count == 4, all comparisons passed
r13            0x4                 4    ← count = 4
```

The generated framebuffer matches `desired_output` byte-for-byte. `ebx = 1` confirms the program will take the branch to `win()`.

---

## 10. Reverse Engineering Pipeline Summary

| Step | Tool                      | Goal                                                         |
| ---- | ------------------------- | ------------------------------------------------------------ |
| 1    | `readelf`, `file`         | Identify binary type                                         |
| 2    | `strings`, `nm`           | Find relevant strings and symbols                            |
| 3    | Ghidra (Auto-Analyzer)    | Load binary, decompile all functions                         |
| 4    | `objdump -d` + Ghidra     | Static analysis of `main` control flow                       |
| 5    | Ghidra (Decompiler)       | Recover `display()` → understand pixel→ANSI algo             |
| 6    | Ghidra (Data) / `objdump` | Extract `desired_output` from `.data` @ `0x404020`           |
| 7    | Manual analysis           | Reverse algorithm: ANSI slot → Pixel [R,G,B,A]               |
| 8    | `gdb`                     | Verify hypotheses at runtime (framebuffer vs desired_output) |
| 9    | Python                    | Generate `.cimg` file with reversed data                     |
| 10   | Server execution          | Obtain the flag                                              |

---

