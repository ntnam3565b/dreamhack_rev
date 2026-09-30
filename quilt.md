# quilt 

Challenge difficulty: Gold IV

Challenge link: <https://dreamhack.io/wargame/challenges/1636>

## Content inspection
The challenge contains two files:
- `main`: Executable Linked File, written in C, little-endian, AMD64 architecture
- `quilt.bmp`: Bitmap picture, containing a $16\times 16$ grid of colors.

First, I run the program with no arguments, and I receive this instruction message, which means I need to pass a string (flag) as argument:

`Usage: ./quilt <text>`



## Reversing the mechanics



I use Ghidra for reversing the main program. Jumping into the `main` function (first argument of the `__libc_start_main` function in the entry), we can see this:

```C
int main(int argc, char **argv)
{
    char *flag;
    
    lVar1 = *(in_FS_OFFSET + 0x28);
    if (argc == 2) {
        size = strlen(argv[1]);
        if (size < 0xc0) {
            local_22e = DAT_00104028;
            uStack_22c = DAT_00104028 >> 0x10;
            /* Data for something...*/
            output_buffer = fopen("quilt.bmp", "wb");
        }

        /* Further process */
    }

    else {
        fprintf(stderr, "Usage: %s <text>\n", *argv);
        iVar2 = 1;
    }

    //...
}      
```

The program takes 1 additional argument to start writing data to a Bitmap file. A bitmap file has a header, starting with a BM keyword and additional data such as its dimensions.

Source: <https://en.wikipedia.org/wiki/BMP_file_format>

In further process, we see this:

```C
rng = open("/dev/urandom", 0);
if (rng < 0) {
    perror("Failed to open /dev/urandom");
    iVar2 = 1;
}
else {
    sVar3 = read(rng,text,0xc0);
    if (sVar3 == 0xc0) {
        sVar3 = read(rng, &offset,1);
        if (sVar3 == 1) {
            close(rng);
            size = strlen(argv[1]);
            flag = argv[1];
            ssize = strlen(argv[1]);
            strncpy(text + offset % (0xc0 - ssize), flag, size);
            base64_index_encoder(text, local_138);
            
            // Write a 54-byte header before the data

            image_encoder(local_138, output_buffer, &local_22a + 2);
            fclose(output_buffer);
            iVar2 = 0;
        }
        else {
            perror("Failed to read /dev/urandom");
            iVar2 = 1;
        }
    // Error handling
    }
}
```
We have known that the flag is inserted into a random 192-byte field and then the field is encoded. The program then writes the header and use the data to generate the image.
### Data encode function (`base64_index_encoder`)

Why I name this Base64 index-encoder? If you dive into the function, you will see:

```C
while (local_20 < 0xc0) {
    iVar1 = local_20 + 1;
    lVar4 = local_20;
    iVar2 = local_20 + 2;
    local_20 = local_20 + 3;
    uVar3 = src[iVar2] + src[lVar4] * 0x10000 + src[iVar1] * 0x100;
    dest[local_1c] = uVar3 >> 0x12;
    dest[local_1c + 1] = uVar3 >> 0xc & 0x3f;
    iVar1 = local_1c + 3;
    dest[local_1c + 2] = uVar3 >> 6 & 0x3f;
    local_1c = local_1c + 4;
    dest[iVar1] = uVar3 & 0x3f;
}
```

First, every three bytes will be read and placed side-by-side, then that representation is cut into four 6-bit pieces, so it is reminicent of the Base64 encoding.

### Image encode function (`image_encode`)
```C
while (true) {
    iVar4 = iVar3;
    if (iVar3 < 0) {
        iVar4 = iVar3 + 0x1f;
    }
    local_4c = iVar3;
    if (iVar4 >> 5 <= local_60) break;
    local_5c = 0;
    while (true) {
        iVar4 = iVar2;
        if (iVar2 < 0) {
            iVar4 = iVar2 + 0x1f;
        }
        if (iVar4 >> 5 <= local_5c) break;
        if ((local_60 & 1) == 0) {
            local_58 = local_5c;
        }
        else {
            local_58 = 0xf - local_5c;
        }
        for (local_54 = 0; local_54 < 0x20; local_54 = local_54 + 1) {
            for (local_50 = 0; local_50 < 0x20; local_50 = local_50 + 1) {
                bVar1 = param_1[local_5c + local_60 * 0x10];
                puVar1 = __ptr[local_54 + local_60 * 0x20] + (local_50 + local_58 * 0x20) * 3;
                *puVar1 = *(&DAT_00102020 + bVar1 * 3);
                puVar1[2] = (&DAT_00102022)[bVar1 * 3];
            }
        }
        local_5c = local_5c + 1;
    }
    local_60 = local_60 + 1;
}
```
`DAT_00102020` and `DAT_00102022` are part of a 192-byte array, which is a pallete of 64 RGB colors. The colors are chosen by the indexes of that Base64 encoding, the color will be filled in reverse if the row index (`local_60`) is even and in order otherwise.

And then comes another snippet of code, in which the program fills the pictures with reverse order for the rows.
```C
while (local_4c = local_4c + -1, -1 < local_4c) {
    fwrite(__ptr[local_4c], 3, iVar2, image);
    fwrite(&local_23, 1, iVar2 * -3 & 3, image);
}
```
## Solution

```python
width, height = 512, 512

with open('./quilt.bmp', 'rb') as r:
    s = [i for i in r.read()[0x36:]]

mapboard = [
    0x0FF, 0x0FF, 0x0FF, 0x0D3, 0x0D3, 0x0D3, 0x0A9, 0x0A9, 0x0A9,
    0, 0, 0, 0x80, 0, 0, 0x87, 0x0CE, 0x0EB, 0, 0, 0x0FF, 0x20,
    0, 0x80, 0x22, 0x8B, 0x22, 0x32, 0x0CD, 0x32, 0, 0x0FF, 0x0FF,
    0, 0x0D7, 0x0FF, 0x0FA, 0x0E6, 0x0E6, 0x80, 0, 0x80, 0x0CB,
    0x0C0, 0x0FF, 0x2A, 0x2A, 0x0A5, 0x0FF, 0x69, 0x0B4, 0x0FF, 0x0A5,
    0, 0x0FF, 0x0C0, 0x0CB, 0x0AD, 0x0D8, 0x0E6, 0, 0x80, 0x80,
    0x0F0, 0x0E6, 0x8C, 0x2E, 0x8B, 0x57, 0x0D2, 0x0B4, 0x8C, 0x7F,
    0x0FF, 0x0D4, 0x0FF, 0x0E4, 0x0E1, 0x0F0, 0x80, 0x80, 0x98, 0x0FB,
    0x98, 0x0FF, 0x0E4, 0x0C4, 0x0FF, 0x0FA, 0x0CD, 0x8A, 0x2B, 0x0E2,
    0x0F4, 0x0A4, 0x60, 0x48, 0x3D, 0x8B, 0x0DA, 0x70, 0x0D6, 0,
    0x0BF, 0x0FF, 0x0F5, 0x0F5, 0x0DC, 0x40, 0x0E0, 0x0D0, 0x0FF,
    0x14, 0x93, 0x0DC, 0x14, 0x3C, 0, 0x64, 0, 0x0AD, 0x0FF, 0x2F,
    0x0FF, 0x45, 0, 0x80, 0x80, 0, 0x0FF, 0x0DA, 0x0B9, 0, 0x0FA,
    0x9A, 0x46, 0x82, 0x0B4, 0x0D8, 0x0BF, 0x0D8, 0x0FF, 0x63, 0x47,
    0x4B, 0, 0x82, 0x0F0, 0x0FF, 0x0FF, 0x64, 0x95, 0x0ED, 0x0FF,
    0x0F5, 0x0EE, 0, 0x0FF, 0x7F, 0x0F0, 0x0FF, 0x0F0, 0x0FF, 0x0B6,
    0x0C1, 0x77, 0x88, 0x99, 0x0F5, 0x0DE, 0x0B3, 0x0FF, 0x0A0, 0x7A,
    0x0E9, 0x96, 0x7A, 0x8F, 0x0BC, 0x8F, 0x2F, 0x4F, 0x4F, 0x0AA,
    0x0B2, 0x20, 0x0DB, 0x70, 0x93, 0, 0x8C, 0x0FF
]

combined_mb = []

base64_table = [0] * 256

for i in range(0, len(mapboard), 3):
    combined_mb.append(mapboard[i] | (mapboard[i + 1] << 8) | (mapboard[i + 2] << 16))

for i in range(16):
    for j in range(16):
        position = (i * 32 * 32 * 16 + j * 32) * 3

        palette = s[position] | (s[position + 1] << 8) | (s[position + 2] << 16)

        col = j if (i & 1) else 15 - j

        base64_table[((15 - i) * 16 + col)] = combined_mb.index(palette)

u = []

for i in range(16):
    u += base64_table[16 * i: 16 * (i + 1)]

message = [0] * 192

for i in range(0, 256, 4):
    chunk = base64_table[i + 3] | (base64_table[i + 2] << 6) | (base64_table[i + 1] << 12) | (base64_table[i] << 18)

    message[(3 * i // 4) + 2] = chunk & 0xff
    message[(3 * i // 4) + 1] = (chunk >> 8) & 0xff
    message[(3 * i // 4)] = (chunk >> 16) & 0xff

m = bytes(message)

print(m)
```

The message printed will look some thing like this:

`b'\xb7\x1a...DH{1d91e9b0934706f4d0808166c04d9d1ca85b0dd8a2e852cb0c13a1add09c439c}...\x0e\''`

So the flag is __`DH{1d91e9b0934706f4d0808166c04d9d1ca85b0dd8a2e852cb0c13a1add09c439c}`__, which is correct