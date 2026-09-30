# Dance in the Light
_Don't stop the music, dance in the light!_

Challenge link: <https://dreamhack.io/wargame/challenges/1598>

## Content inspection

The challenge contains two files: 

- `main`: Executable Linked File, written in C, little-endian, AMD64 architecture
- `output.mp3`: MP3 file, playable

First, I run the `main` executable and receive the instruction:

`How to use: ./main [input_mp3_file] [output_filename] [flag]`

This program takes a input MP3 file (2<sup>nd</sup> argument) and a secret flag (4<sup>th</sup>) to make an output (3<sup>rd</sup>).

## Reversing the mechanics

I use Ghidra for reversing the `main` program. Jumping into the `main` function (first argument of the `__libc_start_main` function in the `entry`), we can see this:

```C
int main(int argc, char **argv)
{
    // Renamed variables
    
    if (argc == 4) {
        input_stream = fopen(argv[1],"r");
        output_stream = fopen(argv[2],"w");
        __s = argv[3];
        /* Processing the input */
    }
    else {
        iVar1 = 1;
        __printf_chk(1,"How to use: %s [input_mp3_file] [output_filename] [flag]\n",*argv);
  }
  /* Program ends */
}
```

The program requires 4 arguments, reads the files named in the 2 first extra arguments and does the below processing:

- First, it processes through the secret flag: 

```C
sVar2 = strlen(__s);
if (0 < sVar2) {
    uVar3 = 0;

    while (true) {
        iVar1 = 0;
        // Parse through all bits of each character in __s in reverse
        while (true) {
            file_write_process(input_stream, output_stream, __s[uVar3] >> (iVar1 & 0x1f) & 1);

            if (iVar1 + 1 == 8) break;
            
            __s = argv[3];
            iVar1 = iVar1 + 1;
        }

        if (sVar2 - 1 == uVar3) break; // For all characters

        __s = argv[3];
        uVar3 = uVar3 + 1;
    }
}
```

- Then it continues the process by _'padding'_ 0s until end of file (Explanation below).

```C
do {
    iVar1 = file_write_process(input_stream, output_stream, 0);
} while (iVar1 != 0);
```
### MP3 structure
But first, to understand 

### File processing function (`file_write_process`)

We now dive deep into this function. First, it reads the first 4 bytes from the current position, then checks for requirements:

Then it decides the amount to read and process from those data:

And then it parses the XOR checksum, and more processing for the bit, then checks if it is different from the given bit (3<sup>rd</sup> argument). If it is, the third read byte will be OR'ed by 1.

## Solution and flag:
```Python
# Read the bytes

with open('output.mp3', 'rb') as r:
    a = r.read()

print(len(a))

# Arrays to determine the size of data to process:
#   arr1 as the int array from 
#   arr2 as the int array from 

arr1 = [0, 0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60, 0x70, 0x80, 0x0A0,
0x0C0, 0x0E0, 0x100, 0x140, 0, 8, 0x10, 0x18, 0x20, 0x28, 0x30,
0x38, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0x0A0]

arr2 = [0xac44, 0xbb80, 0x7d00]

pos, byte = 0, 0

bit_arr = []

while pos < len(a):
    # Read the first four bytes

    fourB = a[pos: pos + 4]

    uVar4 = fourB[1] >> 3 & 3
    uVar7 = fourB[2] >> 2 & 3

    # Get processed data size
    iVar5 = 0x480 if (uVar4 != 2) else 0x240
    
    uVar4 = (iVar5 * arr1[(uVar4 ^ 3) * 0xf + (fourB[2] >> 4)] * 0x7d) // (arr2[uVar7] >> (uVar4 != '\x03')) + (fourB[2] >> 1 & 1)

    # Get checksum bit and XOR it  
    bVar3 = 0
    for i in range(4, uVar4):
        bVar3 ^= a[pos +i]

    bVar3 = bVar3 ^ bVar3 >> 4
    bVar3 = bVar3 >> 2 ^ bVar3
    bVar3 = (bVar3 >> 1 ^ bVar3) & 1;    

    # Add to known bytes
    bit_arr.append((fourB[2] & 1) ^ bVar3)
    
    pos += uVar4; byte += 1


# Get the message

y = [0] * (len(bit_arr) // 8)
for i in range(0, 800, 8):
    for j in range(8):
        y[i >> 3] |= bit_arr[i + j] << j

print(bytes(y[:99]))
```

Executing this program, we will receive this:

`b'DH{b70d8b7cefd79ae6a7369ee7f4df6e8eb912e44415410ca78029fcd5b1555771}\x00\x00\x00\x00\x00...'`

And the flag is **`DH{b70d8b7cefd79ae6a7369ee7f4df6e8eb912e44415410ca78029fcd5b1555771}`**, which is a correct answer.