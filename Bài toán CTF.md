---
title: Bài toán CTF

---

# Vernichtet (4)
## Bước 1: Thăm dò
Nhập thử ./main ta có
![image](https://hackmd.io/_uploads/SJuBIM9m-x.png)
Vậy nên chúng ta cần một tệp nhị phân, chẳng hạn x1.txt để trả lời. 
## Bước 2: Dùng ghidra và objdump đối chiếu code
Bây giờ chúng ta cần dịch ngược thử phần mềm, ta nhận được một số hàm không xác định (func_0xhhhhhhhh):
![image](https://hackmd.io/_uploads/Hy_bUM9QZl.png)
Vậy nên chúng ta quay trở lại và dùng objdump để kiểm tra những hàm này:
![image](https://hackmd.io/_uploads/rk8ePGcQZl.png)
Đối chiếu hai hình này ta thấy:
* Nếu nhập ./main (file_name), phần mềm sẽ tìm và mở tệp có tên này trong chế độ rb
* Khi đã mở được rồi, phần mềm đi đến cuối tệp và trả vị trí của con trỏ so với đầu tệp:
    * Phần mềm xử lý hàm `fseek(file, 0, 2)`, tức là đi tới đúng vị trí của cuối file, tham số 2 ở cuối là cho việc đi tới cuối file này, số 0 (tham số thứ 2) chỉ offset từ vị trí đó, tức là đúng chỗ mình cần tìm
    * Hàm `ftell(file)` chỉ vị trí của con trỏ so với vị trí ban đầu, ở đây là số ký tự trong tệp
    * Hàm `rewind(file)` đưa con trỏ về đầu tệp
* Nếu tệp này có 225 ký tự, cấp phát (`malloc(0xE1)`) cho uVar4 225 ký tự, rồi đọc hết (`fread(cont, 1, 225, file)`) từ file sang mảng uVar4 trên

Nếu đọc hết được, phần mềm xử lý qua hai công đoạn sau:
## Bước 3: Giải mã hàm xử lý

### Công đoạn 1
Đầu tiên, chúng ta xem hàm FUN_00101269:
```cpp
while( true ) {
if (0xe0 < iStack_c) {
  return 1;
}

//Đặt *(0x104020 + 3 * x) = a
//Đặt *(0x104021 + 3 * x) = b
//Đặt *(0x104022 + 3 * x) = c

if ((*(char *)((long)iStack_c * 3 + 0x104022) != '\0') &&
   (bVar1 = *(byte *)((long)iStack_c * 3 + 0x104021),
   *(char *)(param_1 +
            (int)((uint)*(byte *)((long)iStack_c * 3 + 0x104020) +
                 ((uint)bVar1 * 0x10 - (uint)bVar1))) !=
   *(char *)((long)iStack_c * 3 + 0x104022))) break;
iStack_c = iStack_c + 1;
}
return 0;
```

Phân tích đoạn mã trên ta thấy:
- Hàm này phân tích hết 225 trường hợp
- Mỗi trường hợp, hàm kiểm tra với bộ ba số a, b, c: Nếu c khác 0 và `param_1[15 * b + a] == c`, xem phần tử tiếp theo...

Khi này chúng ta kiểm tra địa chỉ 0x104020 đến 0x104020 + 674, ta có trường 675 dòng, và ta điền dần bảng:

```python
s0, s1, s2 = [], [], []

res = [0] * 225

with open("m.txt", "r+") as k:
    for i in range(675):
        s = k.readline().strip()[9:11]

        match i % 3:
            case 0: s0.append(int(s, 16))
            case 1: s1.append(int(s, 16))
            case 2: s2.append(int(s, 16))


for i in range(225):
    if s2[i] != 0: res[(s1[i] * 15 + s0[i]) % 256] = s2[i]
    
for i in range(15):
    print('\t'.join(str(i) for i in res[15 * i: 15 + 15 * i])) 
```
Kết quả sẽ ra:
![image](https://hackmd.io/_uploads/rJTwAGqmbe.png)

### Công đoạn 2:

Còn ở trong hàm FUN_0x0010138e, chúng ta có tiếp:
- Đoạn mã dưới đây tìm vị trí của số 1 trong mảng trên (khi lập thành bảng vuông cạnh 15):

```cpp
cStack_23 = '\0';
cStack_22 = '\0';
for (iStack_1c = 0; iStack_1c < 0xf; iStack_1c = iStack_1c + 1) {
    for (iStack_18 = 0; iStack_18 < 0xf; iStack_18 = iStack_18 + 1) {
        if (*(char *)(param_1 + (iStack_18 + iStack_1c * 0xf)) == '\x01') {
            cStack_23 = (char)iStack_18;
            cStack_22 = (char)iStack_1c;
        }
    }
}
```
Và sau đó phần mềm sẽ tìm số tiếp theo liên tiếp nó mà có thế đi lên, xuống, sang hoặc xiên 1 bước:
- Đầu tiên, đi tìm các ô có thể đến được:
```cpp
if (0xe0 < iStack_14) {
  return 1;
}
if (cStack_23 < '\x01') {
  cStack_21 = cStack_23;
}
else {
  cStack_21 = cStack_23 + -1;
}
if (cStack_23 < '\x0e') {
  cStack_20 = cStack_23 + '\x01';
}
else {
  cStack_20 = cStack_23;
}
if (cStack_22 < '\x01') {
  cStack_1f = cStack_22;
}
else {
  cStack_1f = cStack_22 + -1;
}
if (cStack_22 < '\x0e') {
  cStack_1e = cStack_22 + '\x01';
}
else {
  cStack_1e = cStack_22;
}
```
- Sau đó tìm ô mà có giá trị liên tiếp với giá trị của tâm
```cpp
for (iStack_10 = (int)cStack_1f; iStack_10 <= cStack_1e; iStack_10 = iStack_10 + 1) {
  for (iStack_c = (int)cStack_21; iStack_c <= cStack_20; iStack_c = iStack_c + 1) {
    if (((iStack_10 != cStack_22) || (iStack_c != cStack_23)) &&
       ((uint)*(byte *)(param_1 + (iStack_c + iStack_10 * 0xf)) == iStack_14 + 1U)) {
      bVar1 = true;
      cStack_23 = (char)iStack_c;
      cStack_22 = (char)iStack_10;
    }
  }
}
if (!bVar1) break;
```
Lặp lại tới khi tìm được ô số 225.

Khi này, dùng tay giải ta có:
![image](https://hackmd.io/_uploads/HJjTl797bx.png)
Xuất kết quả ra x1.txt:

```python
m = []

with open("s1.txt", "r") as k:
    for i in range(15):
        m += [int(i) for i in k.readline().split()]

with open("x1.txt", "wb") as x:
    x.write(bytes(m))
```

Khi đó chúng ta có kết quả
![image](https://hackmd.io/_uploads/S1-V-mq7bx.png)

# Carta (4)

## Bước 1: Thăm dò
Khi tải bài toán về, chúng ta thấy cấu trúc file như sau:
![image](https://hackmd.io/_uploads/HkF_nFRQWg.png)
Trước hết chúng ta thử chạy chương trình main:
![image](https://hackmd.io/_uploads/BJfz6FCmWx.png)
Bài toán sẽ lấy một màn chơi bất kỳ và bắt người chơi tìm các cặp ô có cùng số. Bây giờ chúng ta đi tìm hiểu xem màn chơi được tạo như thế nào.
## Bước 2: Dùng ghidra dịch ngược
Khi dịch xong, chúng ta lấy hàm khởi tạo và để ý tới các chi tiết:
- Mỗi nước đi sẽ được gọi bằng hàng rồi cột, hai số từ 0 đến 15.
```cpp
printf("%s pick: ",puVar1);
__isoc99_scanf("%d %d",local_20 + local_28,local_20 + (long)local_28 + 2);
if ((((local_20[local_28] < 0) || (0xf < local_20[local_28])) ||
    (local_20[(long)local_28 + 2] < 0)) || (0xf < local_20[(long)local_28 + 2])) {
    puts("Invalid Input!");
    goto LAB_0010173e;
}
if ((&DAT_00104180)[(long)local_20[local_28] * 0x10 + (long)local_20[(long)local_28 + 2]] != '\0') {
    puts("Already Matched!");
    goto LAB_0010173e;
}
// Bảng 16 * 16, local_20[local_28] là hàng, local_20[local_28 + 2] là cột
```
- Khi phá đảo màn sau tối đa 128 nước, cờ sẽ đến tay: 

```cpp
while( true ) { 
    //DAT_00104280 là số nước đã đi
    iVar1 = FUN_00101754();
    if (iVar1 == 0) break;
    DAT_00104280 = DAT_00104280 + 1;
    FUN_001014a9(DAT_00104280); 
}
    printf("Game Cleared! Trials: %d\n",(ulong)DAT_00104280);
    if ((int)DAT_00104280 < 0x81) {
    printf("Perfect Gamer! Get the Flag: ");
    // In cờ ra sau
    }
```
- Bảng được tạo ra theo một số là màn và có một quy tắc cố định
Giờ chúng ta giải mã quy tắc này.
## Bước 3: Giải mã
Đây là chương trình phá đảo màn chơi:
```cpp
int main() {
    vector<vector<int>> match(128);

    // Màn chơi lấy từ terminal, lấy sau
    cin >> seed; FUN_0010132b(seed); // Tạo bảng

    for (int i = 0; i < 256; ++i) {
      match[board[i]].push_back(i);

      // Ô có số nào cho vào cùng chỗ
    }

    for (auto i: match) {
      for (int j: i) cout << j / 16 << ' ' <<  j % 16 << '\n';

      //Hàng trước cột sau
    }
    return 0;
}
```
Khi giải chúng ta lấy được
![image](https://hackmd.io/_uploads/B1qGvcA7We.png)
Khi này chúng ta kết nối với dreamhack:
![image](https://hackmd.io/_uploads/BkrRjFAmbx.png)
Làm tương tự như trên ta được:
![image](https://hackmd.io/_uploads/B1dMOcRQbg.png)