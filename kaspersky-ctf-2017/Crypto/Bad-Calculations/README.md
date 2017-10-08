# Bad Calculations - 800 Points - Cryptography

This is a write-up on the 800 Points Crypto challenge in Kaspersky's CTF.

So, when looking at the code at first, it looks like an RSA encryption (generating p and q, multiplying (p-1)*(q-1), and so on and so forth..).

When trying to run the given script, we can notice that it takes really long to execute, which makes it kind of suspicious.
This was the point I decided to try and optimize the code and make it run faster.
Throughout the optimization process, I noticed a few things:
1) There parts in the code that were made complicated, but can be done in an easy way.
2) I did not see where the RSA encryption was taking place.

So, I started from the beginning of the main, and started optimizing.
The first thing I noticed was that, g, the number that is chosen in a "weird" way from a foor loop, can actually be generated in a 
different, easier way.
If you notice, g is always equal to : (p*q)+1.

Next, the initialization of the "rc" variable (using the function 'sdsd') basically generates a list of prime numbers,
in the range: 2-((p*q)+1).
So, I changed the 'sdsd' function, and optimized the primality test as well (I made it loop up to the square root of (p*q+1), and 
created some more changes)

After changing the 'sdsd' function, I took a look at the 'dcew' variable.
Using some math, I was able to simplify the term (this is not much of a difference, but still, a change...).
The value after simplifying: ((g**22)*(r**n)) % (n*n).

Next comes the **final** and most important part!

The final encryption loop.
At first I tried understanding what each line is doing, but then, I decided to use the power of debugging.
I put a print before and after each line.
The first line's effect did not give me anything useful, it seemed like it is generating some odd number.
The second line's effect was the heart of the challenge.
I put a print before the second line and after, and I noticed:

The value of the cell in the array changes from x, to x+b, where b is a constant assigned with the value 22.

This means that, after this whole RSA-like behavior, what the encryption does, is basically incease each value of the content inside the
KLCTF flag format brackets (i.e, the content here is flag123 : KLCTF{flag123}) by 22, and returns the base63 encoded string.

I quickly made a script that that uses the encoded string, decodes it, and for each byte it decreases the value by 22.

I ran it, and I got the flag.

**The flag is: KLCTF{paillier_homomorphic_encryption}**


------------> Related Links <-----------------
[###**A script to generate the flag**](https://github.com/j0nathanj/CTF-WriteUps/blob/master/kaspersky-ctf-2017/Crypto/Bad-Calculations/solve.py)
[###**The simplified python script**](https://github.com/j0nathanj/CTF-WriteUps/blob/master/kaspersky-ctf-2017/Crypto/Bad-Calculations/simplified.py)

