from base64 import b64decode

b = 22 # the "magic constant" given in the original script

cipher_base64 = "hnd/goJ/e4h1foWDhYOFiIZ+f3l1e4R5iI+Gin+FhA=="
decoded_base64 = b64decode(cipher_base64)
plaintext = ""

for character in decoded_base64:
	source_character = ord(character) - b
	plaintext += chr(source_character)

print plaintext # At this point, the plaintext holds the flag.

print "Flag: KLCTF{"+str(plaintext)+"}"
