#!/usr/bin/python

import sys
import urllib2
import base64
import random
from StringIO import StringIO as BytesIO

# The oracle
def oracle(cookie):
	c = urllib2.build_opener()
	c.addheaders.append(('Cookie', 'user='+cookie))

	try:
		c.open('http://localhost:4555')
		return 1
	except urllib2.HTTPError as e:
		if e.code == 404:
			return 1
		else:
			return 0

# The Last word oracle
def last_word_oracle(y):
	# Block sizes in bytes, and number of possible words (bytes)
	b = 16
	w = 256
	r = ""

	# 1. Pick a few random words r1...rb and take i=0
	for x in range(b):
		r += chr(random.choice(range(w)))

	for i in range(w):
		# 2. pick r = r1...rb-1(rb XOR i)
		r1 = r[:b-1] + chr(ord(r[b-1]) ^ i)

		if (oracle(base64.b64encode(r1+y)) == 1):
			break

	# 4. replace rb by rb XOR i
	# This is already done above

	# 5. for n = b down to 2 do...
	for n in range(b, 1, -1):
		# (a) take r = r1..rb-n(rb-n+1 XOR 1)rb-n+2..rb
		r2 = r1[:b-n+1] + (chr(ord(r1[b-n+1]) ^ 1)) + r1[b-n+2:]
		# (b) if O(r|y) = 0 ...
		if (oracle(base64.b64encode(r2+y)) == 0):
			# then stop and output (rb-n+1 XOR n) ... (rb XOR n)
			r3 = r2[b-n+1:]
			r4 = ""
			for j in range(len(r3)):
				r4 += chr(ord(r[j]) ^ (j+1))

			break

	# 6. output rb XOR 1
	return (chr(ord(r1[b-1]) ^ 1))

# Block Decryption Oracle
def block_oracle(y, y_prime, j):
	b = 16
	w = 256
	r = ""
	r1 = ""
	r2 = ""

	# 1. take rk = ak XOR (b-j+2) for k = j,...,b
	for k in range(j,b+1):
		index = abs(j-k)
		r += chr(ord(y_prime[index]) ^ (index + 2))
	
	# 2. Pick r1, ... , rj-1 at random and i=0
	i = 0
	for x in range(j-1):
		r1 += chr(random.choice(range(w)))

	# 3. take r = r1..rj-2(rj-1 XOR i)rj..rb
	while (True):
		r2 = r1[:-1] + chr(ord(r1[j-2]) ^ i) + r 

		# 4. if O(r|y) = 0 then increment i and go back to previous step
		# Otherwise break
		if (oracle(base64.b64encode(r2+y)) == 1):
			break;
		else:
			i += 1;

	# 5. output rj-1 XOR i XOR (b-j+2)
	f = chr(ord(r2[j-2]) ^ 1)
	return f

# CBC Mode decryption
def cbc_decrypt(d_block, iv):
	plaintext = ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(d_block, iv))

	return plaintext


#### Main ####
def main():
	# Grab the cookie from command line arguments
	cookie = sys.argv[1]
	
	# The cookie is base64 encoded. We need to decode it when working with it
	cookie_decoded = base64.b64decode(cookie)
	cookie_len = len(cookie_decoded)
	total_blocks = cookie_len / 16
	total_decrypts = total_blocks - 1 # for IV
	iv = cookie_decoded[:16]

	plaintext = ''

	for x in range(total_decrypts):
		begin = -1* ((x+1) * 16)
		end = -1* ((x) * 16)
		if (x == 0):
			end = cookie_len
		
		y = cookie_decoded[begin:end]

		# Call the last word oracle
		lw = last_word_oracle(y)

		# Block decryption
		f = lw
		for j in range(16, 1, -1):
			f = block_oracle(y, f, j) + f	

		# CBC mode
		d_block = f
		begin = -1* ((x+1) * 32)
		end = -1* ((x+1) * 16)
		ci = cookie_decoded[begin:end]

		if (x+1 == total_decrypts):
			ci = iv
		
		p = cbc_decrypt(d_block, ci)

		print "Printing plaintext i"
		print base64.b64encode(p)

		plaintext = p + plaintext
		
	print plaintext

if __name__ == "__main__":
	main()
