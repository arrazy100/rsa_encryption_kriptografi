from Crypto.PublicKey.RSA import construct, import_key
from math import gcd
import base64
import Crypto.Util.number
import math
import random

def is_prime(n):
	if n == 2 or n == 3:
		return True
	if n < 2 or n % 2 == 0:
		return False
	if n < 9:
		return True
	if n % 3 == 0:
		return False
	r = int(n ** 0.5)
	
	f = 5
	while f <= r:
		if n % f == 0: return False
		if n % (f + 2) == 0: return False
		f += 6

	return True

def choose_big_prime(n_bits):
	prime_number = Crypto.Util.number.getPrime(n_bits, randfunc=Crypto.Random.get_random_bytes)

	return prime_number

def choose_random_prime(n_bits):
	if (n_bits > 16):
		return choose_big_prime(n_bits)
		
	prime_number = [x for x in range(2 ** (n_bits - 1) + 1, (2 ** n_bits) - 1) if is_prime(x)]

	return random.choice(prime_number)

def modinv(a, m):
	m0 = m
	y = 0
	x = 1
	
	if (m == 1):
		return 0

	while (a > 1):
		q = a // m
		t = m

		m = a % m
		a = t
		t = y

		y = x - q * y
		x = t

	if (x < 0):
		x = x + m0

	return x

def generate_key(bits):
	bit = bits // 2
	p = choose_random_prime(bit)
	q = choose_random_prime(bit)

	n = p * q

	e = 2
	phi = (p - 1) * (q - 1)
	
	while (e < phi):
		if (gcd(e, phi) == 1):
			break
		else:
			e += 1

	d = modinv(e, phi)

	return [e, n, d]

def get_rsa_key(bits):
	[e, n, d] = generate_key(bits)
	public_key = construct((n, e)).export_key().decode("utf-8")
	public_key = public_key.replace("-----BEGIN PUBLIC KEY-----\n", "")
	public_key = public_key.replace("\n-----END PUBLIC KEY-----", "")
	private_key = construct((n, e, d)).export_key().decode("utf-8")
	private_key = private_key.replace("-----BEGIN RSA PRIVATE KEY-----\n", "")
	private_key = private_key.replace("\n-----END RSA PRIVATE KEY-----", "")

	return [public_key, private_key]

def string_to_int(message):
	i = int.from_bytes(message.encode('utf-8'), byteorder='big')
	
	return i

def int_to_string(i):
	s = i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")
	s = s.decode("utf-8")

	return s

def encode64(i):
	s = str(i)
	coded = base64.b64encode(s.encode("utf-8"))

	return coded

def decode64(coded):
	decoded = base64.b64decode(coded)
	string = decoded.decode('utf-8')

	return string

def encrypt(message, e, n):
	i = string_to_int(message)
	c = pow(i, e, n)

	return c

def decrypt(encrypted, d, n):
	m = pow(encrypted, d, n)

	return m

def encrypt_with_key(message, key):
	public_key = "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"
	public_key = import_key(public_key.encode("utf-8"))

	max_length = public_key.n.bit_length() // 8

	if (len(message) > max_length):
		return "Tidak bisa melakukan proses enkripsi, maksimal panjang karakter adalah " + str(max_length) + " untuk RSA Key yang digunakan"

	c = encrypt(message, public_key.e, public_key.n)
	c = str(c)
	c = encode64(c).decode("utf-8")

	return c

def decrypt_with_key(message, key):
	s = decode64(message)
	i = int(s)
	private_key = "-----BEGIN RSA PRIVATE KEY-----\n" + key + "\n-----END RSA PRIVATE KEY-----"
	private_key = import_key(private_key.encode("utf-8"))
	m = decrypt(i, private_key.d, private_key.n)
	m = int_to_string(m);

	return m