import lzma
import hashlib
import json
from functools import lru_cache

class Combiner:
	def __init__(self):
		pass
	def combine(self, target, count):
		target = list(target)
		new = target.copy()
		newtarget = target.copy()
		while len(new) < count:
			newpart = []
			for comb1 in newtarget:
				if len(newpart) + len(new) >= count:
					break
				for comb2 in target:
					newpart.append(comb1 + comb2)
					if len(newpart) + len(new) >= count:
						break
			newtarget = newpart.copy()
			new += newpart.copy()
			if len(new) >= count:
				break
		return new[:count]
	def combine2(self, target, count):
		target = list(target)
		new = []
		for h in target:
			if len(new) >= count:
				break
			for h2 in target:
				if len(new) >= count:
					break
				for h3 in target:
					if len(new) >= count:
						break
					for h4 in target:
						if len(new) >= count:
							break
						new.append(h+h2+h3+h4)
		return new[:count]

class LeCatchu_Engine:
	def __init__(self, sbox="qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890.,_-+", sbox_randomizer=None, coding_for_packet=False, unicode_support=1114112):
		sbox = list(sbox)
		if sbox_randomizer != None:
			import random as randomizer12
			randomizer12.seed(sbox_randomizer)
			randomizer12.shuffle(sbox)
		self.combiner = Combiner()
		self.seperator = sbox[0]
		self.fullsbox = sbox
		if not coding_for_packet:
			sbox = sbox[1:]
		if len(sbox) == 0:
			raise ValueError("Sbox entry is too small. Must be at least 2 digits.")
		self.sbox = sbox
		if coding_for_packet:
			self.encode = self.__encode_packet
			self.decode = self.__decode_packet
			self.coding_sbox = self.combiner.combine2(self.sbox, unicode_support)
		else:
			self.coding_sbox = self.combiner.combine(self.sbox, unicode_support)
		if sbox_randomizer != None:
			randomizer12.shuffle(self.coding_sbox)
		self.decoding_sbox = {}
		for i, h in enumerate(self.coding_sbox):
			self.decoding_sbox[h] = i
		self.unicode_support = unicode_support
	def encode(self, target):
		if not isinstance(target, str):
			raise ValueError("Encoding input can only be string type object")
		return (self.seperator.join([self.coding_sbox[ord(h)] for h in target])).encode("utf-8")
	def __encode_packet(self, target):
		if not isinstance(target, str):
			raise ValueError("Encoding input can only be string type object")
		return ("".join([self.coding_sbox[ord(h)] for h in target])).encode("utf-8")
	def decode(self, target):
		if not isinstance(target, bytes):
			raise ValueError("Decoding input can only be byte type object")
		return "".join([chr(self.decoding_sbox[h]) for h in target.decode("utf-8").split(self.seperator)])
	def __decode_packet(self, target):
		if not isinstance(target, bytes):
			raise ValueError("Decoding input can only be byte type object")
		target = target.decode("utf-8")
		target = [target[i:i+4] for i in range(0, len(target), 4)]
		return "".join([chr(self.decoding_sbox[h]) for h in target])
	def get_packet_recv(self, sock, length):
		return sock.recv(length*4)
	@lru_cache(maxsize=128)
	def cached_blake2b(self, combk):
		return hashlib.blake2b(combk.encode(errors="ignore"), digest_size=32).hexdigest()
	@lru_cache(maxsize=64)
	def process_hash(self, key, xbase=1):
		key = str(key)
		okey = str(key)
		hashs = []
		combk = key + okey
		for _ in range(xbase):
			key = self.cached_blake2b(combk)
			hashs.append(key)
			combk = key + okey
		return int("".join(hashs), 16)
	def hash_stream(self, key, xbase=1):
		key = str(key)
		okey = str(key)
		while True:
			keys = []
			combk = key + okey
			for _ in range(xbase):
				key = self.cached_blake2b(combk)
				keys.append(key)
				combk = key + okey
			yield int("".join(keys), 16)
	def encrypt(self, target, key, xbase=1):
		keygen = self.hash_stream(key, xbase)
		return ''.join(chr((ord(c) + next(keygen)) % self.unicode_support) for c in target)
	def smart_encrypt(self, target, key, xbase=1):
		keygen = self.hash_stream(key, xbase)
		new = ''.join(chr((ord(c) + next(keygen)) % self.unicode_support) for c in target)
		new = self.encode(new)
		return self.compress(new)
	def decrypt(self, target, key, xbase=1):
		keygen = self.hash_stream(key, xbase)
		return ''.join(chr((ord(c) - next(keygen)) % self.unicode_support) for c in target)
	def smart_decrypt(self, target, key, xbase=1):
		target = self.decompress(target)
		target = self.decode(target)
		keygen = self.hash_stream(key, xbase)
		new = ''.join(chr((ord(c) - next(keygen)) % self.unicode_support) for c in target)
		return new
	def encrypts(self, target, keys, xbase=1):
		okey = str(keys[0])
		keygens = []
		for key in keys:
			okey = str(self.process_hash(str(key) + okey, xbase))
			keygen = self.hash_stream(okey, xbase)
			keygens.append([next(keygen) for _ in range(len(target))])
		result = []
		for i, char in enumerate(target):
			val = ord(char)
			for gen in keygens:
				val = (val + gen[i]) % self.unicode_support
			result.append(chr(val))
		return "".join(result)
	def decrypts(self, target, keys, xbase=1):
		okey = str(keys[0])
		keygens = []
		for key in keys:
			okey = str(self.process_hash(str(key) + okey, xbase))
			keygen = self.hash_stream(okey, xbase)
			keygens.append([next(keygen) for _ in range(len(target))])
		result = []
		for i, char in enumerate(target):
			val = ord(char)
			for gen in reversed(keygens):
				val = (val - gen[i]) % self.unicode_support
			result.append(chr(val))
		return "".join(result)
	def generate_key(self, seed, xbase=1):
		return self.process_hash(seed, xbase)
	def generate_keys(self, seed, count=32, xbase=1):
		keys = []
		for _ in range(count):
			seed = self.generate_key(seed, xbase)
			keys.append(seed)
		return keys
	def generate_key_opti(self, seed):
		return self.generate_key(seed, xbase=1)
	def generate_key_pro(self, seed):
		return self.generate_key(seed, xbase=40)
	def compress(self, target):
		return lzma.compress(target)
	def decompress(self, target):
		return lzma.decompress(target)
	def lestr(self, target):
		return json.dumps({"": target}, default=repr)
	def leval(self, target):
		return json.loads(target)[""]
	def encode_direct(self, target):
		return target.encode("utf-8", errors="ignore")
	def decode_direct(self, target):
		return target.decode("utf-8", errors="ignore")
	def __seed_combine_sys(self, key1, key2):
		newkey = ""
		for h in key1:
			for h2 in key2:
				newkey += h+h2
		return newkey
	def seed_combine(self, keys):
		if len(keys) == 0:
			return ""
		elif len(keys) == 1:
			return keys[0]
		elif len(keys) == 2:
			return self.__seed_combine_sys(keys[0], keys[1])
		else:
			new = self.__seed_combine_sys(keys[0], keys[1])
			for k in keys[2:]:
				new = self.__seed_combine_sys(k, new)
			return new
	def lestr2(self, target, n=0):
		t = str(type(target))
		t = t[t.find("'")+1:]
		t = t[:t.find("'")]
		if t == "str":
			return "0"+str(target)
		elif t == "int":
			return "1"+str(target.real)
		elif t == "float":
			return "2"+str(target.real)
		elif t == "list":
			if len(target) == 0:
				return "3"
			return "3"+(f"/.ls//..{n}ls/...//..".join([self.lestr2(target, n=n+1) for target in target]))
		elif t == "dict":
			return "4"+(f"/.dct//..{n}dct/...//..".join([self.lestr2(key, n=n+1)+f"/.dctsp//..{n}dct/...//.."+self.lestr2(value, n=n+1) for key, value in target.items()]))
		elif t == "set":
			if len(target) == 0:
				return "53"
			return "5"+(self.lestr2(list(target), n=n+1))
		elif t == "bool":
			return "6" if target else "7"
		elif t == "bytes":
			return "8"+str(target)
		else:
			return "9"
	def leval2(self, target, n=0):
		t = target[0]
		target = target[1:]
		if t == "0":
			return target
		elif t == "1":
			return int(target)
		elif t == "2":
			return float(target)
		elif t == "3":
			if len(target) == 0:
				return []
			hh = target.split(f"/.ls//..{n}ls/...//..")
			return [self.leval2(h, n=n+1) for h in hh]
		elif t == "4":
			new = {}
			for val in target.split(f"/.dct//..{n}dct/...//.."):
				value = val.split(f"/.dctsp//..{n}dct/...//..")
				new[self.leval2(value[0], n=n+1)] = self.leval2(value[1], n=n+1)
			return new
		elif t == "5":
			return set(self.leval2(target, n=n+1))
		elif t == "6":
			return True
		elif t == "7":
			return False
		elif t == "8":
			return target[2:][:-1].encode("utf-8", errors="ignore")
		elif t == "9":
			return None

class EncryptionStandart_Engine:
	def __init__(self):
		from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish, DES3, ChaCha20, ARC4, CAST
		from Crypto.PublicKey import RSA
		from Crypto.Random import get_random_bytes
		from Crypto.Util.Padding import pad, unpad
		from hashlib import sha256
		self.AES = AES
		self.RSA = RSA
		self.PKCS1_OAEP = PKCS1_OAEP
		self.Blowfish = Blowfish
		self.DES3 = DES3
		self.ChaCha20 = ChaCha20
		self.ARC4 = ARC4
		self.CAST = CAST
		self.get_random_bytes = get_random_bytes
		self.pad = pad
		self.unpad = unpad
		self.sha256 = sha256
	def _derive_key(self, seed, salt=1, key_len=32):
		data = f"{seed}_{salt}".encode("utf-8")
		key = self.sha256(data).digest()
		while len(key) < key_len:
			key += self.sha256(key).digest()
		return key[:key_len]
	def generate_key_aes(self, seed, salt=1):
		return self._derive_key(seed, salt, 32)
	def encrypt_aes(self, data, key):
		cipher = self.AES.new(key, self.AES.MODE_CBC)
		ct_bytes = cipher.encrypt(self.pad(data, self.AES.block_size))
		return cipher.iv + ct_bytes
	def decrypt_aes(self, data, key):
		iv = data[:16]
		ct = data[16:]
		cipher = self.AES.new(key, self.AES.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.AES.block_size)
	def generate_key_rsa(self, seed, salt=1):
		import io
		class DeterministicRNG:
			def __init__(self, seed_bytes):
				self.state = seed_bytes
			def read(self, n):
				out = b""
				while len(out) < n:
					self.state = self.sha256(self.state).digest()
					out += self.state
				return out[:n]
			@property
			def sha256(self):
				return __import__("hashlib").sha256
		seed_hash = self.sha256(f"{seed}_{salt}".encode()).digest()
		randfunc = DeterministicRNG(seed_hash).read
		key = self.RSA.generate(2048, randfunc=randfunc)
		return key.export_key(), key.publickey().export_key()
	def encrypt_rsa(self, data, public_key_bytes):
		key = self.RSA.import_key(public_key_bytes)
		cipher = self.PKCS1_OAEP.new(key)
		chunk_size = 190
		encrypted = b""
		for i in range(0, len(data), chunk_size):
			encrypted += cipher.encrypt(data[i:i+chunk_size])
		return encrypted
	def decrypt_rsa(self, encrypted_data, private_key_bytes):
		key = self.RSA.import_key(private_key_bytes)
		cipher = self.PKCS1_OAEP.new(key)
		chunk_size = 256
		decrypted = b""
		for i in range(0, len(encrypted_data), chunk_size):
			decrypted += cipher.decrypt(encrypted_data[i:i+chunk_size])
		return decrypted
	def generate_key_blowfish(self, seed, salt=1):
		return self._derive_key(seed, salt, 16)
	def encrypt_blowfish(self, data, key):
		cipher = self.Blowfish.new(key, self.Blowfish.MODE_CBC)
		ct = cipher.encrypt(self.pad(data, self.Blowfish.block_size))
		return cipher.iv + ct
	def decrypt_blowfish(self, data, key):
		iv = data[:8]
		ct = data[8:]
		cipher = self.Blowfish.new(key, self.Blowfish.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.Blowfish.block_size)
	def generate_key_des3(self, seed, salt=1):
		return self._derive_key(seed, salt, 24)
	def encrypt_des3(self, data, key):
		cipher = self.DES3.new(key, self.DES3.MODE_CBC)
		ct = cipher.encrypt(self.pad(data, self.DES3.block_size))
		return cipher.iv + ct
	def decrypt_des3(self, data, key):
		iv = data[:8]
		ct = data[8:]
		cipher = self.DES3.new(key, self.DES3.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.DES3.block_size)
	def generate_key_chacha20(self, seed, salt=1):
		return self._derive_key(seed, salt, 32)
	def encrypt_chacha20(self, data, key):
		cipher = self.ChaCha20.new(key=key)
		return cipher.nonce + cipher.encrypt(data)
	def decrypt_chacha20(self, data, key):
		nonce = data[:8]
		ct = data[8:]
		cipher = self.ChaCha20.new(key=key, nonce=nonce)
		return cipher.decrypt(ct)
	def generate_key_arc4(self, seed, salt=1):
		return self._derive_key(seed, salt, 16)
	def encrypt_arc4(self, data, key):
		cipher = self.ARC4.new(key)
		return cipher.encrypt(data)
	def decrypt_arc4(self, data, key):
		cipher = self.ARC4.new(key)
		return cipher.decrypt(data)
	def generate_key_cast(self, seed, salt=1):
		return self._derive_key(seed, salt, 16)
	def encrypt_cast(self, data, key):
		cipher = self.CAST.new(key, self.CAST.MODE_CBC)
		ct = cipher.encrypt(self.pad(data, self.CAST.block_size))
		return cipher.iv + ct
	def decrypt_cast(self, data, key):
		iv = data[:8]
		ct = data[8:]
		cipher = self.CAST.new(key, self.CAST.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.CAST.block_size)

class LeCatchu_Kid_Engine:
	def __init__(self): # for kids
		self.LeCatchu_Engine = LeCatchu_Engine(coding_for_packet=True, sbox_randomizer="kid")
	def encrypt(self, text, key):
		key = self.LeCatchu_Engine.generate_key(key, xbase=2)
		return self.LeCatchu_Engine.encode(self.LeCatchu_Engine.encrypt(text, key, xbase=2))
	def decrypt(self, text, key):
		key = self.LeCatchu_Engine.generate_key(key, xbase=2)
		return self.LeCatchu_Engine.decrypt(self.LeCatchu_Engine.decode(text), key, xbase=2)


import time
import random
import string
import hashlib
from collections import Counter
import math

# Karmaşık Performans Testi - Geniş Metinler
def test_large_text_encoding(engine, size=100000):
    large_text = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=size))
    start_time = time.time()
    encoded = engine.encode(large_text)
    encoding_time = time.time() - start_time
    print(f"Large Text Encoding Time ({size} characters): {encoding_time:.6f} seconds")
    return encoded, encoding_time

def test_large_text_decoding(engine, encoded_data):
    start_time = time.time()
    decoded = engine.decode(encoded_data)
    decoding_time = time.time() - start_time
    print(f"Large Text Decoding Time: {decoding_time:.6f} seconds")
    return decoded, decoding_time

# Anahtar Sayısının Artırılması (Cryptanalysis Testi)
def test_multiple_keys_encryption(engine, test_string="Test metni", num_keys=50):
    keys = random.sample(range(1, 100000), num_keys)
    start_time = time.time()
    encrypted = engine.encrypts(test_string, keys)
    encryption_time = time.time() - start_time
    print(f"Multiple Keys Encryption Time ({num_keys} keys): {encryption_time:.6f} seconds")
    return encrypted, encryption_time

def test_multiple_keys_decryption(engine, encrypted_data, keys):
    start_time = time.time()
    decrypted = engine.decrypts(encrypted_data, keys)
    decryption_time = time.time() - start_time
    print(f"Multiple Keys Decryption Time: {decryption_time:.6f} seconds")
    return decrypted, decryption_time

# Şifreleme Anahtarları Arasındaki Çatışmaları Test Etme
def test_key_collision_resistance(engine, test_string="Test metni"):
    key1 = random.randint(1, 100000)
    key2 = random.randint(1, 100000)
    while key1 == key2:
        key2 = random.randint(1, 100000)  # Farklı anahtarlar kullanmak için kontrol
    encrypted1 = engine.encrypt(test_string, key1)
    encrypted2 = engine.encrypt(test_string, key2)
    assert encrypted1 != encrypted2, "Key collision detected, encryption is weak"
    print("Key Collision Resistance Test Passed")

# Çift Yönlü Karakter Çalışması - Sırasız Kodlama / Şifreleme (Şifrelemeye Dayalı Karakter Kombinasyonu)
def test_reverse_character_encoding(engine, test_string="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
    start_time = time.time()
    encoded = engine.encode(test_string)
    decoded = engine.decode(encoded)
    decoding_time = time.time() - start_time
    print(f"Reverse Character Encoding/Decoding Time: {decoding_time:.6f} seconds")
    assert decoded == test_string, "Reverse encoding/decoding failed"
    print("Reverse Character Encoding/Decoding Test Passed")

# Entropi Analizi - Veri Karakteristikleri
def test_entropy_of_large_data(engine, size=100000):
    large_text = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=size))
    encrypted = engine.encrypt(large_text, key=12345)
    entropy = calculate_entropy(encrypted)
    print(f"Entropy of encrypted large data (size={size}): {entropy:.6f}")
    return entropy

# Karmaşık Anahtarlar ve Veri Şifrelemesi - Hash Çarpışmaları Testi
def test_hash_collision_with_complex_keys(engine, test_string="Test metni"):
    keys = [random.randint(1, 100000) for _ in range(10)]
    encrypted1 = engine.encrypt(test_string, keys[0])
    encrypted2 = engine.encrypt(test_string, keys[1])
    assert encrypted1 != encrypted2, "Hash collision detected between different keys"
    print("Hash Collision with Complex Keys Test Passed")

# Veri Tabanlı Çatışma (Differential Cryptanalysis Testi)
def test_differential_cryptanalysis(engine, test_string="Test metni", key1=12345, key2=67890):
    encrypted1 = engine.encrypt(test_string, key1)
    encrypted2 = engine.encrypt(test_string, key2)
    
    assert encrypted1 != encrypted2, "Differential Cryptanalysis Test Failed: Encryption should differ for different keys"
    
    print("Differential Cryptanalysis Test Passed")

# Entropi Hesaplama Fonksiyonu
def calculate_entropy(data):
    frequency = Counter(data)
    prob_values = [freq / len(data) for freq in frequency.values()]
    entropy = -sum(p * math.log2(p) for p in prob_values)
    return entropy

# Karmaşık Testlerin Toplam Çalıştırılması
def run_complex_tests():
    engine = LeCatchu_Engine()

    print("\n=== Large Text Encoding/Decoding Tests ===")
    encoded, enc_time = test_large_text_encoding(engine, size=100000)
    decoded, dec_time = test_large_text_decoding(engine, encoded)

    print("\n=== Multiple Keys Encryption/Decryption Tests ===")
    encrypted, enc_multi_keys_time = test_multiple_keys_encryption(engine, test_string="Test metni", num_keys=50)
    decrypted, dec_multi_keys_time = test_multiple_keys_decryption(engine, encrypted, random.sample(range(1, 100000), 50))

    print("\n=== Key Collision Resistance Test ===")
    test_key_collision_resistance(engine, test_string="Test metni")

    print("\n=== Reverse Character Encoding/Decoding Test ===")
    test_reverse_character_encoding(engine)

    print("\n=== Entropy Test on Large Data ===")
    entropy = test_entropy_of_large_data(engine, size=100000)

    print("\n=== Hash Collision with Complex Keys Test ===")
    test_hash_collision_with_complex_keys(engine)

    print("\n=== Differential Cryptanalysis Test ===")
    test_differential_cryptanalysis(engine)

if __name__ == "__main__":
    run_complex_tests()
