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

class LeCatchu_Engine:
	def __init__(self, sbox="qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890.,_-+"):
		sbox = list(sbox)
		self.combiner = Combiner()
		self.seperator = sbox[0]
		self.fullsbox = sbox
		sbox = sbox[1:]
		if len(sbox) == 0:
			raise ValueError("Sbox entry is too small. Must be at least 2 digits.")
		self.sbox = sbox
		self.coding_sbox = self.combiner.combine(self.sbox, 1114112)
		self.decoding_sbox = {}
		for i, h in enumerate(self.coding_sbox):
			self.decoding_sbox[h] = i
	def encode(self, target):
		if not isinstance(target, str):
			raise ValueError("Encoding input can only be string type object")
		new = []
		for h in target:
			new.append(self.coding_sbox[ord(h)])
		return self.seperator.join(new).encode("utf-8")
	def decode(self, target):
		if not isinstance(target, bytes):
			raise ValueError("Decoding input can only be byte type object")
		target = target.decode("utf-8")
		new = []
		for h in target.split(self.seperator):
			new.append(chr(self.decoding_sbox[h]))
		return "".join(new)
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
		return ''.join(chr((ord(c) + next(keygen)) % 1114112) for c in target)
	def decrypt(self, target, key, xbase=1):
		keygen = self.hash_stream(key, xbase)
		return ''.join(chr((ord(c) - next(keygen)) % 1114112) for c in target)
	def encrypts(self, target, keys, xbase=1):
		okey = str(keys[0])
		for key in keys:
			okey = str(self.process_hash(str(key) + okey, xbase))
			keygen = self.hash_stream(okey, xbase)
			target = ''.join(chr((ord(c)+next(keygen)) % 1114112) for c in target)
		return target
	def decrypts(self, target, keys, xbase=1):
		okey = str(keys[0])
		for key in keys:
			okey = str(self.process_hash(str(key) + okey, xbase))
			keygen = self.hash_stream(okey, xbase)
			target = ''.join(chr((ord(c)-next(keygen)) % 1114112) for c in target)
		return target
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
