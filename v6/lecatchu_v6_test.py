# LeCatchu v6

import lzma
import hashlib
import json
from functools import lru_cache
import sys

version = 6
sys.set_int_max_str_digits((2**31)-1)	# Max C int digits for 32-bit systems

class Combiner:
	"""A utility class to generate combinations of values, used as a generator/engine."""
	
	def __init__(self):
		"""Initialize the Combiner class."""
		pass
	
	def combine(self, target, count):
		"""Generate combinations of items in the list based on the specified count.
		
		Args:
			target: List of items to combine.
			count: Number of combinations to generate.
		
		Returns:
			List of combined items, up to the specified count.
		"""
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
	
	def combine2(self, target, count, length=4, target2=None):
		"""Create a compact list of combinations, each containing a specific number of items.
		
		Args:
			target: List of items to combine.
			count: Number of combinations to generate.
			length: Number of items per combination (default: 4).
			target2: Optional secondary target list (default: None).
		
		Returns:
			List of combined items, up to the specified count.
		"""
		if length == 1:
			return list(target)
		target = list(target)
		if target2 is None:
			target2 = target.copy()
		new = []
		for h in target2:
			for h2 in target:
				new.append(h + h2)
				if len(new) >= count:
					break
		if length > 2:
			new = self.combine2(target, count, length=length-1, target2=new)
		return new[:count]
	
	def combine3(self, target, count):
		"""Generate combinations efficiently (faster version of combine).
		
		Args:
			target: List of items to combine.
			count: Number of combinations to generate.
		
		Returns:
			List of combined items, up to the specified count.
		"""
		new = self.combine2(list(target), count, length=1)
		result = list(new)
		while len(result) < count:
			new = self.combine2(new, count, length=2, target2=target)
			result.extend(new)
		return result[:count]

class LeCatchu_Engine:
	"""A cryptographic engine for encoding, decoding, encryption, and decryption with customizable settings."""
	
	def __init__(self, sbox="qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890.,_-+", 
				 sbox_randomizer=None, coding_for_packet=False, coding_for_packet_perlength=4, 
				 unicode_support=1114112, chaos_seed=None, chaos_coding_unicode_range=1024, data=None):
		"""Initialize the LeCatchu Cryptographic Engine.
		
		Args:
			sbox: Character string for text encoding.
			sbox_randomizer: Seed to shuffle the sbox for enhanced security.
			coding_for_packet: Enable compact text encoding for data packets.
			coding_for_packet_perlength: Length of compact characters in packet mode.
			unicode_support: Maximum Unicode character support.
			chaos_seed: Seed for experimental Chaos mode (not recommended for daily use).
			chaos_coding_unicode_range: Maximum Unicode range for Chaos mode sbox.
			data: Optional saved engine data for faster initialization.
		"""
		if data is not None:
			self.load(data)
		else:
			self.chaos_multi = ""
			if chaos_seed is not None:
				seed = self.hash_stream(chaos_seed, xbase=9)
				nsbox = []
				for h in range(0, chaos_coding_unicode_range):
					if len(nsbox) <= 2 or next(seed) % 2 == 0:
						nsbox.append(chr(h))
					else:
						nsbox.append(chr(h))
				sbox = nsbox
				sbox_randomizer = str(next(seed))
				coding_for_packet = True
				coding_for_packet_perlength = (next(seed) % 2) + 4
				self.chaos_multi = str(next(seed))
				self.cached_blake2b = self.__chaos_cached_blake2b
			sbox = list(sbox)
			for h in sbox:
				if sbox.count(h) >= 2:
					raise ValueError("Sbox contains repeated characters.")
			if sbox_randomizer is not None:
				import random as randomizer12
				randomizer12.seed(self.process_hash(sbox_randomizer, xbase=16))
				randomizer12.shuffle(sbox)
			self.combiner = Combiner()
			self.seperator = sbox[0]
			self.fullsbox = sbox
			if not coding_for_packet:
				sbox = sbox[1:]
			if len(sbox) == 0:
				raise ValueError("Sbox is too small. Must be at least 2 characters.")
			self.sbox = sbox
			if coding_for_packet:
				self.encode = self.__encode_packet
				self.decode = self.__decode_packet
				self.coding_sbox = self.combiner.combine2(self.sbox, unicode_support, length=coding_for_packet_perlength)
			else:
				self.coding_sbox = self.combiner.combine3(self.sbox, unicode_support)
			if len(self.coding_sbox) < unicode_support:
				raise ValueError(
					f"The s-box has {len(self.coding_sbox)} combinations (using {len(sbox)} characters, "
					f"perlength={coding_for_packet_perlength}), but the engine requires {unicode_support}; "
					"increase the character set or the per-combination length."
				)
			if sbox_randomizer is not None:
				randomizer12.shuffle(self.coding_sbox)
			self.decoding_sbox = {h: i for i, h in enumerate(self.coding_sbox)}
			self.unicode_support = unicode_support
			self.coding_for_packet_perlength = coding_for_packet_perlength
			self.coding_for_packet = coding_for_packet
	
	def encode(self, target):
		"""Encode the input string data.
		
		Args:
			target: String text to encode.
		
		Returns:
			Encoded data as bytes.
		"""
		if not isinstance(target, str):
			raise TypeError("Encoding input must be a string.")
		return (self.seperator.join([self.coding_sbox[ord(h)] for h in target])).encode("utf-8")
	
	def __encode_packet(self, target):
		"""Encode the input string data in packet mode.
		
		Args:
			target: String text to encode.
		
		Returns:
			Encoded data as bytes.
		"""
		if not isinstance(target, str):
			raise TypeError("Encoding input must be a string.")
		return ("".join([self.coding_sbox[ord(h)] for h in target])).encode("utf-8")
	
	def decode(self, target):
		"""Decode the input bytes data.
		
		Args:
			target: Bytes text to decode.
		
		Returns:
			Decoded data as a string.
		"""
		if not isinstance(target, bytes):
			raise TypeError("Decoding input must be bytes.")
		return "".join([chr(self.decoding_sbox[h]) for h in target.decode("utf-8").split(self.seperator)])
	
	def __decode_packet(self, target):
		"""Decode the input bytes data in packet mode.
		
		Args:
			target: Bytes text to decode.
		
		Returns:
			Decoded data as a string.
		"""
		if not isinstance(target, bytes):
			raise TypeError("Decoding input must be bytes.")
		target = target.decode("utf-8")
		target = [target[i:i+self.coding_for_packet_perlength] for i in range(0, len(target), self.coding_for_packet_perlength)]
		return "".join([chr(self.decoding_sbox[h]) for h in target])
	
	def get_packet_recv(self, sock, length):
		"""Retrieve data for packet exchange encoded with LeCatchu.
		
		Args:
			sock: Socket object.
			length: Buffer size.
		
		Returns:
			Received data as bytes.
		"""
		return sock.recv(length * self.coding_for_packet_perlength)
	
	@lru_cache(maxsize=128)
	def cached_blake2b(self, combk):
		"""Compute and cache a BLAKE2b hash of the input.
		
		Args:
			combk: String input to hash.
		
		Returns:
			Hexadecimal hash as a string.
		"""
		return hashlib.blake2b(combk.encode(errors="ignore"), digest_size=32).hexdigest()
	
	@lru_cache(maxsize=128)
	def __chaos_cached_blake2b(self, combk):
		"""Compute and cache a BLAKE2b hash with chaos mode modifications.
		
		Args:
			combk: String input to hash.
		
		Returns:
			Hexadecimal hash with chaos_multi appended as a string.
		"""
		return hashlib.blake2b(combk.encode(errors="ignore"), digest_size=32).hexdigest() + self.chaos_multi
	
	@lru_cache(maxsize=64)
	def process_hash(self, key, xbase=1):
		"""Convert input data into a hash number.
		
		Args:
			key: Input data to hash.
			xbase: Multiplier for the length of the resulting hash.
		
		Returns:
			Integer hash value.
		"""
		key = okey = str(key)
		hashs = []
		for _ in range(xbase):
			key = self.cached_blake2b((key + okey))
			hashs.append(key)
		return int("".join(hashs), 16)
	
	def hash_stream(self, key, xbase=1):
		"""Generate a stream of hash numbers from input data.
		
		Args:
			key: Input data to hash.
			xbase: Multiplier for the length of the resulting hash.
		
		Yields:
			Integer hash value.
		"""
		key = okey = str(key)
		while True:
			keys = []
			for _ in range(xbase):
				key = self.cached_blake2b((key + okey))
				keys.append(key)
			yield int("".join(keys), 16)
	
	def encrypt(self, target, key, xbase=1):
		"""Encrypt the input data using the provided key.
		
		Args:
			target: String input data.
			key: Integer encryption key.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Encrypted string.
		"""
		keygen = self.hash_stream(key, xbase)
		return ''.join(chr((ord(c) + next(keygen)) % self.unicode_support) for c in target)
	
	def smart_encrypt(self, target, key, xbase=1):
		"""Encrypt, encode, and compress the input data with automatic processing.
		
		Args:
			target: String input data.
			key: Integer encryption key.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Compressed and encoded bytes.
		"""
		keygen = self.hash_stream(key, xbase)
		new = ''.join(chr((ord(c) + next(keygen)) % self.unicode_support) for c in target)
		return self.compress(self.encode(new))
	
	def decrypt(self, target, key, xbase=1):
		"""Decrypt the input data using the provided key.
		
		Args:
			target: String input data.
			key: Integer encryption key.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Decrypted string.
		"""
		keygen = self.hash_stream(key, xbase)
		return ''.join(chr((ord(c) - next(keygen)) % self.unicode_support) for c in target)
	
	def smart_decrypt(self, target, key, xbase=1):
		"""Decompress, decode, and decrypt the input data.
		
		Args:
			target: Encrypted bytes data.
			key: Integer encryption key.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Decrypted string.
		"""
		target = self.decode(self.decompress(target))
		keygen = self.hash_stream(key, xbase)
		new = ''.join(chr((ord(c) - next(keygen)) % self.unicode_support) for c in target)
		return new
	
	def encrypts(self, target, keys, xbase=1):
		"""Encrypt the input data using multiple keys.
		
		Args:
			target: String input data.
			keys: List of integer encryption keys.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Encrypted string.
		"""
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
		"""Decrypt the input data using multiple keys.
		
		Args:
			target: String input data.
			keys: List of integer encryption keys.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Decrypted string.
		"""
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
		"""Generate a hashed key based on the seed.
		
		Args:
			seed: String input data.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			Integer key.
		"""
		return self.process_hash(seed, xbase)
	
	def generate_keys(self, seed, count=32, xbase=1):
		"""Generate multiple keys based on the seed.
		
		Args:
			seed: String input data.
			count: Number of keys to generate.
			xbase: Multiplier for the length of the hash.
		
		Returns:
			List of integer keys.
		"""
		keys = []
		for _ in range(count):
			seed = self.generate_key(seed, xbase)
			keys.append(seed)
		return keys
	
	def generate_key_fast(self, seed):
		"""Generate a short key for fast encryption (lower security).
		
		Args:
			seed: String input data.
		
		Returns:
			Integer key.
		"""
		return self.generate_key(seed, xbase=1)
	
	def generate_key_net(self, seed):
		"""Generate a balanced key for speed and strength.
		
		Args:
			seed: String input data.
		
		Returns:
			Integer key.
		"""
		return self.generate_key(seed, xbase=9)
	
	def generate_key_big(self, seed):
		"""Generate a large key for high-security encryption (slower).
		
		Args:
			seed: String input data.
		
		Returns:
			Integer key.
		"""
		return self.generate_key(seed, xbase=40)
	
	def compress(self, target):
		"""Compress the input data using LZMA.
		
		Args:
			target: Bytes input data.
		
		Returns:
			Compressed bytes.
		"""
		return lzma.compress(target)
	
	def decompress(self, target):
		"""Decompress the input data using LZMA.
		
		Args:
			target: Bytes input data.
		
		Returns:
			Decompressed bytes.
		"""
		return lzma.decompress(target)
	
	def lestr(self, target):
		"""Convert input data to a JSON-formatted string (safer alternative to repr).
		
		Args:
			target: Input data (int/float/str/list/dict, etc.).
		
		Returns:
			JSON string.
		"""
		return json.dumps({".": target}, default=repr)
	
	def leval(self, target):
		"""Convert a JSON-formatted string back to its original form (safer alternative to eval).
		
		Args:
			target: JSON string.
		
		Returns:
			Original data type.
		"""
		return json.loads(target)["."]
	
	def encode_direct(self, target):
		"""Encode text to UTF-8, ignoring invalid characters.
		
		Args:
			target: String input.
		
		Returns:
			Encoded bytes.
		"""
		return target.encode("utf-8", errors="ignore")
	
	def decode_direct(self, target):
		"""Decode UTF-8 bytes to text, ignoring invalid characters.
		
		Args:
			target: Bytes input.
		
		Returns:
			Decoded string.
		"""
		return target.decode("utf-8", errors="ignore")
	
	def __seed_combine_sys(self, key1, key2):
		"""Combine two keys by interleaving their characters systematically.
		
		Args:
			key1: First string key.
			key2: Second string key.
		
		Returns:
			Combined string key.
		"""
		newkey = ""
		for h in key1:
			for h2 in key2:
				newkey += h + h2
		return newkey
	
	def seed_combine(self, keys):
		"""Combine multiple seed keys by interleaving permutations.
		
		Args:
			keys: List of string keys.
		
		Returns:
			Combined string key.
		"""
		if len(keys) == 0:
			return ""
		elif len(keys) == 1:
			return keys[0]
		elif len(keys) == 2:
			return self.__seed_combine_sys(keys[0], keys[1])
		else:
			new = self.__seed_combine_sys(keys[0], keys[1])
			for k in keys[2:]:
				new = self.__seed_combine_sys(new, k)
			return new
	
	def lestr2(self, target, n=0):
		"""Convert input data to a special string format.
		
		Args:
			target: Input data (str/int/float/list/dict/set/bool/bytes/None).
			n: Recursion depth (default: 0).
		
		Returns:
			Formatted string.
		"""
		t = str(type(target))
		t = t[t.find("'") + 1: t.rfind("'")]
		if t == "str":
			return "0" + str(target)
		elif t == "int":
			return "1" + str(target.real)
		elif t == "float":
			return "2" + str(target.real)
		elif t == "list":
			if len(target) == 0:
				return "3"
			return "3" + (f"/.ls//..{n}ls/...//..".join([self.lestr2(target, n=n+1) for target in target]))
		elif t == "dict":
			return "4" + (f"/.dct//..{n}dct/...//..".join(
				[self.lestr2(key, n=n+1) + f"/.dctsp//..{n}dct/...//.." + self.lestr2(value, n=n+1) for key, value in target.items()]
			))
		elif t == "set":
			if len(target) == 0:
				return "53"
			return "5" + (self.lestr2(list(target), n=n+1))
		elif t == "bool":
			return "6" if target else "7"
		elif t == "bytes":
			return "8" + str(target)
		else:
			return "9"
	
	def leval2(self, target, n=0):
		"""Convert a specially formatted string back to its original form.
		
		Args:
			target: Formatted string.
			n: Recursion depth (default: 0).
		
		Returns:
			Original data type.
		"""
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
			if len(target) == 0:
				return {}
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
			return target[2:-1].encode("utf-8", errors="ignore")
		elif t == "9":
			return None
	
	def add_mactag(self, text, checktext="/t/"):
		"""Add a Message Authentication Code (MAC) tag to the text.
		
		Args:
			text: Input string.
			checktext: MAC tag string (default: "/t/").
		
		Returns:
			String with MAC tags added.
		"""
		checktext = str(self.process_hash(checktext, xbase=9))
		return checktext + text + checktext
	
	def check_mactag(self, text, checktext="/t/"):
		"""Verify MAC tags in the text.
		
		Args:
			text: Input string with MAC tags.
			checktext: MAC tag string (default: "/t/").
		
		Returns:
			Text without MAC tags if valid, else raises ValueError.
		"""
		checktext = str(self.process_hash(checktext, xbase=9))
		if text.startswith(checktext) and text.endswith(checktext):
			return text[len(checktext):-len(checktext)]
		raise ValueError("Decryption failed: MAC tag not found or invalid.")
	
	def text_to_binary(self, text):
		"""Convert text to binary format.
		
		Args:
			text: Input string.
		
		Returns:
			Binary string.
		"""
		return ' '.join(format(ord(char), '08b') for char in text)
	
	def binary_to_text(self, binary):
		"""Convert binary string to text.
		
		Args:
			binary: Binary string.
		
		Returns:
			Original text.
		"""
		return ''.join(chr(int(char, 2)) for char in binary.split())
	
	def text_to_ascii(self, text):
		"""Convert text to ASCII codes.
		
		Args:
			text: Input string.
		
		Returns:
			ASCII code string.
		"""
		return " ".join(str(ord(char)) for char in text)
	
	def ascii_to_text(self, ascii_values):
		"""Convert ASCII codes to text.
		
		Args:
			ascii_values: ASCII code string.
		
		Returns:
			Original text.
		"""
		return "".join(chr(int(char)) for char in ascii_values.split())
	
	def text_to_hex(self, text):
		"""Convert text to hexadecimal format.
		
		Args:
			text: Input string.
		
		Returns:
			Hexadecimal string.
		"""
		return " ".join(format(ord(c), '02x') for c in text)
	
	def hex_to_text(self, hex):
		"""Convert hexadecimal string to text.
		
		Args:
			hex: Hexadecimal string.
		
		Returns:
			Original text.
		"""
		return "".join(chr(int(h, 16)) for h in hex.split())
	
	def text_to_freq(self, text):
		"""Convert text to frequency data.
		
		Args:
			text: Input string.
		
		Returns:
			List of 0s and 1s representing frequency values.
		"""
		binary = ''.join(format(byte, '08b') for byte in text.encode('utf-8'))
		return [int(bit) for bit in binary]
	
	def freq_to_text(self, freq_list):
		"""Convert frequency data to text.
		
		Args:
			freq_list: List of 0s and 1s.
		
		Returns:
			Original text.
		"""
		binary_str = ''.join('1' if f >= 0.5 else '0' for f in freq_list)
		bytes_list = []
		for i in range(0, len(binary_str), 8):
			byte = binary_str[i:i+8]
			if len(byte) == 8:
				bytes_list.append(int(byte, 2))
		return bytes(bytes_list).decode('utf-8', errors='ignore')
	
	def save(self):
		global version
		"""Generate save data for the encryption engine.
		
		Returns:
			JSON string of engine state.
		"""
		data = {
			"chaos_multi": self.chaos_multi,
			"seperator": self.seperator,
			"fullsbox": self.fullsbox,
			"sbox": self.sbox,
			"coding_sbox": self.coding_sbox,
			"decoding_sbox": self.decoding_sbox,
			"unicode_support": self.unicode_support,
			"coding_for_packet_perlength": self.coding_for_packet_perlength,
			"coding_for_packet": self.coding_for_packet,
			"version": version
		}
		return json.dumps(data)
	
	def load(self, data, ignore_version=False):
		global version
		"""Load saved engine data.
		
		Args:
			data: JSON string of engine state.
		"""
		data = json.loads(data)
		if data["version"] != version and ignore_version == False:
			raise ValueError("The versions do not match, this can cause problems. If you are sure about this process, you can make ignore_version=True.")
		self.chaos_multi = ""
		if data["chaos_multi"] != "":
			self.cached_blake2b = self.__chaos_cached_blake2b
			self.chaos_multi = data["chaos_multi"]
		self.combiner = Combiner()
		self.seperator = data["seperator"]
		self.fullsbox = data["fullsbox"]
		self.sbox = data["sbox"]
		self.coding_sbox = data["coding_sbox"]
		self.decoding_sbox = data["decoding_sbox"]
		self.unicode_support = data["unicode_support"]
		self.coding_for_packet_perlength = data["coding_for_packet_perlength"]
		self.coding_for_packet = data["coding_for_packet"]
		if data["coding_for_packet"]:
			self.encode = self.__encode_packet
			self.decode = self.__decode_packet

class EncryptionStandart_Engine:
	"""A standard encryption engine supporting multiple cryptographic algorithms."""
	
	def __init__(self):
		"""Initialize the standard encryption engine with support for AES, RSA, Blowfish, DES3, ChaCha20, ARC4, and CAST."""
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
		"""Derive a cryptographic key using SHA-256.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
			key_len: Desired key length in bytes.
		
		Returns:
			Derived key as bytes.
		"""
		data = f"{seed}_{salt}".encode("utf-8")
		key = self.sha256(data).digest()
		while len(key) < key_len:
			key += self.sha256(key).digest()
		return key[:key_len]
	
	def generate_key_aes(self, seed, salt=1):
		"""Generate a 32-byte key for AES encryption.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			32-byte key.
		"""
		return self._derive_key(seed, salt, 32)
	
	def encrypt_aes(self, data, key):
		"""Encrypt data using AES in CBC mode with padding.
		
		Args:
			data: Bytes input.
			key: 32-byte AES key.
		
		Returns:
			Ciphertext with IV prepended.
		"""
		cipher = self.AES.new(key, self.AES.MODE_CBC)
		ct_bytes = cipher.encrypt(self.pad(data, self.AES.block_size))
		return cipher.iv + ct_bytes
	
	def decrypt_aes(self, data, key):
		"""Decrypt AES-encrypted data in CBC mode with unpadding.
		
		Args:
			data: Bytes input with IV prepended.
			key: 32-byte AES key.
		
		Returns:
			Decrypted bytes.
		"""
		iv = data[:16]
		ct = data[16:]
		cipher = self.AES.new(key, self.AES.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.AES.block_size)
	
	def generate_key_rsa(self, seed, salt=1):
		"""Generate a 2048-bit RSA key pair deterministically.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			Tuple of private and public key in bytes.
		"""
		import io
		class DeterministicRNG:
			"""Internal class for deterministic random number generation."""
			def __init__(self, seed_bytes):
				self.state = seed_bytes
			def read(self, n):
				"""Read n bytes deterministically using SHA-256.
				
				Args:
					n: Number of bytes.
				
				Returns:
					Bytes output.
				"""
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
		"""Encrypt data using RSA with PKCS1_OAEP padding in chunks.
		
		Args:
			data: Bytes input.
			public_key_bytes: Public RSA key in bytes.
		
		Returns:
			Encrypted bytes.
		"""
		key = self.RSA.import_key(public_key_bytes)
		cipher = self.PKCS1_OAEP.new(key)
		chunk_size = 190
		encrypted = b""
		for i in range(0, len(data), chunk_size):
			encrypted += cipher.encrypt(data[i:i+chunk_size])
		return encrypted
	
	def decrypt_rsa(self, encrypted_data, private_key_bytes):
		"""Decrypt RSA-encrypted data with PKCS1_OAEP padding in chunks.
		
		Args:
			encrypted_data: Bytes input.
			private_key_bytes: Private RSA key in bytes.
		
		Returns:
			Decrypted bytes.
		"""
		key = self.RSA.import_key(private_key_bytes)
		cipher = self.PKCS1_OAEP.new(key)
		chunk_size = 256
		decrypted = b""
		for i in range(0, len(encrypted_data), chunk_size):
			decrypted += cipher.decrypt(encrypted_data[i:i+chunk_size])
		return decrypted
	
	def generate_key_blowfish(self, seed, salt=1):
		"""Generate a 16-byte key for Blowfish encryption.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			16-byte key.
		"""
		return self._derive_key(seed, salt, 16)
	
	def encrypt_blowfish(self, data, key):
		"""Encrypt data using Blowfish in CBC mode with padding.
		
		Args:
			data: Bytes input.
			key: 16-byte Blowfish key.
		
		Returns:
			Ciphertext with IV prepended.
		"""
		cipher = self.Blowfish.new(key, self.Blowfish.MODE_CBC)
		ct = cipher.encrypt(self.pad(data, self.Blowfish.block_size))
		return cipher.iv + ct
	
	def decrypt_blowfish(self, data, key):
		"""Decrypt Blowfish-encrypted data in CBC mode with unpadding.
		
		Args:
			data: Bytes input with IV prepended.
			key: 16-byte Blowfish key.
		
		Returns:
			Decrypted bytes.
		"""
		iv = data[:8]
		ct = data[8:]
		cipher = self.Blowfish.new(key, self.Blowfish.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.Blowfish.block_size)
	
	def generate_key_des3(self, seed, salt=1):
		"""Generate a 24-byte key for Triple DES encryption.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			24-byte key.
		"""
		return self._derive_key(seed, salt, 24)
	
	def encrypt_des3(self, data, key):
		"""Encrypt data using Triple DES in CBC mode with padding.
		
		Args:
			data: Bytes input.
			key: 24-byte DES3 key.
		
		Returns:
			Ciphertext with IV prepended.
		"""
		cipher = self.DES3.new(key, self.DES3.MODE_CBC)
		ct = cipher.encrypt(self.pad(data, self.DES3.block_size))
		return cipher.iv + ct
	
	def decrypt_des3(self, data, key):
		"""Decrypt Triple DES-encrypted data in CBC mode with unpadding.
		
		Args:
			data: Bytes input with IV prepended.
			key: 24-byte DES3 key.
		
		Returns:
			Decrypted bytes.
		"""
		iv = data[:8]
		ct = data[8:]
		cipher = self.DES3.new(key, self.DES3.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.DES3.block_size)
	
	def generate_key_chacha20(self, seed, salt=1):
		"""Generate a 32-byte key for ChaCha20 encryption.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			32-byte key.
		"""
		return self._derive_key(seed, salt, 32)
	
	def encrypt_chacha20(self, data, key):
		"""Encrypt data using ChaCha20 with a nonce.
		
		Args:
			data: Bytes input.
			key: 32-byte ChaCha20 key.
		
		Returns:
			Ciphertext with nonce prepended.
		"""
		cipher = self.ChaCha20.new(key=key)
		return cipher.nonce + cipher.encrypt(data)
	
	def decrypt_chacha20(self, data, key):
		"""Decrypt ChaCha20-encrypted data using the provided nonce.
		
		Args:
			data: Bytes input with nonce prepended.
			key: 32-byte ChaCha20 key.
		
		Returns:
			Decrypted bytes.
		"""
		nonce = data[:8]
		ct = data[8:]
		cipher = self.ChaCha20.new(key=key, nonce=nonce)
		return cipher.decrypt(ct)
	
	def generate_key_arc4(self, seed, salt=1):
		"""Generate a 16-byte key for ARC4 encryption.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			16-byte key.
		"""
		return self._derive_key(seed, salt, 16)
	
	def encrypt_arc4(self, data, key):
		"""Encrypt data using ARC4 stream cipher.
		
		Args:
			data: Bytes input.
			key: 16-byte ARC4 key.
		
		Returns:
			Encrypted bytes.
		"""
		cipher = self.ARC4.new(key)
		return cipher.encrypt(data)
	
	def decrypt_arc4(self, data, key):
		"""Decrypt ARC4-encrypted data using the stream cipher.
		
		Args:
			data: Bytes input.
			key: 16-byte ARC4 key.
		
		Returns:
			Decrypted bytes.
		"""
		cipher = self.ARC4.new(key)
		return cipher.decrypt(data)
	
	def generate_key_cast(self, seed, salt=1):
		"""Generate a 16-byte key for CAST encryption.
		
		Args:
			seed: String input.
			salt: Integer or string salt.
		
		Returns:
			16-byte key.
		"""
		return self._derive_key(seed, salt, 16)
	
	def encrypt_cast(self, data, key):
		"""Encrypt data using CAST in CBC mode with padding.
		
		Args:
			data: Bytes input.
			key: 16-byte CAST key.
		
		Returns:
			Ciphertext with IV prepended.
		"""
		cipher = self.CAST.new(key, self.CAST.MODE_CBC)
		ct = cipher.encrypt(self.pad(data, self.CAST.block_size))
		return cipher.iv + ct
	
	def decrypt_cast(self, data, key):
		"""Decrypt CAST-encrypted data in CBC mode with unpadding.
		
		Args:
			data: Bytes input with IV prepended.
			key: 16-byte CAST key.
		
		Returns:
			Decrypted bytes.
		"""
		iv = data[:8]
		ct = data[8:]
		cipher = self.CAST.new(key, self.CAST.MODE_CBC, iv)
		return self.unpad(cipher.decrypt(ct), self.CAST.block_size)

class LeCatchu_Kid_Engine:
	"""A simplified encryption engine for kids using LeCatchu_Engine."""
	
	def __init__(self):
		"""Initialize the kid-friendly encryption engine with preset parameters."""
		self.LeCatchu_Engine = LeCatchu_Engine(coding_for_packet=True, sbox_randomizer="kid", unicode_support=256)
	
	def encrypt(self, text, key):
		"""Encrypt text with a MAC tag using a generated key.
		
		Args:
			text: String input.
			key: String or integer key.
		
		Returns:
			Encrypted bytes.
		"""
		text = self.LeCatchu_Engine.add_mactag(text)
		key = self.LeCatchu_Engine.generate_key(key, xbase=9)
		return self.LeCatchu_Engine.encode(self.LeCatchu_Engine.encrypt(text, key, xbase=9))
	
	def decrypt(self, text, key):
		"""Decrypt text, verify the MAC tag, and return the original text.
		
		Args:
			text: Encrypted bytes.
			key: String or integer key.
		
		Returns:
			Decrypted string.
		"""
		key = self.LeCatchu_Engine.generate_key(key, xbase=9)
		text = self.LeCatchu_Engine.decrypt(self.LeCatchu_Engine.decode(text), key, xbase=9)
		return self.LeCatchu_Engine.check_mactag(text)

class PassSecurityCheck:
	"""A utility to check the security of passwords and usernames."""
	
	def __init__(self):
		"""Initialize the password security checker with a requests session."""
		import requests as reqs
		self.bot = reqs.Session()
		self.bot.headers = {"User-Agent": "LeCatchu_PasswordChecker/6.0"}
		self.bot.get("https://github.com/")
		self.passlist = []
		self.userlist = []
	
	def load_passlist1(self):
		"""Load a common password list from a GitHub repository."""
		print("Loading passlist1...")
		passwords = self.bot.get("https://github.com/jeanphorn/wordlist/raw/refs/heads/master/passlist.txt").text.split()
		print("Extend...")
		self.passlist.extend(passwords)
	
	def load_passlist2(self):
		"""Load an RDP password list from a GitHub repository."""
		print("Loading passlist2...")
		passwords = self.bot.get("https://github.com/jeanphorn/wordlist/raw/refs/heads/master/rdp_passlist.txt").text.split()
		print("Extend...")
		self.passlist.extend(passwords)
	
	def load_passlist3(self):
		"""Load an SSH password list from a GitHub repository."""
		print("Loading passlist3...")
		passwords = self.bot.get("https://github.com/jeanphorn/wordlist/raw/refs/heads/master/ssh_passwd.txt").text.split()
		print("Extend...")
		self.passlist.extend(passwords)
	
	def load_passlist4(self):
		"""Load a probable password list from a GitHub repository."""
		print("Loading passlist4...")
		passwords = self.bot.get(
			"https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/refs/heads/master/Real-Passwords/Top12Thousand-probable-v2.txt"
		).text.split()
		print("Extend...")
		self.passlist.extend(passwords)
	
	def load_userlist1(self):
		"""Load a common username list from a GitHub repository."""
		print("Loading userlist1...")
		users = self.bot.get("https://github.com/jeanphorn/wordlist/raw/refs/heads/master/usernames.txt").text.split()
		print("Extend...")
		self.userlist.extend(users)
	
	def load_all(self):
		"""Load all password and username lists."""
		self.load_passlist1()
		self.load_passlist2()
		self.load_passlist3()
		self.load_passlist4()
		self.load_userlist1()
		print("Finished loading all.")
	
	def check(self, key):
		"""Check if a key is in the password or username lists.
		
		Args:
			key: String to check.
		
		Returns:
			Dictionary with 'pass' and 'user' boolean values.
		"""
		foundpass = key in self.passlist
		founduser = key in self.userlist
		return {"pass": foundpass, "user": founduser}

class LeCatchu_Database:
	"""A secure database system using LeCatchu_Engine for encrypted storage."""
	
	def __init__(self, glokey, sbox="qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890.,_-+", 
				 sbox_randomizer="LeCatchu Database", coding_for_packet=True, coding_for_packet_perlength=4, 
				 unicode_support=1114112, enginedata=None, engine=None, chaos_seed=None, chaos_coding_unicode_range=1024, data=None):
		"""Initialize the secure database system.
		
		Args:
			glokey: Global key for database encryption.
			sbox: Character string for encoding.
			sbox_randomizer: Seed for shuffling sbox.
			coding_for_packet: Enable compact encoding for data packets.
			coding_for_packet_perlength: Length of packet mode characters.
			unicode_support: Maximum supported Unicode characters.
			enginedata: Saved engine data for faster initialization.
			engine: Existing LeCatchu_Engine instance.
			chaos_seed: Seed for Chaos mode.
			chaos_coding_unicode_range: Maximum Unicode range for Chaos mode sbox.
			data: Pre-existing encrypted database data as bytes.
		"""
		if enginedata is None and engine is None:
			engine = LeCatchu_Engine(
				sbox=sbox, sbox_randomizer=sbox_randomizer, coding_for_packet=coding_for_packet,
				coding_for_packet_perlength=coding_for_packet_perlength, unicode_support=unicode_support,
				chaos_seed=chaos_seed, chaos_coding_unicode_range=chaos_coding_unicode_range
			)
		elif engine is None:
			engine = LeCatchu_Engine(data=enginedata)
		self.engine = engine
		self.data = data
		self.__start(glokey)
	
	def __start(self, glokey):
		"""Initialize the database with an encrypted empty dictionary.
		
		Args:
			glokey: Global key for encryption.
		"""
		if self.data is None:
			glokey = self.engine.generate_key_net(glokey)
			self.data = self.engine.encode(self.engine.encrypt(self.engine.add_mactag(self.engine.lestr2({})), glokey, xbase=9))
			glokey = None
			del glokey
	
	def set(self, glokey, cell, cellkey, value):
		"""Store a value in the database with double encryption.
		
		Args:
			glokey: Global key for encryption.
			cell: Cell identifier.
			cellkey: Cell key for encryption.
			value: Data to store.
		"""
		glokey = self.engine.generate_key_net(glokey)
		cellkey = self.engine.generate_key_net(cellkey)
		data = self.engine.leval2(self.engine.check_mactag(self.engine.decrypt(self.engine.decode(self.data), glokey, xbase=9)))
		cell = self.engine.encrypt(self.engine.encrypt(self.engine.lestr2(cell), glokey, xbase=9), cellkey, xbase=9)
		value = self.engine.encrypt(self.engine.encrypt(self.engine.lestr2(value), glokey, xbase=9), cellkey, xbase=9)
		cellkey = None
		del cellkey
		data[str(cell)] = str(value)
		cell = value = None
		del cell, value
		self.data = self.engine.encode(self.engine.encrypt(self.engine.add_mactag(self.engine.lestr2(data)), glokey, xbase=9))
		glokey = None
		del glokey
	
	def get(self, glokey, cell, cellkey):
		"""Retrieve a value from the database with double decryption.
		
		Args:
			glokey: Global key for decryption.
			cell: Cell identifier.
			cellkey: Cell key for decryption.
		
		Returns:
			Stored value.
		"""
		glokey = self.engine.generate_key_net(glokey)
		cellkey = self.engine.generate_key_net(cellkey)
		data = self.engine.leval2(self.engine.check_mactag(self.engine.decrypt(self.engine.decode(self.data), glokey, xbase=9)))
		cell = self.engine.encrypt(self.engine.encrypt(self.engine.lestr2(cell), glokey, xbase=9), cellkey, xbase=9)
		target = self.engine.leval2(self.engine.decrypt(self.engine.decrypt(data[cell], cellkey, xbase=9), glokey, xbase=9))
		cellkey = data = glokey = cell = None
		del cellkey, data, glokey, cell
		return target
	
	def getall(self, glokey):
		"""Retrieve all data from the database without decrypting cell keys.
		
		Args:
			glokey: Global key for decryption.
		
		Returns:
			Dictionary of encrypted data.
		"""
		glokey = self.engine.generate_key_net(glokey)
		return self.engine.leval2(self.engine.check_mactag(self.engine.decrypt(self.engine.decode(self.data), glokey, xbase=9)))
	
	def getall_auto(self, glokey, cellkey):
		"""Retrieve all data with automatic decryption of cell keys.
		
		Args:
			glokey: Global key for decryption.
			cellkey: Cell key for decryption.
		
		Returns:
			Dictionary of decrypted data.
		"""
		glokey = self.engine.generate_key_net(glokey)
		cellkey = self.engine.generate_key_net(cellkey)
		new = {}
		for key, value in self.engine.leval2(self.engine.check_mactag(self.engine.decrypt(self.engine.decode(self.data), glokey, xbase=9))).items():
			try:
				new[self.engine.leval2(self.engine.decrypt(self.engine.decrypt(key, cellkey, xbase=9), glokey, xbase=9))] = \
					self.engine.leval2(self.engine.decrypt(self.engine.decrypt(value, cellkey, xbase=9), glokey, xbase=9))
			except:
				pass
		return new
	
	def search(self, glokey, cellkey, query):
		"""Search for a query string in decrypted database keys and values.
		
		Args:
			glokey: Global key for decryption.
			cellkey: Cell key for decryption.
			query: String to search.
		
		Returns:
			Dictionary of matching key-value pairs.
		"""
		query = str(query)
		data = self.getall_auto(glokey, cellkey)
		results = {}
		for key, value in data.items():
			if query in str(key) + str(value):
				results[key] = value
		return results
	
	def save(self, file):
		"""Save the encrypted database to a file.
		
		Args:
			file: File path.
		"""
		with open(file, "wb") as f:
			f.write(self.data)
			f.flush()
	
	def load(self, file):
		"""Load an encrypted database from a file.
		
		Args:
			file: File path.
		"""
		with open(file, "rb") as f:
			self.data = f.read()

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
