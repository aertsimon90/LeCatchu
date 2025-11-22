# LeCatchu v8
# LehnCATH4 - Most lightweight and secure model ever

from hashlib import blake2b
from functools import lru_cache
from itertools import count, repeat
import sys, json, os, time, socket

sys.set_int_max_str_digits((2**31)-1)
version = 8

class LeCatchu_Engine: # LeCatchu LehnCATH4 Engine
    def __init__(self, sboxseed="Lehncrypt", sboxseedxbase=9, encoding_type="packet", data="", shufflesbox=False, encoding=False, unicodesupport=1114112, special_exchange=None):
        self.special_exchange = special_exchange
        if len(data) > 0:
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.__org_cached_blake2b = self.cached_blake2b
            self.load(data)
        elif encoding:
            self.sbox = {}
            self.resbox = {}
            import random as temprandom
            temprandom.seed(self.process_hash(sboxseed, sboxseedxbase))
            mxn = 256 if encoding_type == "packet" else 255
            n1list = list(range(mxn)) # List of first base characters of sbox encoded forms
            if shufflesbox:
                temprandom.shuffle(n1list)
            n2list = list(range(mxn)) # List of second base characters of sbox encoded forms
            if shufflesbox:
                temprandom.shuffle(n2list)
            n3list = list(range(mxn)) # List of third base characters of sbox encoded forms
            if shufflesbox:
                temprandom.shuffle(n3list)
            ns = [] # Encoded character list (to be shuffled later)
            unin = 0
            unim = unicodesupport if encoding_type == "packet" else unicodesupport-1
            for n1 in n1list:
                if len(ns) >= unim:
                    break
                for n2 in n2list:
                    if len(ns) >= unim:
                        break
                    for n3 in n3list:
                        if len(ns) >= unim:
                           break
                        n = bytes([n1, n2, n3])
                        ns.append(n)
            if shufflesbox:
                temprandom.shuffle(ns) # shuffle
            for n in ns: # Define sbox characters and their equivalents
                self.sbox[chr(unin)] = n
                self.resbox[n] = chr(unin)
                unin += 1
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            if encoding_type == "seperator":
                self.encode = self.__sep_encode
                self.decode = self.__sep_decode
            self.encoding_type = encoding_type
        else:
            self.encoding_type = encoding_type
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.sbox = {};self.resbox = {}
        self.encoding = encoding
        self.unicodesupport = unicodesupport
        self.shufflesbox = shufflesbox
        self.__org_cached_blake2b = self.cached_blake2b
        if self.special_exchange:
            self.cached_blake2b = self.__special_exchanged_cached_blake2b
    def encode(self, string): # Error-free encoding of string data (all characters supported)
        return b"".join([self.sbox[i] for i in string])
    def __sep_encode(self, string): # Error-free encoding of string data (all characters supported) (with seperator)
        return bytes([255]).join([self.sbox[i] for i in string])
    def decode(self, bytestext): # Decode the byte data (all characters are supported and if an error occurs in the encryption or if the sbox is not suitable, the corresponding states may differ on both sides)
        return "".join([self.resbox[bytestext[i:i+3]] for i in range(0, len(bytestext), 3)])
    def __sep_decode(self, bytestext): # Decode the byte data (all characters are supported and if an error occurs in the encryption or if the sbox is not suitable, the corresponding states may differ on both sides) (with seperator)
        return "".join([self.resbox[i] for i in bytestext.split(bytes([255]))])
    @lru_cache(maxsize=128)
    def cached_blake2b(self, combk):
        return blake2b(combk.encode(errors="ignore"), digest_size=32).hexdigest()
    @lru_cache(maxsize=128)
    def __special_exchanged_cached_blake2b(self, combk):
        return blake2b((combk+self.special_exchange).encode(errors="ignore"), digest_size=32).hexdigest()
    @lru_cache(maxsize=64)
    def process_hash(self, key, xbase=1):
        key=okey=str(key)
        hashs=[]
        for _ in range(xbase):
            key = self.cached_blake2b((key+okey))
            hashs.append(key)
        return int("".join(hashs), 16)
    def hash_stream(self, key, xbase=1, interval=1):
        key=okey=tkey=str(key)
        if interval == 1:
            while True:
                hashs=[]
                for _ in range(xbase):
                    key = self.cached_blake2b((key+okey+tkey))
                    hashs.append(key)
                tkey=str(key)
                yield int("".join(hashs), 16)
        else:
            for i in count():
                if i%interval == 0:
                    hashs=[]
                    for _ in range(xbase):
                        key = self.cached_blake2b((key+okey+tkey))
                        hashs.append(key)
                    tkey=str(key)
                    ekey=int("".join(hashs), 16)
                yield ekey
    def hash_streams(self, keys, xbase=1, interval=1):
        okey = "".join([str(key) for key in keys])
        keygens = [self.hash_stream(key+okey, xbase, interval) for key in keys]+[self.hash_stream(okey, xbase)]
        while True:
            yield sum([next(key) for key in keygens])
    def encrypt(self, bytestarget, key, xbase=1, interval=1):
        keygen = self.hash_stream(key, xbase, interval)
        return bytes([(bytestarget[i]+next(keygen))%256 for i in range(len(bytestarget))])
    def decrypt(self, bytestarget, key, xbase=1, interval=1):
        keygen = self.hash_stream(key, xbase, interval)
        return bytes([(bytestarget[i]-next(keygen))%256 for i in range(len(bytestarget))])
    def encrypt_with_iv(self, bytestarget, key, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1): # recommended
        return self.encrypt(self.addiv(bytestarget, ivlength, ivxbase, ivinterval), key, xbase, interval)
    def decrypt_with_iv(self, bytestarget, key, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1): # recommended
        return self.deliv(self.decrypt(bytestarget, key, xbase, interval), ivlength, ivxbase, ivinterval)
    def encrypts(self, bytestarget, keys, xbase=1, interval=1):
        keygen = self.hash_streams(keys, xbase, interval)
        return bytes([(bytestarget[i]+next(keygen))%256 for i in range(len(bytestarget))])
    def decrypts(self, bytestarget, keys, xbase=1, interval=1):
        keygen = self.hash_streams(keys, xbase, interval)
        return bytes([(bytestarget[i]-next(keygen))%256 for i in range(len(bytestarget))])
    def generate_key(self, seed, xbase=1):
        return self.process_hash(seed, xbase)
    def encode_direct(self, text):
        return bytes([ord(i) for i in text])
    def decode_direct(self, bytestext):
        return "".join([chr(bytestext[i]) for i in range(len(bytestext))])
    def add_tactag(self, bytestext, ext=b"MTG", extxbase=1, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1): # Text Authentication Code (TAC) Before the data is encrypted, a TAC tag is added and after it is decrypted, it is checked to ensure that the encryption has extracted the correct data. Otherwise, if your encryption is done incorrectly, you will only get an empty random data stack.
        ext2 = str(self.process_hash(ext, extxbase)).encode()
        return self.encrypt_with_iv(ext2+bytestext+ext2, ext2, xbase, interval, ivlength, ivxbase, ivinterval)
    def check_tactag(self, bytestext, ext=b"MTG", extxbase=1, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1):
        ext2 = str(self.process_hash(ext, extxbase)).encode()
        bytestext = self.decrypt_with_iv(bytestext, ext2, xbase, interval, ivlength, ivxbase, ivinterval)
        bytestext = self.decode_direct(bytestext)
        ext2 = self.decode_direct(ext2)
        if bytestext.startswith(ext2) and bytestext.endswith(ext2):
            return self.encode_direct(bytestext[len(ext2):][:-len(ext2)])
        else:
            raise ValueError("Check failed: TAC tag not found or invalid.")
    def save(self):
        sbox = {}
        for i1, i2 in self.sbox.items():
            bl = ",".join([str(i2[i]) for i in range(3)]) # listed bytes
            sbox[i1] = bl
        return json.dumps({"sbox": sbox, "encoding_type": self.encoding_type, "special_exchange": self.special_exchange, "version": 8})
    def load(self, data):
        data = json.loads(data)
        if data["version"] == 8:
            self.sbox = {}
            self.resbox = {}
            for i1, bl in data["sbox"].items():
                i2 = bytes([int(i) for i in bl.split(",")])
                self.sbox[i1] = i2
                self.resbox[i2] = i1
            self.encoding_type = data["encoding_type"]
            if data["encoding_type"] == "packet":
                self.encode = self.__org_encode
                self.decode = self.__org_decode
            else:
                self.encode = self.__sep_encode
                self.decode = self.__sep_decode
            self.special_exchange = data["special_exchange"]
            if data["special_exchange"]:
                self.cached_blake2b = self.__special_exchanged_cached_blake2b
            else:
                self.cached_blake2b = self.__org_cached_blake2b
        else:
            raise ValueError("Invalid version.")
    def load_only_encoding(self, data):
        data = json.loads(data)
        if data["version"] == 8:
            self.sbox = {}
            self.resbox = {}
            for i1, bl in data["sbox"].items():
                i2 = bytes([int(i) for i in bl.split(",")])
                self.sbox[i1] = i2
                self.resbox[i2] = i1
            self.encoding_type = data["encoding_type"]
            if data["encoding_type"] == "packet":
                self.encode = self.__org_encode
                self.decode = self.__org_decode
            else:
                self.encode = self.__sep_encode
                self.decode = self.__sep_decode
        else:
            raise ValueError("Invalid version.")
    def addiv(self, data, length=256, xbase=1, interval=1): # IV/nonce (Initialization Vector) Add IV
        key = os.urandom(length)
        return key+self.encrypt(data, key, xbase, interval)
    def deliv(self, data, length=256, xbase=1, interval=1): # Remove IV
        key = data[:length];data = data[length:]
        return self.decrypt(data, key, xbase, interval)
class ParallelStreamCipher: # for IP programming
	def __init__(self, engine=None, key="Lehncrypt", xbase=1, interval=1, iv=True, ivlength=256, ivxbase=1, ivinterval=1):
		if engine == None:
			engine = LeCatchu_Engine(encoding=False)
		self.enkey = engine.hash_stream(key, xbase, interval)
		self.dekey = engine.hash_stream(key, xbase, interval)
		self.iv = iv
		self.engine = engine
		if iv:
			self.ivlength = ivlength
			self.ivxbase = ivxbase
			self.ivenkey = self.engine.hash_stream(key, ivxbase, ivinterval)
			self.ivdekey = self.engine.hash_stream(key, ivxbase, ivinterval)
			self.ivinterval = ivinterval
	def generate_ivkey(self):
		return os.urandom(self.ivlength)
	def ivload(self, key):
		if self.iv:
			if len(key) == self.ivlength:
				self.ivenkey = self.engine.hash_stream(key, self.ivxbase, self.ivinterval)
				self.ivdekey = self.engine.hash_stream(key, self.ivxbase, self.ivinterval)
			else:
				raise ValueError("Invalid IV key.")
	def encrypt(self, bytestarget):
		if self.iv:
			bytestarget = bytes([(bytestarget[i]+next(self.ivenkey))%256 for i in range(len(bytestarget))])
			return bytes([(bytestarget[i]+next(self.enkey))%256 for i in range(len(bytestarget))])
		else:
			return bytes([(bytestarget[i]+next(self.enkey))%256 for i in range(len(bytestarget))])
	def decrypt(self, bytestarget):
		if self.iv:
			bytestarget = bytes([(bytestarget[i]-next(self.ivdekey))%256 for i in range(len(bytestarget))])
			return bytes([(bytestarget[i]-next(self.dekey))%256 for i in range(len(bytestarget))])
		else:
			return bytes([(bytestarget[i]-next(self.dekey))%256 for i in range(len(bytestarget))])
	def send_socket(self, s, content):
		s.sendall(self.encrypt(content))
	def recv_socket(self, s, buffer):
		return self.decrypt(s.recv(buffer))
	def connect_socket(self, s, addr):
		s.connect(addr)
		self.send_socket(s, b"1")
		if self.recv_socket(s, 1) == b"1":
			if self.recv_socket(s, 1) == b"1":
				iv = self.generate_ivkey()
				self.send_socket(s, iv)
				if self.recv_socket(s, 1) == b"1":
					self.ivload(iv)
				else:
					raise ValueError("Invalid IV assignment.")
			self.send_socket(s, b"1")
			if self.recv_socket(s, 1) == b"1":
				return True
			else:
				raise ValueError("Connection error.")
		else:
			raise ValueError("Invalid key or invalid protocol.")
	def accept_socket(self, s, errors=False, retry=True):
		c, addr = s.accept()
		if self.recv_socket(c, 1) == b"1":
			if self.iv:
				self.send_socket(c, b"11")
				iv = self.recv_socket(c, self.ivlength)
				self.send_socket(c, b"1")
				self.ivload(iv)
			else:
				self.send_socket(c, b"10")
			if self.recv_socket(c, 1) == b"1":
				self.send_socket(c, b"1")
				return c, addr
			elif errors:
				raise ValueError("Connection error.")
			elif retry:
				return self.accept_socket(s, errors, retry)
		elif errors:
			raise ValueError("Invalid key or invalid protocol.")
		elif retry:
			return self.accept_socket(s, errors, retry)
