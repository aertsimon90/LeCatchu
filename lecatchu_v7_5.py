# LeCatchu v7.5
# LehnCATH4 - Most lightweight and secure model ever

from hashlib import blake2b
from functools import lru_cache
import sys, json, os, time

sys.set_int_max_str_digits((2**31)-1)
version = 7

class LeCatchu_Engine: # LeCatchu LehnCATH4 Engine
    def __init__(self, sboxseed="Lehncrypt", sboxseedxbase=9, encoding_type="packet", data="", mostsecurity=False):
        if len(data) != 0:
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.load(data)
        else:
            self.sbox = {}
            self.resbox = {}
            import random as temprandom
            temprandom.seed(self.process_hash(sboxseed, xbase=sboxseedxbase))
            mxn = 256 if encoding_type == "packet" else 255
            n1list = list(range(mxn)) # List of first base characters of sbox encoded forms
            if mostsecurity:
                temprandom.shuffle(n1list)
            n2list = list(range(mxn)) # List of second base characters of sbox encoded forms
            if mostsecurity:
                temprandom.shuffle(n2list)
            n3list = list(range(mxn)) # List of third base characters of sbox encoded forms
            if mostsecurity:
                temprandom.shuffle(n3list)
            ns = [] # Encoded character list (to be shuffled later)
            unin = 0
            unim = 1114112 if encoding_type == "packet" else 1114111
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
            if mostsecurity:
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
    def encode(self, string): # Error-free encoding of string data (all characters supported)
        return b"".join([self.sbox[i] for i in string])
    def __sep_encode(self, string): # Error-free encoding of string data (all characters supported) (with seperator)
        return bytes([255]).join([self.sbox[i] for i in string])
    def decode(self, bytestext): # Decode the byte data (all characters are supported and if an error occurs in the encryption or if the sbox is not suitable, the corresponding states may differ on both sides)
        return "".join([self.resbox[i] for i in [bytestext[i:i+3] for i in range(0, len(bytestext), 3)]])
    def __sep_decode(self, bytestext): # Decode the byte data (all characters are supported and if an error occurs in the encryption or if the sbox is not suitable, the corresponding states may differ on both sides) (with seperator)
        return "".join([self.resbox[i] for i in bytestext.split(bytes([255]))])
    @lru_cache(maxsize=128)
    def cached_blake2b(self, combk):
        return blake2b(combk.encode(errors="ignore"), digest_size=32).hexdigest()
    @lru_cache(maxsize=64)
    def process_hash(self, key, xbase=1):
        key=okey=str(key)
        hashs=[]
        for _ in range(xbase):
            key = self.cached_blake2b((key+okey))
            hashs.append(key)
        return int("".join(hashs), 16)
    def hash_stream(self, key, xbase=1):
        key=okey=tkey=str(key)
        while True:
            hashs=[]
            for _ in range(xbase):
                key = self.cached_blake2b((key+okey+tkey))
                hashs.append(key)
            tkey=str(key)
            yield int("".join(hashs), 16)
    def hash_streams(self, keys, xbase=1):
        okey = "".join([str(key) for key in keys])
        keygens = [self.hash_stream(key+okey, xbase) for key in keys]+[self.hash_stream(okey, xbase)]
        while True:
            yield sum([next(key) for key in keygens])
    def encrypt(self, bytestarget, key, xbase=1):
        keygen = self.hash_stream(key, xbase)
        return bytes([(bytestarget[i]+next(keygen))%256 for i in range(len(bytestarget))])
    def decrypt(self, bytestarget, key, xbase=1):
        keygen = self.hash_stream(key, xbase)
        return bytes([(bytestarget[i]-next(keygen))%256 for i in range(len(bytestarget))])
    def encrypt_with_iv(self, bytestarget, key, xbase=1, ivlength=256, ivxbase=1):
    	return self.encrypt(self.addiv(bytestarget, ivlength, ivxbase), key, xbase=1)
    def decrypt_with_iv(self, bytestarget, key, xbase=1, ivlength=256, ivxbase=1):
    	return self.deliv(self.decrypt(bytestarget, key, xbase=1), ivlength, ivxbase)
    def encrypts(self, bytestarget, keys, xbase=1):
        keygen = self.hash_streams(keys, xbase)
        return bytes([(bytestarget[i]+next(keygen))%256 for i in range(len(bytestarget))])
    def decrypts(self, bytestarget, keys, xbase=1):
        keygen = self.hash_streams(keys, xbase)
        return bytes([(bytestarget[i]-next(keygen))%256 for i in range(len(bytestarget))])
    def generate_key(self, seed, xbase=1):
        return self.process_hash(seed, xbase)
    def encode_direct(self, text):
        return bytes([ord(i) for i in text])
    def decode_direct(self, bytestext):
        return "".join([chr(bytestext[i]) for i in range(len(bytestext))])
    def add_tactag(self, bytestext, ext=b"MTG"): # Text Authentication Code (TAC) Before the data is encrypted, a TAC tag is added and after it is decrypted, it is checked to ensure that the encryption has extracted the correct data. Otherwise, if your encryption is done incorrectly, you will only get an empty random data stack.
        ext = str(self.process_hash(ext)).encode()
        return b"".join([ext, b"MTG1", bytestext, b"1", ext])
    def check_tactag(self, bytestext, ext=b"MTG"):
        ext = str(self.process_hash(ext)).encode()
        text = self.decode_direct(bytestext)
        ext = self.decode_direct(ext)
        if text.startswith(ext+"MTG1") and text.endswith("1"+ext):
            return self.encode_direct(text[4+len(ext):][:-1-len(ext)])
        else:
            raise ValueError("Check failed: TAC tag not found or invalid.")
    def save(self):
    	sbox = {}
    	for i1, i2 in self.sbox.items():
    		bl = ",".join([str(i2[i]) for i in range(3)]) # listed bytes
    		sbox[i1] = bl
    	return json.dumps({"sbox": sbox, "encoding_type": self.encoding_type, "version": 7})
    def load(self, data):
        data = json.loads(data)
        if data["version"] == 7:
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
    def addiv(self, data, length=256, xbase=1): # IV/nonce (Initialization Vector) Add IV
    	key = os.urandom(length)
    	return key+self.encrypt(data, key, xbase=xbase)
    def deliv(self, data, length=256, xbase=1): # Remove IV
    	key = data[:length];data = data[length:]
    	return self.decrypt(data, key, xbase=xbase)
