# LeCatchu v9
# LehnCATH4 - Most lightweight and secure model ever
from hashlib import blake2b
from functools import lru_cache
from itertools import count, product
from collections import Counter
import sys, json, os, time
import math, random

sys.set_int_max_str_digits((2**31)-1)
version = 9

class LeCatchu_Engine:  # LeCatchu LehnCATH4 Engine
    def __init__(self, sboxseed="Lehncrypt", sboxseedxbase=1, encoding_type="packet", data="", shufflesbox=False, seperatorprov=True, encoding=False, unicodesupport=1114112, perlength=3, special_exchange=None):
        self.special_exchange = special_exchange
        if len(data) > 0:
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.__org_cached_hash = self.cached_hash
            self.load(data)
        elif encoding:
            self.sbox = {}
            self.resbox = {}
            import random as temprandom
            temprandom.seed(self.process_hash(sboxseed, sboxseedxbase))
            mxn = 256 if encoding_type == "packet" else 255
            if encoding_type == "seperator" and seperatorprov:
                ns = sum([[bytes(combo) for combo in product(range(mxn), repeat=i+1)] for i in range(perlength)], start=[])
            else:
                ns = [bytes(combo) for combo in product(range(mxn), repeat=perlength)]
            if shufflesbox:
                temprandom.shuffle(ns)
            for unin, n in enumerate(ns[:unicodesupport]):  # Define sbox characters and their equivalents
                self.sbox[chr(unin)] = n
                self.resbox[n] = chr(unin)
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            if encoding_type == "seperator":
                self.encode = self.__sep_encode
                self.decode = self.__sep_decode
            self.encoding_type = encoding_type
            self.perlength = perlength
        else:
            self.encoding_type = encoding_type
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.sbox = {}
            self.resbox = {}
        self.encoding = encoding
        self.unicodesupport = unicodesupport
        self.shufflesbox = shufflesbox
        self.__org_cached_hash = self.cached_hash
        if self.special_exchange:
            self.cached_hash = self.__special_exchanged_cached_hash

    def encode(self, string):  # Error-free encoding of string data (all characters supported)
        return b"".join([self.sbox[i] for i in string])

    def __sep_encode(self, string):  # Error-free encoding of string data (all characters supported) (with seperator)
        return bytes([255]).join([self.sbox[i] for i in string])

    def decode(self, bytestext):  # Decode the byte data
        return "".join([self.resbox[bytestext[i:i+self.perlength]] for i in range(0, len(bytestext), self.perlength)])

    def __sep_decode(self, bytestext):  # Decode the byte data (with seperator)
        return "".join([self.resbox[i] for i in bytestext.split(bytes([255]))])

    @lru_cache(maxsize=128)
    def cached_hash(self, combk):
        return blake2b(combk.encode(), digest_size=32).hexdigest()

    @lru_cache(maxsize=128)
    def __special_exchanged_cached_hash(self, combk):
        return blake2b((combk + self.special_exchange).encode(), digest_size=32).hexdigest()

    @lru_cache(maxsize=64)
    def process_hash(self, key, xbase=1):
        key = okey = str(key)
        hashs = [key:=self.cached_hash((key + okey)) for _ in range(xbase)]
        return int("".join(hashs), 16)

    def hash_stream(self, key, xbase=1, interval=1):
        key = okey = tkey = str(key)
        if interval == 1:
            while True:
                tkey = str(key)
                yield int("".join([key:=self.cached_hash((key + okey + tkey)) for _ in range(xbase)]), 16)
        else:
            for i in count():
                if i % interval == 0:
                    tkey = str(key)
                    ekey = int("".join([key:=self.cached_hash((key + okey + tkey)) for _ in range(xbase)]), 16)
                yield ekey

    def hash_streams(self, keys, xbase=1, interval=1):
        okey = "".join([str(key) for key in keys])
        keygens = [self.hash_stream(str(key) + okey, xbase, interval) for key in keys] + [self.hash_stream(okey, xbase)]
        while True:
            yield sum([next(key) for key in keygens])

    def encrypt(self, bytestarget, key, xbase=1, interval=1):
        keygen = self.hash_stream(key, xbase, interval)
        return bytes([(bytestarget[i] + next(keygen)) % 256 for i in range(len(bytestarget))])

    def decrypt(self, bytestarget, key, xbase=1, interval=1):
        keygen = self.hash_stream(key, xbase, interval)
        return bytes([(bytestarget[i] - next(keygen)) % 256 for i in range(len(bytestarget))])

    def encrypt_with_iv(self, bytestarget, key, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1):  # recommended
        return self.encrypt(self.addiv(bytestarget, ivlength, ivxbase, ivinterval), key, xbase, interval)

    def decrypt_with_iv(self, bytestarget, key, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1):  # recommended
        return self.deliv(self.decrypt(bytestarget, key, xbase, interval), ivlength, ivxbase, ivinterval)

    def encrypts(self, bytestarget, keys, xbase=1, interval=1):
        keygen = self.hash_streams(keys, xbase, interval)
        return bytes([(bytestarget[i] + next(keygen)) % 256 for i in range(len(bytestarget))])

    def decrypts(self, bytestarget, keys, xbase=1, interval=1):
        keygen = self.hash_streams(keys, xbase, interval)
        return bytes([(bytestarget[i] - next(keygen)) % 256 for i in range(len(bytestarget))])

    def encode_direct(self, text):
        return bytes([ord(i) for i in text])

    def decode_direct(self, bytestext):
        return "".join([chr(bytestext[i]) for i in range(len(bytestext))])

    def add_tactag(self, bytestext, ext=b"MTG", extxbase=1, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1):
        ext2 = str(self.process_hash(ext, extxbase)).encode()
        return self.encrypt_with_iv(ext2 + bytestext + ext2, ext2, xbase, interval, ivlength, ivxbase, ivinterval)

    def check_tactag(self, bytestext, ext=b"MTG", extxbase=1, xbase=1, interval=1, ivlength=256, ivxbase=1, ivinterval=1):
        ext2 = str(self.process_hash(ext, extxbase)).encode()
        bytestext = self.decrypt_with_iv(bytestext, ext2, xbase, interval, ivlength, ivxbase, ivinterval)
        if bytestext[:len(ext2)] == ext2 and bytestext[-len(ext2):] == ext2:
            return bytestext[len(ext2):][:-len(ext2)]
        else:
            raise ValueError("Check failed: TAC tag not found or invalid.")

    def save(self):
        sbox = {}
        for i1, i2 in self.sbox.items():
            bl = ",".join([str(i2[i]) for i in range(3)])  # listed bytes
            sbox[i1] = bl
        return json.dumps({"sbox": sbox, "encoding_type": self.encoding_type, "special_exchange": self.special_exchange, "perlength": self.perlength, "version": 9})

    def load(self, data):
        data = json.loads(data)
        if data["version"] == 9:
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
            self.perlength = data["perlength"]
            if data["special_exchange"]:
                self.cached_hash = self.__special_exchanged_cached_hash
            else:
                self.cached_hash = self.__org_cached_hash
        else:
            raise ValueError("Invalid version.")

    def load_only_encoding(self, data):
        data = json.loads(data)
        if data["version"] == 9:
            self.sbox = {}
            self.resbox = {}
            for i1, bl in data["sbox"].items():
                i2 = bytes([int(i) for i in bl.split(",")])
                self.sbox[i1] = i2
                self.resbox[i2] = i1
            self.encoding_type = data["encoding_type"]
            self.perlength = data["perlength"]
            if data["encoding_type"] == "packet":
                self.encode = self.__org_encode
                self.decode = self.__org_decode
            else:
                self.encode = self.__sep_encode
                self.decode = self.__sep_decode
        else:
            raise ValueError("Invalid version.")

    def addiv(self, data, length=256, xbase=1, interval=1):  # IV/nonce (Initialization Vector) Add IV
        key = os.urandom(length)
        return key + self.encrypt(data, key, xbase, interval)

    def deliv(self, data, length=256, xbase=1, interval=1):  # Remove IV
        key = data[:length]
        data = data[length:]
        return self.decrypt(data, key, xbase, interval)

# Extra Functions:

class LeCatchu_Extra:  # Additional modules (Optional)
    def __init__(self, engine):
        engine.__chain_back_stream = self.__chain_back_stream
        engine.encrypt_chain = self.encrypt_chain
        engine.decrypt_chain = self.decrypt_chain
        engine.encrypt_hard = self.encrypt_hard
        engine.decrypt_hard = self.decrypt_hard
        engine.encrypt_sde = self.encrypt_sde
        engine.decrypt_sde = self.decrypt_sde
        engine.encrypt_raw = self.encrypt_raw
        engine.decrypt_raw = self.decrypt_raw
        engine.encrypt_armor = self.encrypt_armor
        engine.decrypt_armor = self.decrypt_armor
        engine.entropy_score = self.entropy_score
        engine.process_hashard = self.process_hashard
        self.engine = engine

    def encrypt_raw(self, data, key, xbase=1):  # ECB Encryption (Single Block)
        key = self.engine.process_hash(key, xbase)
        return bytes([(data[i] + key) % 256 for i in range(len(data))])

    def decrypt_raw(self, data, key, xbase=1):  # ECB Decryption (Single Block)
        key = self.engine.process_hash(key, xbase)
        return bytes([(data[i] - key) % 256 for i in range(len(data))])
    
    def encrypt_sde(self, data, key, xbase=1, interval=1, slowlevel=2, bytesrange=256, tag=b"SDETAG"): # Slow Decryption (SlowDE)
        sdekey = "".join(chr(int(random.random()*bytesrange)) for _ in range(slowlevel))
        return self.engine.encrypts(tag+data, [sdekey, key], xbase=xbase, interval=interval)
    
    def decrypt_sde(self, data, key, xbase=1, interval=1, slowlevel=2, bytesrange=256, tag=b"SDETAG"): # Slow Decryption (SlowDE)
        for combo in product(range(bytesrange), repeat=slowlevel):
            sdekey = "".join([chr(h) for h in combo])
            if self.engine.decrypts(data[:len(tag)], [sdekey, key], xbase=xbase, interval=interval) == tag:
                return self.engine.decrypts(data, [sdekey, key], xbase=xbase, interval=interval)[len(tag):]
        raise ValueError("Invalid Key.")

    def __chain_back_stream(self, data, xbase=1):
        yield 0
        for i in range(len(data)):
            yield self.engine.process_hash(bytes(data[:i+1]), xbase)

    def encrypt_chain(self, maindata, key, xbase=1, chainxbase=1, interval=1, blocks=512):  # CBC Encryption (Chain)
        keygen = self.engine.hash_stream(key, xbase, interval)
        result = []
        for data in [maindata[i:i+blocks] for i in range(0, len(maindata), blocks)]:
            backgen = self.__chain_back_stream(data, chainxbase)
            result += [(data[i] + next(keygen) + next(backgen)) % 256 for i in range(len(data))]
        return bytes(result)

    def decrypt_chain(self, maindata, key, xbase=1, chainxbase=1, interval=1, blocks=512):  # CBC Decryption (Chain)
        keygen = self.engine.hash_stream(key, xbase, interval)
        results = []
        for data in [maindata[i:i+blocks] for i in range(0, len(maindata), blocks)]:
            last = 0
            result = []
            for i in range(len(data)):
                result += [(data[i] - next(keygen) - last) % 256]
                last = self.engine.process_hash(bytes(result[:i+1]), chainxbase)
            results += result
        return bytes(results)

    def encrypt_armor(self, data, key, xbase=1, interval=1, ivinterval=1, ivlength=256, ivxbase=1, ext=b"MTG", extxbase=1, chainleft=True, chainright=True, chainxbase=1, chainblocks=512): # LCA (LeCatchu Authenticated Armor) Encryption
        key = self.engine.hash_stream(key, xbase, interval)
        data = self.engine.add_tactag(data, ext=ext, extxbase=extxbase, ivinterval=ivinterval, ivxbase=ivxbase, ivlength=ivlength, xbase=xbase, interval=interval)
        if chainleft:
            data = self.engine.encrypt_chain(data, next(key), xbase=xbase, chainxbase=chainxbase, blocks=chainblocks, interval=interval)
        if chainright:
            data = self.engine.encrypt_chain(data[::-1], next(key), xbase=xbase, chainxbase=chainxbase, blocks=chainblocks, interval=interval)[::-1]
        data = self.engine.encrypt_with_iv(data, next(key), xbase=xbase, interval=interval, ivinterval=ivinterval, ivxbase=ivxbase)
        return data

    def decrypt_armor(self, data, key, xbase=1, interval=1, ivinterval=1, ivlength=256, ivxbase=1, ext=b"MTG", extxbase=1, chainleft=True, chainright=True, chainxbase=1, chainblocks=512): # LCA (LeCatchu Authenticated Armor) Decryption
        key = self.engine.hash_stream(key, xbase, interval)
        if chainleft:
            left = next(key)
        if chainright:
            right = next(key)
        iv = next(key)
        data = self.engine.decrypt_with_iv(data, iv, xbase=xbase, interval=interval, ivinterval=ivinterval, ivxbase=ivxbase)
        if chainright:
            data = self.engine.decrypt_chain(data[::-1], right, xbase=xbase, chainxbase=chainxbase, blocks=chainblocks, interval=interval)[::-1]
        if chainleft:
            data = self.engine.decrypt_chain(data, left, xbase=xbase, chainxbase=chainxbase, blocks=chainblocks, interval=interval)
        return self.engine.check_tactag(data, ext=ext, extxbase=extxbase, ivinterval=ivinterval, ivxbase=ivxbase, ivlength=ivlength, xbase=xbase, interval=interval)

    def encrypt_hard(self, data, key, xbase=9, interval=1, ivinterval=1, dolist_min=6, dolist_max=12, ivlength_min=128, ivlength_max=256, ivxbase_min=6, ivxbase_max=16, xbase_min=6, xbase_max=16, ext=b"MTG", keys_min=6, keys_max=12, multikeys=True, tactag=True, special_exchange_annex="Lehncrypt", chain=True, chainleft=True, chainright=True, chainxbase_min=6, chainxbase_max=16, chainblocks_min=256, chainblocks_max=1024, sde=True, sde_slowlevel=1, sde_bytesrange=256):
        key = self.engine.hash_stream(special_exchange_annex + str(key), xbase, interval)
        if tactag:
            data = self.engine.add_tactag(data, ext=ext,
                extxbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                xbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                interval=interval,
                ivlength=((next(key)) % (ivlength_max - ivlength_min)) + ivlength_min,
                ivxbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                ivinterval=ivinterval)
        if multikeys:
            data = self.engine.encrypts(data, [next(key) for _ in range(next(key) % (keys_max - keys_min) + keys_min)],
                xbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min, interval=interval)
        if sde:
            data = self.encrypt_sde(data, next(key), xbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min, interval=interval, slowlevel=sde_slowlevel, bytesrange=sde_bytesrange)
        if chain:
            if chainleft:
                data = self.encrypt_chain(data, next(key),
                    xbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                    chainxbase=((next(key)) % (chainxbase_max - chainxbase_min)) + chainxbase_min,
                    blocks=((next(key)) % (chainblocks_max - chainblocks_min)) + chainblocks_min)
            if chainright:
                data = self.encrypt_chain(data[::-1], next(key),
                    xbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                    chainxbase=((next(key)) % (chainxbase_max - chainxbase_min)) + chainxbase_min,
                    blocks=((next(key)) % (chainblocks_max - chainblocks_min)) + chainblocks_min)[::-1]
        for _ in range((next(key) % (dolist_max - dolist_min)) + dolist_min):
            data = self.engine.encrypt_with_iv(data,
                next(key) + xbase + interval + dolist_min + dolist_max + ivlength_min + ivlength_max + ivxbase_min + ivxbase_max + xbase_min + xbase_max,
                xbase=((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                ivxbase=((next(key)) % (ivxbase_max - ivxbase_min)) + ivxbase_min,
                ivlength=((next(key)) % (ivlength_max - ivlength_min)) + ivlength_min,
                interval=interval, ivinterval=ivinterval)
        return data

    def decrypt_hard(self, data, key, xbase=9, interval=1, ivinterval=1, dolist_min=6, dolist_max=12, ivlength_min=128, ivlength_max=256, ivxbase_min=6, ivxbase_max=16, xbase_min=6, xbase_max=16, ext=b"MTG", keys_min=6, keys_max=12, multikeys=True, tactag=True, special_exchange_annex="Lehncrypt", chain=True, chainleft=True, chainright=True, chainxbase_min=6, chainxbase_max=16, chainblocks_min=256, chainblocks_max=1024, sde=True, sde_slowlevel=1, sde_bytesrange=256):
        key = self.engine.hash_stream(special_exchange_annex + str(key), xbase, interval)
        if tactag:
            tacset = [
                ((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                ((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                ((next(key)) % (ivlength_max - ivlength_min)) + ivlength_min,
                ((next(key)) % (xbase_max - xbase_min)) + xbase_min
            ]
        if multikeys:
            multikeyset = [
                [next(key) for _ in range(next(key) % (keys_max - keys_min) + keys_min)],
                ((next(key)) % (xbase_max - xbase_min)) + xbase_min
            ]
        if sde:
            sdekey = next(key)
            sdexbase = ((next(key)) % (xbase_max - xbase_min)) + xbase_min
        if chain:
            if chainleft:
                chainleftset = (
                    next(key),
                    ((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                    ((next(key)) % (chainxbase_max - chainxbase_min)) + chainxbase_min,
                    ((next(key)) % (chainblocks_max - chainblocks_min)) + chainblocks_min
                )
            if chainright:
                chainrightset = (
                    next(key),
                    ((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                    ((next(key)) % (chainxbase_max - chainxbase_min)) + chainxbase_min,
                    ((next(key)) % (chainblocks_max - chainblocks_min)) + chainblocks_min
                )
        for h in [(next(key) + xbase + interval + dolist_min + dolist_max + ivlength_min + ivlength_max + ivxbase_min + ivxbase_max + xbase_min + xbase_max,
                   ((next(key)) % (xbase_max - xbase_min)) + xbase_min,
                   ((next(key)) % (ivxbase_max - ivxbase_min)) + ivxbase_min,
                   ((next(key)) % (ivlength_max - ivlength_min)) + ivlength_min) for _ in range((next(key) % (dolist_max - dolist_min)) + dolist_min)][::-1]:
            data = self.engine.decrypt_with_iv(data, h[0], xbase=h[1], ivxbase=h[2], ivlength=h[3], interval=interval, ivinterval=ivinterval)
        if chain:
            if chainright:
                data = self.decrypt_chain(data[::-1], chainrightset[0], xbase=chainrightset[1], chainxbase=chainrightset[2], blocks=chainrightset[3])[::-1]
            if chainleft:
                data = self.decrypt_chain(data, chainleftset[0], xbase=chainleftset[1], chainxbase=chainleftset[2], blocks=chainleftset[3])
        if sde:
            data = self.decrypt_sde(data, sdekey, xbase=sdexbase, interval=interval, slowlevel=sde_slowlevel, bytesrange=sde_bytesrange)
        if multikeys:
            data = self.engine.decrypts(data, multikeyset[0], xbase=multikeyset[1], interval=interval)
        if tactag:
            return self.engine.check_tactag(data, extxbase=tacset[0], xbase=tacset[1], ivlength=tacset[2], ivxbase=tacset[3], ext=ext, ivinterval=ivinterval, interval=interval)
        else:
            return data

    def entropy_score(self, data):  # Entropy score calculate function
        if not data:
            return 0
        length = len(data)
        counts = Counter(data)
        H = 0
        for count in counts.values():
            p = count / length
            H -= p * math.log2(p)
        return H / 8
    
    def process_hashard(self, target, xbase=9, lengthinc=True, lengthforce=0.5): # HashHard - Strong Hash
        c = self.engine.process_hash(str(target), xbase=xbase)
        target2 = sum([c:=c+self.engine.process_hash(h, xbase=xbase) for h in target])
        if lengthinc:
            target3 = "".join([str((c:=c+self.engine.process_hash(c, xbase=xbase))%256) for _ in range(((c)%(int(len(target)*lengthforce)+1))+1)])
            return int(str(target2)+target3)
        else:
            return target2

class ParallelStreamCipher:  # Parallel and two-side encryption
    def __init__(self, engine=None, key="Lehncrypt", xbase=1, interval=1, iv=True, ivlength=256, ivxbase=1, ivinterval=1):
        if engine is None:
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
            bytestarget = bytes([(bytestarget[i] + next(self.ivenkey)) % 256 for i in range(len(bytestarget))])
        return bytes([(bytestarget[i] + next(self.enkey)) % 256 for i in range(len(bytestarget))])

    def decrypt(self, bytestarget):
        if self.iv:
            bytestarget = bytes([(bytestarget[i] - next(self.ivdekey)) % 256 for i in range(len(bytestarget))])
        return bytes([(bytestarget[i] - next(self.dekey)) % 256 for i in range(len(bytestarget))])

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

class LeCustomHash: # Full Independence - LeCatchu Special Encryption Algorithm
	def __init__(self, engine, perpart=128, mul=1, mulkey="Lehncrypt", inthashsum=True): # Experimental custom hash
		if inthashsum:
			self.__inthash = self.__sum_inthash # more fast but less security
		else:
			self.__inthash = self.__mul_inthash # more slow but more security
		self.mul = mul
		self.perpart = perpart
		self.mulkey = mulkey
		self.engine = engine
		self.engine.mul = mul
		self.engine.perpart = perpart
		self.engine.mulkey = mulkey
		self.engine.__inthash = self.__inthash
		self.engine.__inthashparts = self.__inthashparts
		if self.engine.special_exchange:
			self.engine.cached_hash = self.special_exchanged_cached_hash
		else:
			self.engine.cached_hash = self.cached_hash
	def __sum_inthash(self, bytestarget): # 50 times faster than multiplication
		c=1;m=self.mul;c = sum([c:=c+((h+1)**m) for h in bytestarget])
		return c
	def __mul_inthash(self, bytestarget):
		c=1;m=self.mul;c = sum([c:=c*((h+1)**m) for h in bytestarget])
		return c
	def __inthashparts(self, bytestarget):
		c2 = len(bytestarget);hp=self.perpart;h=self.__inthash
		for i in range(int(c2/self.perpart)+1):
			c2 = int(h(bytestarget[i*hp:(i+1)*hp])+c2)
		return c2
	@lru_cache(maxsize=128)
	def cached_hash(self, combk, digest_size=32):
		combk=self.__inthashparts((combk+self.engine.mulkey).encode(errors="ignore"))
		return bytes([(combk:=combk+self.__inthashparts(bytes([ord(h) for h in str(combk)])))%256 for _ in range(digest_size)]).hex()
	@lru_cache(maxsize=128)
	def special_exchanged_cached_hash(self, combk, digest_size=32):
		combk=self.__inthashparts((combk+self.engine.mulkey+self.engine.special_exchange).encode(errors="ignore"))
		return bytes([(combk:=combk+self.__inthashparts(bytes([ord(h) for h in str(combk)])))%256 for _ in range(digest_size)]).hex()

class LeRandom: # Deterministic Random Number Generator (DRNG).
	def __init__(self, engine, xbase=1, interval=1, extra_randomize=True):
		self.engine = engine
		self.keygen = self.engine.hash_stream(time.time(), xbase=xbase, interval=interval)
		self.randomk = time.time()
		self.seedused = False
		self.xbase = xbase
		self.interval = interval
		self.extra_randomize = extra_randomize
		self.randomb = 16
		if extra_randomize:
			self.random = self.__extra_random
	def random(self):
		return float("0."+("".join([str(next(self.keygen)%10) for _ in range(self.randomb)])))
	def __extra_random(self):
		if self.seedused:
			return float("0."+("".join([str((next(self.keygen)+self.engine.process_hash(self.randomk, xbase=self.xbase))%10) for _ in range(self.randomb)])))
		else:
			return float("0."+("".join([str((next(self.keygen)+self.engine.process_hash(time.time(), xbase=self.xbase))%10) for _ in range(self.randomb)])))
	def seed(self, seed=None):
		if not seed:
			self.keygen = self.engine.hash_stream(time.time(), xbase=self.xbase, interval=self.interval)
			self.randomk = time.time()
			self.seedused = False
		else:
			self.keygen = self.engine.hash_stream(seed, xbase=self.xbase, interval=self.interval)
			self.randomk = seed
			self.seedused = True
	def _urandom(self, size=1):
		return bytes([int(self.random()*256) for _ in range(size)])
	def randint(self, a, b):
		if a > b:
			a, b = b, a
		range_size = b - a + 1
		r = self.random()
		return a + int(r * range_size)
	def uniform(self, a, b):
		if a > b:
			a, b = b, a
		r = self.random()
		return a + (r * (b - a))
	def shuffle(self, target):
		n = len(target)
		for i in range(n - 1, 0, -1):
			j = self.randint(0, i) 
			target[i], target[j] = target[j], target[i]
	def choice(self, seq):
		if not seq:
			raise IndexError('Cannot choose from an empty sequence')
		return seq[int(self.random() * len(seq))]
	def choices(self, seq, k=1):
		if not seq:
			raise IndexError('Cannot choose from an empty sequence')
		return [self.choice(seq) for _ in range(k)]
	def sample(self, population, k):
		if not 0 <= k <= n:
			raise ValueError("Sample size k must be non-negative and less than or equal to population size.")
		n = len(population)
		result = list(population) 
		for i in range(k):
			j = self.randint(i, n - 1)
			result[i], result[j] = result[j], result[i]
		return result[:k]
	def gauss(self, mu, sigma):
		u1 = self.random()
		u2 = self.random()
		z0 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
		return z0 * sigma + mu
	def randrange(self, start, stop=None, step=1):
		if stop is None:
			stop = start
			start = 0
		if step == 0:
			raise ValueError("step cannot be zero")
		if (step > 0 and start >= stop) or (step < 0 and start <= stop):
			raise ValueError("empty range for randrange()")
		num_steps = (stop - start) // step
		rand_step_index = self.randint(0, num_steps - 1)
		return start + rand_step_index * step
	def getrandbits(self, k):
		if k <= 0:
			return 0
		num_bytes = (k + 7) // 8
		rand_bytes = self._urandom(num_bytes)
		result = int.from_bytes(rand_bytes, byteorder='big')
		return result & ((1 << k) - 1)
