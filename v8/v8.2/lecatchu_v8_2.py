# LeCatchu v8.2
# LehnCATH4 - Most lightweight and secure model ever
from hashlib import blake2b
from functools import lru_cache
from itertools import count, repeat
from collections import Counter
import sys, json, os, time, socket
import math

sys.set_int_max_str_digits((2**31)-1)
version = 8

class LeCatchu_Engine:  # LeCatchu LehnCATH4 Engine
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
            n1list = list(range(mxn))  # List of first base characters of sbox encoded forms
            if shufflesbox:
                temprandom.shuffle(n1list)
            n2list = list(range(mxn))  # List of second base characters of sbox encoded forms
            if shufflesbox:
                temprandom.shuffle(n2list)
            n3list = list(range(mxn))  # List of third base characters of sbox encoded forms
            if shufflesbox:
                temprandom.shuffle(n3list)
            ns = []  # Encoded character list (to be shuffled later)
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
                temprandom.shuffle(ns)  # shuffle
            for n in ns:  # Define sbox characters and their equivalents
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
            self.sbox = {}
            self.resbox = {}
        self.encoding = encoding
        self.unicodesupport = unicodesupport
        self.shufflesbox = shufflesbox
        self.__org_cached_blake2b = self.cached_blake2b
        if self.special_exchange:
            self.cached_blake2b = self.__special_exchanged_cached_blake2b

    def encode(self, string):  # Error-free encoding of string data (all characters supported)
        return b"".join([self.sbox[i] for i in string])

    def __sep_encode(self, string):  # Error-free encoding of string data (all characters supported) (with seperator)
        return bytes([255]).join([self.sbox[i] for i in string])

    def decode(self, bytestext):  # Decode the byte data
        return "".join([self.resbox[bytestext[i:i+3]] for i in range(0, len(bytestext), 3)])

    def __sep_decode(self, bytestext):  # Decode the byte data (with seperator)
        return "".join([self.resbox[i] for i in bytestext.split(bytes([255]))])

    @lru_cache(maxsize=128)
    def cached_blake2b(self, combk):
        return blake2b(combk.encode(errors="ignore"), digest_size=32).hexdigest()

    @lru_cache(maxsize=128)
    def __special_exchanged_cached_blake2b(self, combk):
        return blake2b((combk + self.special_exchange).encode(errors="ignore"), digest_size=32).hexdigest()

    @lru_cache(maxsize=64)
    def process_hash(self, key, xbase=1):
        key = okey = str(key)
        hashs = []
        for _ in range(xbase):
            key = self.cached_blake2b((key + okey))
            hashs.append(key)
        return int("".join(hashs), 16)

    def hash_stream(self, key, xbase=1, interval=1):
        key = okey = tkey = str(key)
        if interval == 1:
            while True:
                hashs = []
                for _ in range(xbase):
                    key = self.cached_blake2b((key + okey + tkey))
                    hashs.append(key)
                tkey = str(key)
                yield int("".join(hashs), 16)
        else:
            for i in count():
                if i % interval == 0:
                    hashs = []
                    for _ in range(xbase):
                        key = self.cached_blake2b((key + okey + tkey))
                        hashs.append(key)
                    tkey = str(key)
                    ekey = int("".join(hashs), 16)
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
        bytestext = self.decode_direct(bytestext)
        ext2 = self.decode_direct(ext2)
        if bytestext.startswith(ext2) and bytestext.endswith(ext2):
            return self.encode_direct(bytestext[len(ext2):][:-len(ext2)])
        else:
            raise ValueError("Check failed: TAC tag not found or invalid.")

    def save(self):
        sbox = {}
        for i1, i2 in self.sbox.items():
            bl = ",".join([str(i2[i]) for i in range(3)])  # listed bytes
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
        engine.encrypt_raw = self.encrypt_raw
        engine.decrypt_raw = self.decrypt_raw
        engine.encrypt_armor = self.encrypt_armor
        engine.decrypt_armor = self.decrypt_armor
        engine.entropy_score = self.entropy_score
        self.engine = engine

    def encrypt_raw(self, data, key, xbase=1):  # ECB Encryption (Single Block)
        key = self.engine.process_hash(key, xbase)
        return bytes([(data[i] + key) % 256 for i in range(len(data))])

    def decrypt_raw(self, data, key, xbase=1):  # ECB Decryption (Single Block)
        key = self.engine.process_hash(key, xbase)
        return bytes([(data[i] - key) % 256 for i in range(len(data))])

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

    def encrypt_hard(self, data, key, xbase=9, interval=1, ivinterval=1, dolist_min=6, dolist_max=12, ivlength_min=128, ivlength_max=256, ivxbase_min=6, ivxbase_max=16, xbase_min=6, xbase_max=16, ext=b"MTG", keys_min=6, keys_max=12, multikeys=True, tactag=True, special_exchange_annex="Lehncrypt", chain=True, chainleft=True, chainright=True, chainxbase_min=6, chainxbase_max=16, chainblocks_min=256, chainblocks_max=1024):
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

    def decrypt_hard(self, data, key, xbase=9, interval=1, ivinterval=1, dolist_min=6, dolist_max=12, ivlength_min=128, ivlength_max=256, ivxbase_min=6, ivxbase_max=16, xbase_min=6, xbase_max=16, ext=b"MTG", keys_min=6, keys_max=12, multikeys=True, tactag=True, special_exchange_annex="Lehncrypt", chain=True, chainleft=True, chainright=True, chainxbase_min=6, chainxbase_max=16, chainblocks_min=256, chainblocks_max=1024):
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
