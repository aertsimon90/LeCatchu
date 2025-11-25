# LeCatchu v0.5
# One of the first attempts where I used my own hashing methods and found encryption errors that occurred as the integer grew continuously.

import lzma

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
        self.coding_sbox = self.combiner.combine(self.sbox, 1114112)  # 0-1114111

    def encode(self, target):
        if not isinstance(target, str):
            raise ValueError("Encoding input can only be string type object")
        new = []
        for h in target:
            new.append(self.coding_sbox[ord(h)])
        return self.seperator.join(new)

    def decode(self, target):
        if not isinstance(target, (bytes, bytearray)):
            raise ValueError("Decoding input can only be byte type object")
        target = target.decode("utf-8")
        new = ""
        for h in target.split(self.seperator):
            new += chr(self.coding_sbox.index(h))
        return new

    def generate_keys(self, seed, count=10):
        key = 0
        for h in str(seed):
            key += ord(h) ** 3.183732828372
            key = key * 2.28274738273

        keys = []
        for _ in range(count):
            key += key * 2.3836273748
            if key % 2 == 0:
                key = -key
            keys.append(key)
            key = key / 2.183727283
        return keys

    def compress(self, target):
        return lzma.compress(target)

    def decompress(self, target):
        return lzma.decompress(target)
