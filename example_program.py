import lzma
import hashlib

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
				if len(newpart)+len(new) >= count:
					break
				for comb2 in target:
					newpart.append(comb1+comb2)
					if len(newpart)+len(new) >= count:
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
		if "str" not in str(type(target)):
			raise ValueError("Encoding input can only be string type object")
		new = []
		for h in target:
			new.append(self.coding_sbox[ord(h)])
		return self.seperator.join(new).encode("utf-8")
	def decode(self, target):
		if "byte" not in str(type(target)):
			raise ValueError("Decoding input can only be byte type object")
		target = target.decode("utf-8")
		new = []
		for h in target.split(self.seperator):
			new.append(chr(self.decoding_sbox[h]))
		return "".join(new)
	def process_hash(self, key, xbase=1): 
		okey = str(key)
		hashs = []
		for _ in range(xbase):
			key = hashlib.sha256(str(key).encode(errors="ignore")).hexdigest()
			hashs.append(key) 
			key = key+okey
		return int("".join(hashs), 16)
	def encrypt(self, target, key, xbase=1):
		new = []
		for h in target:
			new.append(chr((ord(h)+key)%1114112));key = self.process_hash(key, xbase)
		return "".join(new)
	def decrypt(self, target, key, xbase=1):
		new = []
		for h in target:
			new.append(chr((ord(h)-key)%1114112));key = self.process_hash(key, xbase)
		return "".join(new)
	def encrypts(self, target, keys, xbase=1):
		for key in keys:
			target = self.encrypt(target, key, xbase)
		return target
	def decrypts(self, target, keys, xbase=1):
		for key in keys:
			target = self.decrypt(target, key, xbase)
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

import tkinter as tk
from tkinter import ttk

class LeCatchuApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LeCatchu Encryption Engine")
        self.root.geometry("600x500")

        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Target value input
        self.target_label = ttk.Label(self.main_frame, text="Enter your text:")
        self.target_label.grid(row=0, column=0, sticky=tk.W, pady=5)

        self.target_text = tk.Text(self.main_frame, height=5, width=60)
        self.target_text.grid(row=1, column=0, columnspan=2, pady=5)
        self.target_text.insert("1.0", "Target value...")

        # Key input
        self.key_label = ttk.Label(self.main_frame, text="Enter your key:")
        self.key_label.grid(row=2, column=0, sticky=tk.W, pady=5)

        self.key_entry = ttk.Entry(self.main_frame, width=60)
        self.key_entry.grid(row=3, column=0, columnspan=2, pady=5)
        self.key_entry.insert(0, "Your Key...")

        # Buttons frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        self.encrypt_button = ttk.Button(self.button_frame, text="ENCRYPT", command=self.encrypt)
        self.encrypt_button.grid(row=0, column=0, padx=5)

        self.decrypt_button = ttk.Button(self.button_frame, text="DECRYPT", command=self.decrypt)
        self.decrypt_button.grid(row=0, column=1, padx=5)

        # Result area
        self.result_label = ttk.Label(self.main_frame, text="Result:")
        self.result_label.grid(row=5, column=0, sticky=tk.W, pady=5)

        self.result_text = tk.Text(self.main_frame, height=10, width=60)
        self.result_text.grid(row=6, column=0, columnspan=2, pady=5)

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)

    def encrypt(self):
        target_value = self.target_text.get("1.0", tk.END).strip()
        key_entry = self.key_entry.get().strip()

        try:
            # Generate keys
            keys = engine.generate_keys(key_entry, count=64, xbase=16)
            # Encrypt the content
            content = engine.encrypts(target_value, keys, xbase=16)
            # Encode the content
            content = engine.encode(content).decode()
            
            # Clear and update result
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", content)
        except Exception as e:
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", f"Error during encryption: {str(e)}")

    def decrypt(self):
        target_value = self.target_text.get("1.0", tk.END).strip()
        key_entry = self.key_entry.get().strip()

        try:
            # Generate keys
            keys = engine.generate_keys(key_entry, count=64, xbase=16)
            # Decode the content
            target_value = engine.decode(target_value.encode())
            # Decrypt the content
            content = engine.decrypts(target_value, keys, xbase=16)
            
            # Clear and update result
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", content)
        except Exception as e:
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", f"Error during decryption: {str(e)}")

def main():
    root = tk.Tk()
    app = LeCatchuApp(root)
    root.mainloop()

if __name__ == "__main__":
    engine = LeCatchu_Engine()
    main()
