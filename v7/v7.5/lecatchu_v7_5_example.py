# LeCatchu v7.5
# LehnCATH4 - Most lightweight and secure model ever

from hashlib import blake2b
from functools import lru_cache
import sys, json, os, time

sys.set_int_max_str_digits((2**31)-1)
version = 7

class LeCatchu_Engine: # LeCatchu LehnCATH4 Engine
    def __init__(self, sboxseed="Lehncrypt", sboxseedxbase=9, encoding_type="packet", data="", mostsecurity=False, encoding=True, unicodesupport=1114112):
        if len(data) != 0:
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.load(data)
        elif encoding:
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
        else:
            self.encoding_type = encoding_type
            self.__org_encode = self.encode
            self.__org_decode = self.decode
            self.sbox = {};self.resbox = {}
        self.encoding = encoding
        self.unicodesupport = unicodesupport
        self.mostsecurity = mostsecurity
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
    	return self.encrypt(self.addiv(bytestarget, ivlength, ivxbase), key, xbase=xbase)
    def decrypt_with_iv(self, bytestarget, key, xbase=1, ivlength=256, ivxbase=1):
    	return self.deliv(self.decrypt(bytestarget, key, xbase=xbase), ivlength, ivxbase)
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

import tkinter as tk
from tkinter import ttk, messagebox
import base64
from ttkthemes import ThemedTk

class LeCatchuGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LeCatchu v7.5 Encryption Tool")
        
        # Configure theme
        self.root.set_theme("arc")  # Modern, flat theme
        self.style = ttk.Style()
        self.base_font_size = 10
        self.style.configure("TLabel", font=("Segoe UI", self.base_font_size))
        self.style.configure("TButton", font=("Segoe UI", self.base_font_size), padding=6)
        self.style.configure("TFrame", background="#ffffff")
        self.style.configure("Header.TLabel", font=("Segoe UI", self.base_font_size + 4, "bold"))
        
        # Initialize LeCatchu Engine
        self.engine = None
        
        # Create widgets
        self.create_widgets()
        
        # Set initial window size based on content
        self.root.update_idletasks()  # Update layout to calculate sizes
        min_width = max(600, self.root.winfo_reqwidth() + 20)
        min_height = max(500, self.root.winfo_reqheight() + 20)
        self.root.geometry(f"{min_width}x{min_height}")
        self.root.minsize(500, 400)  # Minimum window size
        
        # Bind resize event
        self.root.bind("<Configure>", self.on_resize)
    
    def create_widgets(self):
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="15")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        self.main_frame.rowconfigure(2, weight=1)
        self.main_frame.rowconfigure(3, weight=1)
        self.main_frame.rowconfigure(4, weight=2)
        
        # Header
        ttk.Label(self.main_frame, text="LeCatchu v7.5 - Encryption Tool", style="Header.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        # Input Section
        input_frame = ttk.LabelFrame(self.main_frame, text="Input", padding="10")
        input_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        input_frame.columnconfigure(0, weight=1)
        
        # Input Text
        ttk.Label(input_frame, text="Text:").grid(row=0, column=0, sticky="w")
        self.input_text = tk.Text(input_frame, height=4, font=("Segoe UI", self.base_font_size))
        self.input_text.grid(row=1, column=0, sticky="ew", pady=5)
        self.input_text.bind("<Enter>", lambda e: self.show_tooltip("Enter text to encode/encrypt or Base64-encoded text to decode/decrypt"))
        self.input_text.bind("<Leave>", lambda e: self.hide_tooltip())
        
        # Key
        ttk.Label(input_frame, text="Encryption Key:").grid(row=2, column=0, sticky="w")
        self.key_entry = ttk.Entry(input_frame, font=("Segoe UI", self.base_font_size))
        self.key_entry.grid(row=3, column=0, sticky="ew", pady=5)
        self.key_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter encryption/decryption key"))
        self.key_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        
        # Configuration Section
        config_frame = ttk.LabelFrame(self.main_frame, text="Configuration", padding="10")
        config_frame.grid(row=2, column=0, sticky="nsew", pady=5)
        config_frame.columnconfigure(1, weight=1)
        
        # SBox Seed
        ttk.Label(config_frame, text="SBox Seed:").grid(row=0, column=0, sticky="w")
        self.sboxseed_entry = ttk.Entry(config_frame, width=20, font=("Segoe UI", self.base_font_size))
        self.sboxseed_entry.insert(0, "myseed")
        self.sboxseed_entry.grid(row=0, column=1, sticky="w", pady=5)
        self.sboxseed_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter seed for s-box generation (non-empty string)"))
        self.sboxseed_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        
        # Encoding Type
        ttk.Label(config_frame, text="Encoding Type:").grid(row=1, column=0, sticky="w")
        self.encoding_type = tk.StringVar(value="packet")
        ttk.Radiobutton(config_frame, text="Packet", variable=self.encoding_type, value="packet").grid(row=1, column=1, sticky="w")
        ttk.Radiobutton(config_frame, text="Separator", variable=self.encoding_type, value="separator").grid(row=1, column=2, sticky="w")
        
        # Most Security
        self.most_security = tk.BooleanVar(value=False)
        ttk.Checkbutton(config_frame, text="Most Security", variable=self.most_security).grid(row=2, column=0, columnspan=3, sticky="w", pady=5)
        
        # IV Length
        ttk.Label(config_frame, text="IV Length:").grid(row=3, column=0, sticky="w")
        self.iv_length_entry = ttk.Entry(config_frame, width=10, font=("Segoe UI", self.base_font_size))
        self.iv_length_entry.insert(0, "256")
        self.iv_length_entry.grid(row=3, column=1, sticky="w", pady=5)
        self.iv_length_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter IV length (positive integer, default 256)"))
        self.iv_length_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        
        # XBase
        ttk.Label(config_frame, text="XBase:").grid(row=4, column=0, sticky="w")
        self.xbase_entry = ttk.Entry(config_frame, width=10, font=("Segoe UI", self.base_font_size))
        self.xbase_entry.insert(0, "1")
        self.xbase_entry.grid(row=4, column=1, sticky="w", pady=5)
        self.xbase_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter xbase for hash iterations (positive integer, default 1)"))
        self.xbase_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        
        # Action Buttons
        button_frame = ttk.Frame(self.main_frame, padding="10")
        button_frame.grid(row=3, column=0, sticky="nsew", pady=10)
        button_frame.columnconfigure((0, 1, 2, 3, 4), weight=1)
        
        self.init_button = ttk.Button(button_frame, text="Initialize Engine", command=self.initialize_engine)
        self.init_button.grid(row=0, column=0, padx=5, sticky="ew")
        self.reset_button = ttk.Button(button_frame, text="Reset Engine", command=self.reset_engine, state="disabled")
        self.reset_button.grid(row=0, column=1, padx=5, sticky="ew")
        self.encode_button = ttk.Button(button_frame, text="Encode", command=self.encode_text, state="disabled")
        self.encode_button.grid(row=0, column=2, padx=5, sticky="ew")
        self.decode_button = ttk.Button(button_frame, text="Decode", command=self.decode_text, state="disabled")
        self.decode_button.grid(row=0, column=3, padx=5, sticky="ew")
        self.encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text, state="disabled")
        self.encrypt_button.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        self.decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_text, state="disabled")
        self.decrypt_button.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.encrypt_iv_button = ttk.Button(button_frame, text="Encrypt with IV", command=self.encrypt_with_iv, state="disabled")
        self.encrypt_iv_button.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        self.decrypt_iv_button = ttk.Button(button_frame, text="Decrypt with IV", command=self.decrypt_with_iv, state="disabled")
        self.decrypt_iv_button.grid(row=1, column=3, padx=5, pady=5, sticky="ew")
        ttk.Button(button_frame, text="Clear", command=self.clear_fields).grid(row=0, column=4, padx=5, sticky="ew")
        
        # Output Section
        output_frame = ttk.LabelFrame(self.main_frame, text="Output", padding="10")
        output_frame.grid(row=4, column=0, sticky="nsew", pady=5)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = tk.Text(output_frame, height=6, font=("Segoe UI", self.base_font_size), wrap="word")
        self.output_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_text.config(yscrollcommand=scrollbar.set, state='disabled')
        self.output_text.bind("<Enter>", lambda e: self.show_tooltip("Output (Base64 for encoded/encrypted data, plain text for decoded/decrypted)"))
        self.output_text.bind("<Leave>", lambda e: self.hide_tooltip())
        
        # Status Bar
        self.status_var = tk.StringVar(value="Engine not initialized")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", padding="5")
        status_bar.grid(row=5, column=0, sticky="ew", pady=5)
        
        # Tooltip
        self.tooltip = None
    
    def on_resize(self, event):
        # Adjust font sizes based on window width
        width = event.width
        new_font_size = max(8, min(12, int(width / 80)))  # Scale font size between 8 and 12
        if new_font_size != self.base_font_size:
            self.base_font_size = new_font_size
            self.style.configure("TLabel", font=("Segoe UI", self.base_font_size))
            self.style.configure("TButton", font=("Segoe UI", self.base_font_size), padding=6)
            self.style.configure("Header.TLabel", font=("Segoe UI", self.base_font_size + 4, "bold"))
            self.input_text.config(font=("Segoe UI", self.base_font_size))
            self.key_entry.config(font=("Segoe UI", self.base_font_size))
            self.sboxseed_entry.config(font=("Segoe UI", self.base_font_size))
            self.iv_length_entry.config(font=("Segoe UI", self.base_font_size))
            self.xbase_entry.config(font=("Segoe UI", self.base_font_size))
            self.output_text.config(font=("Segoe UI", self.base_font_size))
    
    def show_tooltip(self, message):
        if self.tooltip:
            self.tooltip.destroy()
        self.tooltip = tk.Toplevel(self.root)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{self.root.winfo_pointerx()+10}+{self.root.winfo_pointery()+10}")
        label = ttk.Label(self.tooltip, text=message, background="lightyellow", relief="solid", borderwidth=1, font=("Segoe UI", max(8, self.base_font_size - 1)))
        label.pack()
    
    def hide_tooltip(self):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
    
    def validate_inputs(self):
        try:
            sboxseed = self.sboxseed_entry.get().strip()
            if not sboxseed:
                raise ValueError("SBox Seed must not be empty")
            iv_length = int(self.iv_length_entry.get())
            if iv_length <= 0:
                raise ValueError("IV length must be positive")
            xbase = int(self.xbase_entry.get())
            if xbase <= 0:
                raise ValueError("XBase must be positive")
            return sboxseed, iv_length, xbase
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
            return None, None, None
    
    def initialize_engine(self):
        sboxseed, iv_length, xbase = self.validate_inputs()
        if sboxseed is None or iv_length is None or xbase is None:
            return
        try:
            self.engine = LeCatchu_Engine(
                sboxseed=sboxseed,
                sboxseedxbase=xbase,
                encoding_type=self.encoding_type.get(),
                mostsecurity=self.most_security.get()
            )
            self.status_var.set("Engine initialized successfully")
            self.update_button_states("normal")
            messagebox.showinfo("Success", "LeCatchu Engine initialized!")
        except Exception as e:
            self.status_var.set("Engine initialization failed")
            self.update_button_states("disabled")
            messagebox.showerror("Error", f"Failed to initialize engine: {str(e)}")
    
    def reset_engine(self):
        self.engine = None
        self.status_var.set("Engine not initialized")
        self.update_button_states("disabled")
        messagebox.showinfo("Success", "Engine reset. Reinitialize to continue.")
    
    def update_button_states(self, state):
        buttons = [
            self.reset_button, self.encode_button, self.decode_button,
            self.encrypt_button, self.decrypt_button, self.encrypt_iv_button, self.decrypt_iv_button
        ]
        for button in buttons:
            button.configure(state=state)
    
    def encode_text(self):
        if not self.engine:
            messagebox.showerror("Error", "Please initialize the engine first!")
            return
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            if not input_text:
                messagebox.showerror("Error", "Input text is empty!")
                return
            encoded = self.engine.encode(input_text)
            encoded_b64 = base64.b64encode(encoded).decode('utf-8')
            self.display_output(encoded_b64)
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")
    
    def decode_text(self):
        if not self.engine:
            messagebox.showerror("Error", "Please initialize the engine first!")
            return
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            if not input_text:
                messagebox.showerror("Error", "Input text is empty!")
                return
            decoded_bytes = base64.b64decode(input_text)
            decoded = self.engine.decode(decoded_bytes)
            self.display_output(decoded)
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")
    
    def encrypt_text(self):
        if not self.engine:
            messagebox.showerror("Error", "Please initialize the engine first!")
            return
        sboxseed, iv_length, xbase = self.validate_inputs()
        if sboxseed is None or iv_length is None or xbase is None:
            return
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            if not input_text or not key:
                messagebox.showerror("Error", "Input text or key is empty!")
                return
            encoded = self.engine.encode(input_text)
            encrypted = self.engine.encrypt(encoded, key, xbase=xbase)
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            self.display_output(encrypted_b64)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        if not self.engine:
            messagebox.showerror("Error", "Please initialize the engine first!")
            return
        sboxseed, iv_length, xbase = self.validate_inputs()
        if sboxseed is None or iv_length is None or xbase is None:
            return
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            if not input_text or not key:
                messagebox.showerror("Error", "Input text or key is empty!")
                return
            encrypted_bytes = base64.b64decode(input_text)
            decrypted = self.engine.decrypt(encrypted_bytes, key, xbase=xbase)
            decoded = self.engine.decode(decrypted)
            self.display_output(decoded)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def encrypt_with_iv(self):
        if not self.engine:
            messagebox.showerror("Error", "Please initialize the engine first!")
            return
        sboxseed, iv_length, xbase = self.validate_inputs()
        if sboxseed is None or iv_length is None or xbase is None:
            return
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            if not input_text or not key:
                messagebox.showerror("Error", "Input text or key is empty!")
                return
            encoded = self.engine.encode(input_text)
            encrypted = self.engine.encrypt_with_iv(encoded, key, xbase=xbase, ivlength=iv_length)
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            self.display_output(encrypted_b64)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption with IV failed: {str(e)}")
    
    def decrypt_with_iv(self):
        if not self.engine:
            messagebox.showerror("Error", "Please initialize the engine first!")
            return
        sboxseed, iv_length, xbase = self.validate_inputs()
        if sboxseed is None or iv_length is None or xbase is None:
            return
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            key = self.key_entry.get().strip()
            if not input_text or not key:
                messagebox.showerror("Error", "Input text or key is empty!")
                return
            encrypted_bytes = base64.b64decode(input_text)
            decrypted = self.engine.decrypt_with_iv(encrypted_bytes, key, xbase=xbase, ivlength=iv_length)
            decoded = self.engine.decode(decrypted)
            self.display_output(decoded)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption with IV failed: {str(e)}")
    
    def display_output(self, text):
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.config(state='disabled')
    
    def clear_fields(self):
        self.input_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        self.sboxseed_entry.delete(0, tk.END)
        self.sboxseed_entry.insert(0, "myseed")
        self.iv_length_entry.delete(0, tk.END)
        self.iv_length_entry.insert(0, "256")
        self.xbase_entry.delete(0, tk.END)
        self.xbase_entry.insert(0, "1")
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state='disabled')

if __name__ == "__main__":
    root = ThemedTk(theme="arc")
    app = LeCatchuGUI(root)
    root.mainloop()
