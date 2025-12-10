import tkinter as tk
from tkinter import filedialog, messagebox
import os
from LeCatchu import *

def initialize_lecatchu_engine():
    engine = LeCatchu_Engine(encoding=False) 
    LeCatchu_Extra(engine)
    return engine

class LeCatchuFileCipherApp:
    def __init__(self, master):
        self.master = master
        master.title("LeCatchu v9 File Cipher")
        self.engine = initialize_lecatchu_engine()
        self.files_to_process = []
        key_frame = tk.Frame(master, padx=10, pady=10)
        key_frame.pack(pady=10, fill='x')

        tk.Label(key_frame, text="Encryption Key:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        self.key_entry = tk.Entry(key_frame, width=40, show="*")
        self.key_entry.pack(side=tk.LEFT, padx=5, expand=True, fill='x')

        tk.Button(master, text="Select Files to Process", command=self.select_files, bg='#3498DB', fg='white', font=('Arial', 10, 'bold')).pack(pady=5, padx=10, fill='x')

        list_frame = tk.Frame(master, padx=10, pady=5)
        list_frame.pack(pady=5, fill='both', expand=True)

        tk.Label(list_frame, text="Selected Files:", font=('Arial', 10, 'bold')).pack(anchor='w')
        self.file_listbox = tk.Listbox(list_frame, height=10, width=60, selectmode=tk.EXTENDED)
        self.file_listbox.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        scrollbar.config(command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        
        tk.Button(master, text="Clear Selection", command=self.clear_files, bg='#E74C3C', fg='white', font=('Arial', 10, 'bold')).pack(pady=5, padx=10, fill='x')

        button_frame = tk.Frame(master, padx=10, pady=10)
        button_frame.pack(pady=10, fill='x')

        tk.Button(button_frame, text="🔒 ENCRYPT", command=self.encrypt_selected_files, bg='#27AE60', fg='white', font=('Arial', 10, 'bold'), width=20).pack(side=tk.LEFT, padx=5, expand=True)

        tk.Button(button_frame, text="🔓 DECRYPT", command=self.decrypt_selected_files, bg='#F39C12', fg='white', font=('Arial', 10, 'bold'), width=20).pack(side=tk.RIGHT, padx=5, expand=True)

        self.status_bar = tk.Label(master, text="Ready.", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill='x')

    def select_files(self):
        filepaths = filedialog.askopenfilenames(
            title="Select files to encrypt/decrypt",
            initialdir=os.getcwd()
        )
        if filepaths:
            for path in filepaths:
                if path not in self.files_to_process:
                    self.files_to_process.append(path)
                    self.file_listbox.insert(tk.END, path)

    def clear_files(self):
        self.files_to_process = []
        self.file_listbox.delete(0, tk.END)
        self.update_status("Selection cleared.")

    def update_status(self, message, color='black'):
        self.status_bar.config(text=message, fg=color)
        self.master.update_idletasks()
        
    def get_key_and_validate(self):
        key = self.key_entry.get()
        if not key:
            messagebox.showerror("Key Error", "Please enter a valid encryption key.")
            return None
        return key

    def process_files(self, operation):
        key = self.get_key_and_validate()
        if key is None:
            return

        if not self.files_to_process:
            messagebox.showwarning("File Error", "No files selected for processing.")
            return

        total_files = len(self.files_to_process)
        processed_count = 0
        failed_files = []

        for file_path in self.files_to_process:
            self.update_status(f"{operation.capitalize()}ing: {os.path.basename(file_path)}...", color='#3498DB')
            
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()

                if operation == 'encrypt':
                    processed_data = self.engine.encrypt_with_iv(data, key)
                    new_filename = file_path + ".lcv9"
                elif operation == 'decrypt':
                    processed_data = self.engine.decrypt_with_iv(data, key)
                    if file_path.endswith(".lcv9"):
                        new_filename = file_path[:-5] 
                    else:
                         new_filename = file_path + ".dec"

                with open(new_filename, 'wb') as f:
                    f.write(processed_data)
                
                os.remove(file_path)

                processed_count += 1
            
            except ValueError as e:
                failed_files.append(os.path.basename(file_path))
                messagebox.showerror("Operation Error", f"Failed to {operation} '{os.path.basename(file_path)}'. Invalid Key or corrupted file/tag. Error: {e}")
            except Exception as e:
                failed_files.append(os.path.basename(file_path))
                messagebox.showerror("General Error", f"An unexpected error occurred while processing '{os.path.basename(file_path)}'. Error: {e}")
            
        if not failed_files:
            self.update_status(f"Successfully {operation}ed {processed_count} files.", color='#27AE60')
            self.clear_files()
        else:
            self.update_status(f"Completed with {len(failed_files)} failures. Total: {total_files}.", color='#E74C3C')
            
    def encrypt_selected_files(self):
        self.process_files('encrypt')

    def decrypt_selected_files(self):
        self.process_files('decrypt')

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = LeCatchuFileCipherApp(root)
        root.mainloop()
    except NameError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
