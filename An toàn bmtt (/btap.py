import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

class DESApp:
    def __init__(self, master):
        self.master = master
        master.title("DES File Encryption/Decryption")

        self.key = None

        self.label = tk.Label(master, text="Enter 8-byte key:")
        self.label.pack()

        self.key_entry = tk.Entry(master, show='*')
        self.key_entry.pack()

        self.browse_button = tk.Button(master, text="Browse File", command=self.browse_file)
        self.browse_button.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def browse_file(self):
        self.filepath = filedialog.askopenfilename()
        if not self.filepath:
            messagebox.showwarning("Warning", "No file selected!")

    def encrypt_file(self):
        self.key = self.key_entry.get().encode('utf-8')
        if len(self.key) != 8:
            messagebox.showerror("Error", "Key must be 8 bytes long!")
            return
        
        with open(self.filepath, 'rb') as f:
            plaintext = f.read()

        cipher = DES.new(self.key, DES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

        with open(self.filepath + '.enc', 'wb') as f:
            f.write(cipher.iv)  # Write IV at the beginning
            f.write(ciphertext)

        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        self.key = self.key_entry.get().encode('utf-8')
        if len(self.key) != 8:
            messagebox.showerror("Error", "Key must be 8 bytes long!")
            return
        
        with open(self.filepath, 'rb') as f:
            iv = f.read(8)  # Read IV
            ciphertext = f.read()

        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

        with open(self.filepath[:-4], 'wb') as f:  # Save without .enc
            f.write(plaintext)

        messagebox.showinfo("Success", "File decrypted successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = DESApp(root)
    root.mainloop()