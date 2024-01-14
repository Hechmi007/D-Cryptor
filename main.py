import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        root.title("Encryption App")

        self.text = tk.StringVar()
        self.result = tk.StringVar()
        self.aes_key = tk.StringVar()
        self.des_key = tk.StringVar()
        self.rsa_key_length = tk.StringVar(value="2048")

        ttk.Label(root, text="Enter Text:").grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(root, textvariable=self.text, width=50)
        self.entry.grid(row=0, column=1, columnspan=3)

        ttk.Label(root, text="RSA Key Length:").grid(row=1, column=0, sticky="w")
        self.rsa_key_entry = ttk.Combobox(root, textvariable=self.rsa_key_length, values=["1024", "2048", "4096"], state="readonly", width=47)
        self.rsa_key_entry.grid(row=1, column=1, columnspan=3)

        ttk.Button(root, text="Generate RSA Key", command=self.generate_rsa_key).grid(row=2, column=0)
        ttk.Button(root, text="Encrypt RSA", command=self.encrypt_rsa).grid(row=2, column=1)
        ttk.Button(root, text="Decrypt RSA", command=self.decrypt_rsa).grid(row=2, column=2)

        ttk.Label(root, text="DES Key (8 bytes):").grid(row=3, column=0, sticky="w")
        self.des_key_entry = ttk.Entry(root, textvariable=self.des_key, width=50)
        self.des_key_entry.grid(row=3, column=1, columnspan=3)

        ttk.Button(root, text="Encrypt DES", command=self.encrypt_des).grid(row=4, column=0)
        ttk.Button(root, text="Decrypt DES", command=self.decrypt_des).grid(row=4, column=1)

        ttk.Label(root, text="AES Key (16/24/32 bytes):").grid(row=5, column=0, sticky="w")
        self.aes_key_entry = ttk.Entry(root, textvariable=self.aes_key, width=50)
        self.aes_key_entry.grid(row=5, column=1, columnspan=3)

        ttk.Button(root, text="Encrypt AES", command=self.encrypt_aes).grid(row=6, column=0)
        ttk.Button(root, text="Decrypt AES", command=self.decrypt_aes).grid(row=6, column=1)

        ttk.Label(root, text="Result:").grid(row=7, column=0, sticky="w")
        self.result_entry = ttk.Entry(root, textvariable=self.result, state='readonly', width=50)
        self.result_entry.grid(row=7, column=1, columnspan=3)

    def generate_rsa_key(self):
      key_length = int(self.rsa_key_length.get())
      self.rsa_key = RSA.generate(key_length)
      self.result.set("RSA Key Generated with length " + str(key_length) + " bits")
    def encrypt_rsa(self):
      data = self.text.get().encode()
      public_key = self.rsa_key.publickey()
      encrypted_data = public_key.encrypt(data, 32)[0]
      self.result.set(b64encode(encrypted_data).decode())

    def decrypt_rsa(self):
      data = b64decode(self.text.get())
      decrypted_data = self.rsa_key.decrypt(data)
      self.result.set(decrypted_data.decode())
	
    def encrypt_des(self):
    
      key = self.des_key.get().encode()
      cipher = DES.new(key, DES.MODE_ECB)
      data = pad(self.text.get().encode(), DES.block_size)
      encrypted_data = cipher.encrypt(data)
      self.result.set(b64encode(encrypted_data).decode())

    def decrypt_des(self):
      key = self.des_key.get().encode()
      cipher = DES.new(key, DES.MODE_ECB)
      data = b64decode(self.text.get())
      decrypted_data = unpad(cipher.decrypt(data), DES.block_size)
      self.result.set(decrypted_data.decode())

    def encrypt_aes(self):
      key = self.aes_key.get().encode()
      cipher = AES.new(key, AES.MODE_CBC)
      data = pad(self.text.get().encode(), AES.block_size)
      encrypted_data = cipher.encrypt(data)
      self.result.set(b64encode(cipher.iv + encrypted_data).decode())
    def decrypt_aes(self):
      key = self.aes_key.get().encode()
      data = b64decode(self.text.get())
      iv = data[:AES.block_size]
      cipher = AES.new(key, AES.MODE_CBC, iv)
      decrypted_data = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
