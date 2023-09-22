import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

private_key_text = ""

def open_private_key():
    global private_key_text
    private_key_file = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    
    if private_key_file:
        with open(private_key_file, 'r') as key_file:
            private_key_text = key_file.read()

def open_file():
    file_path = filedialog.askopenfilename()
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, file_path)

def decrypt_file():
    global private_key_text
    if not private_key_text:
        result_label.config(text="Please select a private_key.pem file first")
        return

    private_key = RSA.import_key(private_key_text)

    file_path = file_path_entry.get()

    try:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        cipher = PKCS1_OAEP.new(private_key)

        decrypted_data = cipher.decrypt(encrypted_data)

        decrypted_file_path = file_path + "_decrypted"
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        result_label.config(text=f"Decrypted file saved as {decrypted_file_path}")
    except Exception as e:
        result_label.config(text=f"Error: {str(e)}")

root = tk.Tk()
root.title("File Decryptor by DRAGON-NOIR-DZ")
root.geometry("680x600")

private_key_button = tk.Button(root, text="Select private_key.pem file", command=open_private_key)
private_key_button.pack()

file_label = tk.Label(root, text="Select an encrypted file:")
file_label.pack()

file_path_entry = tk.Entry(root, width=50)
file_path_entry.pack()

open_button = tk.Button(root, text="Open File", command=open_file)
open_button.pack()

decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()

