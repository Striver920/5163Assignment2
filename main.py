# pip install cryptography
# tkinter 通常已预安装在Python中

from cryptography.hazmat.primitives.asymmetric import dh, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk

# Diffie-Hellman setup and key exchange functions
def dh_setup(generator, key_size):
    parameters = dh.generate_parameters(generator=generator, key_size=key_size)
    return parameters

def dh_generate_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def dh_generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Digital signature functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature

def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

# Step-by-step functions for the GUI
def start_key_exchange():
    global step, paused, completed
    step = 0
    paused = False
    completed = False
    global parameters
    generator = int(generator_var.get())
    key_size = int(key_size_var.get())
    parameters = dh_setup(generator, key_size)
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED)
    reset_labels()
    root.after(1000, process_next_step)

def process_next_step():
    global step, paused, completed
    if paused or completed:
        return

    global Alice_dh_private_key, Alice_dh_public_key, Bob_dh_private_key, Bob_dh_public_key
    global Alice_rsa_private_key, Alice_rsa_public_key, Bob_rsa_private_key, Bob_rsa_public_key
    global Alice_signature, Bob_signature
    global Alice_shared_key, Bob_shared_key

    output_text.config(state=tk.NORMAL)
    if step == 0:
        output_text.insert(tk.INSERT, "Step 1: Generate Diffie-Hellman parameters\n")
    elif step == 1:
        output_text.insert(tk.INSERT, f"Parameters: Generator={generator_var.get()}, Key Size={key_size_var.get()}\n")
    elif step == 2:
        Alice_dh_private_key, Alice_dh_public_key = dh_generate_keys(parameters)
        output_text.insert(tk.INSERT, "Step 2: Alice generates her DH key pair\n")
        Alice_dh_public_label.config(text=f"Alice's DH Public Key:\n{Alice_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}")
    elif step == 3:
        Bob_dh_private_key, Bob_dh_public_key = dh_generate_keys(parameters)
        output_text.insert(tk.INSERT, "Step 3: Bob generates his DH key pair\n")
        Bob_dh_public_label.config(text=f"Bob's DH Public Key:\n{Bob_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}")
    elif step == 4:
        Alice_rsa_private_key, Alice_rsa_public_key = generate_rsa_keys()
        output_text.insert(tk.INSERT, "Step 4: Alice generates her RSA key pair\n")
    elif step == 5:
        Bob_rsa_private_key, Bob_rsa_public_key = generate_rsa_keys()
        output_text.insert(tk.INSERT, "Step 5: Bob generates his RSA key pair\n")
    elif step == 6:
        Alice_dh_public_bytes = Alice_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        Alice_signature = sign_data(Alice_rsa_private_key, Alice_dh_public_bytes)
        output_text.insert(tk.INSERT, "Step 6: Alice signs her DH public key\n")
        Alice_signature_label.config(text=f"Alice's Signature:\n{Alice_signature.hex()}")
    elif step == 7:
        Bob_dh_public_bytes = Bob_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        Bob_signature = sign_data(Bob_rsa_private_key, Bob_dh_public_bytes)
        output_text.insert(tk.INSERT, "Step 7: Bob signs his DH public key\n")
        Bob_signature_label.config(text=f"Bob's Signature:\n{Bob_signature.hex()}")
    elif step == 8:
        output_text.insert(tk.INSERT, "Step 8: Verify signatures\n")
        Alice_dh_public_bytes = Alice_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        Bob_dh_public_bytes = Bob_dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        if not verify_signature(Alice_rsa_public_key, Alice_dh_public_bytes, Alice_signature):
            messagebox.showerror("Error", "Alice's DH public key verification failed!")
            output_text.config(state=tk.DISABLED)
            return
        if not verify_signature(Bob_rsa_public_key, Bob_dh_public_bytes, Bob_signature):
            messagebox.showerror("Error", "Bob's DH public key verification failed!")
            output_text.config(state=tk.DISABLED)
            return
        output_text.insert(tk.INSERT, "Signatures verified successfully\n")
    elif step == 9:
        Alice_shared_key = dh_generate_shared_key(Alice_dh_private_key, Bob_dh_public_key)
        output_text.insert(tk.INSERT, "Step 9: Alice generates shared key\n")
        Alice_shared_key_label.config(text=f"Alice's Shared Key:\n{Alice_shared_key.hex()}")
    elif step == 10:
        Bob_shared_key = dh_generate_shared_key(Bob_dh_private_key, Alice_dh_public_key)
        output_text.insert(tk.INSERT, "Step 10: Bob generates shared key\n")
        Bob_shared_key_label.config(text=f"Bob's Shared Key:\n{Bob_shared_key.hex()}")
        output_text.insert(tk.INSERT, "\n\nShared Keys Match: {}\n".format(Alice_shared_key == Bob_shared_key))
        output_text.config(state=tk.DISABLED)
        completed = True
        return
    
    output_text.config(state=tk.DISABLED)
    step += 1
    root.after(1000, process_next_step)

def pause_key_exchange():
    global paused
    paused = True

def resume_key_exchange():
    global paused
    paused = False
    root.after(1000, process_next_step)

def reset_labels():
    Alice_dh_public_label.config(text="Alice's DH Public Key:")
    Bob_dh_public_label.config(text="Bob's DH Public Key:")
    Alice_signature_label.config(text="Alice's Signature:")
    Bob_signature_label.config(text="Bob's Signature:")
    Alice_shared_key_label.config(text="Alice's Shared Key:")
    Bob_shared_key_label.config(text="Bob's Shared Key:")

def restart_key_exchange():
    start_key_exchange()

# Set up the GUI
root = tk.Tk()
root.title("Secure Diffie-Hellman Key Exchange")

frame = tk.Frame(root, bg="lightblue")
frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

title_label = tk.Label(frame, text="Secure Diffie-Hellman Key Exchange", font=("Arial", 16), bg="lightblue")
title_label.pack(pady=10)

param_frame = tk.Frame(frame, bg="lightblue")
param_frame.pack(pady=10)

generator_label = tk.Label(param_frame, text="Generator:", font=("Arial", 12), bg="lightblue")
generator_label.grid(row=0, column=0, padx=5, pady=5)
generator_var = tk.StringVar(value="2")
generator_entry = ttk.Combobox(param_frame, textvariable=generator_var, values=["2", "5"], state="readonly", font=("Arial", 12))
generator_entry.grid(row=0, column=1, padx=5, pady=5)

key_size_label = tk.Label(param_frame, text="Key Size:", font=("Arial", 12), bg="lightblue")
key_size_label.grid(row=1, column=0, padx=5, pady=5)
key_size_var = tk.StringVar(value="512")
key_size_entry = ttk.Combobox(param_frame, textvariable=key_size_var, values=["512", "1024", "2048"], state="readonly", font=("Arial", 12))
key_size_entry.grid(row=1, column=1, padx=5, pady=5)

button_frame = tk.Frame(frame, bg="lightblue")
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Key Exchange", command=start_key_exchange, font=("Arial", 12), bg="white", fg="black")
start_button.grid(row=0, column=0, padx=5, pady=5)

pause_button = tk.Button(button_frame, text="Pause", command=pause_key_exchange, font=("Arial", 12), bg="white", fg="black")
pause_button.grid(row=0, column=1, padx=5, pady=5)

resume_button = tk.Button(button_frame, text="Resume", command=resume_key_exchange, font=("Arial", 12), bg="white", fg="black")
resume_button.grid(row=0, column=2, padx=5, pady=5)

restart_button = tk.Button(button_frame, text="Restart", command=restart_key_exchange, font=("Arial", 12), bg="white", fg="black")
restart_button.grid(row=0, column=3, padx=5, pady=5)

output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=10, font=("Arial", 10))
output_text.pack(pady=10, fill=tk.BOTH, expand=True)
output_text.config(state=tk.DISABLED)

keys_frame = tk.Frame(frame, bg="lightblue")
keys_frame.pack(pady=10, fill=tk.BOTH, expand=True)

Alice_dh_public_label = tk.Label(keys_frame, text="Alice's DH Public Key:", font=("Arial", 10), bg="lightblue", anchor="w", justify="left", wraplength=600)
Alice_dh_public_label.pack(fill=tk.X)

Bob_dh_public_label = tk.Label(keys_frame, text="Bob's DH Public Key:", font=("Arial", 10), bg="lightblue", anchor="w", justify="left", wraplength=600)
Bob_dh_public_label.pack(fill=tk.X)

Alice_signature_label = tk.Label(keys_frame, text="Alice's Signature:", font=("Arial", 10), bg="lightblue", anchor="w", justify="left", wraplength=600)
Alice_signature_label.pack(fill=tk.X)

Bob_signature_label = tk.Label(keys_frame, text="Bob's Signature:", font=("Arial", 10), bg="lightblue", anchor="w", justify="left", wraplength=600)
Bob_signature_label.pack(fill=tk.X)

Alice_shared_key_label = tk.Label(keys_frame, text="Alice's Shared Key:", font=("Arial", 10), bg="lightblue", anchor="w", justify="left", wraplength=600)
Alice_shared_key_label.pack(fill=tk.X)

Bob_shared_key_label = tk.Label(keys_frame, text="Bob's Shared Key:", font=("Arial", 10), bg="lightblue", anchor="w", justify="left", wraplength=600)
Bob_shared_key_label.pack(fill=tk.X)

root.mainloop()
