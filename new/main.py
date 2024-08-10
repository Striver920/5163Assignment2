from diffie_hellman_funcs import diffie_hellman, des_encrypt, des_decrypt, gen_p, gen_a
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk

# 全局变量
shared_key = None
alice_info = {}
bob_info = {}

def start_key_exchange():
    global shared_key, alice_info, bob_info
    try:
        p = int(p_entry.get())
        g = int(g_entry.get())
        a = int(a_entry.get())
        b = int(b_entry.get())
        shared_key, alice_info, bob_info = diffie_hellman(p, g, a, b)
        messagebox.showinfo("Success", "Key exchange successful!")
        shared_key_label.config(text=f"Shared Key: {shared_key}")
        alice_info_text.config(state=tk.NORMAL)
        alice_info_text.delete(1.0, tk.END)
        alice_info_text.insert(tk.INSERT, f"Alice's DH Public Key: {alice_info['dh_public_key']}\n")
        alice_info_text.insert(tk.INSERT, f"Alice's RSA Public Key: {alice_info['rsa_public_key']}\n")
        alice_info_text.insert(tk.INSERT, f"Alice's Signature: {alice_info['signature']}\n")
        alice_info_text.config(state=tk.DISABLED)

        bob_info_text.config(state=tk.NORMAL)
        bob_info_text.delete(1.0, tk.END)
        bob_info_text.insert(tk.INSERT, f"Bob's DH Public Key: {bob_info['dh_public_key']}\n")
        bob_info_text.insert(tk.INSERT, f"Bob's RSA Public Key: {bob_info['rsa_public_key']}\n")
        bob_info_text.insert(tk.INSERT, f"Bob's Signature: {bob_info['signature']}\n")
        bob_info_text.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encrypt_message():
    if shared_key:
        message = message_entry.get()
        selected_user = user_choice.get()
        if selected_user == "Alice":
            encrypted_message = des_encrypt(message, alice_info['shared_key'])
        else:
            encrypted_message = des_encrypt(message, bob_info['shared_key'])
        output_text.config(state=tk.NORMAL)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.INSERT, f"Encrypted message: {encrypted_message}")
        output_text.config(state=tk.DISABLED)
    else:
        messagebox.showerror("Error", "Key exchange not performed yet")

def decrypt_message():
    if shared_key:
        encrypted_message = message_entry.get()
        try:
            selected_user = user_choice.get()
            if selected_user == "Alice":
                decrypted_message = des_decrypt(encrypted_message, alice_info['shared_key'])
            else:
                decrypted_message = des_decrypt(encrypted_message, bob_info['shared_key'])
            output_text.config(state=tk.NORMAL)
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.INSERT, f"Decrypted message: {decrypted_message}")
            output_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed. Ensure the correct encrypted message is provided.\nError: {str(e)}")
    else:
        messagebox.showerror("Error", "Key exchange not performed yet")

def generate_p_and_g():
    p = gen_p()
    g = gen_a(p)
    p_entry.delete(0, tk.END)
    p_entry.insert(0, str(p))
    g_entry.delete(0, tk.END)
    g_entry.insert(0, str(g))

def reset():
    global shared_key, alice_info, bob_info
    shared_key = None
    alice_info = {}
    bob_info = {}
    p_entry.delete(0, tk.END)
    g_entry.delete(0, tk.END)
    a_entry.delete(0, tk.END)
    b_entry.delete(0, tk.END)
    shared_key_label.config(text="Shared Key: None")
    alice_info_text.config(state=tk.NORMAL)
    alice_info_text.delete(1.0, tk.END)
    alice_info_text.config(state=tk.DISABLED)
    bob_info_text.config(state=tk.NORMAL)
    bob_info_text.delete(1.0, tk.END)
    bob_info_text.config(state=tk.DISABLED)
    message_entry.delete(0, tk.END)
    output_text.config(state=tk.NORMAL)
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED)
    user_choice.set("Alice")

# 设置GUI
root = tk.Tk()
root.title("Secure Diffie-Hellman Key Exchange and DES Encryption")

frame = tk.Frame(root, bg="lightblue")
frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

title_label = tk.Label(frame, text="Secure Diffie-Hellman Key Exchange and DES Encryption", font=("Arial", 16), bg="lightblue")
title_label.pack(pady=10)

param_frame = tk.Frame(frame, bg="lightblue")
param_frame.pack(pady=10)

p_label = tk.Label(param_frame, text="Prime p:", font=("Arial", 12), bg="lightblue")
p_label.grid(row=0, column=0, padx=5, pady=5)
p_entry = tk.Entry(param_frame, font=("Arial", 12), width=30)
p_entry.grid(row=0, column=1, padx=5, pady=5)

g_label = tk.Label(param_frame, text="Primitive Root g:", font=("Arial", 12), bg="lightblue")
g_label.grid(row=1, column=0, padx=5, pady=5)
g_entry = tk.Entry(param_frame, font=("Arial", 12), width=30)
g_entry.grid(row=1, column=1, padx=5, pady=5)

a_label = tk.Label(param_frame, text="Private Key a (Alice):", font=("Arial", 12), bg="lightblue")
a_label.grid(row=2, column=0, padx=5, pady=5)
a_entry = tk.Entry(param_frame, font=("Arial", 12), width=30)
a_entry.grid(row=2, column=1, padx=5, pady=5)

b_label = tk.Label(param_frame, text="Private Key b (Bob):", font=("Arial", 12), bg="lightblue")
b_label.grid(row=3, column=0, padx=5, pady=5)
b_entry = tk.Entry(param_frame, font=("Arial", 12), width=30)
b_entry.grid(row=3, column=1, padx=5, pady=5)

generate_button = tk.Button(param_frame, text="Generate p and g", command=generate_p_and_g, font=("Arial", 12), bg="white", fg="black")
generate_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

button_frame = tk.Frame(frame, bg="lightblue")
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Start Key Exchange", command=start_key_exchange, font=("Arial", 12), bg="white", fg="black")
start_button.grid(row=0, column=0, padx=5, pady=5)

reset_button = tk.Button(button_frame, text="Reset", command=reset, font=("Arial", 12), bg="white", fg="black")
reset_button.grid(row=0, column=1, padx=5, pady=5)

shared_key_label = tk.Label(button_frame, text="Shared Key: None", font=("Arial", 12), bg="lightblue")
shared_key_label.grid(row=0, column=2, padx=5, pady=5)

user_choice = tk.StringVar(value="Alice")
user_choice_menu = ttk.Combobox(button_frame, textvariable=user_choice, values=["Alice", "Bob"], state="readonly", font=("Arial", 12))
user_choice_menu.grid(row=0, column=3, padx=5, pady=5)

info_frame = tk.Frame(frame, bg="lightblue")
info_frame.pack(pady=10, fill=tk.BOTH, expand=True)

alice_info_label = tk.Label(info_frame, text="Alice's Info:", font=("Arial", 12), bg="lightblue")
alice_info_label.pack(pady=5)
alice_info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, width=80, height=5, font=("Arial", 10))
alice_info_text.pack(pady=5, fill=tk.BOTH, expand=True)
alice_info_text.config(state=tk.DISABLED)

bob_info_label = tk.Label(info_frame, text="Bob's Info:", font=("Arial", 12), bg="lightblue")
bob_info_label.pack(pady=5)
bob_info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, width=80, height=5, font=("Arial", 10))
bob_info_text.pack(pady=5, fill=tk.BOTH, expand=True)
bob_info_text.config(state=tk.DISABLED)

message_label = tk.Label(frame, text="Enter Message:", font=("Arial", 12), bg="lightblue")
message_label.pack(pady=5)

message_entry = tk.Entry(frame, font=("Arial", 12), width=50)
message_entry.pack(pady=5)

encrypt_button = tk.Button(frame, text="Encrypt Message", command=encrypt_message, font=("Arial", 12), bg="white", fg="black")
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(frame, text="Decrypt Message", command=decrypt_message, font=("Arial", 12), bg="white", fg="black")
decrypt_button.pack(pady=5)

output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=10, font=("Arial", 10))
output_text.pack(pady=10, fill=tk.BOTH, expand=True)
output_text.config(state=tk.DISABLED)

root.mainloop()
