from tkinter import *
from tkinter import filedialog, messagebox, ttk
import pybase64
from cryptography.fernet import Fernet
import os

root = Tk()
root.title("🔐 Advanced Text/File Encryptor")
root.geometry("700x600")

# ============= Global Variables =============
APP_PASSWORD = ""   # User sets password
ENCRYPTION_METHOD = StringVar(value="Base64")
DARK_MODE = True
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# ============= Functions =============
def set_password():
    global APP_PASSWORD
    pwd = pw_entry.get()
    if pwd.strip():
        APP_PASSWORD = pwd
        status_bar.config(text="Password set successfully ✅")
    else:
        status_bar.config(text="Password cannot be empty ❌")

def clear():
    text_box.delete(1.0, END)
    pw_entry.delete(0, END)
    status_bar.config(text="Cleared all fields")

def encrypt_text():
    global APP_PASSWORD
    secret = text_box.get(1.0, END).strip()
    text_box.delete(1.0, END)

    if not APP_PASSWORD:
        messagebox.showwarning("No Password", "Please set a password first!")
        return

    if pw_entry.get() != APP_PASSWORD:
        messagebox.showwarning("Incorrect!", "Password does not match!")
        return

    if ENCRYPTION_METHOD.get() == "Base64":
        secret = pybase64.b64encode(secret.encode()).decode()
    elif ENCRYPTION_METHOD.get() == "Fernet":
        secret = fernet.encrypt(secret.encode()).decode()
    elif ENCRYPTION_METHOD.get() == "Caesar Cipher":
        shift = 3
        secret = ''.join(chr((ord(c) + shift) % 256) for c in secret)

    text_box.insert(END, secret)
    status_bar.config(text=f"Encrypted using {ENCRYPTION_METHOD.get()} 🔒")

def decrypt_text():
    global APP_PASSWORD
    secret = text_box.get(1.0, END).strip()
    text_box.delete(1.0, END)

    if not APP_PASSWORD:
        messagebox.showwarning("No Password", "Please set a password first!")
        return

    if pw_entry.get() != APP_PASSWORD:
        messagebox.showwarning("Incorrect!", "Password does not match!")
        return

    try:
        if ENCRYPTION_METHOD.get() == "Base64":
            secret = pybase64.b64decode(secret.encode()).decode()
        elif ENCRYPTION_METHOD.get() == "Fernet":
            secret = fernet.decrypt(secret.encode()).decode()
        elif ENCRYPTION_METHOD.get() == "Caesar Cipher":
            shift = 3
            secret = ''.join(chr((ord(c) - shift) % 256) for c in secret)

        text_box.insert(END, secret)
        status_bar.config(text=f"Decrypted using {ENCRYPTION_METHOD.get()} 🔓")
    except Exception as e:
        status_bar.config(text="Decryption failed ❌")

def save_file():
    text = text_box.get(1.0, END).strip()
    if text:
        file = filedialog.asksaveasfile(defaultextension=".txt",
                                        filetypes=[("Text Files", "*.txt")])
        if file:
            file.write(text)
            file.close()
            status_bar.config(text="File saved 💾")
    else:
        status_bar.config(text="Nothing to save ❌")

def open_file():
    file = filedialog.askopenfile(filetypes=[("Text Files", "*.txt"), ("Encrypted Files", "*.enc")])
    if file:
        content = file.read()
        text_box.delete(1.0, END)
        text_box.insert(END, content)
        file.close()
        status_bar.config(text="File loaded 📂")

def encrypt_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    if ENCRYPTION_METHOD.get() == "Base64":
        encrypted = pybase64.b64encode(data)
    else:
        encrypted = fernet.encrypt(data)

    with open(filepath + ".enc", "wb") as f:
        f.write(encrypted)

    status_bar.config(text=f"File encrypted -> {filepath}.enc")

def decrypt_file(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    if ENCRYPTION_METHOD.get() == "Base64":
        decrypted = pybase64.b64decode(data)
    else:
        decrypted = fernet.decrypt(data)

    new_name = filepath.replace(".enc", "_decrypted")
    with open(new_name, "wb") as f:
        f.write(decrypted)

    status_bar.config(text=f"File decrypted -> {new_name}")

def drop_file(event):
    filepath = event.data.strip("{}")  # Windows fix
    if filepath.endswith(".enc"):
        decrypt_file(filepath)
    else:
        encrypt_file(filepath)

def toggle_theme():
    global DARK_MODE
    DARK_MODE = not DARK_MODE
    if DARK_MODE:
        root.config(bg="#2c3e50")
        status_bar.config(bg="#34495e", fg="white")
        text_box.config(bg="#1e272e", fg="white", insertbackground="white")
    else:
        root.config(bg="white")
        status_bar.config(bg="#ddd", fg="black")
        text_box.config(bg="white", fg="black", insertbackground="black")

# ============= UI Layout =============
# Algorithm Dropdown
algo_frame = Frame(root)
algo_frame.pack(pady=10)

Label(algo_frame, text="Encryption Method:", font=("Helvetica", 12)).grid(row=0, column=0, padx=5)
algo_menu = ttk.Combobox(algo_frame, textvariable=ENCRYPTION_METHOD,
                         values=["Base64", "Fernet", "Caesar Cipher"], state="readonly", width=20)
algo_menu.grid(row=0, column=1)

# Buttons Frame
btn_frame = Frame(root)
btn_frame.pack(pady=10)

Button(btn_frame, text="Encrypt 🔒", command=encrypt_text, width=12, bg="green", fg="white").grid(row=0, column=0, padx=5)
Button(btn_frame, text="Decrypt 🔓", command=decrypt_text, width=12, bg="blue", fg="white").grid(row=0, column=1, padx=5)
Button(btn_frame, text="Clear ✨", command=clear, width=12, bg="red", fg="white").grid(row=0, column=2, padx=5)

# Text Area
text_box = Text(root, width=80, height=15, font=("Consolas", 12), wrap=WORD)
text_box.pack(pady=10)

# Password Setup
pw_frame = Frame(root)
pw_frame.pack(pady=5)
Label(pw_frame, text="Set Password:", font=("Helvetica", 12)).grid(row=0, column=0, padx=5)
pw_entry = Entry(pw_frame, font=("Helvetica", 12), width=25, show="*")
pw_entry.grid(row=0, column=1, padx=5)
Button(pw_frame, text="Set", command=set_password).grid(row=0, column=2, padx=5)

# Extra Buttons
extra_frame = Frame(root)
extra_frame.pack(pady=10)
Button(extra_frame, text="Save 💾", command=save_file, width=12).grid(row=0, column=0, padx=5)
Button(extra_frame, text="Open 📂", command=open_file, width=12).grid(row=0, column=1, padx=5)
Button(extra_frame, text="Toggle Theme 🌙", command=toggle_theme, width=15).grid(row=0, column=2, padx=5)

# Status Bar
status_bar = Label(root, text="Welcome 👋", bd=1, relief=SUNKEN,
                   anchor=W, bg="#34495e", fg="white", font=("Helvetica", 10))
status_bar.pack(side=BOTTOM, fill=X)

# Drag & Drop Support (Windows only requires tkdnd)
try:
    import tkdnd
    root.drop_target_register(DND_FILES)
    root.dnd_bind("<<Drop>>", drop_file)
except:
    status_bar.config(text="Drag & Drop not available (tkdnd missing)")

toggle_theme()  # Start in dark mode
root.mainloop()
