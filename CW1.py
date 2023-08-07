import sqlite3
import hashlib
import string
import secrets
import uuid
import pyperclip
import base64
import tkinter as tk

from tkinter import *
from tkinter import simpledialog
from tkinter import messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)  
encryptionKey = 0  

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()
cursor.executescript(""" 
CREATE TABLE IF NOT EXISTS masterpassword(
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoverykey TEXT NOT NULL);
""")
cursor.executescript(""" 
CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL);
""")

def hashpassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()
    return hash

window = Tk()
window.title("Tapash Credential_Manager")

def resetscreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")
    text = Label(window, text="Enter Recovery Key")
    text.config(anchor=CENTER)
    text.pack()
    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    text1 = Label(window)
    text1.config(anchor=CENTER)
    text1.pack()

    def getrecoverykey():
        recoverykeycheck = hashpassword(str(txt.get()).encode('utf-8'))
        cursor.execute(
            'SELECT * FROM masterpassword WHERE id = 1 AND recoverykey = ?', [(recoverykeycheck)])
        return cursor.fetchall()

    def checkRecoverkey():
        checked = getrecoverykey()
        if checked:
            firstscreen()
        else:
            txt.delete(0, 'end')
            text1.config(text='Wrong Key')

    button = Button(window, text="Check Key", command=checkRecoverkey)
    button.pack(pady=10)

def login():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("350x200")
    text = Label(window, text="Enter your main Password.")
    text.config(anchor=CENTER)
    text.pack(pady=20)
    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()
    text1 = Label(window)
    text1.pack()

    def getmasterpassword():
        checkhashed = hashpassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(
            kdf.derive(txt.get().encode()))
        cursor.execute(
            "SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkhashed)])
        return cursor.fetchall()

    def checkpassword():
        password = getmasterpassword()
        if password:
            Passwordstorage()
        else:
            txt.delete(0, 'end')
            text1.config(text="Wrong Password")

    def resetpassword():
        resetscreen()

    button = Button(window, text="SUBMIT", command=checkpassword)
    button.pack(pady=10)
    button = Button(window, text="Reset Password", command=resetpassword)
    button.pack(pady=5)

def Passwordstorage():

    def addEntry():
        tx1 = "Website"
        tx2 = "Username"
        tx3 = "Password"

        website = encrypt(popup(tx1).encode(), encryptionKey)
        username = encrypt(popup(tx2).encode(), encryptionKey)
        password = encrypt(popup(tx3).encode(), encryptionKey)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?,?,?)"""
        cursor.execute(insert_fields, (website, username, password))
        db.commit()
        Passwordstorage()

    for widget in window.winfo_children():
        widget.destroy()

    def removeEntryConfirm(input):
        result = messagebox.askquestion("Confirmation", "Are you sure you want to delete this entry?")
        if result == 'yes':
            cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
            db.commit()
            Passwordstorage()

    def password_suggester():

        def generate_password():
            length = int(length_entry.get())
            if length < 1:
                messagebox.showerror("Invalid Length", "Password length must be at least 1.")
                return
        
            alphabet = string.ascii_letters + string.digits + string.punctuation
            suggested_password = ''.join(secrets.choice(alphabet) for _ in range(length))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, suggested_password)

        suggester_window = tk.Toplevel(window)
        suggester_window.title("Password Suggester")
        suggester_window.geometry("300x200")
        suggester_window.resizable(False, False)
        length_label = tk.Label(suggester_window, text="Password Length:")
        length_label.pack(pady=10)

        length_entry = tk.Entry(suggester_window)
        length_entry.pack(pady=5)

        generate_button = tk.Button(suggester_window, text="Generate", command=generate_password)
        generate_button.pack(pady=10)

        password_entry = tk.Entry(suggester_window)
        password_entry.pack(pady=5)

        copy_button = tk.Button(suggester_window, text="Copy", command=lambda: window.clipboard_append(password_entry.get()))
        copy_button.pack(pady=10)

    window.geometry("750x400")
    window.resizable(height=None, width=None)

    txt1 = Label(window, text="Password storage")
    txt1.grid(row=0, column=0, columnspan=3, pady=5)

    button_add = Button(window, text="+", command=addEntry, width=5, height=1)
    button_add.grid(row=1, column=0, pady=10, columnspan=2)

    button_suggest = Button(window, text="Password Suggester", command=password_suggester, width=20, height=1)
    button_suggest.grid(row=1, column=1, pady=10,columnspan=2)

    lbla = Label(window, text="Website")
    lbla.grid(row=2, column=0, padx=80, sticky="n")
    lbla = Label(window, text="Username")
    lbla.grid(row=2, column=1, padx=80, sticky="n")
    lbla = Label(window, text="Password")
    lbla.grid(row=2, column=2, padx=80, sticky="n")

    cursor.execute('SELECT * FROM vault')

    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()
            if len(array) == 0:
                break

            lbl1 = Label(window, text=decrypt(array[i][1], encryptionKey), font=("Helvetica", 12))
            lbl1.grid(column=0, row=i+3)
            lbl2 = Label(window, text=decrypt(array[i][2], encryptionKey), font=("Helvetica", 12))
            lbl2.grid(column=1, row=i+3)
            lbl3 = Label(window, text=decrypt(array[i][3], encryptionKey), font=("Helvetica", 12))
            lbl3.grid(column=2, row=i+3)

            btn = Button(window, text="Delete", command=lambda idx=array[i][0]: removeEntryConfirm(idx),
                        relief="raised", borderwidth=2, font=("Helvetica", 10, "bold"))
            btn.grid(column=3, row=i+3, pady=5)

            cursor.execute('SELECT * FROM vault')
            if len(cursor.fetchall()) <= i:
                break
            i += 1

def firstscreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("350x250")
    text = Label(window, text="Create your LogIn Password")
    text.config(anchor=CENTER)
    text.pack(pady=25)

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    text1 = Label(window, text="Re-enter the Password")
    text1.pack(pady=30)

    text2 = Entry(window, width=20, show="*")
    text2.pack()
    text2.focus()

    def savePassword():
        if txt.get() == text2.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"
            cursor.execute(sql)

            hashedpass = hashpassword(txt.get().encode('utf-8'))

            key = str(uuid.uuid4().hex)
            recoverykey = hashpassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(
                kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoverykey)
        VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedpass), (recoverykey)))
            db.commit()

            recoveryScreen(key)
        else:
            text.config(text="Password doesn't match")

    button = Button(window, text="SAVE", command=savePassword)
    button.pack(pady=10)


def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("350x250")
    text = Label(window, text="Save this key to recover account")
    text.config(anchor=CENTER)
    text.pack()

    text1 = Label(window, text=key)
    text1.config(anchor=CENTER)
    text1.pack()

    def copykey():
        pyperclip.copy(text1.cget("text"))

    button = Button(window, text="Copy Key", command=copykey)
    button.pack(pady=10)

    def done():
        Passwordstorage()
    button = Button(window, text="Done", command=done)

    button.pack(pady=10)

def popup(text):
    answer = simpledialog.askstring("Input Credentials", text)
    return answer

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login()
else:
    firstscreen()
window.mainloop()