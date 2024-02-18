import mysql.connector
import bcrypt
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

#Database Connection
def create_database_connection():
    return mysql.connector.connect(
        host="",#Input MySQL Host Address
        user="",#Input MySQL Username
        password="",#Input MySQL Password
        database="")#Input MySQL Database Name
#New Databse For Storing Salt
def create_salt_connection():
    return mysql.connector.connect(
        host="",#Input MySQL Host Address
        user="",#Input MySQL Username
        password="",#Input MySQL Password
        database="")#Input MySQL Database Name
#Create Password Database Tables If not Exists
def create_database(connection):
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS KeyPassword (
            id INT AUTO_INCREMENT PRIMARY KEY,
            Password VARCHAR(255) NOT NULL UNIQUE,
            RecoveryKey VARCHAR(255) NOT NULL
        )
    """)
    connection.commit()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Vault (
            id INT AUTO_INCREMENT PRIMARY KEY,
            Website TEXT NOT NULL,
            Username TEXT NOT NULL,
            Password TEXT NOT NULL
        )
    """)
    connection.commit()
    cursor.close()
#Create Salt Database Table If not Exists
def create_salt_connect(connection2):
    cursor = connection2.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS SaltManager (
            id INT PRIMARY KEY,
            Salt VARCHAR(255) NOT NULL
                    )
    """)
    connection.commit()
    cursor.close()

#Get Our Salt And Create Encryption Key
connection = create_database_connection()
create_database(connection)
cursor = connection.cursor()



def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


def popUP(text):
    answer = simpledialog.askstring("Input String", text)
    return answer

window = Tk()

window.title("PyPass Password Vault")


def salt_creator():
    salt = bcrypt.gensalt()
    return salt

def salt_append():
    connection2 = create_salt_connection()
    create_salt_connect(connection2)
    salt = salt_creator()
    cursor2 = connection2.cursor(buffered=True)
    cursor2.execute("Select * FROM SaltManager")
    if cursor2.fetchall():
        sql = "DELETE FROM SaltManager WHERE id = 1"
        cursor2.execute(sql)
        cursor2.execute("""INSERT INTO SaltManager
                (id, Salt) VALUES (1, %s)""", [(salt)])
        connection2.commit()
        cursor2.close()
    else:
        cursor2.execute("""INSERT INTO SaltManager
                (id, Salt) VALUES (1, %s)""", [(salt)])
        connection2.commit()
        cursor2.close()


def HashPassword(password):
    connection2 = create_salt_connection()
    create_salt_connect(connection2)
    cursor2 = connection2.cursor()
    query = ("SELECT Salt FROM SaltManager WHERE id = 1")
    cursor2.execute(query)
    salt = cursor2.fetchone()
    opin = salt[0]
    opin.encode('utf-8')
    hashed_password = hashlib.sha512(opin.encode('utf-8'))
    hashed_password.update(password)
    hashed_password.hexdigest()
    return hashed_password

def originalLogin():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("450x250")
    lbl = Label(window, text = "Create Key Password")
    lbl.config(anchor=CENTER)
    lbl.pack()


    txt = Entry(window, width=15, show="*")
    txt.pack(pady = 5)
    txt.focus()

    lbl1 = Label(window, text = "Re-enter Password")
    lbl1.config(anchor=CENTER)
    lbl1.pack() 

    txt1 = Entry(window, width=15, show="*")
    txt1.pack(pady = 5)

    lbl2 = Label(window)
    lbl2.pack(pady = 2) 

    def savePassword():
        cursor = connection.cursor(buffered=True)
        if txt.get() == txt1.get():
            sql = "DELETE FROM KeyPassword WHERE id = 1"
            cursor.execute(sql)
            hashedPassword = HashPassword(txt.get().encode('utf-8')).hexdigest()
            key = str(uuid.uuid4().hex)
            recoveryKey = hashlib.sha512(key.encode('utf-8')).hexdigest()

            global EncryptKey
            EncryptKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))


            cursor.execute("""INSERT INTO KeyPassword
            (Password, RecoveryKey) VALUES (%s, %s)""",[hashedPassword, recoveryKey])
            connection.commit()
            cursor.close()

            recoverScreen(key)
        else:
            lbl2.config(text="Passwords do not Match")
    btn = Button(window, text = "Save", command=savePassword)
    btn.pack(pady = 10)


def recoverScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("450x250")
    lbl = Label(window, text = "Save Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text = key)
    lbl1.config(anchor=CENTER)
    lbl1.pack() 

    def CopyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text = "Save", command=CopyKey)
    btn.pack(pady = 10)

    def Done():
        PyPassVault();
    
    btn = Button(window, text = "Done", command=Done)
    btn.pack(pady = 10)

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("450x250")
    lbl = Label(window, text = "Enter Recovery Key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=15)
    txt.pack(pady = 5)
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack() 

    def getRecoveryKey():
        cursor = connection.cursor()
        recveryKeyCheck = hashlib.sha512(txt.get().encode('utf-8')).hexdigest()
        cursor.execute("SELECT * FROM KeyPassword WHERE id = 1 AND RecoveryKey = %s", [(recveryKeyCheck)])
        return cursor.fetchall()
    
    def CheckRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            originalLogin()
        else:
            txt.delete((0, 'end'))
            lbl1.config(text = "Wrong Key" )
    
    btn = Button(window, text = "Check Key", command=CheckRecoveryKey)
    btn.pack(pady = 10)

    

def login_screen():
    window.geometry("450x250")
    lbl = Label(window, text = "Enter Key Password")
    lbl.config(anchor=CENTER)
    lbl.pack()


    txt = Entry(window, width=15, show="*")
    txt.pack(pady = 5)
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack() 

    def getMasterPassword():
        cursor = connection.cursor()
        checkHashedPassword = HashPassword(txt.get().encode('utf-8')).hexdigest()
        global EncryptKey
        EncryptKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute("SELECT * FROM KeyPassword WHERE id = 1 AND password = (%s)", [(checkHashedPassword)])
        return cursor.fetchall()
    
    def Check_Password():
        match = getMasterPassword()
        if match:
            PyPassVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    def ResetPass():
        resetScreen();

    btn = Button(window, text = "Done", command=Check_Password)
    btn.pack(pady = 10)

    btn = Button(window, text = "Reset Password", command=ResetPass)
    btn.pack(pady = 10)

def PyPassVault():
    cursor = connection.cursor(buffered=True)
    for widget in window.winfo_children():
        widget.destroy()

    def Add_Account():
        cursor = connection.cursor(buffered=True)
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = encrypt(popUP(text1).encode(), EncryptKey)
        username = encrypt(popUP(text2).encode(), EncryptKey)
        password = encrypt(popUP(text3).encode(), EncryptKey)

        cursor.execute( """INSERT INTO Vault(Website, Username, Password)
                VALUES(%s, %s, %s)""", [website, username, password])
        connection.commit()

        PyPassVault()
    
    def Remove_Account(input):
        cursor = connection.cursor()
        cursor.execute("DELETE FROM Vault WHERE id = %s",(input,) )
        connection.commit()

        PyPassVault()


    window.geometry("750x400")
    lbl = Label(window, text = "PyPass Vault")
    lbl.grid(column=1)

    btn = Button(window, text = "Add Account", command=Add_Account)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM Vault")
    if(cursor.fetchall() != None):
        i = 0
        while TRUE:
            cursor.execute("SELECT * FROM Vault")
            array = cursor.fetchall()
            try:
                lbl1 = Label(window, text=(decrypt(array[i][1], EncryptKey)), font=("Calibri", 12))
                lbl1.grid(column=0, row=i+3)
                lbl1 = Label(window, text=(decrypt(array[i][2], EncryptKey)), font=("Calibri", 12))
                lbl1.grid(column=1, row=i+3)
                lbl1 = Label(window, text=(decrypt(array[i][3], EncryptKey)), font=("Calibri", 12))
                lbl1.grid(column=2, row=i+3)
            

                btn = Button(window, text="Delete", command= partial(Remove_Account, array[i][0]))
                btn.grid(column=3, row=i+3, pady=10)
            except Exception:
                pass

            i+=1
            cursor.execute("SELECT * FROM Vault")
            if(len(cursor.fetchall()) <= i):
                break
            

connection2 = create_salt_connection()
create_salt_connect(connection2)
cursor2 = connection2.cursor()
query = ("SELECT Salt FROM SaltManager WHERE id = 1")
cursor2.execute(query)
if (cursor2.fetchall() != None):
    salt_append()
    opin=""
else:
    salt = cursor2.fetchall()
    opin = salt[0]
    opin.encode('utf-8')
    cursor2.close()

backend = default_backend()

kdf = PBKDF2HMAC(
    algorithm = hashes.SHA512(),
    length = 32,
    salt = str.encode(opin),
    iterations = 100000,
    backend = backend
)

EncryptKey = 0

cursor.execute("SELECT * FROM KeyPassword")
if cursor.fetchall():
    login_screen();
else:
    originalLogin()

cursor.close()
window.mainloop()