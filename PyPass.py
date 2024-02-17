import mysql.connector, hashlib
from tkinter import *

#Database Connection
def create_database_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="TheDrought?2",
        database="PyPassVault")

def create_database(connection):
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS KeyPassword (
            id INT PRIMARY KEY,
            Password VARCHAR(255) NOT NULL UNIQUE
                    )
    """)
    connection.commit()
    cursor.close()
connection = create_database_connection()
create_database(connection)
cursor = connection.cursor()



window = Tk()

window.title("PyPass Password Vault")

def originalLogin(connection):
    window.geometry("450x250")
    lbl = Label(window, text = "Create Key Password")
    lbl.config(anchor=CENTER)
    lbl.pack()


    txt = Entry(window, width=15, show="*")
    txt.pack(pady = 5)
    txt.focus()

    lbl1 = Label(window, text = "Re-enter Password")
    lbl1.pack() 

    txt1 = Entry(window, width=15, show="*")
    txt1.pack(pady = 5)
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack(pady = 2) 

    def savePassword():
        cursor = connection.cursor(buffered=True)
        if txt.get() == txt1.get():
            hashedPassword = txt.get()
            cursor.execute("""INSERT INTO KeyPassword
            (Password) VALUES (%s)""", [(hashedPassword)])
            connection.commit()
            cursor.close()

            PyPassVault()
        else:
            lbl2.config(text="Passwords do not Match")
    btn = Button(window, text = "Save", command=savePassword)
    btn.pack(pady = 10)




def login_screen(connection):
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
        checkHashedPassword = txt.get()
        cursor.execute("SELECT * FROM KeyPassword WHERE id = 1 AND password = (%s)", [(checkHashedPassword)])
        return cursor.fetchall()
    
    def Check_Password():
        match = getMasterPassword()
        if match:
            PyPassVault()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")


    btn = Button(window, text = "Done", command=Check_Password)
    btn.pack(pady = 10)

def PyPassVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("750x400")
    lbl = Label(window, text = "PyPass Vault")
    lbl.config(anchor=CENTER)
    lbl.pack()






cursor.execute("SELECT * FROM KeyPassword")
if cursor.fetchall():
    login_screen(connection);
else:
    originalLogin(connection)
cursor.close()
window.mainloop()