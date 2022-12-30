from cryptography.fernet import Fernet
import rsa
import base64
import hashlib
from tkinter import *
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog

users = ['adham', 'ahmed']
passwords = ['12345', 'password']



def generateKeys(user):
    (publicKey, privateKey) = rsa.newkeys(1024)
    typ = 'pubkey.pem'
    loc = user+typ
    with open(loc, 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    typ = 'privkey.pem'
    loc = user+typ
    with open(loc, 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

sender = ''
def adduser():
    user = input('Enter the username: ')
    password = input('Enter the password: ')
    generateKeys(user)
    users.append(user)
    passwords.append(password)

        

def main_screen():
    msg = Tk()
    msg.withdraw()

    username = simpledialog.askstring("Nickname", "Please enter the username", parent= msg)
    if username not in users:
        username = simpledialog.askstring("Nickname", "The name you entered is not in the userlist", parent= msg)

    while username not in users:
        print("Error the user is not registered enter the name again")
        username = input("Enter the name of the user: ")


    index = users.index(username)
    pas = passwords[index]
    x = simpledialog.askstring("Nickname", "Please enter the password", parent= msg)
    while x != pas:
        x = simpledialog.askstring("Nickname", "WRONG PASSWORD", parent= msg)

    ch = simpledialog.askstring("Nickname", "Enter 1 to encrypt and 2 to decrypt: ", parent= msg)
    while ch != '1' and ch != '2':
        ch = simpledialog.askstring("Nickname", "Enter 1 to encrypt and 2 to decrypt: ", parent= msg)

    if ch == '2':
        reciver = username
        sender = simpledialog.askstring("Nickname", "Enter the name of the sender", parent= msg)
        while sender not in users:
            sender = simpledialog.askstring("Nickname", "The name you entered is not in the userlist", parent= msg)
        while sender == reciver:
            sender = simpledialog.askstring("Nickname", "The Sender cannot be the same as the reciever", parent= msg)

        enc_key = simpledialog.askstring("Nickname", "Enter the Encrypted Session Key: ", parent= msg)
        enc_key = enc_key.encode(encoding="ascii",errors="ignore")
        x = enc_key.decode('unicode_escape').encode("raw_unicode_escape")
        mmsg = simpledialog.askstring("Nickname", "Enter the Encrypted Message: ", parent= msg)
        enc_msg = mmsg.encode()
        senthash = simpledialog.askstring("Nickname", "Enter the Message Hash: ", parent= msg)
        sentsign = simpledialog.askstring("Nickname", "Enter the Message Signature: ", parent= msg)
        sentsign = sentsign.encode()
        s = sentsign.decode('unicode_escape').encode("raw_unicode_escape")
        typ = 'pubkey.pem'
        loc = sender + typ
        with open(loc, 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())

        typ = 'privkey.pem'
        loc = reciver + typ
        with open(loc, 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        
        print(x)
        print(privateKey)
        z = decrypt(x,privateKey)
        decrypted_key = z.encode()
        fernet = Fernet(decrypted_key)
        decMessage = fernet.decrypt(enc_msg).decode()
        hashed = hashlib.sha256(decMessage.encode('utf-8')).hexdigest()
        x = rsa.verify(decMessage.encode('ascii'), s, publicKey)
        messagebox.showinfo(title=None, message=decMessage)

    elif ch == '1':
        sender = username
        reciver = simpledialog.askstring("Nickname", "Enter the name of the reciever", parent= msg)
        while reciver not in users:
            reciver = simpledialog.askstring("Nickname", "The name you entered is not in the userlist", parent= msg)
        while sender == reciver:
            reciver = simpledialog.askstring("Nickname", "The Sender cannot be the same as the reciever", parent= msg)


        msgg = simpledialog.askstring("Nickname", "Enter the message you want to encrypt", parent= msg)
        key = Fernet.generate_key()
        symkey = key.decode()
        fernet = Fernet(key)
        encMessage = fernet.encrypt(msgg.encode())
        typ = 'pubkey.pem'
        loc = reciver + typ
        with open(loc, 'rb') as p:
            publicKey = rsa.PublicKey.load_pkcs1(p.read())

        typ = 'privkey.pem'
        loc = username + typ
        with open(loc, 'rb') as p:
            privateKey = rsa.PrivateKey.load_pkcs1(p.read())
        encKey = encrypt(symkey,publicKey)
        hashed = hashlib.sha256(msgg.encode('utf-8')).hexdigest()
        encSign = rsa.sign(msgg.encode('ascii'),privateKey, 'SHA-1')
        a ="This message is from: " + username + " to: "+ reciver +"\n"
        b ='\n The Encrypted symmetric session key is: ' + str(encKey) +"\n"
        c ="\n The encrypted message is: " + str(encMessage) + '\n'
        d ='\n Verification hash is: ' + str(hashed) + "\n"
        e ='\n Sender Signature is: ' + str(encSign) + "\n"
        ms = a + b + c + d + e
        messagebox.showinfo(title=None, message=ms)

        text = Text(msg)  
        text.insert(INSERT, ms)  
        text.pack() 

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


"""
    if hashed != senthash:
        print("The hashed are not equal")
    else:
        if x != 'SHA-1':
            print("Failed to authenticate signature")
        else:
            print('Message signature and hash verified')
            print('Message from:', send, 'Sent to:',rec)
            print(decMessage)

"""

main_screen()