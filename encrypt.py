from cryptography.fernet import Fernet
import rsa
import base64
import hashlib

users = ['adham', 'ahmed']
msg = 'Hello other user'
key = Fernet.generate_key()

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

def adduser(name):
    user = input('Enter the username: ')
    generateKeys(user)
    users.append(user)


sender = input("Enter the name of the sender: ")
while sender not in users:
    print("Error the sender is not registered")
    sender = input("Enter the name of the sender: ")

reciver = input("Enter the name of the reciver: ")
while reciver not in users:
    print("Error the reciver is not registered")
    reciver = input("Enter the name of the reciver: ")

while sender == reciver:
    print("Error the sender cannot be the same as the reciver")
    reciver = input("Enter the name of the reciver: ")

symkey = key.decode()

fernet = Fernet(key)

encMessage = fernet.encrypt(msg.encode())

typ = 'pubkey.pem'
loc = reciver + typ
with open(loc, 'rb') as p:
    publicKey = rsa.PublicKey.load_pkcs1(p.read())

typ = 'privkey.pem'
loc = sender + typ
with open(loc, 'rb') as p:
    privateKey = rsa.PrivateKey.load_pkcs1(p.read())

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)

encKey = encrypt(symkey,publicKey)

hashed = hashlib.sha256(msg.encode('utf-8')).hexdigest()

encSign = rsa.sign(msg.encode('ascii'),privateKey, 'SHA-1')



print("This message is from: ", sender, " to: ", reciver)
print('\n')
print('The Encrypted symmetric session key is: ')
print(encKey)
print('\n')
print("The encrypted message is: ")
print(encMessage)
print('\n')
print('Verification hash is: ')
print(hashed)
print('\n')
print('Sender Signature is: ')
print(encSign)

