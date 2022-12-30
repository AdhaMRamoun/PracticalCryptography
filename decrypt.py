from cryptography.fernet import Fernet
import rsa
import base64
import hashlib
sender = 'adham'
reciver = 'ahmed'
enc_key = b'UY\x16\r\x8f\xa6\x0f}\x83\xa9n\xde\x05\x1cU\x1c\x8e)0\xe4\xdf\xfa&\xf0\xecu\xc6\x97J\x8e\x0e\xec-\x93z\x9b\xff\xa3\xdc\x02\x82\x84\xeb\x81\xc5m\xbd\x9a\xd7\xedE\x9f\xeb\x954\xe4\xcaN\xb2R\xd1\x82"\x860\xbf?d\xd3\xc7\xb0\xd1zu\xfb\xfe\x90\xc8\x9e\x98\xf0\xa9i2[}v[\x0fg<@|A\x16\xb2\x93\xcay}\xbbu\x17\x16\xdat\xc6\xcf\x1f\xc6\xf1u\xa7\x9a\x0f\xb5\x7f\x9e\x03\xcf`\x01\xee\xbbi-N\xde'
enc_msg = b'gAAAAABjqapciKnKvBBIS7KC9veanfRzukPCo67AJGcJPP27uFMZF0EIOYMy2tWqMiQWWOGZNmEMHlHWzqOXxD49cBNRNBEcLQ=='
senthash = 'd82aeec82597f82e8c92505a2b77d6f19c8056a476380c759f8c894d72a25bab'
sentsign = b'\x8b\x96\xec\xa6u\xb3\xe4\xb7|\xb3\x9f\x13\x86\xa91\x0b/\\r+\x05\xb3(\xfas\x98^\x1d\x1b\xb2~\xc6E`\x974\x80#\xf2\x90y\r\xa9\xb1\xc1.q\xabn\xc3B\xe9]N\xc7\xb3\xf8\xc9\x0e\x0eV\x8c\x91p@\xee5\xfdX\x82(d\xa8\xaeg\x98r`\xbbK\xb4\x0c\x89.\x82?\xb9k\xe7\xc7\x07\x7f{\xef\xd1L\x8b\\\xd5\x8f\xe2Cu\xd7S\xfc!_vPx=\x95`\xe3\x9b\xe6\xf4U\x9b\xe9\xbf\xe7\xa8\xd6\xc5;R'

typ = 'pubkey.pem'
loc = sender + typ
with open(loc, 'rb') as p:
    publicKey = rsa.PublicKey.load_pkcs1(p.read())

typ = 'privkey.pem'
loc = reciver + typ
with open(loc, 'rb') as p:
    privateKey = rsa.PrivateKey.load_pkcs1(p.read())

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

x = decrypt(enc_key,privateKey)
print(x)
decrypted_key = x.encode()
print(decrypted_key)
fernet = Fernet(decrypted_key)
print(fernet)
decMessage = fernet.decrypt(enc_msg).decode()
print(decMessage)

hashed = hashlib.sha256(decMessage.encode('utf-8')).hexdigest()

x = rsa.verify(decMessage.encode('ascii'), sentsign, publicKey)
if hashed != senthash:
    print("The hashed are not equal")
else:
    if x != 'SHA-1':
        print("Failed to authenticate signature")
    else:
        print('Message signature and hash verified')
        print('Message from:', sender, 'Sent to:',reciver)
        print(decMessage)

