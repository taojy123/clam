# python3.7
# pip install cryptography==2.6.1
# pip install pyaes==1.6.1

import os
import hashlib
import hmac
import pyaes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# default_backend：cryptography.hazmat.backends.openssl.backend


print('============ test for sha256 hmac =============')

hkey = b'clam'
hkey = hmac.new(hkey, b'aaa', hashlib.sha256).digest()
hkey = hmac.new(hkey, b'bbb', hashlib.sha256).digest()
hkey = hmac.new(hkey, b'ccc', hashlib.sha256).digest()
print(hkey)
print(len(hkey))

assert hkey == b'I\x06z\xea\x97\xe6b\xc5\x99[\xad\xe9\xf5\x01\xbbD\xc9\x1a\xd3\x9cze\x01\xc4j`\xca\xa5^\xa3k\xce'


print('============ test for generate key =============')

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_pem = public_pem.decode()
print(public_pem)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(hkey),
    # BestAvailableEncryption evp_cipher: self._lib.EVP_get_cipherbyname(b"aes-256-cbc")
    # encryption_algorithm=serialization.NoEncryption(),
)
private_pem = private_pem.decode()
print(private_pem)

print('============ test for encrypt and decrypt =============')

content = b'hello world!'
# content = os.urandom(32)
print(content, len(content))

public_key = serialization.load_pem_public_key(public_pem.encode(), backend=default_backend())
content_en = public_key.encrypt(content, padding.PKCS1v15())
print(content_en, len(content_en))

private_key = serialization.load_pem_private_key(private_pem.encode(), password=hkey, backend=default_backend())
content_de = private_key.decrypt(content_en, padding.PKCS1v15())
print(content_de)

assert content == content_de

print('============ test rsa for known data ==============')

private_pem = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIL0bTkf2izUcCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBC6UUV8u0pCQqE7Yc2EOjvlBIIE
0EMa92/4oYbOGv26j+fcOnqiy8/9Uv2lp2jick1CXLDGTmXx4Tcv1QSSs2cl3dJ2
EDPIFaxnV346qXK3pFhKIeYTN+0CBZBfbaTvfdp9JaIPm5P4mHfJL8TjhYKvb0uL
J2N1+f9udDy8VHEHRKVIko/gbyVWEEjnfBNGpLaD9J/pBN5y0wDwISJWPPMKAP8J
iyuhgQjsm8OddXzE8xpI3Ky6AxlHiCuPb9C7duNlkZEsGoEP0Hkc1eMHcwcruRG/
CNQhvdNbAjadgOZsS/ZhmyUqYYtwu1Xfu59bV73uIqsLYwuIJ1YReXoFUTVbDRbE
BaNAlMwClQl1RHtuQxIzX8yUk8o6TWoYwi24CbNyT9yiZPzgzZ5atyNqPe1gu6AB
KWnQfUbYCYRjEw//IrZdKbLLHzlzpGNWZeKbVnJZDvD/05rqkqBlmAkegICUbiDh
gCr26JLfXqko2xOMx2hkmffmuTLXQF233qAD4gbMvVM0SYCPzTYLePmAS8Y9imlt
5RCMbswEGWZjaNuk6sgK5WfVTLTwDA1jC7ORcOFdFAuiuJXbSYyMzuBYDCMuLH2h
YCXdL7CJMlbAWD+vDSm4o5kQ68xNfTaGcAnhIwh6DwG4w5blCkTvVOnIM201Maer
LtVNfGsN1NJY0mfYfjGxHOISifb2yNnRPMPqo96mv/d0SDffj5BdKGa88YXA/NHP
/hUGbqQgDAHQawuRWbcEBsPOr23tJSQLENXfqbJ3d0fUfXb3oiscXDHi1wOw34/O
Spc7FRnUql+BYOIyA3SitXFCe479YnzChpB/lhRJEqTGgXajj9L5/gWN4Nd2jQ0S
33gRD68oiDVD/4SWoqngCxdAFHznHJQnJHg74xAIly4R+rQNrj9mbZITc+08R6EF
jVaszRxQU66KSV0A2pz5LNGV4rMwkLThMepGhbOWq9B534MncXNgaAaRAt36IXz1
MUwcQMVeHNVaXrPCspGv09Kc4ki+DBl38ACBzv7VXZnyA5Vku82fz3R9B9VrAqbO
ZbvNik5yhx82CSG83/xes8KOsuZsM1TFVcwccX9CIUFJs8nU1KMZvO4/z+HOGXvR
WWXJX/7qmNEwXsyWWIt0U+Xo64aUw40Ec8APwxRDmneIF92Mx+z60z0gtBLEqVSe
RyG9KBJwcqBHAo887EBkdN6zC7cgspRk8guWLAF7kREI+osvB+eoyy6ZnCkLP9vv
E6LjbrrVbyS8mNDoRGht8XxtFoQRdqJNXPXtyHQVTSjnQDaLUK6Vy8a9rGv3FJje
lyxuR/hTz4/+6Btpz8N8/LC1mrcd7D32qGP4Xgie0gGTF+YoyahCinFqRmvqQkHZ
K+Snd+DKp6bEG6e4acto0BNz84rHUJX5C38nwD1bvLdYz4HvYMmNkcRaUUCEGuRB
9D75W683XkbYhqGzXIrcOiIxsXZMWp8JZBVITmtmNhIFLbRqWjDLq54rKGk6yzI1
BZWrO82ao2wWpLCeGNjWwW47OU9rXwuZ4AMGYn6xjimKPxHzlrl2He4FUO+9mMwr
ZbRbZ6InuRQo1VsJ5wRwS4S/BRwvQlXUejefRIpitjFZ9ebWt8wEPFnIsaXlxqlx
eLVqjgfPcsX7menxrn1HXqWKTACwIqb9K9sXpcGxTm7J
-----END ENCRYPTED PRIVATE KEY-----"""
content_en = b'\x17\x17\xf8+\xbb\x91\xc6\xa1\xe0\xe3\xac\xca\x1d\xf0\x9f\xa3\xef\x8d\xec\x1d\xba?\xf5\xf9\\(\xfbdLG\xfc\xf7\xfc\x13\xbe\x92c_Vt\xa0\xb9PTf}tZ\\FW\xfdgAyY\xf9^\x90\xed\xe1\x7f\xb7eq\xceiH#+\x13i\x94\xf4L\x07\x95*+`\xa0\x05\xfe\xfcr\xbe\xb0\x9eug\xa1\xab\xf1\x9d \xc8` \x12\xed\x05\xa1A\x1f\x1eA{\xce\xc5\xbe\x05\xdfD,\x83\x0f\xae\xbd\xd2\x08?\xc6\x88_\xb6\x0c\xe4\x88\x0c\\\x06\xa8j\xa3^;h\x0b\xaf\x17J_\x88\xcd\x88\x8d\xc0\x99O\xffs\x17\xa9(\x967\x1bi\x88d\xda\x81\xd2\xee\t\x13s\x82\xad8\xf5\xc1\xad\x9ck\x9f\xdf\xd7\xb8 \x8f\x99u\xaa8\xda\xad\xff\xb4h\x04u\xfe\xdd\n\x01\xac\xbd\xe6\x80Y\x90\xf1\x88\x92\xd5\xf7\xbf\xc4IE\xab\x10\x0e\xa7/`\x9e\xbd\xcf}f]\x95\x85\x00\xfbtX\x16\xe0\xd8\xd5\x86\x1dJ\x9b\xa7\xb6\xd9\x81\xa3\x1d(\x9a\xc3E\x81\x9fY\x96,\x0b@\x81\x9e'


private_key = serialization.load_pem_private_key(private_pem.encode(), password=b'abc123', backend=default_backend())
content_de = private_key.decrypt(content_en, padding.PKCS1v15())
print(content_de)

assert content_de == b'hello world!'


print('================== test for aes ctr ==================')

key = os.urandom(32)

print(key)

content = b'hello world!!'
# content = open('C:/Users/taojy/Documents/aaa.pptx', 'rb').read()

print(content, len(content))

aes = pyaes.AESModeOfOperationCTR(key)
content_en = aes.encrypt(content)

print(content_en, len(content_en))

aes = pyaes.AESModeOfOperationCTR(key)
content_de = aes.decrypt(content_en)

# open('C:/Users/taojy/Documents/aaaa.pptx', 'wb').write(content_de)

assert content == content_de

print('================== test aes for known data ==================')



key = b'\x81\x85\xb4T\xf7\xf4\xf8s\xb4\x1b\x12\x94*h\xd0\xd1\xd5\x9f\xc9}(3\xda_\x17\xedS*;\x91 B'

aes = pyaes.AESModeOfOperationCTR(key)
content = b'hello world!!'
content_en = aes.encrypt(content)

assert content_en == b'zR/\xd15\t\xb3V\xce\x9a\xc8\xaa!'

aes = pyaes.AESModeOfOperationCTR(key)
content_de = aes.decrypt(content_en)

print(content_de)

assert content == content_de

print('======================================================')


