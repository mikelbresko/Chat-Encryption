from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from OpenSSL import crypto
import OpenSSL.crypto
import pyaes
import pbkdf2
import binascii
import secrets
import os
import rsa
import base64
import random

# START KEY LOADERS
def load_public_key():
	public_key = RSA.importKey(open("server-key-public.pem", "rb").read())
	return public_key.exportKey('PEM')

def load_private_key():
	private_key = RSA.importKey(open("server-key-private.pem", "rb").read())
	return private_key

def load_public_ca():
	public_key = RSA.importKey(open("ca-key-public.pem", "rb").read())
	return public_key

def generate_sym_key():
	sym_key = os.urandom(32)
	return sym_key
# END KEY LOADERS

#encrypt symmetric key with public key
def encrypt_sym_key(public_key, sym_key):
	key_encryptor = PKCS1_OAEP.new(public_key)
	cipher_key = key_encryptor.encrypt(sym_key)
	return cipher_key

#decrypt symmetric key with private key
def decrypt_sym_key(private_key, ciphertext):
	key_decryptor = PKCS1_OAEP.new(private_key)
	plain_key = key_decryptor.decrypt(ciphertext)
	return plain_key

# encrypt a message with sym key
def sym_encrypt(sym_key, msg):
	aes = pyaes.AESModeOfOperationCTR(sym_key)
	ciphertext = aes.encrypt(msg)

	return ciphertext

# decrypt a message with sym key
def sym_decrypt(sym_key, msg):
	aes = pyaes.AESModeOfOperationCTR(sym_key)
	text = aes.decrypt(msg)

	return text

def read_certificates(username):
	certString = ''
	for filename in os.listdir(os.getcwd()):
		if filename.endswith(".cert"):
			fSplit = filename.split('.')
			fName = fSplit[0]
			if username == fName:
				f = open(filename, "rb")
				certString = f.read(256)
	return certString

def generate_DH_sharedKey():
	private_key = ec.generate_private_key(ec.SECP384R1())
	peer_public_key = ec.generate_private_key(ec.SECP384R1()).public_key()
	shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

	return shared_key

def get_DH_key(shared_key):
	derived_key = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=b'handshake data',).derive(shared_key)

	return derived_key
