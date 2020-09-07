import hashlib
from errors import *
from hmac import compare_digest as compare_hash

_salt = 'caRxywfzaeDKJ3J2293DdcdSZLAdajdjdpcc'

def encrypt_password(plaintext):
    try:
        hashed = hashlib.pbkdf2_hmac('sha256', plaintext.encode('utf-8'), _salt.encode('utf-8'), 100000)
        return hashed.hex()
    except Exception as crypto_exception:
        raise CryptoError(crypto_exception)

def verif_password(user_input, password):
    try:
        hashed_user_input = hashlib.pbkdf2_hmac('sha256', user_input.encode('utf-8'), _salt.encode('utf-8'), 100000) 
        return compare_hash(hashed_user_input.hex(), password)
    except Exception as crypto_exception:
        raise CryptoError(crypto_exception)
