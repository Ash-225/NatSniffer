import random
import base64
from sympy import isprime, mod_inverse

def generate_large_prime(bitsize=1024):
    while True:
        prime_candidate = random.getrandbits(bitsize)
        if isprime(prime_candidate):
            return prime_candidate

def generate_keys(bitsize=1024):
    p = generate_large_prime(bitsize // 2)
    q = generate_large_prime(bitsize // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  # Commonly used prime exponent
    d = mod_inverse(e, phi)
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key

def encrypt(message, public_key):
    e, n = public_key
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    encrypted_message = pow(message_int, e, n)
    encrypted_bytes = encrypted_message.to_bytes((encrypted_message.bit_length() + 7) // 8, byteorder='big')
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_base64

def decrypt(encrypted_base64, private_key):
    d, n = private_key
    encrypted_bytes = base64.b64decode(encrypted_base64.encode('utf-8'))
    encrypted_message = int.from_bytes(encrypted_bytes, byteorder='big')
    decrypted_message_int = pow(encrypted_message, d, n)
    decrypted_message_bytes = decrypted_message_int.to_bytes((decrypted_message_int.bit_length() + 7) // 8, byteorder='big')
    
    try:
        decrypted_message = decrypted_message_bytes.decode('utf-8')
    except UnicodeDecodeError:
        decrypted_message = decrypted_message_bytes.rstrip(b'\x00').decode('utf-8', 'ignore')
        
    return decrypted_message

def encrypt_file(input_file_path, output_file_path, public_key):
    with open(input_file_path, 'r') as file:
        content = file.read()
        
    encrypted_message = encrypt(content, public_key)
    
    with open(output_file_path, 'w') as file:
        file.write(encrypted_message)

def decrypt_file(input_file_path, output_file_path, private_key):
    with open(input_file_path, 'r') as file:
        encrypted_base64 = file.read()
        
    decrypted_message = decrypt(encrypted_base64, private_key)
    
    with open(output_file_path, 'w') as file:
        file.write(decrypted_message)

# Generate keys
public_key, private_key = generate_keys()

# File paths
input_file_path = 'dictionary.csv'
encrypted_file_path = 'encrypted_dictionary.txt'
decrypted_file_path = 'decrypted_dictionary.txt'

# Encrypt the file
encrypt_file(input_file_path, encrypted_file_path, public_key)
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")
print(f"Encrypted file saved at: {encrypted_file_path}")

# Decrypt the file
decrypt_file(encrypted_file_path, decrypted_file_path, private_key)
print(f"Decrypted file saved at: {decrypted_file_path}")
