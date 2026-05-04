# How to develop an end-to-end encrypted chat system using RSA-cryptography and evaluate why RSA is more secure than other ciphertexts such as Advanced Encryption Standard (AES) or Data Encryption Standard (DES) 
Hi, my name is Max Hennebry and I will outline the steps to develop a prototype for a user input using Python code in order to create a secure RSA-cryptosystem by means of end-to-end encryption that will encrypt and decrypt messages and protocols using RSA and compare its runtime performance with those of AES and DES algorithms with regard to the following key evaluation parameters wherever possible:
- size of keys generated
- program runtime
- public and private keys generated
- size of prime numbers generated
- security of functions hashed
- length of message within protocol
Fortunately, Python has certain tools that can help evaluate all the above parameters.

1. Open Python console and install all packages required to test the prototype, namely *pycryptodome* and *cryptography*, as follows:
```python
"""Installing all the relevant packages for testing."""
!pip install pycryptodome cryptography
```

2. Import all the necessary modules from the packages mentioned above, i.e. *cryptography* and *pycryptodome* (also known as *Crypto*):
```python
"""Importing all necessary modules from pycryptodome and cryptography packages for the algorithms."""
from cryptography.hazmat.primitives import asymmetric, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad
import socket
import base64
import time
import hashlib
```

3. Create a suitable class in order to encrypt and decrypt messages using the above algorithms with respect to the key parameters for security and evaluate them:
```python
"""Creating a suitable class in order to encrypt and decrypt messages using the algorithms."""
class RSACrypto:
    def __init__(self, key_size=2048, public_exponent=65537, prime_size=1024, hash_function='SHA-256'):
        """Initializes all the evaluation parameters for the algorithm."""
        self.key_size = key_size
        self.key_size = key_size
        self.public_exponent = public_exponent
        self.hash_function = hash_function
        self.prime_size = prime_size
        self.RSA_generation_time = None
        self.DES_generation_time = None
        self.generate_keys()
        
    def generate_keys(self):
        """Generates RSA key pair with defined parameters."""
        start_time = time.time()
        key = RSA.generate(self.key_size, e=self.public_exponent)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        self.RSA_generation_time = time.time() - start_time
        
    def generate_AES_key(self):
        """Generates a single key for AES (Advanced Encryption Standard)."""
        start_time = time.time()
        key = get_random_bytes(16)
        end_time = time.time()
        self.AES_generation_time = end_time - start_time
        return key, self.AES_generation_time

    def generate_DES_key(self):
        """Generates a single key for DES (Data Encryption Standard)."""
        start_time = time.time()
        key = get_random_bytes(8)
        end_time = time.time()
        self.DES_generation_time = end_time - start_time
        return key, self.DES_generation_time
    
    def public_encrypt(self, message):
        """Encrypts a message using the public key."""
        if self.public_key is None:
            raise ValueError("Public key not generated or loaded.")
        key = RSA.import_key(self.public_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message
    
    def private_decrypt(self, encoded_message):
        """Decrypts a message using the private key."""
        if self.private_key is None:
            raise ValueError("Private key not available.")
        
        key = RSA.import_key(self.private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_message = cipher.decrypt(encoded_message)
        return decrypted_message.decode()

    def get_security_parameters(self):
        """Returns security-related parameters."""
        return {
            'Key Size': self.key_size,
            'Public Exponent': self.public_exponent,
            'Prime Size': self.prime_size,
            'Hash Function': self.hash_function,
            'RSA Key Generation Time': self.RSA_generation_time,
            'DES Key Generation Time': self.DES_generation_time
        }
```

4. Before testing the algorithms, in order to select an appropriate hash function, print the names of all the functions that are available, as follows:
```python
"""Printing names of available hash functions."""
print(hashlib.algorithms_available)
```
The above command will output the following code:
```python
{'sha512_256', 'mdc2', 'shake_256', 'sha1', 'sha512', 'shake_128', 'sha3_256', 'md5-sha1', 'blake2s', 'blake2b', 'ripemd160', 'sm3', 'whirlpool', 'md4', 'sha512_224', 'sha256', 'sha384', 'sha3_512', 'sha3_224', 'sha3_384', 'sha224', 'md5'}
```

5. Lastly, develop instances using the algorithms RSA, AES and DES, then test their encryption and evaluate their key security parameters, including their program runtimes and the difference, by constructing a prototype for a user input and typing any message inside:
```python
"""Using if statement to develop user input prototype for testing the algorithms RSA, AES and DES."""
if __name__ == "__main__":
    rsa = RSACrypto(key_size=2048, hash_function='sha256')
    user_input = input("Please enter a message:")
    encrypted_message = rsa.public_encrypt(user_input)
    decrypted_message = rsa.private_decrypt(encrypted_message)
    print(encrypted_message)
    print(decrypted_message)
    print(rsa.get_security_parameters())
    key_1 = get_random_bytes(16)
    AES_instance = AES.new(key_1, AES.MODE_ECB)
    encrypted_AES = AES_instance.encrypt(pad(user_input.encode('utf-16'), AES.block_size))
    decrypted_AES = unpad(AES_instance.decrypt(encrypted_AES), AES.block_size)
    print(encrypted_AES)
    print(decrypted_AES.decode('utf-16'))
    print(rsa.generate_AES_key())
    difference_1 = rsa.RSA_generation_time - rsa.AES_generation_time
    print("Time Difference =",difference_1)
    print(f"RSA is a more secure algorithm than AES since the difference in generation time {difference_1}>0 implying that AES is faster and therefore less secure and AES will only accept two key parameters out of RSA (key size and generation time) since RSA generates prime numbers and incurs hash functions but AES does not do either of these.")
    key_2 = get_random_bytes(8)
    DES_instance = DES.new(key_2, DES.MODE_ECB)
    encrypted_DES = DES_instance.encrypt(pad(user_input.encode('utf-8'), DES.block_size))
    decrypted_DES = unpad(DES_instance.decrypt(encrypted_DES), DES.block_size)
    print(encrypted_DES)
    print(decrypted_DES.decode('utf-8'))
    print(rsa.generate_DES_key())
    difference_2 = rsa.RSA_generation_time - rsa.DES_generation_time
    print("Time Difference =",difference_2)
    print(f"RSA is a more secure algorithm than DES since the difference in generation time {difference_2}>0 implying that DES is faster and therefore less secure and DES will only accept two key parameters out of RSA (key size and generation time) since RSA generates prime numbers and incurs hash functions but DES does not do either of these.")
```

## What I learned
- Implementing encryption algorithms in Python
- Working with structured code and data
- Applying mathematical concepts in programming


## Summary and Conclusion:
We conclude that RSA will always have a longer program runtime than both AES and DES, since it was designed to encrypt and decrypt messages and protocols more securely and with much stronger keys generated with more bytes by means of number generation. Additionally, the more secure an algorithm, the more bytes will be required for the keys generated and the longer it will take to run.

THE END





