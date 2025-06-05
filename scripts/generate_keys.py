# import os
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.fernet import Fernet
# import base64

# def generate_encryption_key():
#     """Generate a key for encrypting the private key"""
#     key = Fernet.generate_key()
#     with open('encryption.key', 'wb') as f:
#         f.write(key)
#     return key

# def generate_key_pair():
#     """Generate RSA key pair and save them"""
#     # Generate private key
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048
#     )
    
#     # Get public key
#     public_key = private_key.public_key()
    
#     # Save private key encrypted
#     encryption_key = generate_encryption_key()
#     f = Fernet(encryption_key)
    
#     private_pem = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.BestAvailableEncryption(encryption_key)
#     )
    
#     with open('private_key.pem', 'wb') as f:
#         f.write(private_pem)
    
#     # Save public key
#     public_pem = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )
    
#     with open('public_key.pem', 'wb') as f:
#         f.write(public_pem)
    
#     print("Keys generated successfully!")
#     print("Public key (to be sent to server):")
#     print(public_pem.decode())
#     print("\nPrivate key and encryption key have been saved to files.")

# if __name__ == '__main__':
#     generate_key_pair() 