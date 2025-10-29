from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

def encrypt_file(file_content, recipient_public_key_pem):
    """
    Encrypt file content using AES and encrypt AES key with RSA
    
    Args:
        file_content: bytes - The file content to encrypt
        recipient_public_key_pem: str - Recipient's RSA public key in PEM format
    
    Returns:
        tuple: (encrypted_file: bytes, encrypted_aes_key: str) or (None, None) on error
    """
    try:
        # Generate random AES key (256-bit)
        aes_key = get_random_bytes(32)
        
        # Encrypt file with AES-EAX
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_content)
        
        # Combine nonce, tag, and ciphertext
        encrypted_file = cipher_aes.nonce + tag + ciphertext
        
        # Encrypt AES key with recipient's RSA public key
        rsa_key = RSA.import_key(recipient_public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Encode to base64 for storage
        encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
        
        return encrypted_file, encrypted_aes_key_b64
        
    except Exception as e:
        print(f"Error encrypting file: {e}")
        return None, None

def decrypt_file(encrypted_file, encrypted_aes_key_b64, private_key_pem):
    """
    Decrypt file content using RSA private key to decrypt AES key, then AES to decrypt file
    
    Args:
        encrypted_file: bytes - The encrypted file content
        encrypted_aes_key_b64: str - Base64 encoded encrypted AES key
        private_key_pem: str - User's RSA private key in PEM format
    
    Returns:
        bytes: Decrypted file content or None on error
    """
    try:
        # Decrypt AES key with user's RSA private key
        private_key = RSA.import_key(private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        
        # Extract nonce, tag, and ciphertext from encrypted file
        nonce = encrypted_file[:16]
        tag = encrypted_file[16:32]
        ciphertext = encrypted_file[32:]
        
        # Decrypt file with AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_file = cipher_aes.decrypt_and_verify(ciphertext, tag)
        
        return decrypted_file
        
    except ValueError as e:
        print(f"Decryption verification failed: {e}")
        return None
    except Exception as e:
        print(f"Error decrypting file: {e}")
        return None

def validate_rsa_key(key_pem, key_type='public'):
    """
    Validate RSA key format
    
    Args:
        key_pem: str - RSA key in PEM format
        key_type: str - 'public' or 'private'
    
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        key = RSA.import_key(key_pem)
        
        if key_type == 'public' and not key.has_private():
            return True
        elif key_type == 'private' and key.has_private():
            return True
        else:
            return False
            
    except Exception as e:
        print(f"Invalid RSA key: {e}")
        return False