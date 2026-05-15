import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import io
from PIL import Image

# ==============================================================================
# KEY MANAGEMENT (RSA)
# ==============================================================================

def generate_rsa_keypair():
    """Generates a 2048-bit RSA public/private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Converts a public key object to PEM format bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """Converts PEM format bytes back to a public key object."""
    return serialization.load_pem_public_key(pem_bytes)

def get_key_fingerprint(public_key):
    """Computes a SHA-256 fingerprint of a public key for MITM verification."""
    pem = serialize_public_key(public_key)
    hash_val = hashlib.sha256(pem).digest()
    return hash_val.hex().upper()

# ==============================================================================
# HYBRID CRYPTOGRAPHY (RSA Key Exchange)
# ==============================================================================

def encrypt_session_key(session_key, public_key):
    """Encrypts the AES session key using the receiver's RSA public key."""
    ciphertext = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_session_key(encrypted_key, private_key):
    """Decrypts the AES session key using the receiver's RSA private key."""
    plaintext = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# ==============================================================================
# SYMMETRIC ENCRYPTION (AES-CBC)
# ==============================================================================

def generate_aes_key():
    """Generates a 256-bit (32 bytes) AES session key."""
    return os.urandom(32)

def derive_key(password: str, salt: bytes = None):
    """Derives a 256-bit key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def aes_encrypt(plaintext_bytes, key):
    """Encrypts data using AES-256-CBC with PKCS7 padding."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV for use during decryption

def aes_decrypt(ciphertext_with_iv, key):
    """Decrypts AES-256-CBC encrypted data."""
    iv = ciphertext_with_iv[:16]
    actual_ciphertext = ciphertext_with_iv[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext_bytes

# ==============================================================================
# INTEGRITY (SHA-256)
# ==============================================================================

def compute_sha256_hash(data_bytes):
    """Computes SHA-256 hash of the given bytes."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_bytes)
    return digest.finalize()

def verify_hash(data_bytes, received_hash):
    """Verifies that the computed hash matches the received hash."""
    computed = compute_sha256_hash(data_bytes)
    return computed == received_hash

# ==============================================================================
# AUTHENTICATION (RSA Digital Signatures)
# ==============================================================================

def sign_data(data_bytes, private_key):
    """Signs data using RSA-PSS and SHA-256."""
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data_bytes, signature, public_key):
    """Verifies the RSA-PSS digital signature."""
    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ==============================================================================
# PERFECT FORWARD SECRECY (ECDHE)
# ==============================================================================

def generate_ec_keypair():
    """Generates an ephemeral Elliptic Curve key pair (SECP256R1)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_ec_public_key(public_key):
    """Serializes EC public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_ec_public_key(pem_bytes):
    """Deserializes EC public key from PEM format."""
    return serialization.load_pem_public_key(pem_bytes)

def derive_shared_aes_key(private_key, peer_public_key):
    """Computes shared secret and derives a 256-bit AES key using HKDF."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Use HKDF to derive a symmetric key from the shared secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None, # In a real handshake, use a random salt exchanged in plaintext
        info=b'ghost-vault-handshake',
    ).derive(shared_secret)
    
    return derived_key

# ==============================================================================
# STEGANOGRAPHY (LSB)
# ==============================================================================

def hide_data_in_image(cover_image_bytes, data_bytes):
    """
    Hides data_bytes in the Least Significant Bits of cover_image_bytes.
    Returns the stego-image as PNG bytes.
    """
    image = Image.open(io.BytesIO(cover_image_bytes))
    image = image.convert('RGB')
    pixels = image.load()
    
    # Prepend data length (4 bytes)
    data_to_hide = len(data_bytes).to_bytes(4, byteorder='big') + data_bytes
    
    # Convert data to bit stream
    bits = []
    for byte in data_to_hide:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
            
    width, height = image.size
    total_pixels = width * height
    if len(bits) > total_pixels * 3:
        raise ValueError("Data too large for this image.")
        
    bit_index = 0
    for y in range(height):
        for x in range(width):
            if bit_index >= len(bits):
                break
            r, g, b = pixels[x, y]
            
            # Modify LSBs
            if bit_index < len(bits):
                r = (r & ~1) | bits[bit_index]
                bit_index += 1
            if bit_index < len(bits):
                g = (g & ~1) | bits[bit_index]
                bit_index += 1
            if bit_index < len(bits):
                b = (b & ~1) | bits[bit_index]
                bit_index += 1
                
            pixels[x, y] = (r, g, b)
        if bit_index >= len(bits):
            break
            
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()

def extract_data_from_image(stego_image_bytes):
    """
    Extracts data from the Least Significant Bits of stego_image_bytes.
    """
    image = Image.open(io.BytesIO(stego_image_bytes))
    image = image.convert('RGB')
    pixels = image.load()
    
    width, height = image.size
    bits = []
    
    # Extract enough bits to get the length first (32 bits = 4 bytes)
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
            if len(bits) >= 32:
                break
        if len(bits) >= 32:
            break
            
    # Convert first 32 bits to length
    len_bytes = []
    for i in range(4):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        len_bytes.append(byte)
    
    data_len = int.from_bytes(bytes(len_bytes), byteorder='big')
    
    # Extract the rest of the data
    total_bits_needed = 32 + (data_len * 8)
    if total_bits_needed > width * height * 3:
         raise ValueError("Extracted length is invalid. Image may not contain hidden data.")

    # Continue extraction
    bits = []
    bit_count = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            for val in [r, g, b]:
                bits.append(val & 1)
                bit_count += 1
                if bit_count >= total_bits_needed:
                    break
            if bit_count >= total_bits_needed:
                break
        if bit_count >= total_bits_needed:
            break
            
    # Convert bits (skipping first 32) to bytes
    data_bytes = []
    for i in range(4, 4 + data_len):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i * 8 + j]
        data_bytes.append(byte)
        
    return bytes(data_bytes)
