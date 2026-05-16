import os
import sys
import base64
import struct
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response, JSONResponse

# Add project directory to path to import local modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'secure_communication'))
import crypto_utils

app = FastAPI(title="Ghost Vault - Steganographic Secure Storage")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), 'secure_communication', 'static')
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def get_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Ghost Vault</h1><p>Static files not found.</p>")


# ==============================================================================
# KEY VAULT — Generate RSA Key Pair
# ==============================================================================

@app.post("/vault/keygen")
async def generate_keys():
    """
    Generates a 2048-bit RSA key pair.
    - Public key  → shared with anyone who wants to send you a secret message
    - Private key → kept secret by the recipient; used only to unlock Ghost images
    No password or manual key material is needed. The algorithm produces both keys.
    """
    private_key, public_key = crypto_utils.generate_rsa_keypair()
    private_pem = crypto_utils.serialize_private_key(private_key).decode('utf-8')
    public_pem  = crypto_utils.serialize_public_key(public_key).decode('utf-8')
    fingerprint = crypto_utils.get_key_fingerprint(public_key)

    return JSONResponse(content={
        "private_key": private_pem,
        "public_key":  public_pem,
        "fingerprint": fingerprint
    })


# ==============================================================================
# THE FORGE — Encode with RSA-Wrapped AES-256 Key
# ==============================================================================
# Data layout hidden inside the stego-image:
#
#   [ 4 bytes: big-endian length of RSA ciphertext ]
#   [ RSA ciphertext          (256 bytes for RSA-2048) ]
#   [ AES-256-CBC ciphertext  (variable length)        ]
#
# The AES key never travels in the open.  Only someone with the matching
# RSA private key can recover it, and therefore decrypt the message.
# ==============================================================================

@app.post("/vault/forge")
async def forge_ghost(
    image:            UploadFile = File(...),
    secret_message:   str        = Form(...),
    recipient_pubkey: UploadFile = File(...)
):
    """
    THE FORGE — RSA public-key-wrapped AES-256 steganography.

    Flow:
      1. Algorithm generates a fresh random AES-256 session key.
      2. Message is encrypted with AES-256-CBC.
      3. The AES key is encrypted with the recipient's RSA-2048 public key (OAEP).
      4. [RSA-ciphertext | AES-ciphertext] is hidden in the carrier image via LSB.

    The stego-image can travel openly.  No key is ever manually shared.
    """
    try:
        image_bytes  = await image.read()
        pubkey_bytes = await recipient_pubkey.read()

        # 1. Load recipient's RSA public key
        try:
            rsa_pub = crypto_utils.deserialize_public_key(pubkey_bytes)
        except Exception:
            raise HTTPException(status_code=400,
                detail="Invalid recipient public key file. Upload the .pem file from Key Vault.")

        # 2. Algorithm generates a random AES-256 session key
        aes_key = crypto_utils.generate_aes_key()          # os.urandom(32)

        # 3. Encrypt the message with the AES session key
        aes_ciphertext = crypto_utils.aes_encrypt(secret_message.encode('utf-8'), aes_key)

        # 4. Wrap the AES session key with the recipient's RSA public key
        rsa_ciphertext = crypto_utils.encrypt_session_key(aes_key, rsa_pub)

        # 5. Pack: [4-byte RSA len] + [RSA ciphertext] + [AES ciphertext]
        rsa_len_prefix = struct.pack('>I', len(rsa_ciphertext))
        payload = rsa_len_prefix + rsa_ciphertext + aes_ciphertext

        # 6. Hide payload in carrier image via LSB steganography
        stego_bytes = crypto_utils.hide_data_in_image(image_bytes, payload)

        # Return the stego image directly as a PNG download
        return Response(
            content=stego_bytes,
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=ghost_vault.png"}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==============================================================================
# THE ORACLE — Decode with RSA Private Key
# ==============================================================================

@app.post("/vault/oracle")
async def oracle_reveal(
    image:       UploadFile = File(...),
    private_key: UploadFile = File(...)
):
    """
    THE ORACLE — Unlocks the Ghost image using the recipient's RSA private key.

    Flow:
      1. Extract the LSB-hidden payload from the stego image.
      2. Separate the RSA ciphertext and AES ciphertext using the stored length.
      3. Decrypt the AES key using the RSA private key (OAEP).
      4. Decrypt the message using the recovered AES key.

    No password is required at any point.
    """
    try:
        stego_bytes   = await image.read()
        privkey_bytes = await private_key.read()

        # 1. Load recipient's RSA private key
        try:
            rsa_priv = crypto_utils.deserialize_private_key(privkey_bytes)
        except Exception:
            raise HTTPException(status_code=400,
                detail="Invalid private key file. Upload your ghost_private.pem from Key Vault.")

        # 2. Extract the full payload from the stego image
        payload = crypto_utils.extract_data_from_image(stego_bytes)

        # 3. Unpack: read RSA ciphertext length, then split
        if len(payload) < 4:
            raise ValueError("Payload too short — this image may not be a Ghost Vault.")

        rsa_len = struct.unpack('>I', payload[:4])[0]
        rsa_ciphertext = payload[4 : 4 + rsa_len]
        aes_ciphertext = payload[4 + rsa_len :]

        # 4. Recover the AES session key by decrypting with the RSA private key
        try:
            aes_key = crypto_utils.decrypt_session_key(rsa_ciphertext, rsa_priv)
        except Exception:
            raise HTTPException(status_code=400,
                detail="Wrong private key — this key does not match the one used to forge this Ghost.")

        # 5. Decrypt the message using the recovered AES key
        plaintext = crypto_utils.aes_decrypt(aes_ciphertext, aes_key)

        return JSONResponse(content={"message": plaintext.decode('utf-8')})

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400,
            detail="Failed to reveal secret. Wrong key or image is not a Ghost Vault.")


# ==============================================================================
# Legacy endpoints kept for backward compatibility (now just 404 redirectors)
# ==============================================================================
@app.post("/vault/encode")
async def encode_legacy():
    raise HTTPException(status_code=410, detail="Use /vault/forge with the new RSA key flow.")

@app.post("/vault/decode")
async def decode_legacy():
    raise HTTPException(status_code=410, detail="Use /vault/oracle with the new RSA key flow.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
