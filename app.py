import os
import sys
import base64
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

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

@app.post("/vault/encode")
async def encode_secret(
    image: UploadFile = File(...),
    secret_message: str = Form(...),
    password: str = Form(...)
):
    try:
        # 1. Read image bytes
        image_bytes = await image.read()
        
        # 2. Derive key from password
        key, salt = crypto_utils.derive_key(password)
        
        # 3. Encrypt message with AES
        encrypted_message = crypto_utils.aes_encrypt(secret_message.encode(), key)
        
        # 4. Combine salt and encrypted message
        # We need the salt to derive the same key later
        data_to_hide = salt + encrypted_message
        
        # 5. Hide in image
        stego_image_bytes = crypto_utils.hide_data_in_image(image_bytes, data_to_hide)
        
        return Response(
            content=stego_image_bytes, 
            media_type="image/png",
            headers={"Content-Disposition": "attachment; filename=ghost_vault.png"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/vault/decode")
async def decode_secret(
    image: UploadFile = File(...),
    password: str = Form(...)
):
    try:
        # 1. Read stego-image bytes
        stego_image_bytes = await image.read()
        
        # 2. Extract data from image
        extracted_data = crypto_utils.extract_data_from_image(stego_image_bytes)
        
        # 3. Separate salt and encrypted message
        # Salt is the first 16 bytes (based on derive_key implementation)
        salt = extracted_data[:16]
        encrypted_message = extracted_data[16:]
        
        # 4. Derive key from password and salt
        key, _ = crypto_utils.derive_key(password, salt)
        
        # 5. Decrypt message
        decrypted_message = crypto_utils.aes_decrypt(encrypted_message, key)
        
        return {"message": decrypted_message.decode()}
    except Exception as e:
        # If decryption fails, it might be a wrong password or wrong image
        raise HTTPException(status_code=400, detail="Failed to decode. Wrong password or image is not a Ghost Vault?")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
