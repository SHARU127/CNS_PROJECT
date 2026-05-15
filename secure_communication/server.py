import socket
import json
import crypto_utils

HOST = '127.0.0.1'
PORT = 65432

def start_server(log_callback=print):
    log_callback("[SERVER] Starting Secure Server...")
    
    # 1. Generate Server RSA Key Pair
    log_callback("[SERVER] Generating RSA Key Pair...")
    server_private_key, server_public_key = crypto_utils.generate_rsa_keypair()
    server_public_pem = crypto_utils.serialize_public_key(server_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow port reuse
        s.bind((HOST, PORT))
        s.listen()
        log_callback(f"[SERVER] Listening on {HOST}:{PORT}")
        
        while True: # Keep server running for the UI
            try:
                conn, addr = s.accept()
                with conn:
                    log_callback(f"[SERVER] Connected by client at {addr}")

                    # 2. RSA Identity Exchange (Receive Client RSA Pub Key, Send Server RSA Pub Key)
                    client_rsa_pem = conn.recv(1024)
                    client_rsa_key = crypto_utils.deserialize_public_key(client_rsa_pem)
                    conn.sendall(server_public_pem)
                    
                    # MITM Protection: Display fingerprints
                    client_fingerprint = crypto_utils.get_key_fingerprint(client_rsa_key)
                    server_fingerprint = crypto_utils.get_key_fingerprint(server_public_key)
                    log_callback(f"[SERVER] Client RSA Fingerprint: {client_fingerprint}")
                    log_callback(f"[SERVER] Server RSA Fingerprint: {server_fingerprint}")
                    log_callback("[SERVER] Verify these out-of-band to prevent MITM.")

                    # 3. ECDHE Handshake (Perfect Forward Secrecy)
                    log_callback("[SERVER] Initializing ECDHE exchange...")
                    server_ec_priv, server_ec_pub = crypto_utils.generate_ec_keypair()
                    server_ec_pem = crypto_utils.serialize_ec_public_key(server_ec_pub)
                    
                    # Sign the EC public key to prove identity
                    ec_signature = crypto_utils.sign_data(server_ec_pem, server_private_key)
                    
                    # Send EC Public Key + Signature
                    conn.sendall(server_ec_pem)
                    conn.sendall(ec_signature)
                    
                    # Receive Client's EC Public Key + Signature
                    client_ec_pem = conn.recv(1024)
                    client_ec_sig = conn.recv(256)
                    client_ec_pub = crypto_utils.deserialize_ec_public_key(client_ec_pem)
                    
                    # Verify Client's Identity
                    if not crypto_utils.verify_signature(client_ec_pem, client_ec_sig, client_rsa_key):
                        log_callback("[SERVER ERROR] ECDHE Signature Verification Failed! Potential MITM.")
                        continue
                    
                    # Derive Session Key
                    session_key = crypto_utils.derive_shared_aes_key(server_ec_priv, client_ec_pub)
                    log_callback("[SERVER] PFS Session Key derived via ECDHE.")

                    # 4. Receive Data Payload
                    data_package_bytes = conn.recv(4096)
                    if not data_package_bytes:
                        continue

                    data_package = json.loads(data_package_bytes.decode('utf-8'))
                    encrypted_payload = bytes.fromhex(data_package['encrypted_payload'])
                    received_hash = bytes.fromhex(data_package['hash'])
                    signature = bytes.fromhex(data_package['signature'])

                    # 5. Decrypt Payload
                    plaintext_bytes = crypto_utils.aes_decrypt(encrypted_payload, session_key)
                    log_callback("[SERVER] Payload decrypted successfully.")

                    # 6. Integrity Verification (SHA-256)
                    if not crypto_utils.verify_hash(plaintext_bytes, received_hash):
                        log_callback("[SERVER ERROR] Integrity Check Failed!")
                        continue
                    log_callback("[SERVER] Integrity Check Passed (SHA-256 matches).")

                    # 7. Authentication Verification (Digital Signature)
                    if not crypto_utils.verify_signature(plaintext_bytes, signature, client_rsa_key):
                        log_callback("[SERVER ERROR] Authentication Failed!")
                        continue
                    log_callback("[SERVER] Authentication Check Passed (Digital Signature verified).")

                    # 8. Process the Secure Message
                    message_data = json.loads(plaintext_bytes.decode('utf-8'))
                    log_callback(f"[SERVER] SECURE MESSAGE RECEIVED FROM {message_data['sender']}")
                    log_callback(f"[SERVER] TOPIC: {message_data['topic']}")
                    log_callback(f"[SERVER] MESSAGE: {message_data['body']}")
                    
                    # 9. Send Acknowledgment
                    ack_msg = b"Message Received Securely."
                    encrypted_ack = crypto_utils.aes_encrypt(ack_msg, session_key)
                    conn.sendall(encrypted_ack)
                    log_callback("[SERVER] Acknowledgment sent to client.")
                    
            except Exception as e:
                log_callback(f"[SERVER ERROR] {e}")
            finally:
                log_callback("[SERVER] Closing connection.")
