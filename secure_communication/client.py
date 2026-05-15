import socket
import json
import struct
import crypto_utils

HOST = '127.0.0.1'
PORT = 65432

# ---------------------------------------------------------------------------
# Framed I/O helpers (mirrors server.py)
# ---------------------------------------------------------------------------

def send_msg(sock, data: bytes):
    """Send data preceded by a 4-byte length header."""
    sock.sendall(struct.pack('>I', len(data)) + data)

def recv_msg(sock) -> bytes:
    """Receive a complete framed message, blocking until all bytes arrive."""
    raw_len = _recv_exact(sock, 4)
    msg_len = struct.unpack('>I', raw_len)[0]
    return _recv_exact(sock, msg_len)

def _recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from sock, raising ConnectionError on short read."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before all bytes were received.")
        buf.extend(chunk)
    return bytes(buf)

# ---------------------------------------------------------------------------

def start_client(message_body=None, log_callback=print):
    log_callback("[CLIENT] Starting Secure Client...")
    
    # 1. Generate Client RSA Key Pair
    log_callback("[CLIENT] Generating RSA Key Pair...")
    client_private_key, client_public_key = crypto_utils.generate_rsa_keypair()
    client_public_pem = crypto_utils.serialize_public_key(client_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        log_callback(f"[CLIENT] Connecting to Server at {HOST}:{PORT}...")
        try:
            s.connect((HOST, PORT))
            
            # 2. RSA Identity Exchange (Send Client Pub Key, Receive Server Pub Key)
            send_msg(s, client_public_pem)
            server_rsa_pem = recv_msg(s)
            server_rsa_key = crypto_utils.deserialize_public_key(server_rsa_pem)
            
            # MITM Protection: Display fingerprints
            client_fingerprint = crypto_utils.get_key_fingerprint(client_public_key)
            server_fingerprint = crypto_utils.get_key_fingerprint(server_rsa_key)
            log_callback(f"[CLIENT] Client RSA Fingerprint: {client_fingerprint}")
            log_callback(f"[CLIENT] Server RSA Fingerprint: {server_fingerprint}")
            log_callback("[CLIENT] Verify these out-of-band to prevent MITM.")

            # 3. ECDHE Handshake (Perfect Forward Secrecy)
            log_callback("[CLIENT] Initializing ECDHE exchange...")
            client_ec_priv, client_ec_pub = crypto_utils.generate_ec_keypair()
            client_ec_pem = crypto_utils.serialize_ec_public_key(client_ec_pub)
            
            # Receive Server's EC Public Key + Signature
            server_ec_pem = recv_msg(s)
            server_ec_sig = recv_msg(s)
            server_ec_pub = crypto_utils.deserialize_ec_public_key(server_ec_pem)
            
            # Verify Server's Identity
            if not crypto_utils.verify_signature(server_ec_pem, server_ec_sig, server_rsa_key):
                log_callback("[CLIENT ERROR] ECDHE Signature Verification Failed! Potential MITM.")
                return

            # Sign and Send Client's EC Public Key
            ec_signature = crypto_utils.sign_data(client_ec_pem, client_private_key)
            send_msg(s, client_ec_pem)
            send_msg(s, ec_signature)
            
            # Derive Session Key
            session_key = crypto_utils.derive_shared_aes_key(client_ec_priv, server_ec_pub)
            log_callback("[CLIENT] PFS Session Key derived via ECDHE.")

            # 5. Prepare the Message (Data Payload)
            message_data = {
                "sender": "ClientNode_01",
                "topic": "Confidential Report",
                "body": message_body or "This is a highly classified message intended only for the server.",
                "priority": "High"
            }
            plaintext_bytes = json.dumps(message_data).encode('utf-8')

            # 6. Encrypt Payload
            encrypted_payload = crypto_utils.aes_encrypt(plaintext_bytes, session_key)

            # 7. Compute Hash for Integrity Verification
            computed_hash = crypto_utils.compute_sha256_hash(plaintext_bytes)

            # 8. Compute Digital Signature for Authentication
            signature = crypto_utils.sign_data(plaintext_bytes, client_private_key)

            # 9. Package and Transmit
            data_package = {
                "encrypted_payload": encrypted_payload.hex(),
                "hash": computed_hash.hex(),
                "signature": signature.hex()
            }
            send_msg(s, json.dumps(data_package).encode('utf-8'))
            log_callback("[CLIENT] Encrypted message, hash, and signature sent to server.")

            # 10. Receive Acknowledgment
            encrypted_ack = recv_msg(s)
            if encrypted_ack:
                ack_msg = crypto_utils.aes_decrypt(encrypted_ack, session_key)
                log_callback(f"[CLIENT] Server Acknowledgment: {ack_msg.decode('utf-8')}")

        except Exception as e:
            log_callback(f"[CLIENT ERROR] {e}")
        finally:
            log_callback("[CLIENT] Closing connection.")
            session_key = None 

if __name__ == "__main__":
    start_client()