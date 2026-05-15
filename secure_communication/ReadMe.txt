================================================================================
SECURE COMMUNICATION SYSTEM USING HYBRID CRYPTOGRAPHIC TECHNIQUES
================================================================================

Names        : Sharath
Roll Numbers : [Fill Your Roll Number Here]
Contact      : [Fill Your Contacts Here]
Team Name    : TENSOR CREW

================================================================================
DESCRIPTION
================================================================================
This project implements a secure client-server communication framework using 
Hybrid Cryptography. It simulates a Secure Client sending an encrypted message
to a Secure Server.

Cryptographic techniques used:
- Asymmetric Encryption : RSA (2048-bit) for Secure Key Exchange.
- Symmetric Encryption  : AES-256 (CBC Mode) for Data Transmission.
- Integrity             : SHA-256 Hashing.
- Authentication        : RSA Digital Signatures (RSA-PSS).

================================================================================
REQUIREMENTS
================================================================================
- Python 3.7+
- cryptography library

To install the required library:
    pip install cryptography

================================================================================
EXECUTION STEPS
================================================================================
1. Open a terminal and navigate to this directory.
2. Start the server first:
    python3 server.py
    
3. Open a second terminal and navigate to this directory.
4. Run the client:
    python3 client.py

5. Observe the outputs in both terminals:
    - You will see the RSA Key Generation.
    - You will see the Public Key Exchange.
    - You will see the AES Key Exchange (encrypted with RSA).
    - You will see the Data Package transmitted.
    - The server will verify Integrity and Authentication before decrypting and 
      printing the secure message.
    - Finally, an Acknowledgment is sent securely back to the client.

================================================================================
FILES INCLUDED
================================================================================
- crypto_utils.py : Contains all the modular cryptographic primitive functions.
- server.py       : The socket server implementation.
- client.py       : The socket client implementation.
- ReadMe.txt      : This instructions file.
- Project_Report.md : Detailed project report based on rubrics.
