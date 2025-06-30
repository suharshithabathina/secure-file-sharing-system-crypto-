"""QR code based access authentication"""


# QR Code Based Access Authentication 
# Simple implementation for capstone project

"""A Capstone Project made by B.Baby Suharshitha and D.Navya Sree"""


#how to use it?
"""To use this secure file-sharing system, first install the required Python 
libraries by running pip install qrcode[pil] pycryptodome in the terminal of your prefered IDE. Once installed, run
the program and input your file (in the output (as a text format))—it will encrypt the 
file using AES-256 encryption and generate a QR code containing the
decryption key. Share the encrypted file freely (e.g., via email), but keep the QR
code private (e.g., send it separately via secure messaging). To decrypt, the recipient
scans the QR code with any smartphone scanner, runs the decryption command, and gains access
only if the key matches. Unauthorized users without the QR code get "Access Denied," ensuring
your files stay protected. Perfect for sharing sensitive documents, passwords, or private media securely!"""




import qrcode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return cipher.nonce, ciphertext, tag

def generate_qr_code(data, filename="secret_message_qr.png"):
    current_dir = os.getcwd()
    full_path = os.path.join(current_dir, filename)
    
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(full_path)
    return full_path

def decrypt_message(nonce, ciphertext, tag, key):
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except (ValueError, KeyError):
        return None

def main():
    print("\n🔒 Secure Message Sharing System 🔒")
    print("---------------------------------\n")
    
    # 1. Get secret message and generate key
    message = input("Enter your secret message: ")
    original_key = get_random_bytes(16)
    nonce, ciphertext, tag = encrypt_message(message, original_key)
    
    # 2. Generate QR code with original key
    qr_path = generate_qr_code(original_key.hex())
    print(f"\n✅ QR code generated and saved at:\n{qr_path}")
    
    # 3. Get scanned key input
    scanned_hex = input("\nScan QR code and enter the key: ").strip()
    
    try:
        scanned_key = bytes.fromhex(scanned_hex)
    except ValueError:
        scanned_key = None
    
    # 4. Validate and decrypt
    if scanned_key and scanned_key == original_key:  # Critical security check
        decrypted = decrypt_message(nonce, ciphertext, tag, scanned_key)
        if decrypted:
            print("\n🔓 Message decrypted successfully!")
            print(f"Secret content: {decrypted}")
        else:
            print("\n❌ Decryption failed! (Invalid key or corrupted data)")
    else:
        print("\n❌ Access denied! Invalid key.")
    
    # 5. Additional security test (optional)
    if input("\nTest with wrong key? (y/n): ").lower() == 'y':
        wrong_key = get_random_bytes(16)
        failed_attempt = decrypt_message(nonce, ciphertext, tag, wrong_key)
        print("\n🚫 Unauthorized access test result:", failed_attempt or "ACCESS DENIED!")

if __name__ == "__main__":
    main()