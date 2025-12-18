#!/usr/bin/env python3
"""
AES Encryption Tool
All-in-one file containing AES-256-GCM encryption and interactive command-line interface.

Features:
- AES-256-GCM encryption with secure key derivation
- PBKDF2 with SHA-256 for password-based key generation
- Interactive command-line interface for encryption/decryption
- Base64 encoded output for easy sharing
- Support for multiline text input
- Error handling and validation
"""

import base64
import os
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESCrypto:
    """
    A simple AES encryption/decryption class using AES-256-GCM mode.
    GCM (Galois/Counter Mode) provides both confidentiality and authenticity.
    """
    
    def __init__(self):
        self.key_length = 32  # 256 bits
        self.nonce_length = 12  # 96 bits (recommended for GCM)
        self.salt_length = 16  # 128 bits
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a cryptographic key from a password using PBKDF2.
        
        Args:
            password (str): The password to derive the key from
            salt (bytes): Salt for key derivation
            
        Returns:
            bytes: Derived key (256 bits)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100000,  # Number of iterations (security vs speed tradeoff)
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def generate_key(self, password: str) -> tuple:
        """
        Generate a secure AES key from a password.
        
        Args:
            password (str): Password to generate key from
            
        Returns:
            tuple: (key, salt) where both are base64 encoded strings
        """
        salt = os.urandom(self.salt_length)
        key = self._derive_key(password, salt)
        
        # Return base64 encoded versions for easy storage/transmission
        return base64.b64encode(key).decode('utf-8'), base64.b64encode(salt).decode('utf-8')
    
    def encrypt(self, plaintext: str, password: str, key_b64: str = None, salt_b64: str = None) -> str:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Args:
            plaintext (str): Text to encrypt
            password (str): Password for key derivation
            key_b64 (str, optional): Base64 encoded key (if None, generates new)
            salt_b64 (str, optional): Base64 encoded salt (if None, generates new)
            
        Returns:
            str: Base64 encoded encrypted data with nonce and salt
        """
        # Generate or use provided key and salt
        if key_b64 and salt_b64:
            key = base64.b64decode(key_b64.encode('utf-8'))
            salt = base64.b64decode(salt_b64.encode('utf-8'))
        else:
            key, salt = self.generate_key(password)
            key = base64.b64decode(key.encode('utf-8'))
            salt = base64.b64decode(salt.encode('utf-8'))
        
        # Generate random nonce for GCM
        nonce = os.urandom(self.nonce_length)
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the plaintext (must be bytes)
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # Get the authentication tag
        tag = encryptor.tag
        
        # Combine all components: nonce + tag + salt + ciphertext
        encrypted_data = nonce + tag + salt + ciphertext
        
        # Return base64 encoded result
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_b64: str, password: str) -> str:
        """
        Decrypt AES-256-GCM encrypted data.
        
        Args:
            encrypted_b64 (str): Base64 encoded encrypted data
            password (str): Password used for encryption
            
        Returns:
            str: Decrypted plaintext
        """
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_b64.encode('utf-8'))
        
        # Extract components
        nonce = encrypted_data[:self.nonce_length]
        tag = encrypted_data[self.nonce_length:self.nonce_length + 16]
        salt = encrypted_data[self.nonce_length + 16:self.nonce_length + 16 + self.salt_length]
        ciphertext = encrypted_data[self.nonce_length + 16 + self.salt_length:]
        
        # Derive the same key using the same password and salt
        key = self._derive_key(password, salt)
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed. Wrong password or corrupted data.") from e


class InteractiveAES:
    """Interactive AES Encryption Tool"""
    
    def __init__(self):
        self.aes = AESCrypto()
        
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        """Print the application banner."""
        print("=" * 60)
        print("🔐 INTERACTIVE AES ENCRYPTION TOOL 🔐")
        print("=" * 60)
        print("AES-256-GCM Encryption with Secure Key Derivation")
        print("=" * 60)
        
    def get_user_choice(self):
        """Get user's choice for operation."""
        print("\n📋 Choose an operation:")
        print("1. 🔒 Encrypt Text")
        print("2. 🔓 Decrypt Text")
        print("3. 🚪 Exit")
        print("-" * 40)
        
        while True:
            choice = input("Enter your choice (1-3): ").strip()
            if choice in ['1', '2', '3']:
                return choice
            else:
                print("❌ Invalid choice! Please enter 1, 2, or 3.")
                
    def get_multiline_input(self, prompt):
        """Get multiline input from user."""
        print(prompt)
        print("(Press Enter twice or Ctrl+D when finished)")
        lines = []
        try:
            while True:
                line = input()
                if line == '' and lines and lines[-1] == '':
                    break
                lines.append(line)
            # Remove the last empty line if it exists
            if lines and lines[-1] == '':
                lines.pop()
        except EOFError:
            pass
        
        return '\n'.join(lines)
        
    def encrypt_text(self):
        """Handle text encryption."""
        print("\n🔒 ENCRYPT TEXT")
        print("-" * 40)
        
        # Get password
        password = getpass.getpass("Enter password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        # Get plaintext
        plaintext = self.get_multiline_input("Enter text to encrypt:")
        if not plaintext:
            print("❌ No text provided!")
            return
        
        try:
            # Encrypt using the AES instance
            encrypted = self.aes.encrypt(plaintext, password)
            
            print("\n✅ ENCRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"📝 Original text length: {len(plaintext)} characters")
            print(f"🔒 Encrypted length: {len(encrypted)} characters")
            print("\n🔐 ENCRYPTED TEXT (Base64):")
            print("-" * 30)
            print(encrypted)
            print("-" * 30)
            
            # Ask if user wants to copy or save
            print("\n💡 You can now:")
            print("- Copy the encrypted text above")
            print("- Save it to a file")
            print("- Share it securely")
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            
    def decrypt_text(self):
        """Handle text decryption."""
        print("\n🔓 DECRYPT TEXT")
        print("-" * 40)
        
        # Get password
        password = getpass.getpass("Enter password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        # Get encrypted text
        encrypted_text = self.get_multiline_input("Enter encrypted text (Base64):")
        if not encrypted_text:
            print("❌ No encrypted text provided!")
            return
        
        try:
            # Decrypt using the AES instance
            decrypted = self.aes.decrypt(encrypted_text, password)
            
            print("\n✅ DECRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"🔐 Encrypted text length: {len(encrypted_text)} characters")
            print(f"📝 Decrypted text length: {len(decrypted)} characters")
            print("\n📄 DECRYPTED TEXT:")
            print("-" * 30)
            print(decrypted)
            print("-" * 30)
            
        except ValueError as e:
            print(f"❌ Decryption failed: {e}")
            print("💡 Possible reasons:")
            print("   • Wrong password")
            print("   • Corrupted or invalid encrypted data")
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            
    def show_help(self):
        """Show help information."""
        print("\n📖 HELP")
        print("=" * 60)
        print("""
🔐 HOW TO USE THIS TOOL:

1. ENCRYPTION (Option 1):
   • Enter a secure password
   • Type or paste your plaintext
   • Get your encrypted text (Base64 format)
   • Save or share the encrypted text

2. DECRYPTION (Option 2):
   • Enter the same password used for encryption
   • Paste the encrypted text (Base64)
   • Get your original plaintext back

🔒 SECURITY FEATURES:
• AES-256-GCM encryption
• PBKDF2 key derivation (100,000 iterations)
• Random salt and nonce for each encryption
• Built-in authentication to prevent tampering

💡 TIPS:
• Use strong passwords (8+ characters recommended)
• Don't lose your password - data cannot be recovered
• Keep your encrypted data and passwords separate
• Test with small messages first

⚠️  IMPORTANT:
• If you forget your password, your data cannot be recovered
• This tool provides strong encryption but you are responsible for password security
• Always test encryption/decryption with test data first
        """)
        input("\nPress Enter to continue...")
        
    def run(self):
        """Main application loop."""
        self.clear_screen()
        self.print_banner()
        
        print("Welcome! This tool provides AES-256-GCM encryption and decryption.")
        print("Choose an operation to get started.\n")
        
        while True:
            try:
                choice = self.get_user_choice()
                
                if choice == '1':
                    self.encrypt_text()
                elif choice == '2':
                    self.decrypt_text()
                elif choice == '3':
                    print("\n👋 Thank you for using AES Encryption Tool!")
                    print("🔒 Stay secure!")
                    break
                
                # Pause before next operation
                if choice in ['1', '2']:
                    input("\nPress Enter to continue...")
                    self.clear_screen()
                    self.print_banner()
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ An error occurred: {e}")
                input("Press Enter to continue...")


def demo_aes():
    """Demonstration of AES encryption/decryption."""
    print("=== AES Encryption Demo ===")
    
    # Create AES instance
    aes = AESCrypto()
    
    # Example usage
    password = "my_secure_password_123"
    plaintext = "This is a secret message that will be encrypted!"
    
    print(f"Original text: {plaintext}")
    print(f"Password: {password}")
    print()
    
    # Encrypt
    encrypted = aes.encrypt(plaintext, password)
    print(f"Encrypted (base64): {encrypted}")
    print()
    
    # Decrypt
    try:
        decrypted = aes.decrypt(encrypted, password)
        print(f"Decrypted: {decrypted}")
        print()
        
        # Test with wrong password
        try:
            wrong_decrypt = aes.decrypt(encrypted, "wrong_password")
        except ValueError as e:
            print(f"Expected error with wrong password: {e}")
            
    except Exception as e:
        print(f"Decryption error: {e}")


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        # Run demonstration
        demo_aes()
    else:
        # Run interactive tool
        tool = InteractiveAES()
        tool.run()


if __name__ == "__main__":
    main()

