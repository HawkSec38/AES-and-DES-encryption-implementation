#!/usr/bin/env python3
"""
Interactive DES Encryption Tool - All-in-One
All-in-one file containing TripleDES encryption and interactive command-line interface.

Features:
- TripleDES (3DES) encryption with CBC mode and PKCS7 padding
- Interactive command-line interface for encryption/decryption
- Base64 encoded output for easy sharing
- Support for multiline text input
- Error handling and validation

WARNING: Even TripleDES is considered insecure for modern use due to its small key size (112/168 bits).
This implementation is for educational purposes only.
"""

import base64
import os
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class DESCrypto:
    """
    A simple TripleDES encryption/decryption class using 3DES-CBC mode with PKCS7 padding.
    TripleDES uses 168-bit keys (112 effective) and 64-bit blocks.
    """

    def __init__(self):
        self.key_length = 24  # 192 bits (TripleDES uses 168 bits effectively)
        self.block_size = 64  # DES block size in bits
        self.iv_length = 8  # 64 bits for DES

    def _derive_key(self, password: str) -> bytes:
        """
        Derive a TripleDES key from a password.
        TripleDES requires exactly 24 bytes (192 bits), so we truncate or pad as needed.

        Args:
            password (str): The password to derive the key from

        Returns:
            bytes: 24-byte TripleDES key
        """
        # Convert password to bytes and take first 24 bytes, padding if necessary
        password_bytes = password.encode('utf-8')
        if len(password_bytes) >= 24:
            return password_bytes[:24]
        else:
            # Pad with zeros if password is shorter than 24 bytes
            return password_bytes + b'\x00' * (24 - len(password_bytes))

    def encrypt(self, plaintext: str, password: str) -> str:
        """
        Encrypt plaintext using TripleDES-CBC.

        Args:
            plaintext (str): Text to encrypt
            password (str): Password for key derivation

        Returns:
            str: Base64 encoded encrypted data with IV
        """
        # Generate key from password
        key = self._derive_key(password)

        # Generate random IV
        iv = os.urandom(self.iv_length)

        # Create cipher
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the plaintext
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Combine IV and ciphertext
        encrypted_data = iv + ciphertext

        # Return base64 encoded result
        return base64.b64encode(encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_b64: str, password: str) -> str:
        """
        Decrypt TripleDES-CBC encrypted data.

        Args:
            encrypted_b64 (str): Base64 encoded encrypted data
            password (str): Password used for encryption

        Returns:
            str: Decrypted plaintext
        """
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_b64.encode('utf-8'))

        # Extract IV and ciphertext
        iv = encrypted_data[:self.iv_length]
        ciphertext = encrypted_data[self.iv_length:]

        # Generate key from password
        key = self._derive_key(password)

        # Create cipher
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        try:
            unpadder = padding.PKCS7(self.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed. Wrong password or corrupted data.") from e


class InteractiveDES:
    """Interactive DES Encryption Tool"""

    def __init__(self):
        self.des = DESCrypto()

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        """Print the application banner."""
        print("=" * 60)
        print("🔐 INTERACTIVE DES ENCRYPTION TOOL 🔐")
        print("=" * 60)
        print("TripleDES (3DES) Encryption (Educational Purposes Only)")
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
        password = getpass.getpass("Enter password (first 24 chars used): ")
        if not password:
            print("❌ Password cannot be empty!")
            return

        # Get plaintext
        plaintext = self.get_multiline_input("Enter text to encrypt:")
        if not plaintext:
            print("❌ No text provided!")
            return

        try:
            # Encrypt using the DES instance
            encrypted = self.des.encrypt(plaintext, password)

            print("\n✅ ENCRYPTION SUCCESSFUL!")
            print("=" * 50)
            print(f"📝 Original text length: {len(plaintext)} characters")
            print(f"🔒 Encrypted length: {len(encrypted)} characters")
            print("\n🔐 ENCRYPTED TEXT (Base64):")
            print("-" * 30)
            print(encrypted)
            print("-" * 30)

            # Security warning
            print("\n⚠️  SECURITY WARNING:")
            print("   TripleDES encryption is insecure and should not be used")
            print("   for protecting sensitive information!")

            # Ask if user wants to copy or save
            print("\n💡 You can now:")
            print("- Copy the encrypted text above")
            print("- Save it to a file")
            print("- Share it securely (for educational purposes only)")

        except Exception as e:
            print(f"❌ Encryption failed: {e}")

    def decrypt_text(self):
        """Handle text decryption."""
        print("\n🔓 DECRYPT TEXT")
        print("-" * 40)

        # Get password
        password = getpass.getpass("Enter password (first 24 chars used): ")
        if not password:
            print("❌ Password cannot be empty!")
            return

        # Get encrypted text
        encrypted_text = self.get_multiline_input("Enter encrypted text (Base64):")
        if not encrypted_text:
            print("❌ No encrypted text provided!")
            return

        try:
            # Decrypt using the DES instance
            decrypted = self.des.decrypt(encrypted_text, password)

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
   • Enter a password (first 24 characters are used)
   • Type or paste your plaintext
   • Get your encrypted text (Base64 format)
   • Save or share the encrypted text

2. DECRYPTION (Option 2):
   • Enter the same password used for encryption
   • Paste the encrypted text (Base64)
   • Get your original plaintext back

🔒 SECURITY INFORMATION:
• TripleDES uses 168-bit keys (112 effective, still weak)
• 3DES-CBC with PKCS7 padding is used
• This implementation is for educational purposes only
• DO NOT use 3DES for protecting sensitive information

💡 TIPS:
• Passwords longer than 24 characters are truncated
• Use strong passwords even though 3DES is weak
• Don't lose your password - data cannot be recovered
• Test with small messages first

⚠️  IMPORTANT SECURITY WARNING:
• TripleDES encryption is considered insecure
• It can be broken by modern computers in reasonable time
• Use AES encryption for any real security needs
• This tool is for educational purposes only

If you need secure encryption, use the AES tool instead!
        """)
        input("\nPress Enter to continue...")

    def run(self):
        """Main application loop."""
        self.clear_screen()
        self.print_banner()

        print("Welcome! This tool provides TripleDES encryption and decryption.")
       
        print("Choose an operation to get started.\n")

        while True:
            try:
                choice = self.get_user_choice()

                if choice == '1':
                    self.encrypt_text()
                elif choice == '2':
                    self.decrypt_text()
                elif choice == '3':
                    print("\n👋 Thank you for using DES Encryption Tool!")
                    
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


def demo_des():
    """Demonstration of TripleDES encryption/decryption."""
    print("=== TripleDES Encryption Demo ===")
    
    # Create DES instance
    des = DESCrypto()

    # Example usage
    password = "password123"
    plaintext = "This is a secret message that will be encrypted with TripleDES!"

    print(f"Original text: {plaintext}")
    print(f"Password: {password} (first 24 chars used)")
    print()

    # Encrypt
    encrypted = des.encrypt(plaintext, password)
    print(f"Encrypted (base64): {encrypted}")
    print()

    # Decrypt
    try:
        decrypted = des.decrypt(encrypted, password)
        print(f"Decrypted: {decrypted}")
        print()

        # Test with wrong password
        try:
            wrong_decrypt = des.decrypt(encrypted, "wrongpwd")
        except ValueError as e:
            print(f"Expected error with wrong password: {e}")

       

    except Exception as e:
        print(f"Decryption error: {e}")


def main():
    """Main entry point."""
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        # Run demonstration
        demo_des()
    else:
        # Run interactive tool
        tool = InteractiveDES()
        tool.run()


if __name__ == "__main__":
    main()
