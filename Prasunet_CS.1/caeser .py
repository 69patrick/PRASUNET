import os

def caesar_cipher(text, shift, key, mode='encrypt'):
    """
    Encrypts or decrypts a text using the Caesar Cipher algorithm with an additional key.
    
    Parameters:
    text (str): The input message to be encrypted or decrypted.
    shift (int): The number of positions to shift each character.
    key (int): The additional key to be applied to each character.
    mode (str): 'encrypt' to encrypt the message, 'decrypt' to decrypt it.
    
    Returns:
    str: The encrypted or decrypted message.
    """
    if mode == 'decrypt':
        shift = -shift
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            combined_shift = shift + (key if mode == 'encrypt' else -key)
            new_char = chr((ord(char) - ascii_offset + combined_shift) % 26 + ascii_offset)
            result += new_char
        else:
            result += char
            
    return result

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    print(r"""
  _____                      _____ _  __         
 / ____|                    / ____(_)/ _|        
| |     __ _ ___  ___  ___ | |     _| |_ ___ _ __ 
| |    / _` / __|/ _ \/ __|| |    | |  _/ _ \ '__|
| |___| (_| \__ \  __/\__ \| |____| | ||  __/ |   
 \_____\__,_|___/\___||___(_)_____|_|_| \___|_|   

                Caesar Cipher Tool
    """)

def main():
    clear_screen()
    display_banner()
    
    print("Welcome to the Caesar Cipher CryptoTool")
    print("--------------------------------------")
    mode = input("Do you want to (e)ncrypt or (d)ecrypt? ").lower()
    if mode not in ['e', 'd']:
        print("Invalid choice. Please choose 'e' for encrypt or 'd' for decrypt.")
        return
    
    text = input("Enter the message: ")
    shift = int(input("Enter the shift value: "))
    key = int(input("Enter the key value: "))
    
    if mode == 'e':
        encrypted_text = caesar_cipher(text, shift, key, mode='encrypt')
        print("\nEncrypted Message:", encrypted_text)
        
        # Immediate decryption option
        decrypt_now = input("Do you want to decrypt this message immediately? (y/n): ").lower()
        if decrypt_now == 'y':
            while True:
                reentered_key = int(input("Re-enter the key value for decryption: "))
                if reentered_key == key:
                    decrypted_text = caesar_cipher(encrypted_text, shift, reentered_key, mode='decrypt')
                    print("\nDecrypted Message:", decrypted_text)
                    break
                else:
                    print("Incorrect key. Please enter the correct key for decryption.")
    else:
        while True:
            reentered_key = int(input("Re-enter the key value for decryption: "))
            if reentered_key == key:
                decrypted_text = caesar_cipher(text, shift, reentered_key, mode='decrypt')
                print("\nDecrypted Message:", decrypted_text)
                break
            else:
                print("Incorrect key. Please enter the correct key for decryption.")
    
    print("\nThank you for using the Caesar Cipher CryptoTool!")

if __name__ == "__main__":
    main()
