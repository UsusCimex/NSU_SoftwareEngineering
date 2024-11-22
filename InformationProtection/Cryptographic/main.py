from rc4 import rc4_encrypt, rc4_decrypt
from idea import IDEAEncrypt, IDEADecrypt, ExtendKey, GenerateDecryptionSubkeys
from idea_hash import IDEAHash

def main():
    print("Выберите алгоритм:")
    print("1. RC4")
    print("2. IDEA")
    print("3. IDEA Hash")
    alg_choice = input("Введите номер алгоритма: ")

    if alg_choice == '1':  # RC4
        key = input("Введите ключ шифрования: ")
        plaintext = input("Введите текст для шифрования: ")
        ciphertext = rc4_encrypt(key, plaintext)
        decrypted_text = rc4_decrypt(key, ciphertext)
        print("Зашифрованный текст (в шестнадцатеричном виде):", ciphertext.encode('utf-8').hex())
        print("Расшифрованный текст:", decrypted_text)
    elif alg_choice == '2':  # IDEA
        plaintext_input = input("Введите текст для шифрования: ")
        plaintext = plaintext_input.encode('utf-8')
        enc_subkeys = ExtendKey()
        encrypted_data = IDEAEncrypt(plaintext, enc_subkeys)
        dec_subkeys = GenerateDecryptionSubkeys(enc_subkeys)
        decrypted_data = IDEADecrypt(encrypted_data, dec_subkeys)
        decrypted_text = decrypted_data.decode('utf-8')
        print("Зашифрованный текст (в шестнадцатеричном виде): ", encrypted_data.hex())
        print("Расшифрованный текст: ", decrypted_text)
    elif alg_choice == '3':  # IDEA Hash
        message_input = input("Введите сообщение для хеширования: ")
        message = message_input.encode('utf-8')
        hash_value = IDEAHash(message)
        print(f"Хеш-значение (hex): {hash_value.hex()}")
    else:
        print("Неверный выбор. Попробуйте снова.")

if __name__ == "__main__":
    main()
