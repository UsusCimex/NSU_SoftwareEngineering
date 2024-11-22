def rc4_encrypt(key, plaintext):
    S = list(range(256))
    j = 0
    key_length = len(key)
    # Алгоритм ключевого расписания (KSA)
    for i in range(256):
        j = (j + S[i] + ord(key[i % key_length])) % 256
        S[i], S[j] = S[j], S[i]  # Swap

    # Генерация псевдослучайной последовательности (PRGA)
    i = j = 0
    keystream = []
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)

    # Шифрование
    ciphertext = []
    for c, k in zip(plaintext, keystream):
        ciphertext.append(chr(ord(c) ^ k))

    return ''.join(ciphertext)

def rc4_decrypt(key, ciphertext):
    # RC4 является симметричным шифром
    return rc4_encrypt(key, ciphertext)