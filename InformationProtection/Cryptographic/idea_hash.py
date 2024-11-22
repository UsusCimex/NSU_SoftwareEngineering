import hashlib
from idea import ExtendKey, pad, key, IDEAEncryptBlock

def IDEAHash(message):
    # Генерация ключей для шифрования
    enc_subkeys = ExtendKey()
    
    # Дополняем данные до кратности 8 байтам
    data = pad(message)
    
    # Начальное значение для хэширования
    hash_state = bytearray(b"IDEAHASH")
    
    # Разделяем данные на блоки и шифруем каждый блок, обновляя состояние
    len_blocks = len(data) // 8
    for count in range(len_blocks):
        block = bytearray(data[count * 8:(count + 1) * 8])  # Преобразование в bytearray
        # XOR блока данных с текущим состоянием
        for i in range(8):
            block[i] ^= hash_state[i]
        
        # Шифруем результат XOR
        hash_state = IDEAEncryptBlock(block, enc_subkeys)
    
    # Дополнительный этап - применение хэширования SHA-256 для большей безопасности
    final_hash = hashlib.sha256(hash_state).digest()
    
    return final_hash
