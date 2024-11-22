key = b"1234567812345678"

IDEA_ADD_MODULAR = 65536  # 2^16
IDEA_MP_MODULAR = 65537   # 2^16 + 1

def add_mod(a, b):
    # Сложение по модулю 2^16
    return (a + b) % IDEA_ADD_MODULAR

def add_inv(a):
    # Аддитивное обратное по модулю 2^16
    return (-a) % IDEA_ADD_MODULAR

def multi_mod(a, b):
    # Умножение по модулю 2^16 + 1, где 0 заменяется на 2^16
    if a == 0:
        tmp_a = IDEA_ADD_MODULAR
    else:
        tmp_a = a
    if b == 0:
        tmp_b = IDEA_ADD_MODULAR
    else:
        tmp_b = b
    tmp = (tmp_a * tmp_b) % IDEA_MP_MODULAR
    if tmp == IDEA_ADD_MODULAR:
        tmp = 0
    return tmp

def multi_inv(a):
    # Мультипликативное обратное по модулю 2^16 + 1
    if a == 0:
        a = IDEA_ADD_MODULAR
    t0, t1 = 0, 1
    r0, r1 = IDEA_MP_MODULAR, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if t0 < 0:
        t0 += IDEA_MP_MODULAR
    if r0 > 1:
        return 0  # Обратного элемента не существует
    return t0

def RolLeft(tmpKey):
    # Циклический сдвиг ключа на 25 бит влево (5 раз по 16 бит)
    highPart = tmpKey[0] >> (16 - 5)
    for i in range(7):
        tmpKey[i] = ((tmpKey[i] << 5) | (tmpKey[i+1] >> (16 - 5))) & 0xFFFF
    tmpKey[7] = ((tmpKey[7] << 5) | highPart) & 0xFFFF

def ExtendKey():
    # Генерация расширенного ключа (52 субключа по 16 бит)
    tmpKey = []
    subKey = []
    for i in range(8):
        # Инициализация начального ключа из 128 битного ключа
        subkey_i = (key[2 * i] << 8) | key[2 * i + 1]
        subKey.append(subkey_i)
        tmpKey.append(subkey_i)
    for i in range(1, 6):
        for k in range(5):
            RolLeft(tmpKey)
        for j in range(8):
            subKey.append(tmpKey[j])
    # Последние 4 субключа
    for k in range(5):
        RolLeft(tmpKey)
    for i in range(4):
        subKey.append(tmpKey[i])
    return subKey

def GenerateDecryptionSubkeys(enc_subkeys):
    # Генерация субключей для расшифровки на основе субключей шифрования
    dec_subkeys = [0]*52
    for i in range(8):
        en_key_index = 6 * (8 - i)
        en_key_index_prev = 6 * (7 - i)
        dec_key_index = i * 6

        dec_subkeys[dec_key_index] = multi_inv(enc_subkeys[en_key_index % 52])

        if i == 0:
            dec_subkeys[dec_key_index + 1] = add_inv(enc_subkeys[(en_key_index + 1) % 52])
            dec_subkeys[dec_key_index + 2] = add_inv(enc_subkeys[(en_key_index + 2) % 52])
        else:
            dec_subkeys[dec_key_index + 1] = add_inv(enc_subkeys[(en_key_index + 2) % 52])
            dec_subkeys[dec_key_index + 2] = add_inv(enc_subkeys[(en_key_index + 1) % 52])

        dec_subkeys[dec_key_index + 3] = multi_inv(enc_subkeys[(en_key_index + 3) % 52])

        dec_subkeys[dec_key_index + 4] = enc_subkeys[(en_key_index_prev + 4) % 52]
        dec_subkeys[dec_key_index + 5] = enc_subkeys[(en_key_index_prev + 5) % 52]

    # Субключи последнего раунда
    dec_subkeys[48] = multi_inv(enc_subkeys[0])
    dec_subkeys[49] = add_inv(enc_subkeys[1])
    dec_subkeys[50] = add_inv(enc_subkeys[2])
    dec_subkeys[51] = multi_inv(enc_subkeys[3])

    return dec_subkeys

def IDEARound(x, round, subKey):
    # Один раунд алгоритма IDEA
    tmp = [0]*4
    for i in range(4):
        tmp[i] = x[i]
    # Шаг 1: Применение операций к блокам данных и субключам
    tmp[0] = multi_mod(x[0], subKey[6*round]) & 0xFFFF
    tmp[1] = add_mod(x[1], subKey[6*round+1]) & 0xFFFF
    tmp[2] = add_mod(x[2], subKey[6*round+2]) & 0xFFFF
    tmp[3] = multi_mod(x[3], subKey[6*round+3]) & 0xFFFF
    # Шаг 2: Вычисление промежуточных значений
    out0 = tmp[0] ^ tmp[2]
    out1 = tmp[1] ^ tmp[3]
    out2 = multi_mod(out0, subKey[6*round+4]) & 0xFFFF
    out3 = add_mod(out1, out2) & 0xFFFF
    out4 = multi_mod(out3, subKey[6*round+5]) & 0xFFFF
    out5 = add_mod(out2, out4) & 0xFFFF
    # Шаг 3: Обновление значений
    out = [0]*4
    out[0] = tmp[0] ^ out4
    out[1] = tmp[1] ^ out5
    out[2] = tmp[2] ^ out4
    out[3] = tmp[3] ^ out5
    # Шаг 4: Перестановка
    temp = out[1]
    out[1] = out[2]
    out[2] = temp
    for i in range(4):
        x[i] = out[i] & 0xFFFF

def IDEAEncryptBlock(data_block, subKey):
    # Шифрование одного блока данных (8 байт)
    x = []
    for i in range(4):
        x_i = (data_block[2*i] <<8) | data_block[2*i+1]
        x.append(x_i)
    # Выполнение 8 раундов
    for j in range(8):
        IDEARound(x, j, subKey)
    # Обратная перестановка
    temp = x[1]
    x[1] = x[2]
    x[2] = temp
    # Применение субключей выходного преобразования
    x[0] = multi_mod(x[0], subKey[48]) & 0xFFFF
    x[1] = add_mod(x[1], subKey[49]) & 0xFFFF
    x[2] = add_mod(x[2], subKey[50]) & 0xFFFF
    x[3] = multi_mod(x[3], subKey[51]) & 0xFFFF
    # Формирование зашифрованного блока
    result_block = bytearray(8)
    for i in range(4):
        result_block[2*i] = (x[i] >>8) & 0xFF
        result_block[2*i+1] = x[i] & 0xFF
    return result_block

def IDEADecryptBlock(data_block, subKey):
    # Расшифровка одного блока данных (8 байт)
    x = []
    for i in range(4):
        x_i = (data_block[2*i] <<8) | data_block[2*i+1]
        x.append(x_i)
    # Выполнение 8 раундов
    for j in range(8):
        IDEARound(x, j, subKey)
    # Обратная перестановка
    temp = x[1]
    x[1] = x[2]
    x[2] = temp
    # Применение субключей выходного преобразования
    x[0] = multi_mod(x[0], subKey[48]) & 0xFFFF
    x[1] = add_mod(x[1], subKey[49]) & 0xFFFF
    x[2] = add_mod(x[2], subKey[50]) & 0xFFFF
    x[3] = multi_mod(x[3], subKey[51]) & 0xFFFF
    # Формирование расшифрованного блока
    result_block = bytearray(8)
    for i in range(4):
        result_block[2*i] = (x[i] >>8) & 0xFF
        result_block[2*i+1] = x[i] & 0xFF
    return result_block

def pad(data):
    # Дополнение данных до кратности 8 байтам (PKCS5)
    pad_len = 8 - (len(data) % 8)
    padding = bytes([pad_len] * pad_len)
    return data + padding

def unpad(data):
    # Удаление дополнения
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Недопустимый padding")
    return data[:-pad_len]

def IDEAEncrypt(data, subKey):
    # Шифрование данных
    data = pad(data)
    len_blocks = len(data) //8
    encrypted_data = bytearray()
    for count in range(len_blocks):
        block = data[count*8:(count+1)*8]
        enc_block = IDEAEncryptBlock(block, subKey)
        encrypted_data.extend(enc_block)
    return encrypted_data

def IDEADecrypt(data, subKey):
    # Расшифровка данных
    if len(data) % 8 != 0:
        print("Ошибка в выравнивании шифрованного текста!")
        return None
    len_blocks = len(data) //8
    decrypted_data = bytearray()
    for count in range(len_blocks):
        block = data[count*8:(count+1)*8]
        dec_block = IDEADecryptBlock(block, subKey)
        decrypted_data.extend(dec_block)
    decrypted_data = unpad(decrypted_data)
    return decrypted_data
