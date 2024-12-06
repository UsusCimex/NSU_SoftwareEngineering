from PIL import Image

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def embed_message(in_image_path, out_image_path, message):
    img = Image.open(in_image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    width, height = img.size
    msg_bits = text_to_bits(message) + '00000000'  # маркер конца строки
    
    if len(msg_bits) > width * height:
        raise ValueError("Сообщение слишком длинное для данного изображения")
    
    pixels = list(img.getdata())
    new_pixels = []
    bit_index = 0

    for r, g, b in pixels:
        if bit_index < len(msg_bits):
            new_b = (b & ~1) | int(msg_bits[bit_index])
            new_pixels.append((r, g, new_b))
            bit_index += 1
        else:
            new_pixels.append((r, g, b))
    
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_pixels)
    new_img.save(out_image_path, 'PNG')

def extract_message(stego_image_path):
    img = Image.open(stego_image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    bits = []
    pixels = list(img.getdata())
    
    for r, g, b in pixels:
        bits.append(str(b & 1))
        if len(bits) >= 8:
            last_byte = ''.join(bits[-8:])
            if last_byte == '00000000':
                bitstring = ''.join(bits[:-8])
                return bits_to_text(bitstring)
    
    bitstring = ''.join(bits)
    return bits_to_text(bitstring)

embed_message('cat.png', 'secret.png', 'Secret message or funny cats')
secret = extract_message('secret.png')
print("Извлеченное сообщение:", secret)
