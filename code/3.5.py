import itertools
import time

# 置换和功能相关函数
def permute(input_bits, permutation_table):
    return ''.join(input_bits[i - 1] for i in permutation_table)

def left_shift(bits, num_shifts):
    return bits[num_shifts:] + bits[:num_shifts]

def sbox(input_bits, sbox_table):
    row = int(input_bits[0] + input_bits[3], 2)  # 行
    col = int(input_bits[1] + input_bits[2], 2)  # 列
    return f'{sbox_table[row][col]:02b}'

def key_schedule(key):
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    key = permute(key, p10)
    
    left_half, right_half = key[:5], key[5:]
    left_half = left_shift(left_half, 1)
    right_half = left_shift(right_half, 1)
    
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]
    k1 = permute(left_half + right_half, p8)
    
    left_half = left_shift(left_half, 2)
    right_half = left_shift(right_half, 2)
    
    k2 = permute(left_half + right_half, p8)
    
    return k1, k2

def fk(bits, subkey):
    left_half, right_half = bits[:4], bits[4:]
    ep = [4, 1, 2, 3, 2, 3, 4, 1]
    expanded_right = permute(right_half, ep)
    xor_result = f'{int(expanded_right, 2) ^ int(subkey, 2):08b}'
    
    sbox_1 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]
    
    sbox_2 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]
    
    left_sbox = xor_result[:4]
    right_sbox = xor_result[4:]
    sbox_output = sbox(left_sbox, sbox_1) + sbox(right_sbox, sbox_2)
    p4 = [2, 4, 3, 1]
    
    return permute(sbox_output, p4)

def sdes_encrypt(plain_text, key):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    
    k1, k2 = key_schedule(key)
    text = permute(plain_text, ip)
    
    left_half, right_half = text[:4], text[4:]
    fk_result = fk(text, k1)
    text = right_half + f'{int(left_half, 2) ^ int(fk_result, 2):04b}'
    
    left_half, right_half = text[:4], text[4:]
    fk_result = fk(text, k2)
    text = f'{int(left_half, 2) ^ int(fk_result, 2):04b}' + right_half
    
    return permute(text, ip_inv)

def sdes_decrypt(cipher_text, key):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    ip_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    
    k1, k2 = key_schedule(key)
    text = permute(cipher_text, ip)
    
    left_half, right_half = text[:4], text[4:]
    fk_result = fk(text, k2)
    text = right_half + f'{int(left_half, 2) ^ int(fk_result, 2):04b}'
    
    left_half, right_half = text[:4], text[4:]
    fk_result = fk(text, k1)
    text = f'{int(left_half, 2) ^ int(fk_result, 2):04b}' + right_half
    
    return permute(text, ip_inv)

# 检测密钥唯一性的函数
def check_unique_key(plain_text, cipher_text):
    possible_keys = [''.join(seq) for seq in itertools.product('01', repeat=10)]  # 生成所有10位二进制密钥
    valid_keys = []
    
    for key in possible_keys:
        decrypted_text = sdes_decrypt(cipher_text, key)
        if decrypted_text == plain_text:
            valid_keys.append(key)
    
    return valid_keys

# 检测明文-密文对的唯一密钥
def find_unique_key_pair():
    # 所有可能的8位明文
    possible_texts = [''.join(seq) for seq in itertools.product('01', repeat=8)]
    
    for plain_text in possible_texts:
        for key in itertools.product('01', repeat=10):
            key_str = ''.join(key)
            cipher_text = sdes_encrypt(plain_text, key_str)
            valid_keys = check_unique_key(plain_text, cipher_text)
            if len(valid_keys) == 1:
                print(f"唯一密钥对: 明文={plain_text}, 密文={cipher_text}, 密钥={valid_keys[0]}")
                return plain_text, cipher_text, valid_keys[0]
    
    print("未找到唯一密钥对")
    return None

# 运行检测
if __name__ == "__main__":
    start_time = time.time()
    result = find_unique_key_pair()
    end_time = time.time()
    
    if result:
        print(f"检测时间: {end_time - start_time:.2f}秒")
    else:
        print(f"未找到唯一密钥对，检测时间: {end_time - start_time:.2f}秒")
