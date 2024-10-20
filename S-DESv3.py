def permute(original, permutation):
    return [original[i-1] for i in permutation]

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def key_expansion(key):
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    Left_Shift1 = 1
    Left_Shift2 = 2

    key_p10 = permute(key, P10)
    left_half, right_half = key_p10[:5], key_p10[5:]
    left_half_ls1 = left_shift(left_half, Left_Shift1)
    right_half_ls1 = left_shift(right_half, Left_Shift1)
    K1 = permute(left_half_ls1 + right_half_ls1, P8)
    left_half_ls2 = left_shift(left_half_ls1, Left_Shift2)
    right_half_ls2 = left_shift(right_half_ls1, Left_Shift2)
    K2 = permute(left_half_ls2 + right_half_ls2, P8)

    return K1, K2

def initial_permutation(data):
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    return permute(data, IP)

def inverse_initial_permutation(data):
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    return permute(data, IP_inv)

SBOX_1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
SBOX_2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

def s_box(bits, sbox):
    row = int(f"{bits[0]}{bits[3]}", 2)
    col = int(f"{bits[1]}{bits[2]}", 2)
    return [int(x) for x in format(sbox[row][col], "02b")]

def f_function(right, subkey):
    right_expanded = permute(right, EP)
    xor_result = [right_expanded[i] ^ subkey[i] for i in range(8)]
    left_bits = xor_result[:4]
    right_bits = xor_result[4:]
    left_sbox = s_box(left_bits, SBOX_1)
    right_sbox = s_box(right_bits, SBOX_2)
    return permute(left_sbox + right_sbox, P4)

def fk(data, subkey):
    left, right = data[:4], data[4:]
    f_output = f_function(right, subkey)
    left_new = [left[i] ^ f_output[i] for i in range(4)]
    return left_new + right

def switch(data):
    return data[4:] + data[:4]

def sdes_encrypt(plaintext, key):
    K1, K2 = key_expansion(key)
    data = initial_permutation(plaintext)
    data = fk(data, K1)
    data = switch(data)
    data = fk(data, K2)
    ciphertext = inverse_initial_permutation(data)
    return ciphertext

def sdes_decrypt(ciphertext, key):
    K1, K2 = key_expansion(key)
    data = initial_permutation(ciphertext)
    data = fk(data, K2)
    data = switch(data)
    data = fk(data, K1)
    plaintext = inverse_initial_permutation(data)
    return plaintext

def str_to_bin(s):
    return ''.join(format(ord(x), '08b') for x in s)

def bin_to_str(b):
    chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
    return ''.join(chars)

import tkinter as tk
from tkinter import messagebox

def is_binary(s):
    return all(c in '01' for c in s)

def encrypt_callback():
    plaintext = input_entry.get()
    key = key_entry.get()

    if len(key) != 10 or not is_binary(key):
        messagebox.showerror("Error", "密钥必须是10位二进制")
        return

    try:
        key_bits = [int(x) for x in key]
        
        if is_binary(plaintext) and len(plaintext) == 8:
            # 输入是二进制
            plaintext_bits = [int(x) for x in plaintext]
            encrypted_bits = sdes_encrypt(plaintext_bits, key_bits)
            result_entry.delete(0, tk.END)
            result_entry.insert(0, ''.join(map(str, encrypted_bits)))
        else:
            # 输入是字符串
            binary_plaintext = str_to_bin(plaintext)
            encrypted_bits = []
            for i in range(0, len(binary_plaintext), 8):
                plaintext_bits = [int(x) for x in binary_plaintext[i:i+8]]
                encrypted_bits.extend(sdes_encrypt(plaintext_bits, key_bits))
            result_entry.delete(0, tk.END)
            result_entry.insert(0, ''.join(map(str, encrypted_bits)))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_callback():
    ciphertext = input_entry.get()
    key = key_entry.get()

    if len(key) != 10 or not is_binary(key):
        messagebox.showerror("Error", "密钥必须是10位二进制")
        return

    try:
        key_bits = [int(x) for x in key]

        if is_binary(ciphertext) and len(ciphertext) == 8:
            # 输入是二进制
            ciphertext_bits = [int(x) for x in ciphertext]
            decrypted_bits = sdes_decrypt(ciphertext_bits, key_bits)
            result_entry.delete(0, tk.END)
            result_entry.insert(0, ''.join(map(str, decrypted_bits)))
        else:
            # 输入是加密后的二进制字符串
            decrypted_bits = []
            for i in range(0, len(ciphertext), 8):
                ciphertext_bits = [int(x) for x in ciphertext[i:i+8]]
                decrypted_bits.extend(sdes_decrypt(ciphertext_bits, key_bits))
            # 将二进制结果转为字符串
            decrypted_text = bin_to_str(''.join(map(str, decrypted_bits)))
            result_entry.delete(0, tk.END)
            result_entry.insert(0, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("S-DES 加密/解密")

tk.Label(root, text="输入 (二进制或字符串):").grid(row=0, column=0)
input_entry = tk.Entry(root)
input_entry.grid(row=0, column=1)

tk.Label(root, text="密钥 (10位二进制):").grid(row=1, column=0)
key_entry = tk.Entry(root)
key_entry.grid(row=1, column=1)

encrypt_button = tk.Button(root, text="加密", command=encrypt_callback)
encrypt_button.grid(row=2, column=0)

decrypt_button = tk.Button(root, text="解密", command=decrypt_callback)
decrypt_button.grid(row=2, column=1)

tk.Label(root, text="结果:").grid(row=3, column=0)
result_entry = tk.Entry(root)
result_entry.grid(row=3, column=1)

root.mainloop()
