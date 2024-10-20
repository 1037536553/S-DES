def permute(original, permutation):
    #根据置换表，对数据进行置换
    return [original[i-1] for i in permutation]

def left_shift(bits, shifts):
    #对输入的bit串进行左移
    return bits[shifts:] + bits[:shifts]

def key_expansion(key):
    #定义P10和P8置换表
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    Left_Shift1 = 1
    Left_Shift2 = 2
    #1.对密钥进行P10置换
    key_p10 = permute(key, P10)
    #2.将置换后的密钥分成左右两部分
    left_half, right_half = key_p10[:5], key_p10[5:]
    #3.K1=对左右两部分分别左移1位
    left_half_ls1 = left_shift(left_half, Left_Shift1)
    right_half_ls1 = left_shift(right_half, Left_Shift1)
    K1 = permute(left_half_ls1 + right_half_ls1, P8)
    #4.K2=对左右两部分分别左移2位
    left_half_ls2 = left_shift(left_half_ls1, Left_Shift2)
    right_half_ls2 = left_shift(right_half_ls1, Left_Shift2)
    K2 = permute(left_half_ls2 + right_half_ls2, P8)

    return K1, K2

def initial_permutation(data):
    #初始置换盒IP
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    return permute(data, IP)

def inverse_initial_permutation(data):
    #逆初始置换盒IP^-1
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    return permute(data, IP_inv)
#替换盒定义
SBOX_1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
SBOX_2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

def s_box(bits, sbox):
    #根据行（首尾两位）和列（中间两位）选择S盒的值
    row = int(f"{bits[0]}{bits[3]}", 2)
    col = int(f"{bits[1]}{bits[2]}", 2)
    return [int(x) for x in format(sbox[row][col], "02b")]

def f_function(right, subkey):
    #1.扩展置换EP
    right_expanded = permute(right, EP)
    #2.与子密钥进行异或操作
    xor_result = [right_expanded[i] ^ subkey[i] for i in range(8)]
    #3.使用S盒替换
    left_bits = xor_result[:4]
    right_bits = xor_result[4:]
    left_sbox = s_box(left_bits, SBOX_1)
    right_sbox = s_box(right_bits, SBOX_2)
    #4.使用P4替换
    return permute(left_sbox + right_sbox, P4)

def fk(data, subkey):
    #将输入数据分为左右两部分
    left, right = data[:4], data[4:]
    #对右半数据使用F函数
    f_output = f_function(right, subkey)
    #左半F异或
    left_new = [left[i] ^ f_output[i] for i in range(4)]
    return left_new + right #合并数据

def switch(data):
    #交换左右两部分
    return data[4:] + data[:4]

#加密函数
def sdes_encrypt(plaintext, key):
    #1.生成子密钥
    K1, K2 = key_expansion(key)
    #2.对明文进行初始置换
    data = initial_permutation(plaintext)
    #3.使用K1加密
    data = fk(data, K1)
    #4.左右交换
    data = switch(data)
    #5.使用K2加密
    data = fk(data, K2)
    #6.逆初始置换
    ciphertext = inverse_initial_permutation(data)
    return ciphertext

#解密函数，注释同上
def sdes_decrypt(ciphertext, key):

    K1, K2 = key_expansion(key)

    data = initial_permutation(ciphertext)

    data = fk(data, K2)

    data = switch(data)

    data = fk(data, K1)

    plaintext = inverse_initial_permutation(data)
    return plaintext

#字符串转二进制
def str_to_bin(s):
    return ''.join(format(ord(x), '08b') for x in s)

#二进制转字符串
def bin_to_str(b):
    chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
    return ''.join(chars)

#GUI实现
import tkinter as tk
from tkinter import messagebox

def is_binary(s):
    return all(c in '01' for c in s)

def encrypt_callback():
    #获取用户输入明文和密钥
    plaintext = input_entry.get()
    key = key_entry.get()

    #检查输入长度
    if len(key) != 10 or not is_binary(key):
        messagebox.showerror("Error", "密钥必须是10位二进制")
        return

    try:
        key_bits = [int(x) for x in key]
        
        if is_binary(plaintext) and len(plaintext) == 8:
            # 输入是二进制
            plaintext_bits = [int(x) for x in plaintext]
            encrypted_bits = sdes_encrypt(plaintext_bits, key_bits)
            # 加密结果显示
            result_entry.delete(0, tk.END)
            result_entry.insert(0, ''.join(map(str, encrypted_bits)))
        else:
            # 输入是字符串
            binary_plaintext = str_to_bin(plaintext)
            encrypted_bits = []
            for i in range(0, len(binary_plaintext), 8):
                plaintext_bits = [int(x) for x in binary_plaintext[i:i+8]]
                encrypted_bits.extend(sdes_encrypt(plaintext_bits, key_bits))
            encrypted_str=bin_to_str(''.join(map(str, encrypted_bits)))
            result_entry.delete(0, tk.END)
            result_entry.insert(0, encrypted_str)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_callback():
    #获取密文和密钥
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
            # 输入是加密后的字符串
            binary_ciphertext = str_to_bin(ciphertext)
            decrypted_bits = []
            for i in range(0, len(binary_ciphertext), 8):
                ciphertext_bits = [int(x) for x in binary_ciphertext[i:i+8]]
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
