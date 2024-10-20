import tkinter as tk
from tkinter import ttk, messagebox
import itertools
import threading
import time

# S-DES相关的置换和功能
def permute(input_bits, permutation_table):
    return ''.join(input_bits[i - 1] for i in permutation_table)

def left_shift(bits, num_shifts):
    return bits[num_shifts:] + bits[:num_shifts]

def sbox(input_bits, sbox_table):
    row = int(input_bits[0] + input_bits[3], 2)  # 取行
    col = int(input_bits[1] + input_bits[2], 2)  # 取列
    return f'{sbox_table[row][col]:02b}'  # 返回2位的二进制结果

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

# 暴力破解：给定明文和密文对，尝试找到所有匹配的密钥
def brute_force_decrypt(cipher_text, plain_text, result_var):
    possible_keys = [''.join(seq) for seq in itertools.product('01', repeat=10)]  # 生成所有10位二进制密钥
    found_keys = []
    start_time = time.time()
    
    def try_keys(start, end):
        for key in possible_keys[start:end]:
            decrypted_text = sdes_decrypt(cipher_text, key)
            if decrypted_text == plain_text:
                found_keys.append(key)

    # 使用多线程提高暴力破解速度
    num_threads = 4
    chunk_size = len(possible_keys) // num_threads
    threads = []

    for i in range(num_threads):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_threads - 1 else len(possible_keys)
        thread = threading.Thread(target=try_keys, args=(start, end))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    if found_keys:
        result_var.set(f"找到密钥: {', '.join(found_keys)}")
        messagebox.showinfo("破解成功", f"找到的密钥: {', '.join(found_keys)}\n破解时间: {end_time - start_time:.2f}秒")
    else:
        result_var.set("未能找到密钥")

# GUI实现
def create_gui():
    window = tk.Tk()
    window.title("S-DES 暴力破解")
    window.geometry("400x300")
    
    tk.Label(window, text="明文 (8位二进制):").pack()
    plaintext_entry = tk.Entry(window)
    plaintext_entry.pack()
    
    tk.Label(window, text="密文 (8位二进制):").pack()
    ciphertext_entry = tk.Entry(window)
    ciphertext_entry.pack()

    result_var = tk.StringVar()
    result_label = tk.Label(window, textvariable=result_var)
    result_label.pack(pady=10)
    
    def on_brute_force_click():
        plaintext = plaintext_entry.get()
        ciphertext = ciphertext_entry.get()
        if len(plaintext) != 8 or len(ciphertext) != 8:
            messagebox.showerror("输入错误", "请输入8位二进制的明文和密文")
            return
        result_var.set("破解中...")
        threading.Thread(target=brute_force_decrypt, args=(ciphertext, plaintext, result_var)).start()

    brute_force_button = ttk.Button(window, text="开始暴力破解", command=on_brute_force_click)
    brute_force_button.pack(pady=10)
    
    window.mainloop()

if __name__ == "__main__":
    create_gui()
