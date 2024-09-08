import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
import re
import os

# Custom password strength validator
def validate_password(password):
    strength = 0
    feedback = []

    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    if re.search(r'[A-Z]', password):
        strength += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")

    if re.search(r'[a-z]', password):
        strength += 1

    if re.search(r'\d', password):
        strength += 1
    else:
        feedback.append("Password should contain at least one digit.")

    if re.search(r'\W', password):
        strength += 1
    else:
        feedback.append("Password should contain at least one special character.")

    return strength / 5, feedback

# Helper functions for steganography
def genData(data):
    newd = []
    for i in data:
        newd.append(format(i, '08b'))
    return newd

def modPix(pix, data):
    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):
        pix = [value for value in next(imdata)[:3] +
               next(imdata)[:3] +
               next(imdata)[:3]]

        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j] % 2 != 0):
                pix[j] -= 1
            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if (pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                if (pix[-1] != 0):
                    pix[-1] -= 1
                else:
                    pix[-1] += 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encode_enc(newimg, data, progress):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for i, pixel in enumerate(modPix(newimg.getdata(), data)):
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1
        progress['value'] = (i / len(data)) * 100
        root.update_idletasks()

def plot_histograms(image1, image2):
    fig, axs = plt.subplots(2, 3, figsize=(15, 10))

    titles = ['Red Channel', 'Green Channel', 'Blue Channel']
    colors = ['r', 'g', 'b']

    for i, color in enumerate(colors):
        arr1 = np.array(image1)
        arr2 = np.array(image2)

        hist1, bins1 = np.histogram(arr1[:, :, i].flatten(), bins=256, range=(0, 256))
        hist2, bins2 = np.histogram(arr2[:, :, i].flatten(), bins=256, range=(0, 256))

        axs[0, i].plot(hist1, color=color)
        axs[0, i].set_title(f'Cover Image - {titles[i]}')
        axs[0, i].set_xlim([0, 256])

        axs[1, i].plot(hist2, color=color)
        axs[1, i].set_title(f'Encoded Image - {titles[i]}')
        axs[1, i].set_xlim([0, 256])

    plt.tight_layout()
    plt.show()

def pad_key(key, length=32):
    # Ensure key is the specified length
    key = key.ljust(length, '0')
    return key[:length].encode()

def xor_encrypt(data, key):
    key = pad_key(key, len(data))
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i])
    return encrypted_data

def xor_decrypt(data, key):
    return xor_encrypt(data, key)  # XOR decryption is the same as encryption

def aes_encrypt(data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def aes_decrypt(data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return decrypted_data.decode()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(data, public_key):
    max_chunk_size = 190  # For 2048-bit key and OAEP padding
    encrypted_chunks = []
    for i in range(0, len(data), max_chunk_size):
        chunk = data[i:i + max_chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(encrypted_chunk)
    return b"".join(encrypted_chunks)

def rsa_decrypt(data, private_key):
    max_chunk_size = 256  # For 2048-bit key with padding
    decrypted_chunks = []
    for i in range(0, len(data), max_chunk_size):
        chunk = data[i:i + max_chunk_size]
        decrypted_chunk = private_key.decrypt(
            chunk,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)
    return b"".join(decrypted_chunks).decode()

def encode():
    img_path = filedialog.askopenfilename(filetypes=[("Image files", ".png;.jpg;*.jpeg")])
    if not img_path:
        return

    image = Image.open(img_path, 'r')
    preview_img = ImageTk.PhotoImage(image)
    preview_label.config(image=preview_img)
    preview_label.image = preview_img

    data = data_entry.get("1.0", "end").strip()
    if len(data) == 0:
        messagebox.showwarning("Warning", "Data is empty!")
        return

    algorithm = algorithm_var.get()
    if algorithm not in ["AES", "XOR", "RSA"]:
        messagebox.showerror("Error", "Invalid encryption algorithm selected!")
        return

    if algorithm == "RSA":
        private_key, public_key = generate_rsa_keys()
        encrypted_data = rsa_encrypt(data, public_key)
        save_private_key(private_key)
        print_private_key(private_key)  # Print the private key to the terminal
    else:
        key = simpledialog.askstring("Password", "Enter encryption key:", show='*')
        if not key:
            messagebox.showerror("Error", "Invalid key!")
            return

        strength, feedback = validate_password(key)
        if strength < 0.5:
            feedback_msg = "\n".join(str(f) for f in feedback)
            messagebox.showwarning("Weak Password", f"Password is too weak:\n{feedback_msg}")
            return

        if algorithm == "AES":
            key = pad_key(key)  # Adjust key length
            encrypted_data = aes_encrypt(data, key)
        else:  # XOR
            encrypted_data = xor_encrypt(data.encode(), key)

    newimg = image.copy()
    progress['value'] = 0
    encode_enc(newimg, encrypted_data, progress)
    new_img_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                filetypes=[("PNG files", "*.png")])
    if new_img_path:
        newimg.save(new_img_path)
        messagebox.showinfo("Success", "Encoding complete!")
        encoded_image = Image.open(new_img_path)
        display_side_by_side(image, encoded_image)
        plot_histograms(image, encoded_image)
    else:
        messagebox.showwarning("Warning", "File not saved.")


def decode():
    algorithm = algorithm_var.get()
    if algorithm not in ["AES", "XOR", "RSA"]:
        messagebox.showerror("Error", "Invalid encryption algorithm selected!")
        return

    img_path = filedialog.askopenfilename(filetypes=[("Image files", ".png;.jpg;*.jpeg")])
    if not img_path:
        return

    try:
        image = Image.open(img_path, 'r')
        data = bytearray()
        imgdata = iter(image.getdata())

        while True:
            pixels = [value for value in next(imgdata)[:3] +
                      next(imgdata)[:3] +
                      next(imgdata)[:3]]
            binstr = ''
            for i in pixels[:8]:
                if i % 2 == 0:
                    binstr += '0'
                else:
                    binstr += '1'
            data.append(int(binstr, 2))
            if pixels[-1] % 2 != 0:
                break

        if algorithm == "RSA":
            private_key = load_private_key()
            decrypted_data = rsa_decrypt(bytes(data), private_key)
        elif algorithm == "AES":
            key = simpledialog.askstring("Password", "Enter decryption key:", show='*')
            if not key:
                messagebox.showerror("Error", "Invalid key!")
                return
            key = pad_key(key)  # Adjust key length
            decrypted_data = aes_decrypt(bytes(data), key)
        else:  # XOR
            key = simpledialog.askstring("Password", "Enter decryption key:", show='*')
            if not key:
                messagebox.showerror("Error", "Invalid key!")
                return
            decrypted_data = xor_decrypt(bytes(data), key).decode()

        decoded_data.config(state="normal")
        decoded_data.delete("1.0", "end")
        decoded_data.insert("1.0", decrypted_data)
        decoded_data.config(state="disabled")

        messagebox.showinfo("Success", "Decoding complete!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


def save_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    filename = 'private_key.pem'
    count = 1
    while os.path.exists(filename):
        filename = f'private_key_{count}.pem'
        count += 1
    with open(filename, 'wb') as f:
        f.write(pem)


def load_private_key():
    pem_files = [file for file in os.listdir() if file.endswith('.pem')]
    if not pem_files:
        messagebox.showerror("Error", "No private key files found!")
        return None
    elif len(pem_files) == 1:
        filename = pem_files[0]
    else:
        filename = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if not filename:
            return None

    with open(filename, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )
    return private_key


def print_private_key(private_key):
    print("RSA Private Key:")
    print(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())


def display_side_by_side(image1, image2):
    side_by_side = Image.new('RGB', (image1.width + image2.width, max(image1.height, image2.height)))
    side_by_side.paste(image1, (0, 0))
    side_by_side.paste(image2, (image1.width, 0))

    side_by_side_img = ImageTk.PhotoImage(side_by_side)
    side_by_side_label.config(image=side_by_side_img)
    side_by_side_label.image = side_by_side_img


# GUI
root = tk.Tk()
root.title("Steganography")
root.geometry("1200x800")
root.config(bg="#121502")

font_style = ("Times New Roman", 16)
button_style = ("Times New Roman", 16, "bold")
label_style = ("Times New Roman", 16)

main_frame = tk.Frame(root, bg="#121502")
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

encode_frame = tk.LabelFrame(main_frame, text="Encode", bg="#ffffff", fg="#333333", font=font_style)
encode_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

data_label = tk.Label(encode_frame, text="Enter data to be encoded:", bg="#ffffff", fg="#333333", font=font_style)
data_label.pack(pady=(10, 5))

data_entry = tk.Text(encode_frame, height=5)
data_entry.pack(padx=10, pady=(0, 10), fill="both", expand=True)

algorithm_label = tk.Label(encode_frame, text="Select Encryption Algorithm:", bg="#ffffff", fg="#333333",
                           font=font_style)
algorithm_label.pack(pady=(10, 5))

algorithm_var = tk.StringVar(value="AES")
aes_radio = tk.Radiobutton(encode_frame, text="AES", variable=algorithm_var, value="AES", font=label_style,
                           bg="#ffffff")
aes_radio.pack(anchor="w", padx=20)

xor_radio = tk.Radiobutton(encode_frame, text="XOR", variable=algorithm_var, value="XOR", font=label_style,
                           bg="#ffffff")
xor_radio.pack(anchor="w", padx=20)

rsa_radio = tk.Radiobutton(encode_frame, text="RSA", variable=algorithm_var, value="RSA", font=label_style,
                           bg="#ffffff")
rsa_radio.pack(anchor="w", padx=20)

encode_button = tk.Button(encode_frame, text="Encode", command=encode, font=button_style, bg="#4CAF50", fg="#ffffff")
encode_button.pack(pady=(10, 20))

progress = ttk.Progressbar(encode_frame, orient="horizontal", length=300, mode="determinate")
progress.pack(pady=(0, 20))

decode_frame = tk.LabelFrame(main_frame, text="Decode", bg="#ffffff", fg="#333333", font=font_style)
decode_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

decoded_label = tk.Label(decode_frame, text="Decoded data:", bg="#ffffff", fg="#333333", font=font_style)
decoded_label.pack(pady=(10, 5))

decoded_data = tk.Text(decode_frame, height=5, state="disabled")
decoded_data.pack(padx=10, pady=(0, 10), fill="both", expand=True)

decode_button = tk.Button(decode_frame, text="Decode", command=decode, font=button_style, bg="#f44336", fg="#ffffff")
decode_button.pack(pady=(10, 20))

image_frame = tk.Frame(main_frame, bg="#121502")
image_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

preview_label = tk.Label(image_frame, bg="#121502")
preview_label.pack(side="left", padx=10, pady=10)

side_by_side_label = tk.Label(image_frame, bg="#121502")
side_by_side_label.pack(side="right", padx=10, pady=10)

root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)
main_frame.grid_rowconfigure(1, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)

root.mainloop()
