# Encryption-Based-Image-Steganography

This project provides a GUI tool for encoding and decoding hidden messages within images using steganography. The encoded message is encrypted for additional security using various encryption algorithms such as AES, XOR, and RSA. 

## Features

- **Steganography**: Hides data within an image by altering pixel values.
- **Encryption Algorithms**:
  - **AES**: Advanced Encryption Standard (128-bit key size).
  - **XOR**: Simple XOR encryption with a custom key.
  - **RSA**: Asymmetric encryption with public and private key pairs.
- **Password Strength Validation**: Ensures strong passwords for encryption.
- **Image Comparison**: Displays original and encoded images side-by-side and plots histograms for better visual comparison.
- **Private Key Management**: RSA private keys are generated, saved, and loaded for encryption and decryption.

## Requirements

- Python 3.7 or higher
- Libraries:
  - `tkinter`
  - `Pillow`
  - `matplotlib`
  - `cryptography`
  - `numpy`
  - `re`
  - `os`

Install the required dependencies using:

```bash
pip install Pillow matplotlib cryptography numpy
```
## Usage
### Encode a Message
- Select an image file (.png, .jpg, .jpeg).
- Enter the text you want to encode.
- Choose an encryption algorithm:
   - AES: Enter a password for encryption.
   - XOR: Enter a password for XOR encryption.
   - RSA: Automatically generates a public/private key pair.
- Click Encode.
- Save the newly encoded image.
- View the original and encoded images side-by-side.
  ![image](https://github.com/user-attachments/assets/9e0fdec5-1c3a-43f1-baf3-eff83ab68093)
  ![image](https://github.com/user-attachments/assets/1b9c9097-078b-4146-a864-20b8bff5cc44)
  ![image](https://github.com/user-attachments/assets/22fd23a2-6d9b-4800-93c4-b3a88788d9d5)



### Decode a Message
- Select an encoded image file.
- Choose the encryption algorithm used during encoding.
- Enter the decryption key:
  - For RSA, load the private key (.pem file).
  - For AES and XOR, enter the key used during encoding.
- Click Decode.
- The hidden message will be displayed.

![image](https://github.com/user-attachments/assets/cd56d6a6-6eab-4066-90c3-3a494f9bc28a)
![image](https://github.com/user-attachments/assets/73884848-b176-4233-88c7-e0fdfc51d458)



### Password Strength Validator
For AES and XOR, the password entered for encryption is validated against the following criteria:

- At least 8 characters long
- Contains at least one uppercase letter
- Contains at least one digit
- Contains at least one special character
### RSA Key Management
- Private Key Generation: RSA private and public keys are generated when RSA is selected for encryption.
- Save Key: The private key is saved as a .pem file for later use.
- Load Key: During decoding, the private key is used to decrypt the data.
### GUI Overview
- Encode Section: Input the data to be encoded, choose encryption, and encode into the selected image.
- Decode Section: Select an encoded image, choose the correct decryption algorithm, and retrieve the hidden data.
- Image Comparison: Visualize the differences between the original and encoded images, both side-by-side and using histograms for each RGB channel.
### Future Enhancements
- Support for other file formats.
- Improve the performance of the encoding/decoding process for larger images.
- Add support for more advanced encryption algorithms.
## License
This project is open-source and free to use under the MIT License.
