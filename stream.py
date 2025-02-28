import os
import sys
from functools import reduce

# Function to generate a keystream from the password
def generate_lck(password, n):
    # Magic numbers used for the Linear Congruential Generator (LCG)
    a = 1103515245
    c = 12345
    m = 256  # modulus 2^8 (byte size)

    # Generate seed from the password (using sdbm hash)
    seed = sdbm_hash(password)
    keystream_blist = []
    x_value = seed

    # Generate the keystream bytes
    for _ in range(n):
        x_value = (a * x_value + c) % m
        keystream_blist.append(x_value)

    return keystream_blist

# Function to generate hash from password using sdbm hash function
def sdbm_hash(s):
    return reduce(lambda h, c: (ord(c) + (h << 6) + (h << 16) - h) & 0xFFFFFFFF, s, 0)

# Function to XOR the keystream with the file bytes and produce encrypted output
def scrypt(n, keystream_blist, file_blist, output_file):
    with open(output_file, "wb") as f:
        for i in range(n):
            # XOR the file byte with the corresponding keystream byte
            key_byte = keystream_blist[i]
            file_byte = int.from_bytes(file_blist[i], "big")
            encrypted_byte = key_byte ^ file_byte

            # Write the encrypted byte to the output file
            f.write(encrypted_byte.to_bytes(1, 'big'))

# Function to read file and return list of bytes
def read_file(file_name):
    with open(file_name, 'rb') as f:
        return [bytes([byte]) for byte in f.read()]

# Main function to process command line input and perform encryption
def main():
    if len(sys.argv) != 4:
        print("Usage: python3 stream_cipher.py <password> <input_file> <output_file>")
        sys.exit(1)

    password = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    # Read the file to be encrypted
    file_blist = read_file(input_file)

    # Generate keystream based on the password and file length
    keystream_blist = generate_lck(password, len(file_blist))

    # Encrypt the file using the stream cipher
    scrypt(len(file_blist), keystream_blist, file_blist, output_file)
    print(f"Encryption complete. Encrypted file saved as {output_file}")

if __name__ == "__main__":
    main()
