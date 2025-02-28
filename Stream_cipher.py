import socket
import threading
import sys
from stream import generate_lck, scrypt, read_file  # Importing your stream cipher functions

def handle_receive(client_socket, keystream_blist):
    """This function will handle receiving and decrypting messages from the other peer."""
    while True:
        try:
            # Receive encrypted message as bytes
            message = client_socket.recv(1024)
            if not message:  # If no message is received, break the loop
                break

            # Decrypt the received message using XOR and keystream
            decrypted_message = decrypt_message(message, keystream_blist)
            print(f"Peer: {decrypted_message.decode()}")

        except Exception as e:
            print(f"Error while receiving message: {e}")
            break

def decrypt_message(encrypted_message, keystream_blist):
    """Decrypt a message using the keystream (XOR operation)."""
    decrypted_bytes = []
    for i in range(len(encrypted_message)):
        decrypted_byte = encrypted_message[i] ^ keystream_blist[i]
        decrypted_bytes.append(decrypted_byte)
    return bytes(decrypted_bytes)

def start_server(port, password):
    """This function will act as a server to accept incoming connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(1)
    print(f"Waiting for connection on port {port}...")

    client_socket, client_address = server_socket.accept()
    print(f"Connected to {client_address}")

    # Generate the keystream based on the password and file length
    keystream_blist = generate_lck(password, 1024)  # Arbitrary length for keystream

    # Start a thread to receive and decrypt messages from the peer
    threading.Thread(target=handle_receive, args=(client_socket, keystream_blist), daemon=True).start()

    return client_socket, keystream_blist

def start_client(host, port, password):
    """This function will connect to another peer's server."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to peer at {host}:{port}")

    # Generate the keystream based on the password and file length
    keystream_blist = generate_lck(password, 1024)  # Arbitrary length for keystream

    # Start a thread to receive and decrypt messages from the server
    threading.Thread(target=handle_receive, args=(client_socket, keystream_blist), daemon=True).start()

    return client_socket, keystream_blist

def send_encrypted_message(client_socket, message, keystream_blist):
    """Encrypt and send a message to the peer."""
    encrypted_message = encrypt_message(message, keystream_blist)
    client_socket.send(encrypted_message)

def encrypt_message(message, keystream_blist):
    """Encrypt a message using the keystream."""
    message_bytes = bytes(message, "utf-8")
    encrypted_bytes = []

    # XOR the message with the keystream bytes
    for i in range(len(message_bytes)):
        encrypted_byte = message_bytes[i] ^ keystream_blist[i]
        encrypted_bytes.append(encrypted_byte)

    # Return the encrypted message as bytes
    return bytes(encrypted_bytes)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 stream_cipher_chat.py <password>")
        sys.exit(1)

    password = sys.argv[1]

    # Ask if this client will start as server or client
    role = input("Do you want to be the server (wait for connection)? (y/n): ").strip().lower()

    if role == 'y':
        # Start as a server, waiting for incoming connections
        port = int(input("Enter port number to listen on: "))
        client_socket, keystream_blist = start_server(port, password)
    else:
        # Start as a client, connecting to another peer
        host = input("Enter the IP address of the peer: ").strip()
        port = int(input("Enter the port number of the peer: "))
        client_socket, keystream_blist = start_client(host, port, password)

    try:
        while True:
            # Get user input for message
            message = input("You: ")
            send_encrypted_message(client_socket, message, keystream_blist)

            if message.lower() == 'exit':
                print("Closing connection.")
                break
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
