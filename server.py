"""
chat server with RSA key exchange and encrypted messaging
"""

import socket
import threading
import base64

from rsa_crypto import (
    generate_keypair, rsa_encrypt_bytes, rsa_decrypt_bytes,
    symmetric_encrypt, symmetric_decrypt,
    compute_hash, verify_integrity,
    send_message, receive_message,
    generate_symmetric_key
)


class Server:

    def __init__(self, port):
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.client_keys = {}  # symmetric key per client
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)

        # generate server RSA keys
        print("[server] generating RSA keys...")
        self.public_key, self.private_key = generate_keypair(1024)
        print(f"[server] keys ready (e={self.public_key[0]}, n is {self.public_key[1].bit_length()} bits)")
        print(f"[server] listening on {self.host}:{self.port}")

        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"\n[server] {username} connecting from {addr}")

            # send our public key to client
            send_message(c, {
                "type": "server_public_key",
                "e": str(self.public_key[0]),
                "n": str(self.public_key[1])
            })
            print(f"[server] sent public key to {username}")

            # get clients public key
            client_key_msg = receive_message(c)
            client_pub_key = (int(client_key_msg["e"]), int(client_key_msg["n"]))
            print(f"[server] got public key from {username}")

            # generate unique symmetric key for this client
            sym_key = generate_symmetric_key(32)
            self.client_keys[c] = sym_key
            print(f"[server] generated symmetric key for {username}")

            # encrypt symmetric key with clients RSA public key and send it
            # only they can decrypt it with their private key
            encrypted_sym_key = rsa_encrypt_bytes(sym_key, client_pub_key)
            send_message(c, {
                "type": "encrypted_secret",
                "blocks": [str(b) for b in encrypted_sym_key]
            })
            print(f"[server] sent encrypted symmetric key to {username}")
            print(f"[server] secure connection established with {username}")

            self.username_lookup[c] = username
            self.clients.append(c)

            # tell everyone about new user
            self.broadcast(f'[server] {username} joined the chat', exclude=c)

            threading.Thread(
                target=self.handle_client,
                args=(c, addr,),
                daemon=True
            ).start()

    def broadcast(self, msg, exclude=None):
        """send message to all clients
        for each client: hash the plaintext, encrypt it, send both
        receiver can then decrypt and check hash to verify integrity
        """
        for client in self.clients:
            if client == exclude:
                continue
            try:
                sym_key = self.client_keys.get(client)
                if sym_key is None:
                    continue

                msg_bytes = msg.encode('utf-8')

                # 1) compute hash of plaintext
                msg_hash = compute_hash(msg_bytes)

                # 2) encrypt with this clients symmetric key
                encrypted_data = symmetric_encrypt(msg_bytes, sym_key)

                # 3) send hash + encrypted data together
                send_message(client, {
                    "type": "chat",
                    "hash": msg_hash,
                    "data": base64.b64encode(encrypted_data).decode('ascii')
                })
            except Exception as e:
                print(f"[server] error sending to client: {e}")
                self.remove_client(client)

    def handle_client(self, c, addr):
        """handle incoming messages from a client
        decrypt -> check integrity -> forward to others
        """
        while True:
            try:
                msg_data = receive_message(c)
                if msg_data is None:
                    break

                sym_key = self.client_keys[c]
                username = self.username_lookup[c]

                # get hash and encrypted data
                received_hash = msg_data["hash"]
                encrypted_data = base64.b64decode(msg_data["data"])

                # decrypt
                decrypted_bytes = symmetric_decrypt(encrypted_data, sym_key)
                decrypted_msg = decrypted_bytes.decode('utf-8')

                # verify integrity - compare hashes
                if verify_integrity(decrypted_bytes, received_hash):
                    print(f"[server] msg from {username}: integrity OK")
                else:
                    print(f"[server] WARNING: msg from {username}: integrity FAILED")
                    continue  # drop tampered messages

                # forward to other clients
                full_msg = f"{username}: {decrypted_msg}"
                self.broadcast(full_msg, exclude=c)

            except Exception as e:
                print(f"[server] error with client {addr}: {e}")
                break

        self.remove_client(c)

    def remove_client(self, c):
        if c in self.clients:
            username = self.username_lookup.get(c, "Unknown")
            self.clients.remove(c)
            self.username_lookup.pop(c, None)
            self.client_keys.pop(c, None)
            print(f"[server] {username} disconnected")
            self.broadcast(f"[server] {username} left the chat")
            c.close()


if __name__ == "__main__":
    s = Server(9001)
    s.start()
