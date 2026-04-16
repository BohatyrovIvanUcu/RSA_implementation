"""
chat client with RSA key exchange and encrypted messaging
"""

import socket
import threading
import base64

from rsa_crypto import (
    generate_keypair, rsa_decrypt_bytes,
    symmetric_encrypt, symmetric_decrypt,
    compute_hash, verify_integrity,
    send_message, receive_message
)


class Client:

    def __init__(self, server_ip, port, username):
        self.server_ip = server_ip
        self.port = port
        self.username = username

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client] could not connect:", e)
            return

        # send username first (before key exchange)
        self.s.send(self.username.encode())

        # generate our RSA key pair
        print("[client] generating RSA keys...")
        self.public_key, self.private_key = generate_keypair(1024)
        print(f"[client] RSA keys ready")

        # get servers public key
        server_key_msg = receive_message(self.s)
        self.server_public_key = (
            int(server_key_msg["e"]),
            int(server_key_msg["n"])
        )
        print(f"[client] got servers public key")

        # send our public key to server
        send_message(self.s, {
            "type": "client_public_key",
            "e": str(self.public_key[0]),
            "n": str(self.public_key[1])
        })
        print(f"[client] sent our public key")

        # receive encrypted symmetric key from server
        # server encrypted it with OUR public key so only we can decrypt
        secret_msg = receive_message(self.s)
        encrypted_blocks = [int(b) for b in secret_msg["blocks"]]

        # decrypt symmetric key using our private RSA key
        self.symmetric_key = rsa_decrypt_bytes(encrypted_blocks, self.private_key)
        print(f"[client] got symmetric key ({len(self.symmetric_key)} bytes)")
        print(f"[client] secure connection ready\n")

        # start read and write threads
        message_handler = threading.Thread(target=self.read_handler, daemon=True)
        message_handler.start()

        input_handler = threading.Thread(target=self.write_handler, daemon=True)
        input_handler.start()

        input_handler.join()

    def read_handler(self):
        """receive messages - decrypt and check integrity"""
        while True:
            try:
                msg_data = receive_message(self.s)
                if msg_data is None:
                    print("\n[client] disconnected from server")
                    break

                # get hash and encrypted data
                received_hash = msg_data["hash"]
                encrypted_data = base64.b64decode(msg_data["data"])

                # decrypt with our symmetric key
                decrypted_bytes = symmetric_decrypt(encrypted_data, self.symmetric_key)
                decrypted_msg = decrypted_bytes.decode('utf-8')

                # check integrity - hash of decrypted should match received hash
                if verify_integrity(decrypted_bytes, received_hash):
                    print(f"{decrypted_msg}")
                else:
                    print(f"[WARNING] received tampered message! hash mismatch")

            except Exception as e:
                print(f"\n[client] connection error: {e}")
                break

    def write_handler(self):
        """read input and send encrypted messages"""
        while True:
            try:
                message = input()
                if not message:
                    continue

                msg_bytes = message.encode('utf-8')

                # 1) hash the plaintext
                msg_hash = compute_hash(msg_bytes)

                # 2) encrypt with symmetric key
                encrypted_data = symmetric_encrypt(msg_bytes, self.symmetric_key)

                # 3) send hash + encrypted together
                send_message(self.s, {
                    "type": "chat",
                    "hash": msg_hash,
                    "data": base64.b64encode(encrypted_data).decode('ascii')
                })

            except (EOFError, KeyboardInterrupt):
                print("\n[client] exiting...")
                self.s.close()
                break
            except Exception as e:
                print(f"[client] send error: {e}")
                break


if __name__ == "__main__":
    username = input("Enter username: ")
    cl = Client("127.0.0.1", 9001, username)
    cl.init_connection()
