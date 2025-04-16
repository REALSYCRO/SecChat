import socket
import threading
import json
import base64
import os
from utils.crypto import *

with open("config.json") as f:
    config = json.load(f)

server_ip = config["server_ip"]
server_port = config["server_port"]
username = config["default_username"] or input("Enter your username: ")
debug = config.get("debug", False)

private_key, public_key = generate_rsa_keypair()
pem_public = serialize_public_key(public_key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_ip, server_port))
client.send(json.dumps({"username": username, "pubkey": pem_public}).encode())

known_public_keys = {}


def listen_for_messages():
    while True:
        try:
            data = client.recv(16384)
            if not data:
                break
            message = json.loads(data.decode())

            if message["type"] == "keylist":
                known_public_keys.update(message["keys"])
                print(f"[+] Active users: {list(known_public_keys.keys())}")

            elif message["type"] == "message":
                sender = message["from"]
                encrypted = message["data"]
                signature = message["signature"]
                decrypted = decrypt_message(private_key, encrypted)
                sender_key = load_public_key(known_public_keys[sender])
                if verify_signature(sender_key, decrypted, signature):
                    print(f"\n[{sender}] » {decrypted}")
                else:
                    print(f"[!] Signature verification failed from {sender}.")

            elif message["type"] == "file":
                filename = message["filename"]
                content = base64.b64decode(message["data"])
                with open(f"received_{filename}", "wb") as f:
                    f.write(content)
                print(f"[📁] Received file '{filename}' from {message['from']}")

        except Exception as e:
            print(f"[!] Error receiving message: {e}")


threading.Thread(target=listen_for_messages, daemon=True).start()

while True:
    cmd = input("Command (msg/file): ").strip()
    if cmd == "msg":
        recipient = input("To: ").strip()
        if recipient not in known_public_keys:
            print("[!] Unknown recipient.")
            continue
        msg = input("Message: ")
        pub_key = load_public_key(known_public_keys[recipient])
        encrypted_msg = encrypt_message(pub_key, msg)
        signature = sign_message(private_key, msg)

        client.send(json.dumps({
            "type": "message",
            "from": username,
            "to": recipient,
            "data": encrypted_msg,
            "signature": signature
        }).encode())

    elif cmd == "file":
        recipient = input("To: ").strip()
        path = input("File path: ").strip()
        if not os.path.exists(path):
            print("[!] File not found.")
            continue
        filename = os.path.basename(path)
        with open(path, "rb") as f:
            content = base64.b64encode(f.read()).decode()

        client.send(json.dumps({
            "type": "file",
            "from": username,
            "to": recipient,
            "filename": filename,
            "data": content
        }).encode())
