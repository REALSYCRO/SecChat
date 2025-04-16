import socket
import threading
import json
import os

clients = {}


def send_message(sender, recipient, data):
    if recipient in clients:
        conn, _ = clients[recipient]
        try:
            conn.send(json.dumps(data).encode())
        except Exception as e:
            print(f"[!] Failed to send message to {recipient}: {e}")


def handle_client(conn):
    username = ""
    try:
        hello = json.loads(conn.recv(8192).decode())
        username = hello["username"]
        public_key = hello["pubkey"]
        clients[username] = (conn, public_key)
        print(f"[+] {username} connected.")

        public_keys = {u: k for u, (_, k) in clients.items()}
        conn.send(json.dumps({"type": "keylist", "keys": public_keys}).encode())

        while True:
            data = conn.recv(16384)
            if not data:
                break
            message = json.loads(data.decode())
            if message["type"] in ["message", "file"]:
                send_message(message["from"], message["to"], message)

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        if username in clients:
            del clients[username]
            print(f"[-] {username} disconnected.")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print("[*] Server running on port 9999...")
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()


if __name__ == "__main__":
    start_server()