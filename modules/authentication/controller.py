from nacl.public import PrivateKey, PublicKey, Box
import socket
import json
from nacl.hash import blake2b

import threading
import os
from datetime import datetime

import json, os

KEYS_FILE = "agent_keys.json"

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_keys(agent_keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(agent_keys, f, indent=2)


def handle_agent(conn, addr, agent_keys):
    print(f"[Controller] Connection from {addr}")
    try:
        # Receive Agent's info
        agent_msg = conn.recv(4096).decode()
        agent_data = json.loads(agent_msg)
        agent_pubkey_bytes = bytes.fromhex(agent_data["agent_pubkey"])
        agent_public_key = PublicKey(agent_pubkey_bytes)
        mac_address = agent_data["mac_address"]
        device_id = agent_data["device_id"]

        print(f"[Controller] Agent {device_id} ({mac_address}) connected.")

        # Derive secret key deterministically
        master_secret = b"MASTER_KEY_ONLY_CONTROLLER_KNOWS"
        input_bytes = mac_address.encode() + master_secret
        shared_secret_key = blake2b(input_bytes, digest_size=32)

        # Store the key
        agent_keys[device_id] = {
            "mac_address": mac_address,
            "secret_key": shared_secret_key.hex(),
            "last_seen": datetime.utcnow().isoformat()
        }

        save_keys(agent_keys)

        # Generate Controller key pair
        controller_private_key = PrivateKey.generate()
        controller_public_key = controller_private_key.public_key

        # Encrypt and send
        ctrl_box = Box(controller_private_key, agent_public_key)
        ciphertext = ctrl_box.encrypt(shared_secret_key)

        msg_out = {
            "controller_pubkey": controller_public_key.encode().hex(),
            "ciphertext": ciphertext.hex(),
        }
        conn.sendall(json.dumps(msg_out).encode())
        print(f"[Controller] Sent ciphertext to {device_id}")

        # Wait for acknowledgment
        ack = conn.recv(4096).decode()
        print(f"[Controller] {device_id} says: {ack}")

    except Exception as e:
        print(f"[Controller] Error handling agent {addr}: {e}")
    finally:
        conn.close()


#agent's details
#HOST = "127.0.0.1"
#PORT = 7777

def main():
    agent_keys = load_keys()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 7777))
        s.listen(5)
        print("[Controller] Listening for agent connections on port 7777...")

        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_agent, args=(conn, addr, agent_keys))
            thread.daemon = True
            thread.start()


if __name__ == "__main__":
    main()
