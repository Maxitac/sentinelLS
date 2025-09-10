from nacl.public import PrivateKey, PublicKey, Box
import socket
import json
import uuid

# Agent's details
HOST = "127.0.0.1"  
PORT = 5000   

def get_mac_address():
    mac_int = uuid.getnode()
    mac_str = ':'.join(f"{(mac_int >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    return mac_str

def main():
    # 1. Generate a long-term key pair for the agent
    agent_private_key = PrivateKey.generate()
    agent_public_key = agent_private_key.public_key
    device_id = "agent-1234"  # Unique attribute (e.g., hostname, serial no.)
    print("[Agent] Public Key:", agent_public_key.encode().hex())

    # Get MAC address
    mac_address = get_mac_address()
    print("[Agent] MAC Address:", mac_address)

    # 2. Start server and wait for Controller
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("[Agent] Waiting for Controller connection...")
        conn, addr = s.accept()

        with conn:
            print("[Agent] Connected by", addr)

            # 3. Send agent's info (public key + device ID) to Controller
            msg_out = {
                "agent_pubkey": agent_public_key.encode().hex(),
                "mac_address": mac_address,
                "device_id": device_id,
            }
            conn.sendall(json.dumps(msg_out).encode())
            print("[Agent] Sent public key + MAC address + device ID to Controller.")

               # 4. Receive Controller’s response (public key + ciphertext)
            ctrl_msg = conn.recv(4096).decode()
            ctrl_data = json.loads(ctrl_msg)

            controller_pubkey_bytes = bytes.fromhex(ctrl_data["controller_pubkey"])
            controller_public_key = PublicKey(controller_pubkey_bytes)

            ciphertext = bytes.fromhex(ctrl_data["ciphertext"])
            print("[Agent] Received ciphertext:", ciphertext.hex())

            # 5. Decrypt shared secret key using Box
            agent_box = Box(agent_private_key, controller_public_key)
            decrypted_secret_key = agent_box.decrypt(ciphertext)

            print("[Agent] Decrypted Secret Key:", decrypted_secret_key.hex())

            # 6. Send confirmation back to Controller
            conn.sendall(b"Decryption successful")

if __name__ == "__main__":
    main()
