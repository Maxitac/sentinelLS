from nacl.public import PrivateKey, PublicKey, Box
import socket
import os, json
import uuid

AGENT_INFO_FILE = "agent_info.json"

def save_agent_info(agent_id, shared_key):
    data = {"agent_id": agent_id, "shared_secret_key": shared_key.hex()}
    with open(AGENT_INFO_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_agent_info():
    if os.path.exists(AGENT_INFO_FILE):
        with open(AGENT_INFO_FILE, "r") as f:
            return json.load(f)
    return None


# Controller's details
HOST = "127.0.0.1"  
PORT = 7777   

def get_mac_address():
    mac_int = uuid.getnode()
    mac_str = ':'.join(f"{(mac_int >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    return mac_str

def main():

    agent_info = load_agent_info()
    if agent_info:
        device_id = agent_info["agent_id"]
        print("[Agent] Already registered. Using existing shared key.")
    else:
        print("[Agent] Starting registration process...")
        device_id = str(uuid.uuid4())
        
    # 1. Generate a long-term key pair for the agent
    agent_private_key = PrivateKey.generate()
    agent_public_key = agent_private_key.public_key

    print("[Agent] Public Key:", agent_public_key.encode().hex())

    # Get MAC address
    mac_address = get_mac_address()
    print("[Agent] MAC Address:", mac_address)

    # 2. Start server and wait for Controller
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[Agent] Connected to Controller.")

        # 3. Send agent's info (public key + device ID) to Controller
        msg_out = {
            "agent_pubkey": agent_public_key.encode().hex(),
            "mac_address": mac_address,
            "device_id": device_id,
        }
        s.sendall(json.dumps(msg_out).encode())
        print("[Agent] Sent public key + MAC address + device ID to Controller.")

        # 4. Receive Controller’s response (public key + ciphertext)
        ctrl_msg = s.recv(4096).decode()
        ctrl_data = json.loads(ctrl_msg)

        controller_pubkey_bytes = bytes.fromhex(ctrl_data["controller_pubkey"])
        controller_public_key = PublicKey(controller_pubkey_bytes)

        ciphertext = bytes.fromhex(ctrl_data["ciphertext"])
        print("[Agent] Received ciphertext:", ciphertext.hex())

        # 5. Decrypt shared secret key using Box
        agent_box = Box(agent_private_key, controller_public_key)
        decrypted_secret_key = agent_box.decrypt(ciphertext)

        # 6. Save agent info
        save_agent_info(device_id, decrypted_secret_key)
        print("[Agent] Decrypted Secret Key:", decrypted_secret_key.hex())
        os.chmod(AGENT_INFO_FILE, 0o600)

        # 7. Send confirmation back to Controller
        s.sendall(b"Decryption successful")

if __name__ == "__main__":
    main()
