from nacl.public import PrivateKey, PublicKey, Box
import os
import socket
import json

#agent's details
HOST = "127.0.0.1"
PORT = 5000

def main():
    #IPV4, TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[Controller] Connected to Agent.")

        #Receive Agent's public key
        agent_msg = s.recv(4096).decode()
        agent_data = json.loads(agent_msg)
        agent_pubkey_bytes = bytes.fromhex(agent_data["agent_pubkey"])
        agent_public_key = PublicKey(agent_pubkey_bytes)
        print("[Controller] Received Agent Public Key:", agent_data["agent_pubkey"])

        device_id = agent_data["device_id"].encode()
        master_secret = b"MASTER_KEY_ONLY_CONTROLLER_KNOWS"
        # Modify later to derive the shared secret key from device id
        shared_secret_key = os.urandom(32)
        print("[Controller] Secret key generated:", shared_secret_key.hex())

        #Generate Controller's Key Pair
        controller_private_key = PrivateKey.generate()
        controller_public_key = controller_private_key.public_key
        # Create a Box for encrypting messages to the agent
        ctrl_box = Box(controller_private_key, agent_public_key)
        ciphertext = ctrl_box.encrypt(shared_secret_key)

        # Send controller's public key and ciphertext to agent
        msg_out = {
            "controller_pubkey": controller_public_key.encode().hex(),
            "ciphertext": ciphertext.hex(),
        }
        s.sendall(json.dumps(msg_out).encode())
        print("[Controller] Sent ciphertext to Agent.")

        # Wait for Agent's response
        ack = s.recv(4096).decode()
        print("[Controller] Received response from Agent:", ack)

if __name__ == "__main__":
    main()
