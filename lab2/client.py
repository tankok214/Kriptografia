"""
Client - RSA-2048 and symmetric encryption client
==================================================
Client functions:
1. RSA-2048 key pair generation
2. Registration with KeyServer
3. Querying public keys of other clients
4. Key exchange with other clients (symmetric key + algorithm negotiation)
5. Encrypted communication with other clients
"""

import socket
import json
import threading
import sys
import os
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# Add parent directory to path to import Crypto_Framework
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from Crypto_Framework.algorithms import CustomVigenere, AESAdapter
from Crypto_Framework.c_modes import ECBMode, CBCMode, CTRMode, OFBMode, CFBMode
from Crypto_Framework.paddings import ZeroPadding, DESBitPadding, SchneierFergusonPadding


class Client:
    def __init__(self, client_id, host='localhost', port=None):
        """
        Initialize the client.

        Args:
            client_id: Unique client identifier (e.g. "8001")
            host: Client address
            port: Client port (if None, client_id will be used)
        """
        self.client_id = str(client_id)
        self.host = host
        self.port = int(port) if port else int(client_id)

        # RSA key pair generation
        self.log("Generating RSA-2048 key pair...")
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.log("RSA key pair successfully generated")

        # KeyServer configuration
        self.keyserver_host = 'localhost'
        self.keyserver_port = 8000

        # Communication state
        self.running = False
        self.server_socket = None

        # Key exchange state (Diffie-Hellman-like)
        self.my_secret_key = None  # key1 or key2 (own secret)
        self.peer_half_key = None  # Half-key sent by peer

        # Symmetric encryption (peer-to-peer)
        self.symmetric_key = None  # commonkey = combine(key1, key2)
        self.symmetric_algorithm = None
        self.symmetric_mode = None
        self.block_size = None
        self.padding = None        # Supported algorithms
        self.supported_algorithms = [
            "AES-128-CBC",
            "AES-128-ECB",
            "AES-128-CTR",
            "AES-128-OFB",
            "AES-128-CFB",
            "CustomVigenere-128-CBC",
            "CustomVigenere-128-CFB"
        ]

    def log(self, message):
        """Logging with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [Client-{self.client_id}] {message}")

    def register_to_keyserver(self):
        """Registration with KeyServer"""
        self.log(f"Registering with KeyServer ({self.keyserver_host}:{self.keyserver_port})")

        try:
            # Connect to KeyServer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.keyserver_host, self.keyserver_port))

            # Public key in PEM format
            public_key_pem = self.public_key.export_key().decode('utf-8')

            # Registration request
            request = {
                'action': 'register',
                'client_id': self.client_id,
                'public_key': public_key_pem
            }

            sock.send(json.dumps(request).encode('utf-8'))

            # Receive response
            response_data = sock.recv(4096)
            response = json.loads(response_data.decode('utf-8'))

            if response['status'] == 'ok':
                self.log(f"Successful registration: {response['message']}")
            else:
                self.log(f"Registration error: {response.get('message', 'Unknown error')}")

            sock.close()
            return response['status'] == 'ok'

        except Exception as e:
            self.log(f"Error during registration: {e}")
            return False

    def query_public_key(self, target_client_id):
        """
        Query public key from KeyServer

        Args:
            target_client_id: Target client identifier

        Returns:
            RSA public key object or None
        """
        self.log(f"Querying public key: {target_client_id}")

        try:
            # Connect to KeyServer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.keyserver_host, self.keyserver_port))

            # Query request
            request = {
                'action': 'query',
                'client_id': target_client_id
            }

            sock.send(json.dumps(request).encode('utf-8'))

            # Receive response
            response_data = sock.recv(16384)
            response = json.loads(response_data.decode('utf-8'))

            sock.close()

            if response['status'] == 'ok':
                public_key_pem = response['public_key']
                public_key = RSA.import_key(public_key_pem)
                self.log(f"Public key received: {target_client_id}")
                return public_key
            else:
                self.log(f"Query error: {response.get('message', 'Unknown error')}")
                return None

        except Exception as e:
            self.log(f"Error during query: {e}")
            return None

    def start_server(self):
        """Start the client's server (accepts connections from other clients)"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.log(f"Server mode active: {self.host}:{self.port}")

            # Start server thread
            server_thread = threading.Thread(target=self.accept_connections)
            server_thread.daemon = True
            server_thread.start()

        except Exception as e:
            self.log(f"Error starting server: {e}")

    def accept_connections(self):
        """Accept connections from other clients"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self.log(f"Incoming connection: {address}")

                # Handle each connection in a separate thread
                thread = threading.Thread(target=self.handle_incoming, args=(client_socket, address))
                thread.daemon = True
                thread.start()

            except Exception as e:
                if self.running:
                    self.log(f"Error accepting connection: {e}")

    def handle_incoming(self, client_socket, address):
        """
        Handle incoming message

        Args:
            client_socket: Connection socket object
            address: Sender's address
        """
        try:
            # Receive data
            data = client_socket.recv(65536)
            if not data:
                return

            message = json.loads(data.decode('utf-8'))
            msg_type = message.get('type')

            if msg_type == 'key_exchange':
                self.handle_key_exchange_request(client_socket, message, address)
            elif msg_type == 'encrypted_message':
                self.handle_encrypted_message(client_socket, message, address)
            else:
                self.log(f"Unknown message type: {msg_type}")

        except Exception as e:
            self.log(f"Error handling incoming message: {e}")
        finally:
            client_socket.close()

    def initiate_key_exchange(self, target_host, target_port, target_client_id):
        """
        Initiate key exchange with another client (Diffie-Hellman-like protocol)

        According to diagram:
        1. Query peer's public key (getPublicKey)
        2. Generate a secret half-key (key1)
        3. Send it encrypted with RSA (sendHalfSecret)
        4. Receive peer's half-key (key2) encrypted with RSA
        5. Combine the two half-keys into a common key (commonkey)
        6. Initialize block cipher (initBlockCipher)

        Args:
            target_host: Target client address
            target_port: Target client port
            target_client_id: Target client identifier

        Returns:
            True if key exchange was successful
        """
        self.log("=" * 50)
        self.log(f"INITIATING KEY EXCHANGE: {target_client_id}")
        self.log("=" * 50)

        # 1. Query target client's public key (getPublicKey)
        target_public_key = self.query_public_key(target_client_id)
        if not target_public_key:
            self.log("Failed to query target client's public key")
            return False

        # 2. Generate a secret half-key (key1 = generateRandomSecret)
        self.my_secret_key = get_random_bytes(16)  # 128 bit
        self.log(f"Generated own secret half-key (key1): {self.my_secret_key.hex()}")

        # 3. Encrypt with RSA (encrypted with pubkey2)
        cipher_rsa = PKCS1_OAEP.new(target_public_key)
        encrypted_key = cipher_rsa.encrypt(self.my_secret_key)
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')

        # 4. Assemble key exchange message (sendHalfSecret + blockcipher_list)
        request = {
            'type': 'key_exchange',
            'sender_id': self.client_id,
            'encrypted_half_key': encrypted_key_b64,  # sendHalfSecret(key1)
            'supported_algorithms': self.supported_algorithms  # blockcipher_list
        }

        try:
            # Connect to target client (sendAck)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_host, target_port))

            self.log(f"Sending half-key (key1) to {target_host}:{target_port}")
            sock.send(json.dumps(request).encode('utf-8'))

            # Receive response (getPublicKey back + sendHalfSecret(key2))
            response_data = sock.recv(65536)
            response = json.loads(response_data.decode('utf-8'))

            sock.close()

            if response['status'] == 'ok':
                # 5. Received peer's half-key (key2)
                peer_half_key_b64 = response['encrypted_half_key']
                peer_half_key_encrypted = base64.b64decode(peer_half_key_b64)

                # Decrypt with our private key
                cipher_rsa_decrypt = PKCS1_OAEP.new(self.rsa_key)
                self.peer_half_key = cipher_rsa_decrypt.decrypt(peer_half_key_encrypted)
                self.log(f"Peer half-key received and decrypted (key2): {self.peer_half_key.hex()}")

                # Chosen algorithm
                chosen_algorithm = response['algorithm']
                self.log(f"Key exchange successful!")
                self.log(f"  Chosen algorithm: {chosen_algorithm}")

                # 6. Generate common key (commonkey = generateCommonSecret(key1, key2))
                self.generate_common_key()

                # 7. Initialize block cipher (initBlockCipher(commonkey))
                self.setup_symmetric_crypto(self.symmetric_key, chosen_algorithm)
                return True
            else:
                self.log(f"Key exchange failed: {response.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            self.log(f"Error during key exchange: {e}")
            return False

    def generate_common_key(self):
        """
        Generate common key from two half-keys (diagram: commonkey = generateCommonSecret(key1, key2))

        Simple XOR combination, but could be more complex (e.g. HKDF)
        """
        if not self.my_secret_key or not self.peer_half_key:
            raise ValueError("Both half-keys are required to generate common key")

        # XOR combination of the two half-keys
        common_key = bytes(a ^ b for a, b in zip(self.my_secret_key, self.peer_half_key))
        self.symmetric_key = common_key
        self.log(f"Common key generated (commonkey): {common_key.hex()}")

    def handle_key_exchange_request(self, client_socket, message, address):
        """
        Handle key exchange request (diagram: receive key1, send key2)

        Args:
            client_socket: Connection socket object
            message: Key exchange message
            address: Sender's address
        """
        sender_id = message['sender_id']
        self.log("=" * 50)
        self.log(f"RECEIVING KEY EXCHANGE REQUEST: {sender_id}")
        self.log("=" * 50)

        try:
            # 1. Decode encrypted half-key (key1)
            encrypted_half_key_b64 = message['encrypted_half_key']
            encrypted_half_key = base64.b64decode(encrypted_half_key_b64)

            # 2. Decrypt with our private key
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
            self.peer_half_key = cipher_rsa.decrypt(encrypted_half_key)
            self.log(f"Peer half-key decrypted (key1): {self.peer_half_key.hex()}")

            # 3. Algorithm selection (first common algorithm)
            sender_algorithms = message['supported_algorithms']
            common_algorithm = None

            for alg in self.supported_algorithms:
                if alg in sender_algorithms:
                    common_algorithm = alg
                    break

            if not common_algorithm:
                response = {
                    'status': 'error',
                    'message': 'No common algorithm'
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                self.log("No common algorithm")
                return

            self.log(f"Common algorithm: {common_algorithm}")

            # 4. Generate our own secret half-key (key2 = generateRandomSecret)
            self.my_secret_key = get_random_bytes(16)  # 128 bit
            self.log(f"Own secret half-key generated (key2): {self.my_secret_key.hex()}")

            # 5. Query sender's public key (getPublicKey(idClient1))
            sender_public_key = self.query_public_key(sender_id)
            if not sender_public_key:
                response = {
                    'status': 'error',
                    'message': 'Failed to query sender public key'
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                self.log("Failed to query sender public key")
                return

            # 6. Encrypt our half-key with sender's public key
            cipher_rsa_encrypt = PKCS1_OAEP.new(sender_public_key)
            encrypted_my_half_key = cipher_rsa_encrypt.encrypt(self.my_secret_key)
            encrypted_my_half_key_b64 = base64.b64encode(encrypted_my_half_key).decode('utf-8')

            # 7. Generate common key (commonkey = generateCommonSecret(key1, key2))
            self.generate_common_key()

            # 8. Set up symmetric encryption (initBlockCipher(commonkey))
            self.setup_symmetric_crypto(self.symmetric_key, common_algorithm)

            # 9. Send response (sendHalfSecret(key2) + chosen algorithm)
            response = {
                'status': 'ok',
                'algorithm': common_algorithm,
                'encrypted_half_key': encrypted_my_half_key_b64  # key2 encrypted with pubkey1
            }
            client_socket.send(json.dumps(response).encode('utf-8'))

            self.log("Key exchange completed")

        except Exception as e:
            self.log(f"Error handling key exchange: {e}")
            response = {
                'status': 'error',
                'message': str(e)
            }
            client_socket.send(json.dumps(response).encode('utf-8'))

    def setup_symmetric_crypto(self, key, algorithm_spec):
        """
        Set up symmetric encryption system (diagram: initBlockCipher(commonkey))

        Args:
            key: Symmetric key (bytes) - already set as self.symmetric_key
            algorithm_spec: Algorithm specification (e.g. "AES-128-CBC")
        """
        # Key is already set by generate_common_key()
        # just verify
        if self.symmetric_key is None:
            self.symmetric_key = key

        parts = algorithm_spec.split('-')
        alg_name = parts[0]
        mode_name = parts[-1]

        # Set block size
        self.block_size = 16  # 128 bit

        # Set algorithm
        if alg_name == 'AES':
            self.symmetric_algorithm = AESAdapter(self.symmetric_key, self.block_size)
        elif alg_name == 'CustomVigenere':
            self.symmetric_algorithm = CustomVigenere(self.symmetric_key, self.block_size)
        else:
            raise ValueError(f"Unknown algorithm: {alg_name}")

        # Generate IV
        iv = get_random_bytes(self.block_size)

        # Set mode
        if mode_name == 'ECB':
            self.symmetric_mode = ECBMode(self.symmetric_algorithm, self.block_size, iv)
        elif mode_name == 'CBC':
            self.symmetric_mode = CBCMode(self.symmetric_algorithm, self.block_size, iv)
        elif mode_name == 'CTR':
            self.symmetric_mode = CTRMode(self.symmetric_algorithm, self.block_size, iv)
        elif mode_name == 'OFB':
            self.symmetric_mode = OFBMode(self.symmetric_algorithm, self.block_size, iv)
        elif mode_name == 'CFB':
            self.symmetric_mode = CFBMode(self.symmetric_algorithm, self.block_size, iv)
        else:
            raise ValueError(f"Unknown mode: {mode_name}")

        # Set padding
        self.padding = SchneierFergusonPadding()

        self.log(f"Symmetric encryption configured: {algorithm_spec}")

    def send_encrypted_message(self, target_host, target_port, plaintext):
        """
        Send encrypted message (diagram loop: sendEncryptedMessage)

        Args:
            target_host: Target client address
            target_port: Target client port
            plaintext: Text to encrypt

        Returns:
            True if send was successful
        """
        if not self.symmetric_key or not self.symmetric_mode:
            self.log("Key exchange must be performed first!")
            return False

        try:
            # Encryption (diagram: encrypted with commonkey / BlockCipher)
            plaintext_bytes = plaintext.encode('utf-8')
            padded = self.padding.pad(plaintext_bytes, self.block_size)
            ciphertext = self.symmetric_mode.encrypt(padded)
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

            # Get IV for modes that need it
            iv_b64 = base64.b64encode(self.symmetric_mode.iv).decode('utf-8') if self.symmetric_mode.iv else None

            self.log(f"Message encrypted with commonkey ({len(plaintext)} characters, {len(ciphertext)} bytes)")

            # Assemble message (diagram: sendEncryptedMessage(msg))
            message = {
                'type': 'encrypted_message',
                'sender_id': self.client_id,
                'ciphertext': ciphertext_b64,
                'iv': iv_b64  # Include IV for decryption
            }

            # Send
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_host, target_port))
            sock.send(json.dumps(message).encode('utf-8'))

            # Receive response (diagram: sendAck)
            response_data = sock.recv(4096)
            response = json.loads(response_data.decode('utf-8'))

            sock.close()

            if response['status'] == 'ok':
                self.log(f"Message sent successfully")
                return True
            else:
                self.log(f"Message send failed: {response.get('message', '')}")
                return False

        except Exception as e:
            self.log(f"Error sending message: {e}")
            return False

    def handle_encrypted_message(self, client_socket, message, address):
        """
        Handle received encrypted message

        Args:
            client_socket: Connection socket object
            message: Encrypted message
            address: Sender's address
        """
        sender_id = message['sender_id']

        try:
            if not self.symmetric_key or not self.symmetric_mode:
                self.log("Symmetric encryption not configured!")
                response = {
                    'status': 'error',
                    'message': 'Encryption not configured'
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                return

            # Decryption
            ciphertext_b64 = message['ciphertext']
            ciphertext = base64.b64decode(ciphertext_b64)

            # Get IV from message
            iv_b64 = message.get('iv')
            if iv_b64:
                iv = base64.b64decode(iv_b64)
            else:
                iv = get_random_bytes(self.block_size)

            # New algorithm object for decryption
            if isinstance(self.symmetric_algorithm, AESAdapter):
                decrypt_algorithm = AESAdapter(self.symmetric_key, self.block_size)
            else:
                decrypt_algorithm = CustomVigenere(self.symmetric_key, self.block_size)

            # New mode object for decryption with the correct IV
            if isinstance(self.symmetric_mode, ECBMode):
                decrypt_mode = ECBMode(decrypt_algorithm, self.block_size, iv)
            elif isinstance(self.symmetric_mode, CBCMode):
                decrypt_mode = CBCMode(decrypt_algorithm, self.block_size, iv)
            elif isinstance(self.symmetric_mode, CTRMode):
                decrypt_mode = CTRMode(decrypt_algorithm, self.block_size, iv)
            elif isinstance(self.symmetric_mode, OFBMode):
                decrypt_mode = OFBMode(decrypt_algorithm, self.block_size, iv)
            elif isinstance(self.symmetric_mode, CFBMode):
                decrypt_mode = CFBMode(decrypt_algorithm, self.block_size, iv)

            decrypted = decrypt_mode.decrypt(ciphertext)
            unpadded = self.padding.unpad(decrypted)
            plaintext = unpadded.decode('utf-8')

            self.log("=" * 50)
            self.log(f"ENCRYPTED MESSAGE RECEIVED: {sender_id}")
            self.log(f"Message: {plaintext}")
            self.log("=" * 50)

            # Response
            response = {
                'status': 'ok',
                'message': 'Message received and decrypted'
            }
            client_socket.send(json.dumps(response).encode('utf-8'))

        except Exception as e:
            self.log(f"Error decrypting message: {e}")
            response = {
                'status': 'error',
                'message': str(e)
            }
            client_socket.send(json.dumps(response).encode('utf-8'))

    def stop(self):
        """Stop the client"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.log("Client stopped")


def main():
    """Main program - Start client"""
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id> [host]")
        print("Example: python client.py 8001")
        sys.exit(1)

    client_id = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'

    print("=" * 60)
    print(f"RSA-2048 Client - {client_id}")
    print("=" * 60)

    client = Client(client_id, host)

    # Registration
    if not client.register_to_keyserver():
        print("Registration failed!")
        sys.exit(1)

    # Start server mode
    client.start_server()

    # Interactive mode
    print("\nCommands:")
    print("  connect <client_id> <host> <port> - Key exchange with another client")
    print("  send <host> <port> <message> - Send encrypted message")
    print("  quit - Exit")
    print()

    try:
        while True:
            try:
                cmd = input(f"[Client-{client_id}]> ").strip()
                if not cmd:
                    continue

                parts = cmd.split(maxsplit=1)
                command = parts[0].lower()

                if command == 'quit':
                    break
                elif command == 'connect' and len(parts) > 1:
                    args = parts[1].split()
                    if len(args) >= 3:
                        target_id = args[0]
                        target_host = args[1]
                        target_port = int(args[2])
                        client.initiate_key_exchange(target_host, target_port, target_id)
                    else:
                        print("Usage: connect <client_id> <host> <port>")
                elif command == 'send' and len(parts) > 1:
                    args = parts[1].split(maxsplit=2)
                    if len(args) >= 3:
                        target_host = args[0]
                        target_port = int(args[1])
                        message = args[2]
                        client.send_encrypted_message(target_host, target_port, message)
                    else:
                        print("Usage: send <host> <port> <message>")
                else:
                    print("Unknown command!")

            except EOFError:
                break
            except KeyboardInterrupt:
                print()
                break

    finally:
        client.stop()


if __name__ == '__main__':
    main()
