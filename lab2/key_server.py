"""
Protocol:
- Registration: {"action": "register", "client_id": "...", "public_key": "..."}
- Query: {"action": "query", "client_id": "..."}
- Response: {"status": "ok/error", "public_key": "..." or "message": "..."}
"""

import socket
import json
import threading
import sys
from datetime import datetime


class KeyServer:
    def __init__(self, host='localhost', port=8000):
        """
        Initialize the KeyServer.

        Args:
            host: Server address
            port: Server port
        """
        self.host = host
        self.port = port
        self.keys_db = {}  # {client_id: public_key_pem}
        self.running = False
        self.server_socket = None

    def log(self, message):
        """Logging with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [KeyServer] {message}")

    def start(self):
        """Start the KeyServer"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.log(f"KeyServer started at {self.host}:{self.port}")
            self.log("Waiting for client connections...")

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    self.log(f"New connection: {address}")
                    # Handle each client request in a separate thread
                    thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.log(f"Error accepting connection: {e}")

        except Exception as e:
            self.log(f"Error starting server: {e}")
            sys.exit(1)

    def handle_client(self, client_socket, address):
        """
        Handle a client request

        Args:
            client_socket: The client socket object
            address: The client address
        """
        try:
            # Receive data (max 16KB)
            data = client_socket.recv(16384)
            if not data:
                return

            request = json.loads(data.decode('utf-8'))
            action = request.get('action')

            if action == 'register':
                self.handle_register(client_socket, request, address)
            elif action == 'query':
                self.handle_query(client_socket, request, address)
            else:
                response = {
                    'status': 'error',
                    'message': 'Unknown action'
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                self.log(f"Unknown request from {address}: {action}")

        except json.JSONDecodeError:
            self.log(f"Invalid JSON format from {address}")
            response = {'status': 'error', 'message': 'Invalid JSON'}
            client_socket.send(json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.log(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def handle_register(self, client_socket, request, address):
        """
        Handle client registration

        Args:
            client_socket: The client socket object
            request: The request dictionary
            address: The client address
        """
        client_id = request.get('client_id')
        public_key = request.get('public_key')

        if not client_id or not public_key:
            response = {
                'status': 'error',
                'message': 'Missing client_id or public_key'
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            self.log(f"Incomplete registration request from {address}")
            return

        # Store or update the key
        was_registered = client_id in self.keys_db
        self.keys_db[client_id] = public_key

        if was_registered:
            self.log(f"Client updated: {client_id} (from: {address})")
        else:
            self.log(f"New client registered: {client_id} (from: {address})")

        self.log(f"  Total {len(self.keys_db)} registered clients")

        response = {
            'status': 'ok',
            'message': 'Successful registration' if not was_registered else 'Key updated'
        }
        client_socket.send(json.dumps(response).encode('utf-8'))

    def handle_query(self, client_socket, request, address):
        """
        Handle public key query

        Args:
            client_socket: The client socket object
            request: The request dictionary
            address: The client address
        """
        client_id = request.get('client_id')

        if not client_id:
            response = {
                'status': 'error',
                'message': 'Missing client_id'
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            self.log(f"Incomplete query request from {address}")
            return

        if client_id not in self.keys_db:
            response = {
                'status': 'error',
                'message': f'Client {client_id} is not registered'
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            self.log(f"Query for non-existent client: {client_id} (from {address})")
            return

        public_key = self.keys_db[client_id]
        response = {
            'status': 'ok',
            'public_key': public_key,
            'client_id': client_id
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        self.log(f"Public key served: {client_id} -> {address}")

    def stop(self):
        """Stop the KeyServer"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.log("KeyServer stopped")


def main():
    """Main program - Start KeyServer"""
    print("=" * 60)
    print("RSA-2048 KeyServer")
    print("=" * 60)

    # Default configuration
    host = 'localhost'
    port = 8000

    # Process command line arguments
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]

    server = KeyServer(host, port)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n")
        server.log("Interrupted (Ctrl+C)")
        server.stop()


if __name__ == '__main__':
    main()
