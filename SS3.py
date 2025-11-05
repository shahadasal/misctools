import os
import sys
import base64
import socket
import time
import socks
import tkinter as tk
from tkinter import filedialog
# socks.set_default_proxy(
#     socks.SOCKS5,       # Proxy type
#     "127.0.0.1",        # Proxy host
#     9150,               # Proxy port (e.g., Tor default)
#     True,               # Remote DNS (True = resolve via proxy)
#
# )
socket.socket = socks.socksocket

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Protocol constants
MAGIC = b"GCM1"  # 4 bytes
TAG_LEN = 16  # GCM tag size
SESSION_NONCE_LEN = 8  # 8 bytes; per-transfer random prefix
CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks (adjust as needed)
MODE_UPLOAD = b"UPLD"
MODE_DOWNLOAD = b"DWLD"


def validate_key(key: bytes):
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES key must be 16, 24, or 32 bytes; got {len(key)} bytes")


def pack_u32(x: int) -> bytes:
    return x.to_bytes(4, 'big', signed=False)


def pack_u64(x: int) -> bytes:
    return x.to_bytes(8, 'big', signed=False)


def unpack_u32(b: bytes) -> int:
    return int.from_bytes(b, 'big', signed=False)


def unpack_u64(b: bytes) -> int:
    return int.from_bytes(b, 'big', signed=False)


def format_size(size_bytes):
    """Format bytes to human readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def format_time(seconds):
    """Format seconds to human readable time"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{int(minutes)}m {int(seconds)}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)}h {int(minutes)}m"


def recvall(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes or raise ConnectionError."""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError(f"Connection closed with {n - len(data)} bytes left to read")
        data += packet
    return data


def make_nonce(session_nonce: bytes, chunk_index: int) -> bytes:
    # 12-byte nonce = 8-byte session_nonce + 4-byte chunk index
    return session_nonce + pack_u32(chunk_index)


def aad_for_chunk(session_nonce: bytes, chunk_index: int, chunk_len: int) -> bytes:
    # Bind protocol version + session + index + length into the authentication
    return MAGIC + session_nonce + pack_u32(chunk_index) + pack_u32(chunk_len)


def start_server(host='0.0.0.0', port=65432, key_b64=None, keep_alive=False):
    """
    Start server to handle file transfers.
    
    Args:
        host: Host address to bind to
        port: Port to listen on
        key_b64: Base64-encoded encryption key
        keep_alive: If True, server stays running after each operation. If False, exits after one operation.
    """
    if key_b64 is None:
        raise ValueError("key_b64 must be provided")
    key = base64.b64decode(key_b64.encode("ascii"))
    validate_key(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, int(port)))
        server_socket.listen(1)
        print(f"Server listening on {host}:{port}")
        if not keep_alive:
            print("Server will exit after completing one operation.")

        while True:
            try:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"Connected by {addr}")
                    
                    # Receive mode
                    mode = recvall(conn, 4)
                    
                    if mode == MODE_UPLOAD:
                        handle_upload(conn, key)
                    elif mode == MODE_DOWNLOAD:
                        handle_download(conn, key)
                    else:
                        print(f"Unknown mode: {mode}")
                        if keep_alive:
                            continue
                        else:
                            break
                    
                    # Exit after one operation if not in keep_alive mode
                    if not keep_alive:
                        print("Operation completed. Server shutting down.")
                        break
                        
            except KeyboardInterrupt:
                print("\nShutting down server...")
                break
            except Exception as e:
                print(f"Error handling client: {e}")
                if not keep_alive:
                    break
                continue


def handle_upload(conn, key):
    """Handle file upload from client"""
    try:
        # Receive filename first
        filename_len = unpack_u32(recvall(conn, 4))
        output_file = recvall(conn, filename_len).decode('utf-8')
        if not output_file:
            output_file = "uploaded_file"
        
        # Header: MAGIC(4) | session_nonce(8) | file_size(8)
        magic = recvall(conn, len(MAGIC))
        if magic != MAGIC:
            raise ValueError(f"Bad magic header: {magic!r}")
        session_nonce = recvall(conn, SESSION_NONCE_LEN)
        file_size = unpack_u64(recvall(conn, 8))
        
        print(f"Incoming file: {output_file} ({format_size(file_size)})")

        temp_path = output_file + ".part"
        total_written = 0
        chunk_index = 0
        start_time = time.time()
        last_update = start_time

        try:
            with open(temp_path, "wb") as out:
                while total_written < file_size:
                    # Per-chunk frame: len(4) | tag(16) | ciphertext(len)
                    chunk_len = unpack_u32(recvall(conn, 4))
                    if chunk_len == 0:
                        # Optional sentinel; not required since we know file_size
                        break
                    tag = recvall(conn, TAG_LEN)
                    nonce = make_nonce(session_nonce, chunk_index)
                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()
                    decryptor.authenticate_additional_data(aad_for_chunk(session_nonce, chunk_index, chunk_len))

                    remaining = chunk_len
                    while remaining > 0:
                        to_read = min(65536, remaining)
                        ct_piece = conn.recv(to_read)
                        if not ct_piece:
                            raise ConnectionError("Connection closed while receiving chunk data")
                        remaining -= len(ct_piece)
                        pt_piece = decryptor.update(ct_piece)
                        out.write(pt_piece)

                    # Verify tag for this chunk
                    decryptor.finalize()

                    total_written += chunk_len
                    chunk_index += 1

                    current_time = time.time()
                    if chunk_index % 16 == 0 or current_time - last_update >= 1.0:
                        # Update progress at most once per second or every 16 chunks
                        elapsed = current_time - start_time
                        percent = (total_written / file_size) * 100

                        if elapsed > 0:
                            speed = total_written / elapsed
                            remaining_bytes = file_size - total_written
                            eta = remaining_bytes / speed if speed > 0 else 0

                            print(f"Progress: {percent:.1f}% | "
                                  f"{format_size(total_written)}/{format_size(file_size)} | "
                                  f"{format_size(speed)}/s | ETA: {format_time(eta)}")

                        last_update = current_time

            if total_written != file_size:
                raise ValueError(f"Incomplete file: got {total_written} of {file_size} bytes")

            os.replace(temp_path, output_file)
            total_time = time.time() - start_time
            avg_speed = file_size / total_time if total_time > 0 else 0
            print(f"File received and decrypted to: {output_file}")
            print(f"Total time: {format_time(total_time)} | Avg speed: {format_size(avg_speed)}/s")

        except Exception as e:
            # Clean up partial output on any failure
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            raise
            
    except Exception as e:
        print(f"Upload failed: {e}")


def handle_download(conn, key):
    """Handle file download request from client"""
    try:
        # Get file path from client
        filepath_len = unpack_u32(recvall(conn, 4))
        file_path = recvall(conn, filepath_len).decode('utf-8')
        
        print(f"\n{'='*60}")
        print(f"Download request received for: {file_path}")
        print(f"{'='*60}")
        
        if not os.path.exists(file_path):
            print("❌ File not found on server")
            # Send error response to client
            conn.sendall(pack_u32(0))  # Empty file size indicates error
            return
        
        file_size = os.path.getsize(file_path)
        print(f"File size: {format_size(file_size)}")
        
        # Ask for user confirmation
        while True:
            response = input("\nAllow download? (yes/no): ").strip().lower()
            if response in ['yes', 'y']:
                print("✓ Download approved. Starting transfer...")
                break
            elif response in ['no', 'n']:
                print("✗ Download rejected by server.")
                # Send error response to client
                conn.sendall(pack_u32(0))  # Empty file size indicates rejection
                return
            else:
                print("Please answer 'yes' or 'no'")
        
        session_nonce = os.urandom(SESSION_NONCE_LEN)
        print(f"Sending file: {file_path} ({format_size(file_size)})")

        # Header: MAGIC(4) | session_nonce(8) | file_size(8)
        conn.sendall(MAGIC + session_nonce + pack_u64(file_size))

        chunk_index = 0
        bytes_sent = 0
        start_time = time.time()
        last_update = start_time

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                nonce = make_nonce(session_nonce, chunk_index)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                encryptor.authenticate_additional_data(aad_for_chunk(session_nonce, chunk_index, len(chunk)))
                ciphertext = encryptor.update(chunk) + encryptor.finalize()
                tag = encryptor.tag

                # Frame: len(4) | tag(16) | ciphertext
                conn.sendall(pack_u32(len(chunk)))
                conn.sendall(tag)
                conn.sendall(ciphertext)

                bytes_sent += len(chunk)
                chunk_index += 1

                current_time = time.time()
                if chunk_index % 16 == 0 or current_time - last_update >= 1.0:
                    # Update progress at most once per second or every 16 chunks
                    elapsed = current_time - start_time
                    percent = (bytes_sent / file_size) * 100

                    if elapsed > 0:
                        speed = bytes_sent / elapsed
                        remaining_bytes = file_size - bytes_sent
                        eta = remaining_bytes / speed if speed > 0 else 0

                        print(f"Progress: {percent:.1f}% | "
                              f"{format_size(bytes_sent)}/{format_size(file_size)} | "
                              f"{format_size(speed)}/s | ETA: {format_time(eta)}")

                    last_update = current_time

        total_time = time.time() - start_time
        avg_speed = file_size / total_time if total_time > 0 else 0
        print(f"File sent successfully in {format_time(total_time)} | Avg speed: {format_size(avg_speed)}/s")
        
    except Exception as e:
        print(f"Download failed: {e}")


def send_file(file_path=None, host="127.0.0.1", port=65432, key_b64=None):
    if file_path == "[select]" or file_path == None:
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )

        if file_path:
            print("Selected file:", file_path)
        else:
            print("No file selected.")
            exit(-1)

    if key_b64 is None:
        raise ValueError("key_b64 must be provided")
    key = base64.b64decode(key_b64.encode("ascii"))
    validate_key(key)

    file_size = os.path.getsize(file_path)
    session_nonce = os.urandom(SESSION_NONCE_LEN)

    print(f"Sending file: {file_path} ({format_size(file_size)})")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, int(port)))
        print(f"Connected to {host}:{port}")
        
        # Send mode
        client_socket.sendall(MODE_UPLOAD)
        
        # Send filename
        filename_bytes = os.path.basename(file_path).encode('utf-8')
        client_socket.sendall(pack_u32(len(filename_bytes)))
        client_socket.sendall(filename_bytes)

        # Header: MAGIC(4) | session_nonce(8) | file_size(8)
        client_socket.sendall(MAGIC + session_nonce + pack_u64(file_size))

        chunk_index = 0
        bytes_sent = 0
        start_time = time.time()
        last_update = start_time

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break

                nonce = make_nonce(session_nonce, chunk_index)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                encryptor.authenticate_additional_data(aad_for_chunk(session_nonce, chunk_index, len(chunk)))
                ciphertext = encryptor.update(chunk) + encryptor.finalize()
                tag = encryptor.tag

                # Frame: len(4) | tag(16) | ciphertext
                client_socket.sendall(pack_u32(len(chunk)))
                client_socket.sendall(tag)
                client_socket.sendall(ciphertext)

                bytes_sent += len(chunk)
                chunk_index += 1

                current_time = time.time()
                if chunk_index % 16 == 0 or current_time - last_update >= 1.0:
                    # Update progress at most once per second or every 16 chunks
                    elapsed = current_time - start_time
                    percent = (bytes_sent / file_size) * 100

                    if elapsed > 0:
                        speed = bytes_sent / elapsed
                        remaining_bytes = file_size - bytes_sent
                        eta = remaining_bytes / speed if speed > 0 else 0

                        print(f"Progress: {percent:.1f}% | "
                              f"{format_size(bytes_sent)}/{format_size(file_size)} | "
                              f"{format_size(speed)}/s | ETA: {format_time(eta)}")

                    last_update = current_time

        total_time = time.time() - start_time
        avg_speed = file_size / total_time if total_time > 0 else 0
        print(f"File sent successfully in {format_time(total_time)} | Avg speed: {format_size(avg_speed)}/s")


def request_download(host="127.0.0.1", port=65432, key_b64=None):
    """Request to download a file from server"""
    
    file_path = input("Enter full path of file to request: ").strip()
    
    output_file = input("Enter filename to save downloaded file as: ").strip()
    if not output_file:
        output_file = "downloaded_file"
    
    if key_b64 is None:
        raise ValueError("key_b64 must be provided")
    key = base64.b64decode(key_b64.encode("ascii"))
    validate_key(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, int(port)))
        print(f"Connected to {host}:{port}")
        # Send mode
        client_socket.sendall(MODE_DOWNLOAD)
        
        # Send file path to request
        filepath_bytes = file_path.encode('utf-8')
        client_socket.sendall(pack_u32(len(filepath_bytes)))
        client_socket.sendall(filepath_bytes)
        
        # Check if file exists on server (file size = 0 means error)
        initial_data = recvall(client_socket, len(MAGIC) + SESSION_NONCE_LEN + 8)
        magic = initial_data[:len(MAGIC)]
        if magic != MAGIC:
            print("File not found on server")
            return
            
        session_nonce = initial_data[len(MAGIC):len(MAGIC)+SESSION_NONCE_LEN]
        file_size = unpack_u64(initial_data[len(MAGIC)+SESSION_NONCE_LEN:])
        
        if file_size == 0:
            print("File not found on server")
            return
            
        print(f"Incoming file size: {format_size(file_size)}")

        temp_path = output_file + ".part"
        total_written = 0
        chunk_index = 0
        start_time = time.time()
        last_update = start_time

        try:
            with open(temp_path, "wb") as out:
                while total_written < file_size:
                    # Per-chunk frame: len(4) | tag(16) | ciphertext(len)
                    chunk_len = unpack_u32(recvall(client_socket, 4))
                    if chunk_len == 0:
                        # Optional sentinel; not required since we know file_size
                        break
                    tag = recvall(client_socket, TAG_LEN)
                    nonce = make_nonce(session_nonce, chunk_index)
                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()
                    decryptor.authenticate_additional_data(aad_for_chunk(session_nonce, chunk_index, chunk_len))

                    remaining = chunk_len
                    while remaining > 0:
                        to_read = min(65536, remaining)
                        ct_piece = client_socket.recv(to_read)
                        if not ct_piece:
                            raise ConnectionError("Connection closed while receiving chunk data")
                        remaining -= len(ct_piece)
                        pt_piece = decryptor.update(ct_piece)
                        out.write(pt_piece)

                    # Verify tag for this chunk
                    decryptor.finalize()

                    total_written += chunk_len
                    chunk_index += 1

                    current_time = time.time()
                    if chunk_index % 16 == 0 or current_time - last_update >= 1.0:
                        # Update progress at most once per second or every 16 chunks
                        elapsed = current_time - start_time
                        percent = (total_written / file_size) * 100

                        if elapsed > 0:
                            speed = total_written / elapsed
                            remaining_bytes = file_size - total_written
                            eta = remaining_bytes / speed if speed > 0 else 0

                            print(f"Progress: {percent:.1f}% | "
                                  f"{format_size(total_written)}/{format_size(file_size)} | "
                                  f"{format_size(speed)}/s | ETA: {format_time(eta)}")

                        last_update = current_time

            if total_written != file_size:
                raise ValueError(f"Incomplete file: got {total_written} of {file_size} bytes")

            os.replace(temp_path, output_file)
            total_time = time.time() - start_time
            avg_speed = file_size / total_time if total_time > 0 else 0
            print(f"File received and decrypted to: {output_file}")
            print(f"Total time: {format_time(total_time)} | Avg speed: {format_size(avg_speed)}/s")

        except Exception as e:
            # Clean up partial output on any failure
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            raise


def printhelp():
    help_text = """
Usage:
  python script.py gk
      - Generate a random 32-byte AES key (base64)

  python script.py serve <port> <base64_key> [--keep-alive]
      - Start server on 0.0.0.0:<port> with <base64_key>
      - Server supports upload/download modes
      - By default, exits after one operation
      - Use --keep-alive to keep server running

  python script.py send <host> <port> <file_path> <base64_key>
      - Upload <file_path> to <host>:<port> encrypted with <base64_key>

  python script.py download <host> <port> <base64_key>
      - Download a file from <host>:<port> encrypted with <base64_key>
"""
    print(help_text)


def main():
    if len(sys.argv) < 2:
        printhelp()
        sys.exit(1)

    args = sys.argv[1:]
    cmd = args[0]

    if cmd == "gk":
        printhelp()
        random_bytes = os.urandom(32)
        encoded = base64.b64encode(random_bytes).decode("ascii")
        print(encoded)

    elif cmd == "serve":
        if len(args) < 3:
            print("Error: serve requires at least 2 arguments.")
            printhelp()
            sys.exit(1)
        port = int(args[1])
        encoded_key = args[2]
        keep_alive = "--keep-alive" in args or "-k" in args
        start_server("0.0.0.0", port, encoded_key, keep_alive)

    elif cmd == "send":
        if len(args) != 5:
            print("Error: send requires 4 arguments.")
            printhelp()
            sys.exit(1)
        host = args[1]
        port = int(args[2])
        file_path = args[3]
        encoded_key = args[4]
        send_file(file_path, host, port, encoded_key)

    elif cmd == "download":
        if len(args) != 4:
            print("Error: download requires 3 arguments.")
            printhelp()
            sys.exit(1)
        host = args[1]
        port = int(args[2])
        encoded_key = args[3]
        request_download(host, port, encoded_key)

    else:
        print(f"Unknown command: {cmd}")
        printhelp()
        sys.exit(1)


if __name__ == "__main__":
    main()
