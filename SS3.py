import os
import sys
import base64
import socket
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Protocol constants
MAGIC = b"GCM1"  # 4 bytes
TAG_LEN = 16  # GCM tag size
SESSION_NONCE_LEN = 8  # 8 bytes; per-transfer random prefix
CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks (adjust as needed)


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


def start_server(host='0.0.0.0', output_file="file_output", port=65432, key_b64=None):
    if key_b64 is None:
        raise ValueError("key_b64 must be provided")
    key = base64.b64decode(key_b64.encode("ascii"))
    validate_key(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, int(port)))
        server_socket.listen(1)
        print(f"Server listening on {host}:{port}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")

            # Header: MAGIC(4) | session_nonce(8) | file_size(8)
            magic = recvall(conn, len(MAGIC))
            if magic != MAGIC:
                raise ValueError(f"Bad magic header: {magic!r}")
            session_nonce = recvall(conn, SESSION_NONCE_LEN)
            file_size = unpack_u64(recvall(conn, 8))
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


def send_file(file_path, host="127.0.0.1", port=65432, key_b64=None):
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


def printhelp():
    help_text = """
Usage:
  python script.py gk
      - Generate a random 32-byte AES key (base64)

  python script.py serve <port> <output_file> <base64_key>
      - Start server on 0.0.0.0:<port> and write decrypted file to <output_file>
      - Streaming, chunked AES-GCM to avoid high memory usage

  python script.py send <host> <port> <file_path> <base64_key>
      - Send <file_path> to <host>:<port> encrypted with <base64_key>
      - Streaming, chunked AES-GCM
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
        if len(args) != 4:
            print("Error: serve requires 3 arguments.")
            printhelp()
            sys.exit(1)
        port = int(args[1])
        output_file = args[2]
        encoded_key = args[3]
        start_server("0.0.0.0", output_file, port, encoded_key)

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

    else:
        print(f"Unknown command: {cmd}")
        printhelp()
        sys.exit(1)


if __name__ == "__main__":
    main()
