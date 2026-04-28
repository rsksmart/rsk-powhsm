#!/usr/bin/env python3

import argparse
import os
import socket
import sys
import threading
from datetime import datetime

# On Linux, the parent instance typically listens on CID_ANY so any local enclave
# can connect. The enclave connects to the parent using CID 3.
VMADDR_CID_ANY = getattr(socket, "VMADDR_CID_ANY", -1)

def log(msg: str) -> None:
    sys.stdout.write(msg)
    sys.stdout.flush()

def handle_client(conn: socket.socket, addr) -> None:
    # addr for AF_VSOCK is generally (cid, port)
    peer_cid, peer_port = addr
    log(f"connection from cid={peer_cid} port={peer_port}\n")

    try:
        while True:
            data = conn.recv(16*1024)
            if not data:
                log(f"peer cid={peer_cid} closed connection\n")
                break

            text = data.decode()
            log(text)

            # Echo back what we received
            conn.sendall(data)
    except Exception as e:
        log(f"connection error from cid={peer_cid}: {e}\n")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main() -> int:
    parser = argparse.ArgumentParser(description="Basic Nitro Enclave vsock echo server")
    parser.add_argument("--port", type=int, default=5000, help="vsock port to listen on")
    args = parser.parse_args()

    if not hasattr(socket, "AF_VSOCK"):
        print("This Python build does not expose AF_VSOCK.", file=sys.stderr)
        return 1

    srv = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    # Reuse the port if the process restarts quickly
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        pass

    srv.bind((VMADDR_CID_ANY, args.port))
    srv.listen()

    log(f"listening on vsock cid=ANY port={args.port}\n")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("shutting down\n")
    finally:
        srv.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
