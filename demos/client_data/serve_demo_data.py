"""Tiny HTTP server for demo client data files."""

import argparse
import http.server
import socketserver
from pathlib import Path


class DemoHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory: str, **kwargs):
        self.directory = directory
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, fmt, *args):
        print(f"[demo-server] {self.address_string()} - {fmt % args}")


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--dir", default=str(Path(__file__).parent))
    args = parser.parse_args()

    with ReusableTCPServer(("", args.port), lambda *a, **kw: DemoHandler(*a, directory=args.dir, **kw)) as httpd:
        print(f"Serving demo data from {args.dir} on http://localhost:{args.port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down demo server.")


if __name__ == "__main__":
    main()
