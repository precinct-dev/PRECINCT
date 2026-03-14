"""
Minimal Python agent for Docker build testing
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import os


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK\n")
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Hello from Python agent\n")

    def log_message(self, format, *args):
        # Suppress request logs
        pass


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    print(f"Starting Python agent on port {port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
