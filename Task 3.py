# firewall_server.py

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import sys

# List of suspicious parameter substrings to block (from Spring4Shell exploit)
BLOCKED_PATTERNS = [
    "class.module.classLoader",
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
    "class.module.classLoader.resources.context.parent.pipeline.first.suffix",
    "class.module.classLoader.resources.context.parent.pipeline.first.directory",
    "class.module.classLoader.resources.context.parent.pipeline.first.prefix",
    "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat"
]

def contains_blocked_pattern(data: str) -> bool:
    """Check if any blocked pattern is in the data string."""
    for pattern in BLOCKED_PATTERNS:
        if pattern in data:
            return True
    return False

class FirewallHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        query = url.query

        # Check query string for blocked patterns
        if contains_blocked_pattern(query):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked by firewall: Suspicious pattern detected in query string.\n")
            return

        # Check headers for blocked patterns
        for key, value in self.headers.items():
            if contains_blocked_pattern(key) or contains_blocked_pattern(value):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Blocked by firewall: Suspicious pattern detected in headers.\n")
                return

        # If no malicious pattern, allow
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request allowed.\n")

    def do_POST(self):
        url = urlparse(self.path)
        query = url.query

        # Check query string for blocked patterns
        if contains_blocked_pattern(query):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked by firewall: Suspicious pattern detected in query string.\n")
            return

        # Check headers for blocked patterns
        for key, value in self.headers.items():
            if contains_blocked_pattern(key) or contains_blocked_pattern(value):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Blocked by firewall: Suspicious pattern detected in headers.\n")
                return

        # Read POST body
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""

        # Check POST body for blocked patterns
        if contains_blocked_pattern(post_data):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked by firewall: Suspicious pattern detected in POST data.\n")
            return

        # If no malicious pattern, allow
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request allowed.\n")

def run(server_class=HTTPServer, handler_class=FirewallHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Firewall HTTP server running on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    port = 8080
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run(port=port)
