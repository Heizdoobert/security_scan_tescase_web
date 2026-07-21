import http.server, json, os, webbrowser, sys
from datetime import datetime

PROJECT_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(PROJECT_DIR, "reports")
VIEWER = os.path.join(REPORT_DIR, "viewer.html")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/reports":
            os.makedirs(REPORT_DIR, exist_ok=True)
            files = sorted([f for f in os.listdir(REPORT_DIR) if f.endswith(".json")])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(files).encode())
            return
        if self.path.startswith("/api/report/"):
            name = self.path.split("/api/report/")[1]
            path = os.path.join(REPORT_DIR, name)
            if not os.path.exists(path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"error":"not found"}')
                return
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
            return
        if os.path.exists(VIEWER):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open(VIEWER, encoding="utf-8") as f:
                self.wfile.write(f.read().encode())
            return
        super().do_GET()

    def log_message(self, format, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {args[0]} {args[1]}")


os.chdir(PROJECT_DIR)
print(f"Report viewer: http://localhost:{PORT}")
webbrowser.open(f"http://localhost:{PORT}")
http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
