import json
import os
import hmac
import time
import base64
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "5500"))
PRODUCTS_FILE = Path(__file__).with_name("products.json")


def env_value(*keys, default=""):
    for key in keys:
        value = os.environ.get(key)
        if value is not None and value != "":
            return value
    return default


ADMIN_USERNAME = env_value("ADMIN_USERNAME", "ADMINUSERNAME", default="Admin")
ADMIN_PASSWORD = env_value("ADMIN_PASSWORD", "ADMINPASSWORD", default="142536")
TOKEN_SECRET = env_value(
    "TOKEN_SECRET", "TOKENSECRET", default="change-this-secret-in-production"
)
TOKEN_TTL_SECONDS = int(
    env_value("TOKEN_TTL_SECONDS", "TOKENTTLSECONDS", default="43200")
)


DEFAULT_PRODUCTS = [
    {
        "id": "default-1",
        "name": "El Dokuma Kilim",
        "price": "2.450 TL",
        "imageUrl": "https://images.unsplash.com/photo-1616628182509-6a9d865f5f84?auto=format&fit=crop&w=900&q=80",
        "orderLink": "https://example.com/kilim",
        "description": "Dogal ipliklerden uretilmis geleneksel desenli kilim.",
    },
    {
        "id": "default-2",
        "name": "Seramik Vazo",
        "price": "980 TL",
        "imageUrl": "https://images.unsplash.com/photo-1577083552431-6e5fd01988f6?auto=format&fit=crop&w=900&q=80",
        "orderLink": "https://example.com/seramik-vazo",
        "description": "El yapimi, rustik dokulu dekoratif seramik vazo.",
    },
]


def ensure_products_file():
    if not PRODUCTS_FILE.exists():
        PRODUCTS_FILE.write_text(
            json.dumps(DEFAULT_PRODUCTS, ensure_ascii=True, indent=2), encoding="utf-8"
        )


def read_products():
    ensure_products_file()
    try:
        content = PRODUCTS_FILE.read_text(encoding="utf-8")
        data = json.loads(content)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return DEFAULT_PRODUCTS


def write_products(items):
    PRODUCTS_FILE.write_text(
        json.dumps(items, ensure_ascii=True, indent=2), encoding="utf-8"
    )


class AppHandler(SimpleHTTPRequestHandler):
    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw)

    def _send_json(self, status_code, payload):
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _create_token(self, username):
        expires_at = int(time.time()) + TOKEN_TTL_SECONDS
        payload = f"{username}:{expires_at}"
        signature = hmac.new(
            TOKEN_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        token_raw = f"{payload}:{signature}".encode("utf-8")
        return base64.urlsafe_b64encode(token_raw).decode("utf-8")

    def _verify_token(self, token):
        try:
            decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
            username, expires_at_str, signature = decoded.split(":", 2)
            payload = f"{username}:{expires_at_str}"
            expected_signature = hmac.new(
                TOKEN_SECRET.encode("utf-8"),
                payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_signature):
                return False
            if int(expires_at_str) < int(time.time()):
                return False
            return username == ADMIN_USERNAME
        except Exception:
            return False

    def _is_authorized(self):
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token = auth_header.replace("Bearer ", "", 1).strip()
        return self._verify_token(token)

    def do_GET(self):
        if self.path == "/api/products":
            self._send_json(200, read_products())
            return
        if self.path == "/api/admin/verify":
            self._send_json(200, {"ok": self._is_authorized()})
            return
        return super().do_GET()

    def do_PUT(self):
        if self.path != "/api/products":
            self._send_json(404, {"error": "Not found"})
            return
        if not self._is_authorized():
            self._send_json(401, {"ok": False, "error": "Unauthorized"})
            return

        try:
            data = self._read_json_body()
            if not isinstance(data, list):
                raise ValueError("Payload must be a list")
            write_products(data)
            self._send_json(200, {"ok": True})
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})

    def do_POST(self):
        if self.path == "/api/admin/login":
            try:
                data = self._read_json_body()
                username = str(data.get("username", "")).strip()
                password = str(data.get("password", ""))
                if hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(
                    password, ADMIN_PASSWORD
                ):
                    token = self._create_token(username)
                    self._send_json(200, {"ok": True, "token": token})
                    return
                self._send_json(401, {"ok": False, "error": "Invalid credentials"})
            except Exception as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            return

        if self.path != "/api/products/save":
            self._send_json(404, {"error": "Not found"})
            return
        if not self._is_authorized():
            self._send_json(401, {"ok": False, "error": "Unauthorized"})
            return

        try:
            data = self._read_json_body()
            if not isinstance(data, list):
                raise ValueError("Payload must be a list")
            write_products(data)
            self._send_json(200, {"ok": True})
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})


if __name__ == "__main__":
    ensure_products_file()
    server = ThreadingHTTPServer((HOST, PORT), AppHandler)
    print(f"Serving on http://{HOST}:{PORT}")
    server.serve_forever()
