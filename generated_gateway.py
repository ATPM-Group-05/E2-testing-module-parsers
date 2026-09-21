import struct

MAGIC_HEADER = b"PASS"
MAX_BUFFER_SIZE = 128

class APIGatewayGenerated:
    def __init__(self):
        self.state = "IDLE"
        self.is_authenticated = False

    def process_request(self, raw_bytes: bytes) -> dict:
        self.state = "PARSING_HEADER"

        if len(raw_bytes) < 38:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid packet length"}

        magic = raw_bytes[0:4]
        if magic != MAGIC_HEADER:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid magic header"}

        payload_len = struct.unpack(">H", raw_bytes[4:6])[0]

        if payload_len > MAX_BUFFER_SIZE:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Payload exceeds maximum allowed size"}

        calculated_offset = 8 + (payload_len * 4)

        token = raw_bytes[6:38].decode("utf-8", errors="ignore").rstrip("\x00")

        self.state = "AUTHENTICATING"
        if token == "SECRET_TOKEN_2026":
            self.is_authenticated = True
        else:
            self.is_authenticated = False
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid token"}

        self.state = "PROCESSING_PAYLOAD"
        payload = raw_bytes[38:38 + payload_len]

        self.state = "GRANTED"
        return {"status": "SUCCESS", "state": self.state, "data": payload, "offset": calculated_offset}
