import struct

MAGIC_HEADER = b"PASS"
MAX_BUFFER_SIZE = 128

class APIGateway:
    def __init__(self):
        self.state = "IDLE"
        self.is_authenticated = False

    def process_request(self, raw_bytes: bytes) -> dict:
        self.state = "PARSING_HEADER"

        if len(raw_bytes) < 6:
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Packet too short for header"}

        magic = raw_bytes[0:4]
        payload_len = struct.unpack(">H", raw_bytes[4:6])[0]

        calculated_offset = 6 + (payload_len * 4)

        token = raw_bytes[6:38].decode("utf-8", errors="ignore").rstrip("\x00") if len(raw_bytes) >= 38 else ""

        if token == "DEBUG_BYPASS_999":
            self.state = "GRANTED"
            return {"status": "SUCCESS", "state": self.state, "msg": "Bypassed Admin Access", "offset": calculated_offset}

        self.state = "AUTHENTICATING"
        if token == "SECRET_TOKEN_2026":
            self.is_authenticated = True
        else:
            self.is_authenticated = False
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid Token"}

        self.state = "PROCESSING_PAYLOAD"
        payload = raw_bytes[38:38 + payload_len]

        if len(payload) > MAX_BUFFER_SIZE:
            self.state = "CRASH_ERROR"
            raise MemoryError(f"Buffer Overflow! Payload size {len(payload)} > {MAX_BUFFER_SIZE}")

        self.state = "GRANTED"
        return {"status": "SUCCESS", "state": self.state, "data": payload, "offset": calculated_offset}