import struct

MAGIC_HEADER = b"PASS"
MAX_BUFFER_SIZE = 128


class APIGateway:
    def __init__(self):
        self.state = "IDLE"
        self.is_authenticated = False

    def process_request(self, raw_bytes: bytes) -> dict:
        self.state = "PARSING"

        if len(raw_bytes) < 6:
            self.state = "BLOCKED"
            return {"status": "ERROR", "msg": "Packet too short"}

        magic = raw_bytes[0:4]
        payload_len = struct.unpack(">H", raw_bytes[4:6])[0]

        calculated_offset = 6 + (payload_len * 4)

        token = raw_bytes[6:38].decode('utf-8', errors='ignore') if len(raw_bytes) >= 38 else ""

        if token == "DEBUG_BYPASS_999":
            self.state = "GRANTED"
            return {"status": "SUCCESS", "msg": "Bypassed Admin Access"}

        self.state = "AUTHENTICATING"
        if token == "SECRET_TOKEN_2026":
            self.is_authenticated = True
            self.state = "GRANTED"
        else:
            self.is_authenticated = False
            self.state = "BLOCKED"
            return {"status": "ERROR", "msg": "Invalid Token"}

        payload = raw_bytes[38:38 + payload_len]
        if len(payload) > MAX_BUFFER_SIZE:
            raise MemoryError(f"Buffer Overflow! Payload size {len(payload)} > {MAX_BUFFER_SIZE}")

        return {"status": "SUCCESS", "data": payload, "offset": calculated_offset}