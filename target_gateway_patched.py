import struct

MAGIC_HEADER = b"PASS"
MAX_BUFFER_SIZE = 128


class APIGatewayPatched:
    def __init__(self):
        self.state = "IDLE"
        self.is_authenticated = False

    def process_request(self, raw_bytes: bytes) -> dict:
        self.state = "PARSING"

        if len(raw_bytes) < 38:
            self.state = "BLOCKED"
            return {"status": "ERROR", "msg": "Invalid Packet Length"}

        magic = raw_bytes[0:4]
        if magic != MAGIC_HEADER:
            self.state = "BLOCKED"
            return {"status": "ERROR", "msg": "Invalid Magic Header"}

        payload_len = struct.unpack(">H", raw_bytes[4:6])[0]

        if payload_len > MAX_BUFFER_SIZE:
            self.state = "BLOCKED"
            return {"status": "ERROR", "msg": "Payload exceeds maximum allowed size"}

        calculated_offset = 6 + (payload_len * 4)

        token = raw_bytes[6:38].decode('utf-8', errors='ignore')

        self.state = "AUTHENTICATING"
        if token == "SECRET_TOKEN_2026":
            self.is_authenticated = True
            self.state = "GRANTED"
        else:
            self.is_authenticated = False
            self.state = "BLOCKED"
            return {"status": "ERROR", "msg": "Invalid Token"}

        payload = raw_bytes[38:38 + payload_len]
        return {"status": "SUCCESS", "data": payload, "offset": calculated_offset}