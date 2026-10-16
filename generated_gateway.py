import struct

MAGIC_HEADER = b"PASS"
MAX_BUFFER_SIZE = 128

class APIGatewayGenerated:
    def __init__(self):
        self.state = "IDLE"
        self.is_authenticated = False
        self.executed_edges = []

    def process_request(self, raw_bytes: bytes) -> dict:
        self.state = "PARSING_HEADER"
        self.executed_edges = ["E_ENTRY"]

        if len(raw_bytes) < 38:
            self.executed_edges.append("E_LEN_FAIL")
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid packet length", "edges": self.executed_edges}

        self.executed_edges.append("E_LEN_PASS")
        magic = raw_bytes[0:4]
        if magic != MAGIC_HEADER:
            self.executed_edges.append("E_MAGIC_FAIL")
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid magic header", "edges": self.executed_edges}

        self.executed_edges.append("E_MAGIC_PASS")
        payload_len = struct.unpack(">H", raw_bytes[4:6])[0]

        if payload_len > MAX_BUFFER_SIZE:
            self.executed_edges.append("E_PAYLOAD_GUARD_BLOCK")
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Payload exceeds maximum allowed size", "edges": self.executed_edges}

        self.executed_edges.append("E_PAYLOAD_GUARD_PASS")
        calculated_offset = 8 + (payload_len * 4)

        token = raw_bytes[6:38].decode("utf-8", errors="ignore").rstrip("\x00")

        self.state = "AUTHENTICATING"
        self.executed_edges.append("E_AUTH_CHECK")
        if token == "SECRET_TOKEN_2026":
            self.executed_edges.append("E_AUTH_PASS")
            self.is_authenticated = True
        else:
            self.executed_edges.append("E_AUTH_FAIL")
            self.is_authenticated = False
            self.state = "BLOCKED"
            return {"status": "ERROR", "state": self.state, "msg": "Invalid token", "edges": self.executed_edges}

        self.state = "PROCESSING_PAYLOAD"
        payload = raw_bytes[38:38 + payload_len]

        self.executed_edges.append("E_PAYLOAD_SAFE")
        self.state = "GRANTED"
        return {"status": "SUCCESS", "state": self.state, "data": payload, "offset": calculated_offset, "edges": self.executed_edges}
