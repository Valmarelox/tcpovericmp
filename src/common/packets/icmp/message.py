from dataclasses import dataclass

@dataclass
class ICMPMessage:
    id: int
    seq: int
    timestamp: int