

MESSAGE_TYPE = {
    8: {
        0: EchoRequest
    }
    0: {
        0: EchoReply
    }
}

def build_response(buf: bytes) -> ICMPHeader:
    hdr = ICMPHeader.frombytes(buf)
    return MESSAGE_TYPE[hdr.type][hdr.code].frombytes(buf[ICMPHeader.size():])
