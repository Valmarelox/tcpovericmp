

class Binder:
    """
    Bind two sockets to one another - passing data from one to the other and vice versa
    """
    def __init__(self, sock1, sock2):
        self.sock1 = sock1
        self.sock2 = sock2

    def loop(self):
        # TODO: Create a select loop and send/recv messages from both sockets