
def main():
    binder = Binder(PingServer(), RawTCPSocket())
    binder.loop()

    