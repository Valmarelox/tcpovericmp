from src.common.binder import Binder
from src.server.pingserver import PingServer


def main():
    binder = Binder(PingServer(), RawTCPSocket())
    binder.loop()

    