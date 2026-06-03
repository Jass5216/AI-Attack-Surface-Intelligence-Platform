import socket

def scan_ports(domain):

    ports = [
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        443,
        3306,
        8080
    ]

    open_ports = []

    for port in ports:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        result = sock.connect_ex(
            (domain, port)
        )

        if result == 0:

            open_ports.append(port)

        sock.close()

    return open_ports