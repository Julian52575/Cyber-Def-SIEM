from scapy.layers.inet import ICMP, IP


def main() -> None:
    # Créer un paquet IP/ICMP (ping)
    paquet_ping = IP(dst="8.8.8.8") / ICMP()
    paquet_ping.show()
    print("scapy imported correcly.")


if __name__ == "__main__":
    main()
