import scapy.all as scapy
import ipaddress
import subprocess
import networkx as nx
import matplotlib.pyplot as plt


def get_network_cards():
    interfaces = {}
    try:
        ifconfig_output = subprocess.check_output("ifconfig", text=True)
        current_iface = None
        for line in ifconfig_output.splitlines():
            if ':' in line:
                current_iface = line.split(':')[0]
            if 'inet ' in line and current_iface:
                parts = line.split()
                ip = None
                mask = None
                for i in range(len(parts)):
                    if parts[i] == 'inet' and ip is None:
                        ip = parts[i + 1]
                    elif parts[i] == 'netmask':
                        mask = parts[i + 1]

                if ip and mask:
                    try:
                        if not ip.startswith("127.") and ipaddress.ip_address(ip).version == 4:
                            mask_int = int(mask, 16)
                            mask_bin = f'{mask_int:032b}'
                            mask_dec = str(ipaddress.ip_network(f'0.0.0.0/{mask_bin.count("1")}', strict=False).netmask)
                            network = ipaddress.ip_network(f"{ip}/{mask_dec}", strict=False)
                            interfaces[current_iface] = {
                                'ip': ip,
                                'mask': mask_dec,
                                'network': str(network)
                            }
                    except ValueError as e:
                        print(f"Unable to process the network address of interface {current_iface}: {e}")
    except Exception as e:
        print(f"Unable to get network card information: {e}")

    return interfaces


def arp_scan(network):
    print(f"Scanning network: {network}")
    arp_request = scapy.ARP(pdst=str(network))
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})

    return devices


def check_ip_status(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return {'ip': answered_list[0][1].psrc, 'mac': answered_list[0][1].hwsrc}
    return None


def generate_html(devices):
    g = nx.Graph()

    for device in devices:
        g.add_node(device['ip'], label=device['ip'])

    for device in devices:
        g.add_edge("Router", device['ip'])

    pos = nx.spring_layout(g)
    nx.draw(g, pos, with_labels=True, node_size=5000, node_color='skyblue', font_size=10)
    plt.savefig("network_graph.png")

    html_content = f"""
    <html>
        <head><title>Network Topology</title></head>
        <body>
            <h1>Network Topology</h1>
            <img src="network_graph.png" alt="Network Diagram">
        </body>
    </html>
    """

    with open("network_graph.html", "w") as f:
        f.write(html_content)


def display_results(devices):
    if devices:
        print("\nActive devices found:")
        for device in devices:
            print(f"IP: {device['ip']} | MAC: {device['mac']}")
    else:
        print("No active devices found.")


def main():
    print("Network Reconnaissance Tool")

    interfaces = get_network_cards()
    if not interfaces:
        print("No network card information could be retrieved.")
        return

    for name, info in interfaces.items():
        print(f"Interface: {name} | IP: {info['ip']} | Mask: {info['mask']} | Network: {info['network']}")

    network_input = input("Please enter the network address to scan (e.g., 192.168.1.0/24): ")
    try:
        network = ipaddress.ip_network(network_input, strict=False)
    except ValueError:
        print("Invalid network address.")
        return

    devices = arp_scan(network)
    display_results(devices)

    ip_to_check = input("\nPlease enter the IP address to check (or enter 'exit' to quit): ")
    while ip_to_check != 'exit':
        status = check_ip_status(ip_to_check)
        if status:
            print(f"{ip_to_check} is active | MAC: {status['mac']}")
        else:
            print(f"{ip_to_check} is not active.")
        ip_to_check = input("\nPlease enter the IP address to check (or enter 'exit' to quit): ")

    generate_html(devices)
    print("HTML report generated: network_graph.html")


if __name__ == "__main__":
    main()
