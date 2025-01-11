# Network Recon Tool

## Objective
The **Network Recon Tool** is designed to perform network reconnaissance and topology visualization with the following capabilities:
- **Network Interface Discovery**: Identify and list network interfaces, their IP addresses, subnet masks, and associated network ranges on the local system.
- **Active Device Scanning**: Perform ARP scans on specified networks to detect active devices and retrieve their IP and MAC addresses.
- **IP Address Status Check**: Verify if a specific IP address is active on the network and obtain its MAC address.
- **Network Topology Visualization**: Generate a graphical representation of the network topology and render it as an HTML report for easy reference.
- **User Interaction**: Provide an interactive tool for users to input networks to scan and IP addresses to check for activity.

---

## Tools Used
### Programming Language
- **Python**

### Libraries & Frameworks
- **Scapy**: For crafting and sending ARP packets and processing network responses.
- **ipaddress**: To validate and process IP and network address ranges.
- **subprocess**: To run system commands (e.g., `ifconfig`) and retrieve network interface details.
- **networkx**: To create and manipulate network graphs for topology visualization.
- **matplotlib**: To generate a graphical network topology as an image.

---

## Features
### 1. **Network Interface Discovery**
- Extracts information about available network interfaces using the `ifconfig` command.
- Parses output to retrieve IP addresses, subnet masks, and associated network ranges.

### 2. **Active Device Scanning**
- Conducts ARP scans using Scapy to identify active devices within a specified network range.
- Collects and displays IP and MAC addresses of detected devices.

### 3. **IP Address Status Check**
- Uses ARP requests to verify whether a specific IP address is active.
- Displays the MAC address if the IP address is active.

### 4. **Network Topology Visualization**
- Constructs a network graph using **NetworkX** with devices as nodes and connections as edges.
- Saves the graph as an image using **Matplotlib**.
- Generates an HTML report embedding the topology image.

### 5. **Interactive User Experience**
- Provides an interactive command-line interface for:
  - Entering network ranges to scan.
  - Specifying IP addresses to check their activity status.
- Displays results dynamically and generates an HTML report for reference.

---

## Usage Instructions
1. **Install Dependencies**:
   - Use `pip` to install the required Python libraries:
     ```bash
     pip install scapy networkx matplotlib
     ```

2. **Run the Tool**:
   - Clone the repository and execute the script:
     ```bash
     python network_recon_tool.py
     ```

3. **Input Parameters**:
   - Enter the network range to scan (e.g., `192.168.1.0/24`).
   - Specify IP addresses to check their activity status.

4. **Output**:
   - View a list of active devices in the terminal, displaying their IP and MAC addresses.
   - HTML report generated as `network_graph.html` with the network topology visualization.

---

## Example Workflow
1. **Discover Network Interfaces**:
   - Lists available network interfaces, their IP addresses, subnet masks, and associated network ranges.

2. **Scan a Network**:
   - Enter a network range (e.g., `192.168.1.0/24`) to scan for active devices.
   - View detected devices with their IP and MAC addresses.

3. **Check an IP Address**:
   - Input a specific IP address to check its activity status.
   - Retrieve the MAC address if the IP is active.

4. **Generate Network Topology**:
   - Creates a graphical representation of the network.
   - Saves the graph as `network_graph.png` and generates an HTML report.

---

## Output
- **Terminal Results**:
  - Lists all active devices and their respective details.
  - Provides activity status for specific IPs.
- **Generated Files**:
  - `network_graph.png`: Image of the network topology.
  - `network_graph.html`: HTML report embedding the network topology.

---

## Project Benefits
- **For Network Administrators**: Enables efficient network reconnaissance and device discovery.
- **For Security Professionals**: Assists in identifying potential vulnerabilities in network configurations.
- **For Students**: Provides hands-on experience with Python-based network programming and visualization.

---

## Contributions
Contributions are welcome! Feel free to submit a pull request or open an issue for feature suggestions or bug reports.

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Contact
For questions or support, contact:
- **Email**: [your-email@example.com](mailto:your-email@example.com)
- **GitHub**: [Your GitHub Profile](https://github.com/your-username)
