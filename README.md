# 🔐 Cybersecurity Portfolio  

---

## 👋 About Me  
Hello, I'm **YMQ**, a passionate cybersecurity enthusiast currently pursuing a master's degree at the **University of Malaya**.  
I am particularly interested in **Digital Forensics**, aiming to delve deeper into investigating and analyzing cyber threats.  

---

## 🛠️ Technical Skills  

- **Penetration Testing Tools**:  
  - Nmap  
  - Metasploit  
  - Burp Suite  
- **Programming Languages**:  
  - Python  
  - Bash  
- **Networking**:  
  - TCP/IP  
  - IDS/IPS  
  - Firewall Configuration  
- **Cloud Security**:  
  - AWS Security Hub  
  - Azure Defender  

---

## 📜 Certifications and Training  

### **Certifications**  
- Cisco Certified CyberOps Associate Certification *(In Progress)*  

### **Courses/Workshops**  
- Cisco Networking Academy:  
  *Learn how to monitor, detect, and respond to cyber threats, and prepare for the Cisco Certified CyberOps Associate certification.*  

---

## 📂 Project Experience  

### 🌐 **Project 1: Network Recon Tool**  

#### **Objective**  
- **Network Interface Discovery**: Identify and list network interfaces, their IP addresses, subnet masks, and associated network ranges.  
- **Active Device Scanning**: Perform ARP scans to detect active devices and retrieve their IP and MAC addresses.  
- **IP Address Status Check**: Verify if specific IP addresses are active on the network and obtain their MAC addresses.  
- **Network Topology Visualization**: Generate graphical representations of network topology as HTML reports.  
- **User Interaction**: Provide an interactive tool for inputting networks to scan and IP addresses to check.  

#### **Tools Used**  
- **Programming Language**: Python  
- **Libraries and Frameworks**:  
  - Scapy: Used for crafting and sending ARP packets.  
  - ipaddress: For validating and processing IP/network ranges.  
  - subprocess: Runs system commands like `ifconfig` to retrieve network interface details.  
  - NetworkX: Creates and manipulates network graphs.  
  - Matplotlib: Generates graphical network topology images.  
- **File Output**: HTML and PNG files for storing network topology visualizations.  

#### **Methodology**  
1. **Network Interface Discovery**:  
   - Extract network interface details using the `ifconfig` command.  
   - Parse output to retrieve IP addresses and subnet masks, converting them to CIDR notation.  
2. **Active Device Scanning**:  
   - Perform ARP scans to identify active devices and their IP/MAC addresses.  
3. **IP Address Status Check**:  
   - Use ARP requests to verify specific IP activity and retrieve MAC addresses.  
4. **Network Topology Visualization**:  
   - Represent the scanned network graphically using NetworkX and Matplotlib.  
   - Embed the generated topology in an HTML report.  
5. **User Interaction**:  
   - Allow users to dynamically select networks for scanning and specify IP addresses for checks.  

#### **Outcome**  
- **Comprehensive Network Scan Tool**: Effectively identifies active devices and collects relevant details.  
- **Enhanced Network Visibility**: Provides graphical topology visualizations for better understanding.  
- **Interactive Experience**: Real-time results with user-friendly input options.  
- **Scalable and Modular Design**: Functions are self-contained and easily customizable.  

---

### 🔍 **Project 2: Web Application Penetration Testing**  

#### **Objective**  
- **Automated Vulnerability Monitoring**: Collect and monitor vulnerability data for network devices and applications.  
- **Visualization and Analysis**: Enable users to analyze and visualize vulnerabilities through interactive charts.  
- **Automated Notifications**: Send detailed monitoring reports via email and Telegram.  
- **History Tracking**: Maintain historical data for trend analysis and future references.  

#### **Tools Used**  
- **Programming Language**: Python  
- **APIs and Services**:  
  - Shodan API: Fetch vulnerability information for target IPs.  
  - NVD (National Vulnerability Database): Analyze CVE data for descriptions, severity, and scores.  
  - Gmail SMTP: Send email reports.  
  - Telegram Bot API: Deliver reports to users or groups.  
- **Data Processing and Visualization**:  
  - Pandas: Efficient data handling and transformation.  
  - Streamlit: Interactive web application interface for dynamic result display.  
  - Plotly: Create interactive visualizations.  
- **File Management**:  
  - gzip: Process compressed files like `.json.gz` from the NVD database.  
  - JSON: Store and parse vulnerability data and history records.  

#### **Methodology**  
1. **Data Acquisition**:  
   - Download CVE data from NVD feeds and retrieve Shodan results for user-specified IPs.  
2. **Data Processing**:  
   - Parse CVE data for details like IDs, descriptions, severity, and scores.  
   - Map Shodan results to NVD data for comprehensive reports.  
3. **Visualization and Analysis**:  
   - Generate interactive charts to illustrate vulnerability distribution and severity.  
   - Display results using Streamlit for seamless interaction.  
4. **Report Generation and Notifications**:  
   - Create HTML-formatted reports for email and Telegram notifications.  
5. **History Management**:  
   - Save monitoring session data for trend analysis and easy review.  

#### **Outcome**  
- **Real-Time Vulnerability Monitoring**: Automates data collection and report generation.  
- **Interactive Analysis**: Provides detailed visualizations for informed decision-making.  
- **Automated Notifications**: Keeps users updated through email and Telegram.  
- **Traceable History Records**: Enables review of past monitoring data.  

---

## 📘 Learning Journey  

### **What I've Learned**  
- **Cybersecurity Principles**:  
  Gained a strong foundation in the CIA triad (Confidentiality, Integrity, Availability) and risk management.  
  Learned about the various types of threats, vulnerabilities, and attack vectors.  
- **Network Fundamentals**:  
  Developed a deeper understanding of TCP/IP, network protocols, and the OSI model.  
  Learned to analyze network traffic using tools like Wireshark.  
- **Security Operations**:  
  Understood the role of a SOC in monitoring and responding to security incidents.  
  Learned incident response processes, threat intelligence, and log analysis.  
- **Cyber Threats and Tools**:  
  Familiarized with malware analysis, phishing attacks, and social engineering techniques.  
  Learned to use tools like Snort for intrusion detection and various SIEM platforms.  
- **Forensics and Endpoint Security**:  
  Acquired skills in basic digital forensics, including identifying and preserving evidence.  
  Learned about endpoint protection solutions and patch management.  
- **Legal and Ethical Responsibilities**:  
  Gained knowledge about compliance requirements, such as GDPR, HIPAA, and ISO standards.  
  Understood the ethical responsibilities of cybersecurity professionals.  

---

## 🎯 Career Objective  

Aspiring to become a **Digital Forensics Expert**.  
Digital forensics is a vital component of cybersecurity, focusing on analyzing and presenting digital evidence in legal contexts.  

### **Key Responsibilities**  
- **Evidence Collection**: Secure data from devices, networks, and cloud services.  
- **Analysis**: Investigate digital evidence to assess threats and damages.  
- **Reporting**: Document findings in a clear, court-admissible format.  
- **Collaboration**: Work with law enforcement and legal teams to resolve cases.  

---

## 📞 Contact Information  

- **GitHub**: [CRYSTALLEO](https://github.com/CRYSTALLEO)  
- **Email**: 23110873@siswa.um.edu.my  
