# Cybersecurity Portfolio

## About Me
Hello, I'm **ymq**, a passionate cybersecurity enthusiast and a master's student at the **University of Malaya**. I have a deep interest in **digital forensics**.

## Technical Skills
- **Penetration Testing Tools**:  
  - Proficient in using **Nmap** for network scanning and vulnerability assessment.  
  - Hands-on experience with **Metasploit** for exploiting vulnerabilities in target systems.  
  - Skilled in **Burp Suite** for web application penetration testing and vulnerability scanning.
- **Programming Languages**:  
  - Strong proficiency in **Python** for automating security tasks, writing exploits, and developing cybersecurity tools.  
  - Comfortable with **Bash** scripting for system administration and network security tasks.
- **Networking**:  
  - Deep understanding of **TCP/IP** protocols and network communication.  
  - Knowledge of **IDS/IPS** systems for intrusion detection and prevention.  
  - Experience in **Firewall Configuration** for securing network traffic and setting up access control rules.
- **Cloud Security**:  
  - Familiar with **AWS Security Hub** for managing and monitoring security configurations in the cloud.  
  - Experience with **Azure Defender** for cloud security posture management and threat protection.
- **Digital Forensics**:  
  - Gained foundational knowledge in **digital forensics**, including evidence collection, data preservation, and analysis.  
  - Understanding of techniques for analyzing digital artifacts from file systems, logs, and mobile devices.  
- **Security Operations**:  
  - Learned about the **Security Operations Center (SOC)** role in threat monitoring, incident detection, and response.  
  - Familiar with tools for **malware analysis** and **phishing attacks**, as well as techniques for **incident response**.
- **Cyber Threats and Tools**:  
  - Knowledge of **cyber threats** such as APTs (Advanced Persistent Threats), social engineering, and network-based attacks.  
  - Proficient in using **Snort** for intrusion detection and SIEM platforms for log management. 

## Certifications and Training
- **Certifications**:  
  - Cisco Certified CyberOps Associate (In Progress)    
- **Courses/Workshops**:  
  - Cisco Networking Academy: Learn how to monitor, detect and respond to cyber threats and prepare for the Cisco Certified CyberOps Associate certification  

## Project Experience

### Project 1: Network Recon Tool
#### **Objective**:
- **Network Interface Discovery**: Identify and list network interfaces, their IP addresses, subnet masks, and associated network ranges on the local system.
- **Active Device Scanning**: Perform ARP scans on specified networks to detect active devices and retrieve their IP and MAC addresses.
- **IP Address Status Check**: Verify if a specific IP address is active on the network and obtain its MAC address.
- **Network Topology Visualization**: Generate a graphical representation of the network topology and render it as an HTML report for easy reference.
- **User Interaction**: Provide an interactive tool for users to input networks to scan and IP addresses to check for activity.

#### **Tools Used**: 
- **Programming Language**: Python
- **Libraries & Frameworks**:
  - Scapy: Used for crafting and sending ARP packets and processing network responses.
  - ipaddress: Validates and processes IP and network address ranges.
  - subprocess: Runs system commands (e.g., ifconfig) to retrieve network interface details.
  - networkx: Creates and manipulates network graphs for topology visualization.
  - matplotlib: Generates the graphical network topology as an image.

#### **Methodology**: 
- **Network Interface Discovery**: Use the `ifconfig` command to extract network interface information and parse it to retrieve IP addresses and subnet masks.
- **Active Device Scanning**: Perform an ARP scan using Scapy to detect active devices along with their IP and MAC addresses.
- **IP Address Status Check**: Use ARP requests to check the activity status of specific IP addresses.
- **Network Topology Visualization**: Represent the network as a graph using NetworkX and generate a PNG image with Matplotlib. Embed this in an HTML report.
- **User Interaction**: Allow users to input networks for scanning and IPs for status checks.

#### **Outcome**: 
- **Comprehensive Network Scan Tool**: Effectively identifies active devices in a given network range.
- **Enhanced Network Visibility**: The network topology is visualized for easy understanding.
- **Interactive User Experience**: Flexible user inputs with real-time results.
- **Portable HTML Report**: Generates a shareable HTML report of the network topology.
- **Scalable and Modular Design**: Modular functions for easy integration into larger projects.

---

### Project 2: Web Application Penetration Testing
#### **Objective**:
- **Automated Vulnerability Monitoring**: Build an automated system to collect and monitor vulnerability information for network devices and applications from multiple sources, including Shodan and NVD CVE databases.
- **Visualization and Analysis**: Analyze and visualize vulnerability data to understand distribution, severity, and impacted systems.
- **Automated Notifications**: Send monitoring results and vulnerability reports through email and Telegram.
- **History Tracking**: Record historical data for trend analysis and future references.

#### **Tools Used**:
- **Programming Language**: Python
- **APIs and Services**:
  - Shodan API: Fetch vulnerability information for target IPs.
  - NVD (National Vulnerability Database): Analyze CVE descriptions, severity, and CVSS scores.
  - Gmail SMTP: Send email reports.
  - Telegram Bot API: Deliver reports to specified Telegram users.
- **Data Processing and Visualization**:
  - Pandas: Efficient data handling and transformation.
  - Streamlit: Interactive web interface for dynamic results display.
  - Plotly: Visualization of vulnerability distributions and severity analysis.

#### **Methodology**:
- **Data Acquisition**: Download the latest CVE database and query Shodan for associated vulnerabilities.
- **Data Processing**: Parse NVD data to extract CVE IDs, descriptions, severity levels, and CVSS scores.
- **Visualization and Analysis**: Create bar charts and pie charts to illustrate the distribution of vulnerabilities, severity levels, and CVSS scores.
- **Report Generation and Notifications**: Generate HTML-formatted email content and send vulnerability reports via Gmail SMTP and Telegram Bot API.
- **History Management**: Store monitoring data in `vulnerability_history.json` and provide a feature to review historical records.

#### **Outcome**:
- **Real-Time Vulnerability Monitoring Tool**: Users input IP addresses and receive automated vulnerability reports.
- **Detailed Vulnerability Analysis**: Includes CVE descriptions, CVSS scores, and severity statistics.
- **Automated Reporting and Notifications**: Receive vulnerability reports automatically via email and Telegram.
- **Traceable History Records**: Access past monitoring sessions stored in JSON format.
- **User-Friendly Web Interface**: Streamlined interactions with a simple web interface built with Streamlit.

---

## Learning Journey

### What I've Learned
- **Core Concepts of Cybersecurity**: Gained a strong foundation in cybersecurity principles, including the CIA triad and risk management.
- **Network Fundamentals**: Developed a deeper understanding of TCP/IP, network protocols, and OSI model.
- **Security Operations**: Learned the role of a Security Operations Center (SOC) in incident monitoring and response.
- **Cyber Threats and Tools**: Familiarized with malware analysis, phishing attacks, and social engineering.
- **Forensics and Endpoint Security**: Acquired skills in digital forensics and endpoint protection solutions.
- **Legal and Ethical Responsibilities**: Gained knowledge about compliance requirements (GDPR, HIPAA) and the ethical responsibilities of cybersecurity professionals.

### Challenges
- **Technical Depth**: Struggled with advanced packet analysis and encryption algorithms initially.
- **Time Management**: Balancing study time with other commitments was challenging.
- **Incident Response Simulation**: Applied theoretical knowledge to simulated incidents under time pressure.
- **Complex Attacks**: Understanding multi-stage attacks and advanced persistent threats (APTs) was difficult.
- **Practical Experience**: Limited access to real-world SOC environments made it hard to relate theory to practice.

### Plans for Improvement
- **Structured Learning**: Set weekly study goals and focus on specific topics to balance theory and practice.
- **Improving Incident Response Skills**: Simulate real-world incident response scenarios and learn from post-incident reviews.
- **Soft Skills Development**: Enhance communication and teamwork skills for technical presentations and collaborative projects.
- **Evaluate and Reflect**: Take mock tests and seek feedback from peers and mentors to continuously improve.

---

## Career Objective
I aspire to become a **Digital Forensics Expert**. As cybercrime continues to escalate, the demand for skilled professionals in digital forensics is growing. My goal is to contribute to identifying, preserving, analyzing, and presenting digital evidence in legal contexts.

#### **Key Responsibilities**:
- **Evidence Collection**: Gather digital evidence from computers, mobile devices, networks, and cloud services, maintaining data integrity.
- **Data Preservation**: Secure evidence to prevent alteration or destruction, following legal protocols.
- **Analysis**: Investigate gathered data to identify incidents and uncover potential threats.
- **Reporting**: Create detailed reports that document findings and methodologies, suitable for legal proceedings.
- **Collaboration**: Work closely with law enforcement and legal teams during investigations.
- **Testifying**: Serve as an expert witness in court cases, explaining findings and methodologies.

---

## Contact Information
- **GitHub**: [https://github.com/CRYSTALLEO](https://github.com/CRYSTALLEO)
- **Email**: [23110873@siswa.um.edu.my](mailto:23110873@siswa.um.edu.my)
