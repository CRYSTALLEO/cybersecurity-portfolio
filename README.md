# cybersecurity-portfolio



## About Me
Hello, I'm ymq, a passionate cybersecurity enthusiast currently as a master student of University of Malaya.  
I am very interested in digital forensics.  



## Technical Skills

- **Penetration Testing Tools**: Nmap, Metasploit, Burp Suite  
- **Programming Languages**: Python, Bash  
- **Networking**: TCP/IP, IDS/IPS, Firewall Configuration  
- **Cloud Security**: AWS Security Hub, Azure Defender      



## Certifications and Training

- **Certifications**:  
  - Cisco Certified CyberOps Associate certification (In Progress)    
- **Courses/Workshops**:   
  - Cisco Networking Academy: Learn how to monitor, detect and respond to cyber threats and prepare for the Cisco Certified CyberOps Associate certification 



## Project Experience

### Project 1: Network Recon Tool
**Objective**: 
•	Network Interface Discovery: Identify and list network interfaces, their IP addresses, subnet masks, and associated network ranges on the local system.
•	Active Device Scanning: Perform ARP scans on specified networks to detect active devices, retrieve their IP and MAC addresses.
•	IP Address Status Check: Verify if a specific IP address is active on the network and obtain its MAC address.
•	Network Topology Visualization: Generate a graphical representation of the network topology and render it as an HTML report for easy reference.
•	User Interaction: Provide an interactive tool for users to input networks to scan and IP addresses to check for activity.
**Tools Used**: 
•	Programming Language: 
  Python.
•	Libraries and Frameworks:
  Scapy: Used for crafting and sending ARP packets and processing network responses.
  ipaddress: Validates and processes IP and network address ranges.
  subprocess: Runs system commands (e.g., ifconfig) to retrieve network interface details.
  networkx: Creates and manipulates network graphs for topology visualization.
  matplotlib: Generates the graphical network topology as an image.
•	File Output:
  HTML and PNG files are created to store and display the network topology visualization.
**Methodology**: 
•	Network Interface Discovery:
  Use the ifconfig command to extract network interface information.
  Parse the command output to retrieve IP addresses and subnet masks.
  Convert subnet masks to CIDR notation and calculate the corresponding network ranges.
•	Active Device Scanning:
  Perform an ARP scan using Scapy by broadcasting ARP requests to all devices in the network.
  Collect responses to identify active devices along with their IP and MAC addresses.
•	IP Address Status Check:
  Use ARP requests to check the activity status of a specific IP address.
  Return the MAC address if the IP is active.
•	Network Topology Visualization:
  Represent the scanned network as a graph using NetworkX, with devices as nodes and edges connecting them to a central router.
  Use Matplotlib to generate a PNG image of the graph.
  Create an HTML file embedding the network topology image.
•	User Interaction:
  Prompt the user to select a network for scanning and specify IP addresses for status checks.
  Display results in the terminal and generate a report for future reference.
**Outcome**: 
•	Comprehensive Network Scan Tool: 
  The tool effectively identifies active devices within a given network range and collects their IP and MAC addresses.
•	Enhanced Network Visibility: 
  The network topology is visualized as a graph, making it easier for users to understand the structure of their local network.
•	Interactive User Experience:
  Users can dynamically input networks to scan and IPs to check, allowing for flexible usage.
  Results are displayed in real time, improving user engagement.
•	Portable HTML Report: 
  The generated report in HTML format provides a graphical snapshot of the network topology, which can be shared or stored for later analysis.
•	Scalable and Modular Design: 
  Each function is self-contained, allowing easy integration into larger projects or customization for specific use cases.

### Project 2: Web Application Penetration Testing
**Objective**: 
•	Automated Vulnerability Monitoring: Build an automated system to collect and monitor vulnerability information for network devices and applications from multiple sources, including Shodan data and NVD CVE databases.
•	Visualization and Analysis: Analyze and visualize collected vulnerability data, enabling users to understand the distribution, severity, and impacted systems effectively.
•	Automated Notifications: Send monitoring results and vulnerability reports through email and Telegram for timely security risk response.
•	History Tracking: Record the historical data of each monitoring session to support trend analysis and future references.
**Tools Used**: 
•	Programming Language: Python.
•	APIs and Services:
  Shodan API: Fetch vulnerability information for target IPs.
  NVD (National Vulnerability Database): Download CVE database to analyze vulnerability descriptions, severity, and scores.
  Gmail SMTP: Send email reports.
  Telegram Bot API: Deliver reports to specified Telegram users or groups.
•	Data Processing and Visualization:
  Pandas: Handle and transform data efficiently.
  Streamlit: Provide an interactive web application interface for user input and dynamic result display.
  Plotly: Create visualizations such as vulnerability distributions and severity analysis charts.
•	File Management:
  gzip: Process compressed files (e.g., .json.gz files from the NVD database).
  JSON: Store and parse vulnerability data and history records.
**Methodology**: 
•	Data Acquisition:
  Download the latest CVE database files from NVD's annual feeds and decompress them for further analysis. 
  Query user-specified IP addresses using the Shodan API to retrieve associated vulnerability data.
•	Data Processing: 
  Parse NVD data into a dictionary structure, extracting CVE IDs, descriptions, severity levels, and CVSS scores. 
  Map Shodan results to NVD data, creating a comprehensive vulnerability report.
•	Visualization and Analysis: 
  Generate bar charts and pie charts to illustrate the distribution of vulnerabilities, severity levels, and CVSS scores. 
  Use Plotly to create interactive graphs and Streamlit for seamless result presentation.
•	Report Generation and Notifications: 
  Generate HTML-formatted email content that includes tabular vulnerability data. 
  Send reports via Gmail SMTP and push the same content to Telegram using the Telegram Bot API.
•	History Management: 
  Save monitoring data, including IPs, Shodan results, CVE details, and timestamps, to a vulnerability_history.json file. 
  Provide a feature to view historical records, allowing users to review previous monitoring sessions.
**Outcome**: 
•	Real-Time Vulnerability Monitoring Tool: 
  Users can input a list of IP addresses, and the system automatically generates a comprehensive vulnerability monitoring report.
•	Detailed Vulnerability Analysis and Visualization:
  Tabular presentation of target device vulnerabilities, ports, organization details, etc.
  CVE descriptions, CVSS scores, and severity statistics enable users to assess risks quickly.
•	Automated Reporting and Notifications:
  Users receive detailed vulnerability reports automatically via email and Telegram.
•	Traceable History Records: 
  All monitoring data is saved in JSON format, allowing users to review past vulnerability assessments.
•	User-Friendly Web Interface: 
  The interactive interface built with Streamlit simplifies operations, eliminating the need for complex command-line interactions.



## Learning Journey

### What I've Learned
- Core Concepts of Cybersecurity:
  Gained a strong foundation in cybersecurity principles, including the CIA triad (Confidentiality, Integrity, Availability) and risk management.
  Learned about the various types of threats, vulnerabilities, and attack vectors.
- Network Fundamentals:
  Developed a deeper understanding of TCP/IP, network protocols, and the OSI model.
  Learned to analyze network traffic using tools like Wireshark.
- Security Operations:
  Understood the role of a Security Operations Center (SOC) in monitoring and responding to security incidents.
  Learned incident response processes, threat intelligence, and the importance of log analysis.
- Cyber Threats and Tools:
  Familiarized with malware analysis, phishing attacks, and social engineering techniques.
  Learned to use tools like Snort for intrusion detection and various SIEM platforms for log management.
- Forensics and Endpoint Security:
  Acquired skills in basic digital forensics, including identifying and preserving evidence.
  Learned about endpoint protection solutions and patch management.
- Legal and Ethical Responsibilities:
  Gained knowledge about compliance requirements, such as GDPR, HIPAA, and ISO standards.
  Understood the ethical responsibilities of cybersecurity professionals.
  Proficiency in using Nmap for scanning and OpenVAS for vulnerability management.  
  Gained foundational knowledge of network protocols and security tools.  

### Challenges
- Technical Depth:
  Difficulty in understanding deeply technical topics like advanced packet analysis and encryption algorithms initially.
  Managing unfamiliar tools and technologies that required significant hands-on practice.
- Time Management:
  Balancing study time with other commitments, especially with the vast amount of topics to cover in the certification syllabus.
- Incident Response Simulation:
  Challenges in applying theoretical knowledge to simulated incident response scenarios under time pressure.
- Understanding Complex Attacks:
  Struggled to grasp the intricacies of multi-stage attacks and advanced persistent threats (APTs).
- Practical Experience:
  Limited access to real-world SOC environments made it difficult to relate some theoretical concepts to practical applications.

### Plans for Improvement
- Structured Learning:
  Create a detailed study plan with weekly goals to focus on specific topics.
  Allocate time for both theoretical study and practical application.
- Improving Incident Response Skills:
  Simulate real-world incident response scenarios and practice creating detailed reports.
  Learn from post-incident reviews to improve response strategies.
- Soft Skills Development:
  Work on communication skills to articulate technical findings to non-technical stakeholders.
  Build teamwork and leadership capabilities for collaborative cybersecurity projects.
- Evaluate and Reflect:
  Regularly assess strengths and weaknesses by taking mock tests or evaluations.
  Seek feedback from peers, mentors, or instructors to identify areas for improvement.



## Career Objective

Aspiring to become a Digital Forensics Experts. 

Digital forensics is a crucial component of cyber security, focusing on the identification, preservation, analysis, and presentation of digital evidence in legal contexts. As cybercrime continues to escalate, the demand for skilled Digital Forensics Experts is on the rise. This role requires a unique combination of technical skills, analytical thinking, and a thorough understanding of legal frameworks.  

Digital Forensics Experts are responsible for a variety of tasks that revolve around the investigation of cyber incidents. Their primary duties include:
•	Evidence Collection: Gathering digital evidence from computers, mobile devices, networks, and cloud services while ensuring the integrity of the data.
•	Data Preservation: Using methods to secure evidence to prevent alteration or destruction, following legal protocols to maintain the chain of custody.
•	Analysis: Investigating the gathered data to identify the cause of incidents, assess damage, and uncover potential threats. This often involves examining file systems, logs, and artifacts.
•	Reporting: Creating detailed reports that document findings, methodologies, and recommendations. These reports must be clear and comprehensible, as they may be presented in court.
•	Collaboration: Working closely with law enforcement, legal teams, and other stakeholders to provide expertise in investigations.
•	Testifying: Serving as expert witnesses in court cases, where they explain their findings and methodologies to judges and juries.



## Contact Information

- **GitHub**: https://github.com/CRYSTALLEO 
- **Email**: 23110873@siswa.um.edu.my
