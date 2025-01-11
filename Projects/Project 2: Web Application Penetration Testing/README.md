# CVE Vulnerability Monitor

This project provides a tool for monitoring and analyzing vulnerabilities associated with IPs, leveraging both Shodan and NVD (National Vulnerability Database) data. It helps users track and visualize CVEs (Common Vulnerabilities and Exposures) associated with a list of IP addresses, integrating key metrics such as CVSS scores and vulnerability types. The project uses Streamlit for an interactive interface, and it includes features for email and Telegram notifications.

## Features

- **Monitor CVEs**: Enter a list of IPs, monitor CVEs associated with them, and view detailed vulnerability data including CVSS scores, severity, and descriptions.
- **View History**: Access previous monitoring runs, view historical data, and analyze trends over time.
- **Data Visualization**: Interactive visualizations using Plotly to represent CVE severity, CVSS scores, and vulnerability types.
- **Email and Telegram Notifications**: Automatically send the vulnerability report via email and Telegram when monitoring is completed.
- **Shodan Integration**: Fetch data from Shodan for given IP addresses, including exposed vulnerabilities and other metadata.
- **NVD Integration**: Download and extract the latest NVD CVE data for detailed vulnerability information.
- **CVE Mapping**: Cross-reference Shodan data with NVD to provide detailed vulnerability reports.

## Requirements

To run this project locally, you'll need to install the required dependencies. Use the following command to install them:

```bash
pip install -r requirements.txt

