import shodan
import requests
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import json
import os
import gzip
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from telegram import Bot
from telegram.error import TelegramError
from datetime import datetime

# Configure Shodan API
SHODAN_API_KEY = "CGt7FmSzNgQj7WyTgokyoCDgUSI3Yztv"  # Replace with your Shodan API Key
NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
NVD_LOCAL_FILE = "nvdcve-1.1-2023.json.gz"  # Local file to store NVD data
NVD_EXTRACTED_FILE = "nvdcve-1.1-2023.json"  # Extracted JSON file

# Configure Gmail and Telegram
GMAIL_SENDER = "ymq0808@gmail.com"
GMAIL_PASSWORD = "jwpppfgalxlekpdt"
GMAIL_RECEIVER = "23110873@siswa.um.edu.my"
TELEGRAM_BOT_TOKEN = "7260957466:AAHkgCowfQrOnboBrBMH8rvBsu5YHdZ6sAM"
TELEGRAM_CHAT_ID = "7546098705"  # Replace with your correct chat ID

# Initialize Shodan client
shodan_client = shodan.Shodan(SHODAN_API_KEY)

# History file to save previous runs
HISTORY_FILE = "vulnerability_history.json"


# Download NVD CVE data
def download_nvd_data(year=2023):
    url = NVD_FEED_URL.format(year=year)
    local_file = f"nvdcve-1.1-{year}.json.gz"

    if not os.path.exists(local_file):
        st.write(f"Downloading NVD data for {year}...")
        response = requests.get(url, stream=True)
        with open(local_file, "wb") as file:
            for chunk in response.iter_content(chunk_size=1024):
                file.write(chunk)
        st.success("NVD data downloaded successfully!")
    else:
        st.info("NVD data already exists locally.")
    return local_file


# Extract JSON data from the gzip file
def extract_nvd_data(gzip_file, extracted_file):
    if not os.path.exists(extracted_file):
        st.write(f"Extracting NVD data from {gzip_file}...")
        with gzip.open(gzip_file, "rt", encoding="utf-8") as gz_file:
            with open(extracted_file, "w", encoding="utf-8") as json_file:
                json_file.write(gz_file.read())
        st.success("NVD data extracted successfully!")
    else:
        st.info("NVD data already extracted.")
    return extracted_file


# Parse NVD CVE data
def parse_nvd_data(json_file):
    st.write(f"Parsing NVD data from {json_file}...")
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)
    cve_data = {}
    for item in data["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        impact = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
        cve_data[cve_id] = {
            "Description": description,
            "CVSS_Score": impact.get("baseScore", "N/A"),
            "Severity": impact.get("baseSeverity", "Unknown")  # Default to "Unknown" if not found
        }
    return cve_data


# Fetch Shodan data for given IPs
def fetch_shodan_data(ip_list):
    data = []
    for ip in ip_list:
        try:
            host = shodan_client.host(ip)
            for vuln in host.get("vulns", []):
                if vuln.startswith("CVE"):
                    data.append({
                        "IP": ip,
                        "CVE": vuln,
                        "Port": ", ".join(map(str, host.get("ports", []))),
                        "Organization": host.get("org", "N/A"),
                        "OS": host.get("os", "N/A"),
                    })
        except Exception as e:
            st.warning(f"Failed to fetch data for {ip}: {e}")
    return pd.DataFrame(data)


# Map CVEs from Shodan to NVD data
def map_cve_with_nvd_data(cve_list, nvd_data):
    cve_details = []
    for cve_id in cve_list:
        if cve_id in nvd_data:
            cve_details.append({
                "CVE_ID": cve_id,
                "Description": nvd_data[cve_id]["Description"],
                "CVSS_Score": nvd_data[cve_id]["CVSS_Score"],
                "Severity": nvd_data[cve_id]["Severity"]
            })
    return pd.DataFrame(cve_details)


# Save results
def save_run_result(ip_list, shodan_data, cve_details):
    run_data = {
        "timestamp": datetime.now().isoformat(),
        "ip_list": ip_list,
        "shodan_data": shodan_data.to_dict(orient="records") if not shodan_data.empty else [],
        "cve_details": cve_details.to_dict(orient="records") if not cve_details.empty else []
    }
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)
    else:
        history = []

    history.append(run_data)

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)


# Generate email body with formatted data
def generate_email_body(shodan_data, cve_details):
    # Generate email body content with HTML formatting
    email_body = "<h2>Vulnerability Monitoring Report</h2>"

    # Shodan data preview
    email_body += "<h3>Shodan Data Preview</h3>"
    email_body += "<table border='1'><tr><th>IP</th><th>CVE</th><th>Port</th><th>Organization</th><th>OS</th></tr>"
    for index, row in shodan_data.iterrows():
        email_body += f"<tr><td>{row['IP']}</td><td>{row['CVE']}</td><td>{row['Port']}</td><td>{row['Organization']}</td><td>{row['OS']}</td></tr>"
    email_body += "</table>"

    # CVE details
    email_body += "<h3>CVE Details</h3>"
    email_body += "<table border='1'><tr><th>CVE ID</th><th>Description</th><th>CVSS Score</th><th>Severity</th></tr>"
    for index, row in cve_details.iterrows():
        email_body += f"<tr><td>{row['CVE_ID']}</td><td>{row['Description']}</td><td>{row['CVSS_Score']}</td><td>{row['Severity']}</td></tr>"
    email_body += "</table>"

    return email_body


# Email function
def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = GMAIL_SENDER
        msg["To"] = GMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html"))
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(GMAIL_SENDER, GMAIL_PASSWORD)
        server.sendmail(GMAIL_SENDER, GMAIL_RECEIVER, msg.as_string())
        server.close()
        st.success("Email sent successfully!")

        # Send the same content to Telegram
        success_telegram = send_telegram_message(body)
        if success_telegram:
            st.success("Telegram message sent successfully!")
        else:
            st.error("Failed to send Telegram message.")

    except Exception as e:
        st.error(f"Failed to send email: {e}")


# Telegram function
def send_telegram_message(message):
    bot = Bot(token=TELEGRAM_BOT_TOKEN)
    try:
        # Split the message into chunks if it's too long
        max_length = 4096  # Maximum length allowed by Telegram
        message_parts = [message[i:i + max_length] for i in range(0, len(message), max_length)]

        # Send each chunk as a separate message
        for part in message_parts:
            bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=part)

        return True
    except TelegramError as e:
        st.error(f"Telegram API error: {e}")
        return False
    except Exception as e:
        st.error(f"Failed to send Telegram message: {e}")
        return False


# Visualization functions
def plot_cve_severity(cve_details, shodan_data):
    severity_counts = cve_details["Severity"].value_counts()

    # Calculate Unknown severity
    cve_types_count = len(shodan_data["CVE"].unique())
    known_severities = severity_counts.get("High", 0) + severity_counts.get("Critical", 0) + severity_counts.get(
        "Medium", 0)
    unknown_count = cve_types_count - known_severities
    severity_counts["Unknown"] = unknown_count

    fig = go.Figure([go.Bar(x=severity_counts.index, y=severity_counts.values)])
    fig.update_layout(title="CVE Severity Distribution", xaxis_title="Severity", yaxis_title="Count")

    pie_fig = go.Figure([go.Pie(labels=severity_counts.index, values=severity_counts.values)])
    pie_fig.update_layout(title="CVE Severity Distribution (Pie Chart)")

    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(fig)
    with col2:
        st.plotly_chart(pie_fig)


def plot_cve_cvss_scores(cve_details):
    cve_details["CVSS_Score"] = pd.to_numeric(cve_details["CVSS_Score"], errors='coerce')
    fig = go.Figure([go.Bar(x=cve_details["CVSS_Score"].dropna().value_counts().index,
                            y=cve_details["CVSS_Score"].dropna().value_counts().values)])
    fig.update_layout(title="Distribution of CVSS Scores", xaxis_title="CVSS Score", yaxis_title="Count")

    pie_fig = go.Figure([go.Pie(labels=["Low", "Medium", "High", "Critical"],
                                values=[len(cve_details[cve_details["CVSS_Score"] <= 3]),
                                        len(cve_details[
                                                (cve_details["CVSS_Score"] > 3) & (cve_details["CVSS_Score"] <= 6)]),
                                        len(cve_details[
                                                (cve_details["CVSS_Score"] > 6) & (cve_details["CVSS_Score"] <= 9)]),
                                        len(cve_details[cve_details["CVSS_Score"] > 9])])])
    pie_fig.update_layout(title="CVSS Score Distribution (Pie Chart)")

    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(fig)
    with col2:
        st.plotly_chart(pie_fig)


def plot_vuln_types(shodan_data):
    vuln_counts = shodan_data["CVE"].value_counts()
    fig = go.Figure([go.Bar(x=vuln_counts.index, y=vuln_counts.values)])
    fig.update_layout(title="Vulnerabilities Types Distribution", xaxis_title="CVE", yaxis_title="Count")

    pie_fig = go.Figure([go.Pie(labels=vuln_counts.index, values=vuln_counts.values)])
    pie_fig.update_layout(title="Vulnerabilities Types Distribution (Pie Chart)")

    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(fig)
    with col2:
        st.plotly_chart(pie_fig)


# Main function
def main():
    st.title("Vulnerability Monitor")
    mode = st.sidebar.radio("Select Mode", ["Monitor CVEs", "View History"])

    if mode == "Monitor CVEs":
        ip_input = st.text_area("Enter IPs (comma separated)")
        if st.button("Monitor CVEs"):
            ip_list = [ip.strip() for ip in ip_input.split(",")]
            st.write(f"Monitoring CVEs for IPs: {', '.join(ip_list)}")

            # Step 1: Download NVD data
            downloaded_file = download_nvd_data()
            extracted_file = extract_nvd_data(downloaded_file, NVD_EXTRACTED_FILE)

            # Step 2: Parse NVD data
            nvd_data = parse_nvd_data(extracted_file)

            # Step 3: Fetch Shodan data
            shodan_data = fetch_shodan_data(ip_list)

            if not shodan_data.empty:
                # Step 4: Map CVEs
                cve_details = map_cve_with_nvd_data(shodan_data["CVE"].unique(), nvd_data)

                # Step 5: Save run result
                save_run_result(ip_list, shodan_data, cve_details)

                # Step 6: Display tables for Shodan data and CVE details
                st.subheader("Shodan Data Preview")
                st.dataframe(shodan_data)  # Display Shodan data in a table
                st.subheader("CVE Details")
                st.dataframe(cve_details)  # Display CVE details in a table

                # Step 7: Visualize CVE Severity and CVSS Scores
                plot_cve_severity(cve_details, shodan_data)
                plot_cve_cvss_scores(cve_details)
                plot_vuln_types(shodan_data)

                # Step 8: Generate and send email with the data
                email_body = generate_email_body(shodan_data, cve_details)
                send_email("Vulnerability Report", email_body)

    elif mode == "View History":
        st.write("Viewing vulnerability monitoring history...")
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r", encoding="utf-8") as file:
                history_data = json.load(file)

            if history_data:
                st.write("History data found.")
                for run in history_data:
                    st.write(f"Run timestamp: {run['timestamp']}")
                    st.write(f"IP list: {', '.join(run['ip_list'])}")
                    st.write("Shodan Data Preview:")
                    st.dataframe(pd.DataFrame(run["shodan_data"]))
                    st.write("CVE Details:")
                    st.dataframe(pd.DataFrame(run["cve_details"]))
            else:
                st.write("No history data found.")
        else:
            st.write("No history file found.")


if __name__ == "__main__":
    main()

