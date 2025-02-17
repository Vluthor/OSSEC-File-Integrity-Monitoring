## **OSSEC: File Integrity Monitoring & Log4Shell Detection**  

This project is a hands-on **intrusion detection** and **vulnerability scanning** lab using **OSSEC HIDS** and **Nessus** to detect **Log4Shell (CVE-2021-44228) exploits** and **unauthorized file changes**. Securing a system isn’t just about **finding vulnerabilities**
it’s about **detecting and preventing unauthorized changes**.  

In this project:  
- **OSSEC** was used to track **unexpected system modifications**  
- **Nessus** was used to scan for the well-known **Log4Shell vulnerability**  



**Key objectives:**  
✔ **Set up OSSEC HIDS** for real-time **file integrity monitoring** (FIM)  
✔ **Scanned for Log4Shell (CVE-2021-44228)** with Nessus to detect unpatched systems  
✔ **Tested OSSEC’s ability** to detect unauthorized file changes and attacker persistence techniques  
✔ **Analyzed security logs** and reports to develop remediation strategies  

---

## 🔹 Tools Used  

- **Nessus Essentials** → Vulnerability scanning & Log4Shell detection  
- **OSSEC HIDS** → Host-based Intrusion Detection System (HIDS)  
- **Linux VM** → Controlled test environment for security analysis  
- **Log4j (Vulnerable version)** → Simulated Log4Shell exploitation  

---

## 🔹 OSSEC Configuration  

🔹 OSSEC was configured to **actively monitor system changes** and alert on modifications.  
🔹 Reviewed `/var/ossec/etc/ossec.conf` to verify **file integrity monitoring rules** were enabled.  
🔹 Ensured that OSSEC **detects and logs new files**, a key step in detecting **backdoors & persistence methods**.  

📸 **OSSEC Configuration File:**  
![image](https://github.com/user-attachments/assets/8ff8c42a-ebce-4acf-ba23-693a05d0f0c3)


---

## 🔹 Detecting Unauthorized File Changes  

One of the most **common post-exploitation techniques** is **dropping malicious files** to maintain access.  
OSSEC’s **syscheck** feature is designed to detect **newly added, modified, or deleted files**.  

**What I did:**  
🔹 Examined `/var/ossec/rules/ossec_rules.xml` to verify rule configurations.  
🔹 Located **Rule #554 (`syscheck_new_entry`)**, which flags **newly added files**.  
🔹 OSSEC now detects **any unexpected files placed on the system**, helping to catch **attacker persistence**.  

📸 **OSSEC File Integrity Rule:**  
![image](https://github.com/user-attachments/assets/501ef05c-6182-4a54-b8c4-6f387809b10e)

---

## 🔹 Nessus Scan: Detecting Log4Shell  

To complement OSSEC’s **real-time monitoring**, I ran a **Nessus scan** to check for **Log4Shell (CVE-2021-44228)** vulnerabilities.  
Nessus was used to **identify vulnerable Log4j instances** and confirm if they were **exploitable**.

**Process:**  
✔ Configured **Nessus Log4Shell Remote Checks** scan.  
✔ Verified that **Log4j versions <2.15.0** were flagged as **high risk**.  
✔ Reviewed Nessus reports for **remediation recommendations**.  

---

## 🔹 Key Takeaways  

✔ **OSSEC provides real-time file integrity monitoring** to detect unauthorized system changes.  
✔ **Rule-based detection (syscheck) helps identify attacker persistence techniques** like file modifications.  
✔ **Nessus effectively scans for Log4Shell and other vulnerabilities** to prevent exploitation.  
✔ **Combining vulnerability scanning (Nessus) with intrusion detection (OSSEC) improves security posture.**  


