# Alert Ticket and Incident Handling

Investigate a suspicious file hash

### Email
![image](https://raw.githubusercontent.com/Mathieu-Marthe/alert-ticket-and-incident-handling/refs/heads/main/Email.png)

## Details

### Ticket ID
A-2703

### Alert Message
SERVER-MAIL Phishing attempt possible download of malware

### Severity
Medium

### Details
The user may have opened a malicious email and opened attachments or clicked links.

### Additional Information
Known malicious file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

## Response

### Ticket status
Escalated

### Ticket comments
The alert detected that an employee downloaded and opened a malicious file from a phishing email. 

There is an inconsistency between the sender’s email address “76tguy6hh6tgftrt7tg.su’” the name used in the email body “Clyde West,” and the sender’s name, “Def Communications.” 

The email body and subject line contained grammatical errors. The email’s body also contained a password-protected attachment, “bfsvc.exe,” which was downloaded and opened on the affected machine. Having previously investigated the file hash, it is confirmed to be a known malicious file. 

Furthermore, the alert severity is reported as medium. With these findings, I chose to escalate this ticket to a level-two SOC analyst to take further action.


## Incident Handler's Journal
### Tool(s) used
For this activity, I used VirusTotal, which is an investigative tool that analyzes files and URLs for malicious content such as viruses, worms, trojans, and more.  It's a very helpful tool to use if you want to quickly check if an indicator of compromise like a website or file has been reported as malicious by others in the cybersecurity community. For this activity, I used VirusTotal to analyze a file hash, which was reported as malicious. 

This incident occurred in the Detection and Analysis phase. The scenario put me in the place of a security analyst at a SOC investigating a suspicious file hash. After the suspicious file was detected by the security systems in place, I had to perform deeper analysis and investigation to determine if the alert signified a real threat. 

### Who 
An unknown malicious actor 

### What
An email sent to an employee contained a malicious file attachment with the SHA-256 file hash of 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b

### Where
An employee's computer at a financial services company

### When 
At 1:20 p.m., an alert was sent to the organization's SOC after the intrusion detection system detected the file

### Why
An employee was able to download and execute a malicious file attachment via e-mail.

### Additional notes
To prevent this incident in the future, we should consider improving security awareness training so that employees are careful with what they click on.
