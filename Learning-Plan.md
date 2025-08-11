Nice — you want an absolute-zero → SOC Analyst 1 plan that’s inch-by-inch, day-by-day, exactly what to do for the next 6 months. I got you. This is a practical, brutal-clear, task-by-task playbook you can follow. Read it, follow it, do the work every day — and I’ll be here to check progress and adjust.

Important legal note (read first): Only practice on machines and networks you own or are explicitly allowed to test (TryHackMe, Hack The Box, VulnHub, your own VMs). Never attack live systems you don’t have permission for.


---

Plan summary — what you’ll achieve in 6 months

By the end of 6 months you will have:

Solid computer & networking fundamentals

Linux + Windows practical skills

Hands-on SOC skills: SIEM (Splunk/Wazuh), log analysis, incident triage

Python scripting for automation (small tools)

5+ documented projects in a GitHub portfolio

1 entry-level cert (Security+ or Google Cybersecurity) ready/completed

Polished resume & LinkedIn, 50+ targeted applications + interview practice


Time expectation: 4–6 hours/day on weekdays, 6–8 hrs/day weekends (aim ~25–30 hrs/week). If you can do less, still follow order but timeline stretches.


---

HOW TO USE THIS PLAYBOOK

1. Follow weeks in order. Don’t skip foundational weeks.


2. Do daily tasks listed for each week (they’re bite-size).


3. At the end of each week, commit a GitHub update named week-XX-checkpoint that contains your notes and deliverable screenshots. This builds your portfolio automatically.


4. I’ll include commands, exact resources, and deliverable templates. Copy/paste and run.




---

Setup: before Day 1 (do these in 1 evening)

Estimated time: 2–3 hours.

1. Create accounts:

GitHub (github.com)

TryHackMe (tryhackme.com) — free tier OK to start

LinkedIn (if you don’t have it)

Coursera (if you will do Google cert) or Udemy for Security+



2. Install virtualization:

Download & install VirtualBox (virtualbox.org) OR VMware Player.



3. Download ISO images:

Ubuntu Desktop ISO (for learning Linux)

Kali Linux ISO (for pentesting tools) — use for labs only.



4. Create a GitHub repo ankush-cyber-portfolio (public). Create README.md with “Week 0: setup”.


5. Install a code editor: VS Code.


6. Make a folder ~/cyber-labs on your host and commit an initial README.


7. Make a simple study calendar in Google Calendar or a notebook.



If you want, I can give the exact VirtualBox VM creation steps — tell me which OS (Windows host / Linux host).


---

Detailed week-by-week plan (day-by-day tasks)

Month 1 — Weeks 1–4: Foundations (Computer, Linux, Networking)

Goal: become comfortable with computers, file systems, terminal, and basic networking.


---

Week 1 — Computer basics & GitHub starter

Daily time: 3–4 hrs

Day 1 (Intro & environment)

Task: Finish setup from “before Day 1” if not done.

Create GitHub repo ankush-cyber-portfolio. Commit day-1-setup.md describing your setup (VM names, OS versions).

Deliverable: GitHub repo with initial README.


Day 2 (Windows basics)

Learn: File Explorer, Task Manager, Services, Event Viewer.

Do: Open Event Viewer → locate Windows Logs → Security and note recent events.

Deliverable: Screenshot of Event Viewer with a short note describing Event ID types.


Day 3 (Install VirtualBox + create Ubuntu VM)

Create Ubuntu VM: 2GB RAM min, 2 vCPUs, 20GB disk.

Commands (on Ubuntu VM terminal):

pwd

ls -la

whoami

sudo apt update && sudo apt upgrade


Deliverable: Commit a screenshot of terminal and paste outputs of the commands into GitHub.


Day 4 (Linux CLI basics)

Learn these commands and practise: pwd, ls, cd, mkdir, rmdir, cp, mv, rm, cat, less, nano, sudo.

Exercise: Create a folder ~/practice, make files file1.txt and file2.txt, write text, move them around.

Deliverable: Terminal transcript or screenshot.


Day 5 (Git + GitHub usage)

Install git: sudo apt install git

Configure: git config --global user.name "Your Name" and git config --global user.email "you@example.com"

Create your first commit: echo "# ankush portfolio" > README.md; git add .; git commit -m "init"; git push origin main

Deliverable: GitHub repo shows commit.


Day 6–7 (Weekend wrap — write Week 1 notes)

Write a one-page journal: "What I learned", include two screenshots of commands and post in repo /week-01/notes.md.

Review: practice more CLI tasks.



---

Week 2 — Core Linux skills (10–12 hrs this week)

Goal: be fluent in the terminal; users, files, permissions, processes.

Day 1 (Users & permissions)

Commands to learn/practice:

whoami, id, adduser testuser, passwd testuser, sudo usermod -aG sudo testuser, su - testuser

ls -l, chmod 644 file, chmod 755 script.sh, chown user:group file


Deliverable: Create ~/practice/perm-demo folder with examples; push to GitHub with explanation.


Day 2 (Processes & system monitoring)

Commands: ps aux | grep <process>, top, htop (sudo apt install htop), kill PID, systemctl status ssh

Exercise: Install and start ssh: sudo apt install openssh-server; sudo systemctl enable --now ssh

Deliverable: SSH into your VM from host (show command ssh user@IP) — screenshot.


Day 3 (Package management & editors)

Commands: sudo apt install <pkg>, dpkg -l | grep <pkg>, snap list

Practice: Install nmap, net-tools: sudo apt install nmap net-tools

Deliverable: nmap --version output in repo.


Day 4 (Networking basics — commands)

Commands: ip a, ip route, ping 8.8.8.8, traceroute google.com, nslookup example.com, dig (install sudo apt install dnsutils)

Exercise: Find your VM IP and default gateway.

Deliverable: Short writeup about OSI model mapping to commands.


Day 5 (Practice mini project: share a small HTTP file)

Install a simple web server: sudo apt install apache2 or python3 -m http.server 8000

From host browser open http://<vm-ip>:8000 to see index page.

Deliverable: GitHub: week-02/apache-serve.md with commands and screenshot.


Day 6–7 (Review + commit)

Consolidate notes, push everything to GitHub.

Start a LinkedIn post summarizing Week 2 progress (one paragraph).



---

Week 3 — Networking: deeper (10–12 hrs)

Goal: understand IP, subnets, ports, protocols. Start nmap.

Day 1 (Subnetting)

Learn CIDR: /24, /25, how to calculate netmask. Practice with 192.168.56.0/24.

Exercise: Write down how many hosts in /24, /25, /26.


Day 2 (Ports & protocols)

Learn common port/protocol mapping: 22 SSH, 80 HTTP, 443 HTTPS, 53 DNS, 25 SMTP, 3389 RDP.

Command practice: ss -tuln, netstat -tulpn

Deliverable: week-03/ports.md file.


Day 3 (Nmap basics)

Install: sudo apt install nmap

Commands to practice:

nmap -sS -p 1-1024 <target-ip>

nmap -sV -O <target-ip> (service and OS detection)

nmap -A <target-ip>


Exercise: Scan your Ubuntu VM from host.

Deliverable: Nmap report in GitHub repo.


Day 4 (Wireshark intro)

Install: sudo apt install wireshark (accept to run as user)

Practice capturing loopback or pcap from python -m http.server requests.

Filter examples: http, tcp.port==80, ip.src==192.168.56.101

Deliverable: Save a pcap and upload week-03/capture.pcap and brief analysis.


Day 5 (Practical)

Combine tools: run nmap then capture traffic using Wireshark. Note steps.

Deliverable: week-03/nmap-wireshark.md


Day 6–7 (Review & TryHackMe intro)

Create TryHackMe account and do the free “Intro to Networking” room.

Commit a one-page summary to GitHub.



---

Week 4 — Windows basics + log analysis intro (10 hrs)

Goal: basic Windows admin, read logs, understand authentication flow.

Day 1 (Windows authentication)

Learn about Event Viewer → Windows Logs → Security

Identify Event IDs: 4624 (login success), 4625 (failure)

Deliverable: Screenshot and short note in GitHub.


Day 2 (Basic PowerShell)

Commands: Get-EventLog -LogName Security -Newest 10 (or Get-WinEvent)

Practice: Export last 50 security events to CSV.

Deliverable: Upload CSV to repo and explain interesting entries.


Day 3 (Log formats & parsing)

Learn syslog format and Windows event basics.

Install jq on Linux for JSON logs parsing: sudo apt install jq.

Deliverable: Small note about differences between Windows and Linux logs.


Day 4–5 (Mini project: Map a failed login)

Simulate failed SSH login to Linux VM (from wrong password) ssh user@ip -> wrong pass a few times.

Capture Linux auth log: sudo tail -f /var/log/auth.log ; identify failed attempts.

Write a small incident note: timestamp, IP, what you did.

Deliverable: Push week-04/incident-failed-ssh.md


Weekend: consolidate month 1 and prepare for Month 2.


---

MONTH 1 DELIVERABLES (must be on GitHub)

week-01 to week-04 folders with notes, screenshots, pcap, CSV, nmap reports, mini incident report.

LinkedIn update: “Month 1 complete: Linux, networking, Windows logs — building towards SOC role.”



---

Month 2 — Weeks 5–8: SOC basics, SIEM, log analysis

Goal: learn SIEM (Splunk), triage alerts, hands-on log queries.


---

Week 5 — Splunk Fundamentals (10–15 hrs)

Day 1 (Install Splunk Free locally)

Splunk download (Splunk Free) — you can run Splunk Enterprise trial in your Ubuntu VM.

Basic steps: download .deb, sudo dpkg -i splunk-*.deb, sudo /opt/splunk/bin/splunk start --accept-license

Deliverable: Screenshot of Splunk Web (http://<vm-ip>:8000) logged in.


Day 2 (Indexing logs)

Upload sample logs (auth.log, apache logs).

Search basics:

index=_internal (default)

sourcetype=linux_secure | stats count by host

index=main sourcetype=linux_secure "Failed password"


Deliverable: Save 3 Splunk searches and screenshots.


Day 3 (Create alerts & dashboards)

Create an alert when Failed password count > 5 in 10 min.

Build a small dashboard showing failed logins, top source IPs.

Deliverable: Export dashboard screenshot and alert config (name+conditions).


Day 4–5 (Practice)

Simulate brute-force attempts by running small script that tries wrong SSH passwords (in lab only). Observe Splunk alert.

Document: week-05/splunk-brute-force.md with timeline.


Weekend: join a TryHackMe “Intro to SIEM” room.


---

Week 6 — Incident Triage and Playbooks (10–12 hrs)

Day 1 (Triage theory)

Learn triage steps: Identify → Contain → Eradicate → Recover → Lessons Learned

Read a basic SOC playbook sample (I’ll give a template below).


Day 2 (Build a simple playbook)

Create playbooks/ssh_bruteforce.md that defines indicators, severity levels, containment steps, escalation contacts.

Deliverable: Playbook in GitHub.


Day 3 (Alert triage drill)

Trigger an alert in Splunk (failed logins). Triage: collect IP, user, timestamps, number of attempts.

Compose an incident ticket (use template below) and commit to repo.


Day 4–5 (Threat intel)

Use VirusTotal, AbuseIPDB (web tools) to check malicious IP reputation.

Document one incident with Intel references.



---

Week 7 — Endpoint + EDR basics (10 hrs)

Day 1 (EDR concepts)

What EDR does: process monitoring, file analysis, rollback.

Learn about endpoints: Windows Defender, basic EDR features.


Day 2 (Simulate detection)

Create a small benign process that writes to a suspicious path, observe if Splunk or logs catch it.

Deliverable: Incident analysis.


Day 3–4 (Log enrichment)

Learn adding geoip and user-agent enrichment in Splunk/Wazuh.

Example SPL: index=main | iplocation src_ip | stats count by Country

Deliverable: dashboard screenshot.


Day 5 (Writeup)

Write “How I detected and triaged a brute force attack” — publish to GitHub and Medium/Hashnode.



---

Week 8 — Blue Team labs & TryHackMe SOC path

Finish TryHackMe SOC Level 1 path; complete min 8 rooms.

Commit summaries of each room into week-08/tryhackme-soc.md.

Prepare to present one case study (video or writeup) for portfolio.


Month 2 deliverables:

Splunk dashboards, alerts, playbook, 1 incident ticket, TryHackMe SOC path completion.



---

Month 3 — Weeks 9–12: Tools deepening & Python automation

Goal: learn Nmap advanced, TCP/IP analysis, start automation with Python.


---

Week 9 — Advanced Nmap, vulnerability scanning

Day 1 (Nmap scripts)

nmap -sV --script=vuln <target> ; nmap -p 80 --script http-enum <target>

Learn NSE scripts usage and output interpretation.


Day 2 (OpenVAS / Nessus basics)

Install OpenVAS (Greenbone Vulnerability Manager) or use an online scanner in lab.

Run a local scan of your test VM.

Deliverable: vulnerability report (export PDF or HTML).


Day 3–4 (Reporting)

Create an executive one-page summary and a technical appendix with remediation steps.

GitHub: projects/ vuln-scan-report/


Day 5 (Ethics + scope)

Write a short doc on legal scope of scanning, permissions, and best practices.



---

Week 10 — Packet analysis (Wireshark deep dive)

Day 1 (Capture with tcpdump)

Command: sudo tcpdump -i eth0 -w /tmp/capture.pcap

Create HTTP traffic: curl http://<vm-ip>/file

Open pcap in Wireshark: practice filters:

ip.addr == 192.168.56.101

tcp.flags.syn == 1

http.request.method == "GET"


Deliverable: projects/packet-analysis/analysis.md + pcap file.


Day 2 (Detect suspicious patterns)

Look for signs: SYN flood (many SYN with no ACK), DNS tunneling (unusual long TXT responses), suspicious user agents.

Deliverable: Write a detection rule proposal for Splunk/Wazuh.


Day 3–4 (Write IDS signatures)

Example Snort/Suricata rule (education only):

alert tcp any any -> 192.168.56.101 22 (msg:"SSH bruteforce"; flags:S,12; threshold: type both, track by_src, count 10, seconds 60; sid:1000001; rev:1;)


Explain reason and detection logic; store in GitHub.


Day 5 (Map to SIEM)

Create a Splunk search that detects high SYN rate:

Example SPL: index=pcap sourcetype=pcap | stats count BY src_ip | where count > 100 (adjust to your data)




---

Week 11 — Python for SOC: log parsers & automation

Day 1 (Python basics recap)

Install Python3, pip, create venv:

sudo apt install python3 python3-venv python3-pip

python3 -m venv venv && source venv/bin/activate


Practice print(), lists, dicts, file I/O.


Day 2 (Write a log parser skeleton)

Task: Create log_parser.py that:

reads /var/log/auth.log

finds lines containing “Failed password”

aggregates counts per IP and prints top 10 offenders



Example code (you can copy into your project):

#!/usr/bin/env python3
from collections import Counter
import re

def parse_authlog(path="/var/log/auth.log"):
    ip_re = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    ips = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            if "Failed password" in line or "Invalid user" in line:
                m = ip_re.search(line)
                if m:
                    ips.append(m.group(1))
    return Counter(ips)

if _name_ == "_main_":
    top = parse_authlog()
    for ip, count in top.most_common(10):
        print(f"{ip} -> {count}")

Deliverable: Add file to tools/log-parser/ and a README explaining usage.


Day 3–4 (Automate alert email)

Extend script to email (or create file) when threshold exceeded (only local).

Use smtplib or write to alerts.log.


Day 5 (Wrap up)

Commit code, create README with sample output.



---

Week 12 — Project: mini-SIEM with Wazuh (installation + rule)

Install Wazuh (server + agent) or use Wazuh cloud trial.

Add your Ubuntu VM agent, configure rules for failed logins.

Demonstrate detection and log enrichment.

Deliverable: projects/wazuh-setup/ with installation steps, commands, screenshots.


Month 3 deliverables:

Vulnerability report, pcap analysis, Python log parser, Wazuh setup.



---

Month 4 — Weeks 13–16: Web app basics, Burp, OWASP, Certifications

Goal: understand web vulnerabilities and complete cert study plan start.


---

Week 13 — Web fundamentals + OWASP Top 10

Day 1–2 (HTTP deep dive)

Understand request/response headers, status codes, cookies, sessions.

Tools: curl examples:

curl -v http://<target>

curl -I http://<target> to see headers



Day 3–4 (OWASP Top 10 study)

Learn XSS, SQLi, CSRF, Insecure Direct Object Ref, etc.

Practice on PortSwigger Web Academy labs (free) or DVWA (local).


Day 5 (Burp Suite intro)

Install Burp (Community edition), configure browser proxy.

Do a simple intercept of a login form.


Deliverable: projects/web-security/ with one Burp screenshot and taken note.


---

Week 14 — Practical web labs

Complete a few PortSwigger labs: XSS and SQLi basics.

Write a report: how vulnerability works + remediation.



---

Week 15–16 — Certification study (Security+ or Google Cybersecurity)

If Security+:

Follow a study schedule: 2 weeks of focused study with practice exams.

Daily: 2hrs video (Professor Messer/ Udemy) + 1hr question bank.

Register for exam after practice tests show 80%+ consistently.


If Google certificate:

Continue the Coursera modules — pace 10–12 hrs/week until completion.


Deliverable: Certification progress logged in GitHub.


---

Month 5 — Weeks 17–20: Projects, portfolio polishing, blog writing

Goal: finalize 4–6 portfolio projects, write 2 technical blog posts, build a resume.


---

Weeks 17–18 — Portfolio deepening

Finish these projects fully documented:

1. Nmap Vulnerability Report (project folder with PDF + remediation).


2. Splunk SOC Case Study (from Week 5/6): full incident ticket + timeline + remediation.


3. Packet Analysis Case with pcap and detection rule.


4. Python Tool: log-parser + alert module.



For each project include:

README.md with:

Objective

Tools used

Step-by-step reproduction

Findings (screenshots)

Learning & next steps



Commit each project into projects/<project-name>/.


---

Week 19 — Write two blog posts

Post 1: “How I detected SSH brute force with Splunk — step by step” (500–900 words with screenshots).

Post 2: “Beginner’s guide to setting up a home SIEM with Wazuh”

Publish on Medium/Hashnode and link in GitHub.



---

Week 20 — Resume, LinkedIn, Elevator pitch

Resume structure (one page). I’ll provide a filled template below. Put projects as bullet points with links.

LinkedIn: headline Aspiring SOC Analyst | Splunk, Linux, Python | TryHackMe: <rank>; about section 2–3 lines + 3 bullets of skills.

Prepare 30-second elevator pitch:

“I’m Ankush — trained in Linux, Splunk, and SIEM operations; completed hands-on projects including detection of SSH brute force, Wazuh deployment, and packet analysis. Looking for SOC Analyst L1 role in Mohali/Chandigarh.”



Deliverable: resume uploaded to GitHub and LinkedIn updated.


---

Month 6 — Weeks 21–24: Interview prep + job hunt

Goal: apply, interview, iterate.


---

Week 21 — Interview prep: technical and behavioral

Prepare answers for:

“What is the CIA triad?” — short answer + example.

“How do you detect brute force attacks?” — list detection methods (logs, spikes in failed logins, unusual IPs), show Splunk search you used.

“Explain a time you handled an incident” — use your case study and STAR format.


Practice live: 3 mock technical interviews (record yourself or with a friend).


Week 22 — Apply (targeted)

Prepare application tracker (spreadsheet columns: company, role, JD link, keywords, resume version used, date applied, recruiter contact, status).

Apply to 8–12 jobs/week focused on Mohali/Chandigarh/Panchkula and remote entry-level roles: keywords SOC Analyst L1, Security Analyst, Security Operations.

Message template to recruiters (short):

Hi <Name>, I'm Ankush Rawat — trained in Linux, Splunk, and SOC monitoring with hands-on projects (links). I'm applying for <role> and would love to discuss how I can help your SOC team. Thank you!

Tailor resume for each JD by matching 5 keywords.


Week 23 — Mock interviews + improvement

Have at least 2 technical mock interviews (use interviewexchange or friends).

Prepare live demos: open GitHub project and walk the interviewer through a detection you did.


Week 24 — Followups + negotiation basics

Follow up on applications after 7–10 days with a polite message.

If you receive offers, assess salary and role fit. Typical fresher pay in Mohali ~ ₹3–5 LPA; internships pay less but give experience.


Final deliverable: at least 50 job applications, 5 recruiter contacts, 1–3 interviews.


---

PROJECT SPECIFICS — exact templates & commands (copy-paste friendly)

1) Incident ticket template (MD file)

Title: SSH Brute Force Detection — [Date]
Severity: Medium
Detected by: Splunk alert "Failed SSH > 5 in 10m"
Indicators:
 - src_ip: 1.2.3.4
 - target_host: ubuntu-vm
 - timestamps: 2025-08-01T10:12 -> 2025-08-01T10:20
Steps taken:
 1. Identified repeated "Failed password" events in /var/log/auth.log
 2. Verified using Splunk search: index=main "Failed password" | stats count by src_ip
 3. GeoIP lookup: AbuseIPDB -> Malicious
Containment:
 - Blocked IP at host firewall: sudo ufw deny from 1.2.3.4
Eradication:
 - Reset affected user password, enforced SSH key auth and disabled password login (see commands below)
Recovery:
 - Monitored for 24 hours, no further alerts
Root Cause:
 - Weak password + open SSH port
Mitigation:
 - Enforce fail2ban, disable root login, use SSH keys
Commands used:
 - grep "Failed password" /var/log/auth.log
 - sudo ufw deny from 1.2.3.4
 - sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart ssh

2) Useful commands to put in your cheat-sheet (save to tools/cheatsheet.md)

Linux basics: ls -la, chmod 755 script.sh, chown user:user file

Network: ip a, ss -tuln, nmap -sS -p- -T4 <ip>, traceroute -n <host>

Logs: sudo tail -n 200 /var/log/auth.log | grep "Failed password"

Packet capture: sudo tcpdump -i eth0 -w /tmp/capture.pcap

Splunk:

Basic search: index=main sourcetype=linux_secure "Failed password" | stats count by src_ip

Top failed login IPs: index=main "Failed password" | top src_ip




---

GITHUB REPO STRUCTURE (exact)

ankush-cyber-portfolio/
├─ README.md
├─ week-01/
│  └─ notes.md
├─ week-02/
│  └─ apache-serve.md
├─ projects/
│  ├─ splunk-ssh-bruteforce/
│  │  ├─ README.md
│  │  ├─ screenshots/
│  │  └─ incident-ticket.md
│  ├─ packet-analysis/
│  │  ├─ capture.pcap
│  │  └─ analysis.md
│  └─ log-parser/
│     ├─ log_parser.py
│     └─ README.md
├─ tools/
│  └─ cheatsheet.md
└─ blog/
   └─ splunk-detection.md

Each README.md must have: objective, prerequisites, exact commands to reproduce, screenshots, and a short learning summary.


---

Resume (1-page ATS friendly) — fill with your details

ANKUSH RAWAT
Mohali, Punjab, India | +91-XXXXXXXXXX | youremail@example.com
LinkedIn: linkedin.com/in/ankush | GitHub: github.com/ankush | TryHackMe: tryhackme.com/p/ankush

Objective
Aspiring SOC Analyst with hands-on experience in Linux, Splunk, Wazuh, Nmap, and Python automation. Completed multiple lab projects demonstrating incident detection, triage, and remediation. Seeking SOC Analyst L1 role to contribute to 24x7 security monitoring and incident response.

Skills
Linux (Ubuntu, Kali), Windows Event Logs, Networking (TCP/IP, DNS), SIEM (Splunk), Wazuh, Wireshark, Nmap, Python scripting, Incident Response, Threat Intelligence, Git/GitHub

Certifications
- Google Cybersecurity Professional — In progress (or CompTIA Security+ — planned)

Projects
- Splunk SSH Brute Force Detection — Built Splunk alerts & dashboards detecting failed SSH attempts; created incident ticket, containment & remediation steps. (github.com/ankush/projects/splunk-ssh-bruteforce)
- Packet Analysis Case Study — Captured and analyzed suspicious traffic with Wireshark; authored detection rule and Splunk search. (link)
- Python Log Parser — Script to parse /var/log/auth.log, aggregate failed login sources and generate alerts. (link)

Education
[Bachelor’s Degree], [College], [Years]

Experience
- TryHackMe / personal labs — Completed 50+ labs including SOC Level 1, Nmap rooms, Wireshark basics.

Achievements
- Published blog "How I detected an SSH brute force with Splunk".

Tailor the keywords to the JD (e.g., “Splunk”, “SIEM”, “SOC”, “incident triage”).


---

Interview Qs + Model Bullet Answers (memorize & practice)

1. What is the CIA triad?



Confidentiality: only authorized access; Integrity: data is not altered; Availability: systems are accessible when needed.


2. How do you detect brute force attacks?



Monitor for repeated failed logins over short time windows, spikes in authentication failures, unusual sourceIps; use Splunk search index=auth "Failed password" | stats count by src_ip | where count > 10.


3. How to triage an alert?



Collect logs & context, identify IOC, determine scope/impact (which hosts/users), contain (block IP), escalate to Tier-2 if needed, document timeline, remediate & lessons learned.


4. What’s the difference between IDS & IPS?



IDS detects and alerts (passive); IPS can actively block malicious traffic (inline).


5. How do you secure SSH?



Disable password auth, use SSH keys, change port, enable fail2ban, use firewall rules.


Practice answering with STAR method and include real findings from your projects.


---

Job application routine (daily/weekly)

Daily: Apply to 2–3 jobs (customized resume). Message one recruiter with a short intro.

Weekly: 8–12 applications, 1 networking message to alumni or local groups.

Track everything in spreadsheet.



---

Weekly checkpoints (mandatory)

Each Sunday evening:

1. Commit week-XX-checkpoint/notes.md to GitHub with screenshots and links.


2. Post a LinkedIn micro-update with one learning highlight.


3. If stuck, message me and paste your notes.md — I’ll debug with you.




---

Final tips & mindset

Consistency beats cramming. Daily practice is everything.

Focus more on explainable deliverables (projects with writeups) than certifications alone.

Use your GitHub + LinkedIn as proof — recruiters want to see what you actually built.

When you get interviews, demo one project live — that’s a huge differentiator.



---

If you want, I can now:

Generate your day-by-day calendar for the first 60 days with exact hour blocks, or

Create the exact GitHub README templates and the Splunk search examples in runnable form, or

Produce the resume filled with your real details (give me your education and phone/email).


Which of those do you want me to make next?
