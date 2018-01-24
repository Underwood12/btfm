# __Blue Team Field Manual__


> Online Copy "re-written" by 2/c John Hammond

* __Updates, Edits, and Supplement Material__: [http://www.blueteamfieldmanual.com/](http://www.blueteamfieldmanual.com/)
* __BTFM is based on the NIST Cybersecurity Framework__: [http://www.nist.gov/cyberframework/](http://www.nist.gov/cyberframework/)


## __1. Identify (Scope)__

### Scanning and Vulnerabilities


#### Nmap


__Ping sweep for network:__

``` 
# nmap -sn -PE <IP ADDRESS OR RANGE>
```

__Scan and show open ports:__

```
# nmap --open <IP ADDRESS OR RANGE>
```

__Determine open services:__

```
# nmap -sV <IP ADDRESS>
```

__Scan two common TCP ports, HTTP and HTTPS:__

```
# nmap -p 80,443 <IP ADDRESS OR RANGE>
```

__Scan common UDP ports, DNS:__

```
# nmap -sU -p 53 <IP ADDRESS OR RANGE>
```

__Scan UDP and TCP together, be verbose on a single host and include optional skip ping:__

```
# nmap -v -Pn -sU -sT -p U:53,11,137,T:21-25,80,189,8080 <IP ADDRESS>
```

-------

#### Nessus

__Basic Nessus Scan:__

```
# nessus -q -x -T html <NESSUS SERVER IP ADDRESS> <NESSUS SERVER PORT 1241> <ADMIN ACCOUNT> <ADMIN PASSWORD> <FILE WITH TARGETS>.txt <RESULTS FILE NAME>.html

# nessus [-vnh] [-c .rcfile] [-V] [-T <format>]
```

__Batch-mode scan:__

```
# nessus -q [-pPS] <HOST> <PORT> <USER NAME> <PASSWORD> <targets-file> <result-file>
```

__Report conversion:__

```
# nessus -i in.[nsr|nbe] -o out.[xml|nsr|nbe|html|txt]
```

-----------------

#### OpenVAS


__Step 1:__ Install the server, client and plugin packages.

```
# apt-get install openvas-server openvas-client openvas-plugins-base openvas-plugins-dfsg
```

__Step 2:__ Update the vulnerability database:

```
# openvas-nvt-sync
```

__Step 3:__ add a user to run the client:

```
# openvas-adduser
```

__Step 4__: Login: sysadm

__Step 5:__ Authentication (pass/cert) [pass]: [HIT ENTER]

__Step 6:__ Login password: <PASSWORD>

You will then be asked to add "User Rules".

__Step 7__: Allow this user to scan authorized network by typing:

```
accept <YOUR IP ADDRESS OR RANGE>
default deny
```

__Step 8:__ type Ctrl-D to exit, and then accept.

__Step 9:__ Start the server

```
# service openvas-server start
```

__Step 10:__ Set targets to scan:

Create a text file with a list of hosts/networks to scan.

```
vi scanme.txt
```

__Step 11:__  Add one host, network per line:

```
<IP ADDRESS PER RANGE>
```

__Step 12:__ Run scan:

```
# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws scanme.txt openvas-output.txt -T txt -V -x
```

__Step 13:__ (Optional) Run scan with HTML format:

```
# openvas-client -q 127.0.0.1 9390 sysadm nsrc+ws scanme.txt openvas-output.txt -T txt -V -x
```

-------

### Windows

#### Network Discovery

__Basic Network Discovery:__

```
C:\> net view /all

C:\> net view \\<HOST NAME>
```

__Basic ping scan and write output to a file:__

```
C:\> for /L %I in (1,1,254) do ping -w 30 -n 1 192.168.1.%I | find "Reply" >> <OUTPUT FILE NAME>.txt
```

------------

#### DHCP

__Enable DHCP server logging:__

```
C:\> reg add HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v ActivityLogFlag /t REG_DWORD /d 1
```

__Default Location Windows Server 2003/2008/2016:__

```
C:\> %windir%\System32\Dhcp
```

--------------


#### DNS

__Default location Windows 2003:__


```
C:\> %SystemRoot%\System32\Dns
```

__Default location Windows 2008:__


```
C:\> %SystemRoot%\System32\Winevt\Logs\DNSServer.evtx
```

__Default location of enhanced Windows 2012 R2:__

```
C:\> %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl
```

Reference [https://technet.microsoft.com/en-us/library/cc940779.aspx](https://technet.microsoft.com/en-us/library/cc940779.aspx)

__Enable DNS Logging:__

```
C:\> DNSCmd <DNS SERVER NAME> /config /logLevel 0x8100F331
```

__Set log location:__

```
C:\> DNSCmd <DNS SERVER NAME> /config /LogFilePath <PATH TO LOG FILE>
```

__Set size of log file:__

```
C:\> DNSCmd <DNS SERVER NAME> /config /logfilemaxsize 0xffffffff
```

----------------

#### Hashing

__File Checksum Integrity Verifier (FCIV):__

Reference [http://support2.microsoft.com/kb/841290](http://support2.microsoft.com/kb/841290)

__Hash a file:__ 

```
C:\> fciv.exe <FILE TO HASH>
```

__Hash all files on C:\ into a database file__

```
C:\> fciv.exe C:\ -r -md5 -xml <FILE NAME>.xml
```

__List all hashed files__

```
C:\> fciv.exe -list -sha1 -xml <FILE NAME>.xml
```

__Verify previous hashes in db with file system__:

```
C:\> fciv.exe -v -sha1 -xml <FILE NAME>.xml
```

__Note: May be possible to create a master db and compare to all systems from a cmd line. Fast baseline and difference.__

Reference: [https://technet.microsoft.com/en-us/library/dn520872.aspx](https://technet.microsoft.com/en-us/library/dn520872.aspx)

```
PS C:\> Get-FileHash <FILE TO HASH> | Format-List

PS C:\> Get-FileHash -Algorithm MD5 <FILE TO HASH>

C:\> certutil -hashfile <FILE TO HASH> SHA1

C:\> certutil -hashfile <FILE TO HASH> MD5
```

----------

#### NetBIOS

__Basic nbtstat scan:__

```
C:\> nbtstat -A <IP ADDRESS>
```

__Cached NetBIOS info on localhost:__

```
C:\> nbtstat -c
```

__Script loop scan:__

```
C:\> for /L %I in (1,1,254) do nbtstat -An 192.168.1.%I
```

----------------

#### User Activity


Reference: [https://technet.microsoft.com/en-us/sysinternals/psloggedon.aspx](https://technet.microsoft.com/en-us/sysinternals/psloggedon.aspx)

__Get users logged on:__

```
C:\> psloggedon \\COMPUTERNAME
```


__Script loop scan:__

```
C:\> for /L %i in (1,1,254) do psloggedon \\192.168.1.%i >> C:\users_output.txt
```

---------------------


#### Passwords

__Password guessing or checks:__

```
C:\> for /f %i in (<PASSWORD FILE NAME>.txt) do @echo %i & net use \\<TARGET IP ADDRESS> %i /u:<USERNAME> 2>nul && pause

C:\> for /f %i in (<USERNAME FILE NAME>.txt) do @(for /f %j in (<PASSWORD FILE NAME>.txt) do @echo %i:%j & @net use \\<TARGET IP ADDRESS> %j /u:%i 2>nul && echo %i:%j >> success.txt && net use \\\<IP ADDRESS> /del)
```

------------------


#### Microsoft Baseline Security Analyzer (MBSA)

__Basic scan of a target IP address:__

```
C:\> mbsacli.exe /target <TARGET IP ADDRESS> /n os+iis+sql+password
```

__Basic scan of a target IP range:__

```
C:\> mbsacli.exe /r <TARGET ADDRESS RANGE> /n os+iis+sql+password
```

__Basic scan of a target domain:__

```
C:\> mbsacli.exe /d <TARGET DOMAIN> /n os+iis+sql+password
```

__Basic scan of target computer names in a text file:__

```
C:\> mbsacli.exe /listfile <LISTNAME OF COMPUTER NAMES>.txt /n os+iis+sql+password
```

------------------------

#### Active Directory Inventory

__List all OUs:__

```
C:\> dsquery ou DC=<DOMAIN>,DC=<DOMAIN EXTENSION>
```

__List of workstations in the domain:__

```
C:\> netdom query WORKSTATION
```

__List of servers in the domain:__

```
C:\> netdom query SERVER
```

__List of domain controllers:__

```
C:\> netdom query DC
```


__List of organizational units under which the specified user can create a machine object:__

```
C:\> netdom query OU
```


__List of primary domain controller:__

```
C:\> netdom query PDC
```


__List the domain trusts:__

```
C:\> netdom query TRUST
```

__Query the domain for the current list of FSMO owners:__

```
C:\> netdom query FSMO
```

__List all computers from Active Directory:__

```
C:\> dsquery COMPUTER "OU=servers,DC=<DOMAIN NAME>,DC=<DOMAIN EXTENSION>" -o rdn -limit 0 > C:\machines.txt
```

__List user accounts inactive longer than 3 weeks__

```
C:\> dsquery user domainroot -inactive 3
```

__Find anything (or user) created on date in UTC using timestamp format YYYMMDDHHMMSS.sZ:__

```
C:\> dsquery * -filter "(whenCreated>=YYYMMDDHHMMSS.0Z)"

C:\> dsquery * -filter "((whenCreated>=YYYMMDDHHMMSS.0Z)&(objectClass=user))"
```

--------------


### Linux

#### Network Discovery

__Net view scan:__

```
# smbtree -b

# smbtree -D

# smbtree -s
```

__View open SMB shares:__

```
# smbclient -L <HOST NAME>

# smbstatus
```

__Basic Ping Scan:__

```
# for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip>/dev/null; [ $? -eq 0 ] && echo "192.168.1.$ip UP" || : ; done
```

-------------------

#### DHCP

__View DHCP lease logs__:

__Red Hat 3:__

```
cat /var/lib/dhcpd/dhcdp.leases
``` 

__Ubuntu:__

```
# grep -Ei 'dhcp' /var/log/syslog.1
```

__Ubuntu DHCP logs:__

```
# tail -f dhcp.log
```

--------------

#### DNS 

__Start DNS logging:__

```
# rndc querlog
```

__View DNS logs:__

```
tail -f /var/log/messages | grep named
```


------------------


#### Hashing

```
# find /<PATHNMAME TO ENUMERATE> -type f -exec md5sum {} >> md5sums.txt \;

# md5deep -rs / > md5sums.txt
```


------------------


#### NetBIOS

__Basic nbtstat scan:__

```
# nbtscan <IP ADDRESS OR RANGE>
```

--------------

#### Passwords

__Password and username guessing or checks:__

```
# while read line; do username=$line; while read line; do smbclient -L <TARGET IP ADDRESS> -U $username%$line -g -d 0; echo "$username:$line"; done < <PASSWORDS>.txt; done < <USERNAME>.txt
```

-----------------

## __3. Protect (Defend)__

### Windows

#### Disable/Stop Services

__Get a list of services and disable or stop them:__

```
C:\> sc query

C:\> sc config "<SERVICE NAME>" start=disabled

C:\> sc stop "<SERVICE NAME>" 

C:\> wmic service where name='<SERVICE NAME>' call ChangeStartmode disabled
```

#### Host System Firewalls

__Show all rules:__

```
C:\> netsh advfirewall firewall show rule name=all
```

__Set firewall on/off:__

```
C:\> netsh advfirewall set currentprofile state on

C:\> netsh advfirewall set currentprofile firewallpolicy blockinboundalways,allowoutbound

C:\> netsh advfirewall set currentprofile set publicprofile state on

C:\> netsh advfirewall set currentprofile set privateprofile state on

C:\> netsh advfirewall set currentprofile set domainprofile state on

C:\> netsh advfirewall set currentprofile set allprofile state on

C:\> netsh advfirewall set currentprofile set allprofile state off
```

__Set firewall rules examples:__

```
C:\> netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=domain

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=public

C:\> netsh advfirewall firewall add rule name="My Application" dir=in action=allow program="C:\MyApp\MyApp.exe" enable=yes remoteip=157.60.0.1,172.16.0.0/16,LocalSubnet profile=private

C:\> netsh advfirewall firewall delete rule name=rule name program="C:\MyApp\MyApp.exe"

C:\> netsh advfirewall firewall delete rule name=rule name protocol=udp localport=500

C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=Yes profile=domain

C:\> netsh advfirewall firewall set rule group="remote desktop" new enable=No profile=public
```


__Setup logging location:__

```
C:\> netsh advfirewall set currentprofile logging C:\<LOCATION>\<FILENAME>
```

__Windows firewall log location and settings:__

```
C:\> more %systemroot%\system32\LogFiles\Firewall\pfirewall.log

C:\> netsh advfirewall set allprofile logging maxfilesize 4096

C:\> netsh advfirewall set allprofile logging droppedconnections enable

C:\> netsh advfirewall set allprofile logging allowedconnections enable
```

__Display firewall logs:__

```
PS C:\> Get-Content $env:systemroot\system32\LogFiles\Firewall\pfirewall.log
```

--------------

#### Passwords

__Change password:__

```
C:\> net user <USERNAME> * /domain

C:\> net user <USERNAME> <NEW PASSWORD>
```


__Change password remotely__

Reference: [https://technet.microsoft.com/en-us/sysinternals/bb897543](https://technet.microsoft.com/en-us/sysinternals/bb897543)

```
C:\> pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE COMPUTER> -u <REMOTE USER NAME> -p <NEW PASSWORD>
```

------------

#### Host File

__Flush DNS of malicious domain/IP:__

```
ipconfig /flushdns
```

__Flush NetBIOS cache of host/IP:__

```
nbtstat -R
```

__Add new malicious domnain to hosts file, and route it to localhost:__

```
C:\> echo 127.0.0.1 <MALICIOUS DOMAIN> >> C:\Windows\System32\drivers\etc\hosts
```


__Check if hosts file is working, by making sure ping gets sent to 127.0.0.1:__

```
C:\> ping <MALICIOUS DOMAIN> -n 1
```

------------------

#### Whitelist

__Use a Proxy Auto Config (PAC) file to create Bad URL or IP list (IE, Firefox, Chrome):__

```
function FindProxyForURL( url, host ){
    
    // Send bad DNS name to the proxy

    if ( dnsDomainIs( host, ".badsite.com" ) )
        return "PROXY http://127.0.0.1:8080";

    // Send bad IPs to the proxy

    if ( isInNet( myIpAddress(), "222.222.222.222", "255.255.255.0" ) )
        return "PROXY http://127.0.0.1:8080";

    // All other traffic bypass proxy

    return "DIRECT"

}
```

-----------


#### Application Restrictions

__AppLocker -- Server 2008 R2 or Windows 7 or higher:__

__Using GUI Wizard configure:__

* Executable Rules (.exe, .com)
* DLL Rules (.dll, .ocx)
* Script Rules (.ps1, .bat, .cmd, .vbs, .js)
* Windows Install Rules

__Steps to employ AppLocker (GUI is needed for digital signed app restrictions)__

__Step 1:__ Create a new GPO.

__Step 2:__ Right-click on it to edit, and then navigate through Computer Configuration, Policies, Windows Settings, Security Settings, Application Control Policies and AppLocker. Click Configure Role Enforcement.

__Step 3:__ Under Executable Rules, check the Configured box and then make sure Enforce Rules is select from the dro-down box. Click OK.

__Step 4:__ In the left pane, click Executable Rules.

__Step 5:__ Right-click in the right pane and select Create New Rule.

__Step 6:__ On the Before You Begin Screen, click Next.

__Step 7:__ On the Permissions screen, click Next.

__Step 8:__ On the Conditions screen, select the Publisher condition and click Next.

__Step 9:__ Click the Browse button and browse to any executable file on your system. It doesn't matter which.

__Step 10:__ Drag the slider up to Any Publisher and then click Next.

__Step 11:__ Click Next on the Exceptions screen.

__Step 12:__ Name policy, Example "Only run executables that are signed" and click Create.

__Step 13:__ If this is your first time creating an AppLocker rule, Windows will prompt you to create default rule, click Tes.

__Step 14:__ Ensure Application Identity Service is running.

```
C:\> net start AppIDSvc

C:\> reg add "HKLM\SYSTEM\CurrentControlSet\services\AppIDSvc" /v Start /t REG_DWORD /d 2 /f
```


__Step 15:__ Changes require reboot.

```
C:\> shutdown.exe /r

C:\> shutdown.exe /r /m \\<IP ADDRESS OR COMPUTER NAME> /f
```

__Add the AppLocker cmdlets into PowerShell:__

```
PS C:\> Import-Module AppLocker
```


__Gets the file information for all of the executable files and scripts in the directory C:\Windows\System32:__

```
PS C:\> Get-AppLockerFileInformation -Directory C:\Windows\System32\ -Recurse -FileTyle Exe, Script
```

__Create an AppLocker policy that allow rules for all of the executable files in C:\Windows\System32:__

```
PS C:\> Get-ChildItem C:\Windows\System32\*.exe | Get-AppLockerFileInformtion | New-AppLockerPolicy -RuleType Publisher, Hash -User Everyone -RuleNamePrefix System32
```

__Sets the local AppLocker policy to the policy specific in C:\Policy.xml:__

```
PS C:\> Set-AppLockerPolicy -XMLPolicy C:\Policy.xml
```

__Uses the AppLocker Policy in C:\Policy.xml to test whether calc.exe and notepad.exe are allowed to run for users who are members of the Everyone Group. If you do not specify a group, the Everyone Group is used by default:__

```
PS C:\> Test-AppLockerPolicy -XMLPolicy C:\Policy.xml -Path C:\Windows\System32\calc.exe,C:\Windows\System32\notepad.exe -User Everyone
```

__Review how many times a file would have been blocked from running if rules were enforced:__

```
PS C:\> Get-AppLockerFileInformation -EventLog -Logname "Microsoft-Windows-AppLocker\EXE and DLL" -EventType Audited -Statistics
```

__Creates a new AppLocker policy from the audited events in the local Microsoft-Windows-AppLocker\EXE and DLL event log, applied to <GROUP> and current AppLocker polcy will be overwritten:__

```
PS C:\> Get-AppLockerFileInformation -EventLog -LogPath "Microsoft-Windows-AppLocker/EXE and DLL" -EventType Audited | New-AppLockerPolicy -RuleType Publisher,Hash -User domain\<GROUP> -IgnoreMissingFileInformation | Set-AppLockerPolicy -LDAP "LDAP://<DC>.<DOMAIN>.com/CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=<DOMAIN>,DC=com"
```

__Export the local AppLocker polcy, comparing User's explicitly denied access to run, and output test file:__

```
PS C:\> Get-AppLockerPolict -Local | Test-AppLockerPolicy -Path C:\Windows\System32\*.exe -User domain\<USER NAME> -Filter Denied | Format-List -Property Path > C:\DeniedFiles.txt
```

__Export the results of the test to a file analysis:__

```
PS C:\> Get-ChildItem <DirectoryPathToReview> -Filter <FileExtensionFilter> -Recurse | Convert-Path | Test-AppLockerPolicy -XMLPolicy <PathToExportedPolicyFile> -User <domain\username> -Filter <TypeOfRuleToFilterFor> | Export-CSV <PathToExportResultsTo>.csv
```


__GridView list of any local rules applicable__:

```
PS C:\> Get-AppLockerPolicy -Local -XML | Out-GridView
```


-----------------------


#### IPsec

__Create an IPsec Local Security Policy, applied to any connection, any protocol, and using a preshard key:__

```
C:\> netsh ipsec static add filter filterlist=MyIPsecFilter srcaddr=Any dstaddr=Any protocol=ANY

C:\> netsh ipsec static add filteraction name=MyIPsecAction action=negotiate

C:\> netsh ipsec static add policy name=MyIPsecPolicy assign=yes

C:\> netsh ipsec static add rule name=MyIPsecRule policy=MyIPsecPolicy filterlist=MyIPsecFilter filteraction=MyIPsecAction conntype=all activate=yes psk=<PASSWORD>
```

__Add rule to allow web browsing port 80 (HTTP) and 443 (HTTPS) over IPsec:__

```
C:\> netsh ipsec static add filteraction name=Allow action=permit

C:\> netsh ipsec static add filter filterlist=WebFilter srcaddr=Any dstaddr=Any protocol=TCP dstport=80

C:\> netsh ipsec static add filter filterlist=WebFilter srcaddr=Any dstaddr=Any protocol=TCP dstport=443

C:\> netsh ipsec static add rule name=WebAllow policy=MyIPsecPolicy filterlist=WebFilter filteraction=Allow conntype=All activate=yes psk=<PASSWORD>
```

__Shows the IPsec Local Security Policy with name "MyIPsecPolicy":__

```
C:\> netsh ipsec static show policy name=MyIPsecPolicy
```

__Stop or Unassign an IPsec Policy:__

```
C:\> netsh ipsec static set policy name=MyIPsecPolicy
```

__Create an IPsec Advanced Firewall Rule and Policy and preshared key from and to any connections:__

```
C:\> netsh advfirewall consec add rule name="IPSEC" endpoint1=any endpoint2=any action=requireinrequireout qmsecmethods=default
```

__Require IPsec preshared key on all outgoing requests:__

```
C:\> netsh advfirewall firewall add rule name="IPSEC_Out" dir=out action=allow enable=yes profile=any localip=any remoteip=any protocol=any interfacetype=any security=authenticate
```

__Create a rule for web browsing:__

```
C:\> netsh advfirewall firewall add rule name="Allow Outbound Port 80" dir=out localport=80 protocol=TCP action=allow
```

__Create a rule for DNS:__

```
C:\> netsh advfirewall firewall add rule name="Allow Outbound Port 53" dir=out localport=53 protocol=UDP action=allow
```

__Delete IPsec Rule:__

```
C:\> netsh advfirewall firewall delet rule name="IPSEC_RULE"
```

-----------------


#### Active Directory / Group Policy Object

__Get and force new policies:__

```
C:\> gpupdate /force

C:\> gpupdate /sync
```

__Audit success and failure for user Bob:__

```
C:\> auditpol /set /user:bob /category:"Detailed Tracking" /include /success:enable /failure:enable
```

__Create an Organizational Unit to move suspected or infected users and machines:__

```
C:\> dsadd ou <QUARANTINE BAD OU>
```

__Move an active directory user object into NEW GROUP:__

```
PS C:\> Move-ADObject 'CN=<USER NAME>,CN='OLD USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>' -TargetPath 'OU=<UNEW USER GROUP>,DC=<OLD DOMAIN>,DC=<OLD EXTENSION>'
```


------------------

#### Stand-Alone System/Miscellaneous

__Disallow running an .exe file:__

```
C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v DisallowRun /t REG_DWORD /d "00000001" /f

C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v badfile.exe /t REG_SZ /d <BAD FILE NAME>.exe /f
```


__Disable Remote Desktop:__

```
C:\> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnectionns /t REG_DWORD /d 1 /f
```

__Send NTLMv2 response only/refurse LM and NTLM (Windows 7 default):__

```
C:\> reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

__Restrict Anonymous Access:__

```
C:\> reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f
```

__Do not allow anonymous enumeration of SAM accounts and shares:__

```
C:\> reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f
```

__Disable IPv6:__

```
C:\> reg add "HKLM\System\CurrentControlSet\services\TCPIP6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f
```

__Disable Sticky Keys:__

```
C:\> reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
```

__Disable Toggle Keys:__

```
C:\> reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f
```

__Disable Filter Keys:__

```
C:\> reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
```

__Disable On-Screen Keyboard:__

```
C:\> reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" /v ShowTabletKeyboard /t REG_DWORD /d 0 /f
```


__Disable Administrative Shares - Workstations:__

```
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
```


__Disable Administrative Shares - Servers:__

```
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
```

__Remove Creation of Hashes Used to Pass the Hash Attack (requires password reset and reboot to purge old hashes):__

```
C:\> reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
```


__Disable IE Password Cache:__

```
C:\> reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
```


__Disable CMD Prompt:__

```
C:\> reg add "HKCU\Sofware\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f
```


__Disable Admin credentials cache on host when using RDP:__

```
C:\> reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

__Do not process the RunOnce list:__

```
C:\> reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1 /f
```

__Require User Access Control (UAC) Permission:__

```
C:\> reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
```

__Change Password at next logon:__

```
PS C:\> Set-ADAccountPassword <USER> -NewPassword $newpwd -Reset -PassThru | Set-ADUser -ChangePasswordAtLogon $True
```

__Change Password at next logon for OU group:__

```
PS C:\> Get-ADUser -filter "department -eq '<OU GROUP>' -AND enabled -eq 'True'" | Set-ADUser -ChangePasswordAtLogon $True
```

__Enable Firewall Logging:__

```
C:\> netsh firewall set logging droppedpackets connections=enable
```

-----

### Linux

#### Disable/Stop Services


__Services Information:__

```
# service --status-all

# ps -ef

# ps -aux
```

__Get a list of upstart jobs:__

```
# initctl list
```

__Example of start, stop, restarting a service in Ubuntu:__

```
# /etc/init.d/apache2 start

# /etc/init.d/apache2 restart

# /etc/init.d/apache2 stop (stops only until reboot)

# service mysql start

# service mysql restart

# service mysql stop  (stops only until reboot)
```

__List all Upstart services:__

```
#  ls /etc/init/*.conf
```

__Show if a program is managed by upstart and the process ID:__

```
# status ssh
```


__If not managed by upstart:__

```
# update-rc.d apache2 disable

# service apache2 stop
```


-----------------


#### Host System Firewalls


__Export existing iptables firewall rules__

```
# iptables-save > firewall.out
```

__Edit firewall rules and chains in firewall.out and save the file:__

```
# vi firewall.out
```

__Apply back to iptables:__

```
# iptables-restore < firewall.out
```

__Example iptables commands (IP, IP range, port blocks):__

```
# iptables -A INPUT -s 10.10.10.10 -j DROP

# iptables -A INPUT -s 10.10.10.0/24 -j DROP

# iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP

# iptables -A INPUT -p tcp --dport ssh -j DROP
```

__Block all connections:__

```
# iptables-policy INPUT DROP

# iptables-policy OUTPUT DROP

# iptables-policy FORWARD DROP
```

__Log all denied iptables rules:__

```
# iptables -I INPUT 5 -m limit --limit 4/min -j LOG --log-prefix "iptables denied: " --log-level 7
```

__Save all current iptables rules:__

__Ubuntu:__

```
# /etc/init.d/iptables save

# /sbin/service iptables save
```

__Red Hat/CentOS:__

```
# /etc/init.d/iptables save

# /sbin/iptables-save
```

__List all current iptables rules:__

```
# iptables -L
```

__Flush all current iptables rules:__

```
# iptables -F
```

__Start/stop iptables service:__

```
# service iptables start

# service iptables stop
```

__Start/stop ufw service:__

```
# ufw enable
# ufw disable
```

__Start/stop ufw logging:__

```
# ufw logging on
# ufw logging off
```

__Backup all current ufw rules:__

```
# cp /lib/ufw/{user.rules,user6.rules} /<BACKUP LOCATION>

# cp /lib/ufw/{user.rules,user6.rules} ./
```

__Example uncomplicated firewall (ufw) commands (IP, IP range, port blocks):__

```
# ufw status verbose

# ufw delete <RULE #>

# ufw allow for <IP ADDRESS>

# ufw allow all 80/tcp

# ufw allow all ssh

# ufw deny from <BAD IP ADDRESS> proto udp to any port 443
```


---------------------

#### Passwords

__Change Password:__

```
$ passwd (for current user)

$ passwd bob (for user bob)

$ sudo su passwd (for root user)
```

---------------

#### Host Files

__Add new malicious domain to hosts file, and route to localhost:__

```
# echo 127.0.0.1 <MALICIOUS DOMAIN> >> /etc/hosts
```

__Check if hosts file is working, by pinging and checking if it goes to 127.0.0.1:__

```
# ping -c 1 <MALICIOUS DOMAIN>
```

__Ubuntu/Debian DNS cache flush:__

```
# /etc/init.d/dns-clean start
```

__Flush nscd DNS cache four ways:__

```
# /etc/init.d/nscd restart

# service nscd restart

# service nscd reload

# nscd -i hosts
```

__Flush dnsmasq DNS cache:__

```
# /etc/init.d/dnsmasq restart
```



-------------------

#### Whitelist 

__Use a Proxy Auto Config (PAC) file to create Bad URL or IP list (IE, Firefox, Chrome):__

```
function FindProxyForURL( url, host ){
    
    // Send bad DNS name to the proxy

    if ( dnsDomainIs( host, ".badsite.com" ) )
        return "PROXY http://127.0.0.1:8080";

    // Send bad IPs to the proxy

    if ( isInNet( myIpAddress(), "222.222.222.222", "255.255.255.0" ) )
        return "PROXY http://127.0.0.1:8080";

    // All other traffic bypass proxy

    return "DIRECT"

}
```

----------------------

#### IPsec

__Allow firewall to pass IPsec traffic:__

```
# iptables -A INPUT -p esp -j ACCEPT

# iptables -A INPUT -p ah -j ACCEPT

# iptables -A INPUT -p udp --dport 500 -j ACCEPT

# iptables -A INPUT -p udp --dport 4500 -j ACCEPT
```


__Pass IPsec traffic:__

__Step 1:__ Install Racoon utiltity on <HOST1 IP ADDRESS> and <HOST2 IP ADDRESS> to enable IPsec tunnel in Ubuntu.

```
# apt-get install racoon
```

__Step 2:__ Choose direct then edit `/etc/ipsec-tools.conf` on <HOST1 IP ADDRESS> AND <HOST2 IP ADDRESS>.

```
flush;

spdflush;

spdadd <HOST1 IP ADDRESS> <HOST2 IP ADDRESS> any -P out ipsec
    esp/transport//require;

spdadd <HOST2 IP ADDRESS> <HOST1 IP ADDRESS> any -P in ipsec
    esp/transport//require;
```

__Step 3:__ Edit `/etc/racoon/racoon.conf` on <HOST1 IP ADDRESS> and <HOST2 IP ADDRESS>.

```
log notify;

path pre_shared_key "/etc/racoon/psk.txt";

path certificate "/etc/racoon/certs";

remote anonymous {
        exchange_mode main,aggresive;
        proposal {

        encryption_algorithm aes_256;
        hash_algorithm sha256l
        authentication_method pre_shared_key;
        dh_group modp1024;
    }
    
    generate_policy off;
}

sainfo anonymous {
    
    pfs_group 2;
    encryption_algorithm aes_256;
    authentication_algorithm hmac_sha256;
    compression_algorithm deflate;
}
```

__Step 4:__ Add preshard key to both hosts.

__On HOST1:__

```
# echo <HOST2 IP ADDRESS> <PRESHARED PASSWORD> >> /etc/racoon/psk.txt
```

__On HOST2:__

```
# echo <HOST1 IP ADDRESS> <PRESHARED PASSWORD> >> /etc/racoon/psk.txt
```

__Step 5:__ Restart service on both machines:

```
# service setkey restart
```

__Check security associations, configuration and policies:__

```
# setkey -D

# setkey -DP
```

--------------------------

## __2. Detect (Visibility)__

### Network Monitoring

#### TCPdump


__View ASCII (-A) or (-X) traffic:__

```
# tcpdump -A

# tcpdump -X
```

__View traffic with timestamps and don't convert addresses and be verbose:__


```
# tcpdump -tttt -n -vv
```

__Find top talkers after 1000 packets (Potential DDOS):__


```
# tcpdump -nn -c 1000 | awk '{print $3}' | cut -d. -f1-4 | sort -n | uniq -c | sort -nr
```

__Capture traffic on any interface from a target host and specific port and output to a file:__

```
tcpdump -w <FILENAME>.pcap -i any dst <TARGET IP ADDRESS> and port 80
```

__View traffic only between two hosts:__

```
# tcpdump host 10.0.0.1 && host 10.0.0.2
```

__View all traffic except from a net or a host:__

```
# tcpdump not net 10.10 && not host 192.168.1.2
```

__View host and either of two other hosts:__

```
# tcpdump host 10.10.10.10 && \(10.10.10.20 or 10.10.10.30\)
```

__Save pcap file on rotating size:__

```
# tcpdump -n -s65535  -C 10000 -w '%host_%Y-%m-%d_%H:%M:%S.pcap'
```

__Save pcap file to a remote host:__

```
# tcpdump -w - | ssh <REMOTE HOST ADDRESS> -p 50005 "cat - > /tmp/remotecapture.pcap"
```

__Grab traffic that contains the word pass:__

```
# tcpdump -n -A -s0 | grep "pass"
```

__Grab many clear text protocol passwords:__

```
# tcpdump -n -A -s0 port http or port ftp or port smtp or port imap or port pop3 | egrep -i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|username:|password:|login:|pass |user ' --color=auto --line-buffered -B20
```

__Get throughput:__

```
# tcpdump -w - | pv -bert >/dev/null
```

__Filter out ipv6 traffic:__

```
# tcpdump not ip6
```

__Filter out ipv4 traffic:__

```
# tcpdump ip6
```


__Script to capture multiple interface tcpdumps to files rotating every hour:__

```
#!/bin/bash

tcpdump -pni any -s65535 -G 3600 -w any%Y-%m-%d_$H:%M:%S.pcap
```

__Script to move multiple tcpdump files to alternate location:__

```
#!/bin/bash

while true; do
sleep 1;
rsync -azvr -progress <USERNAME>@<IP ADDRESS>:<TRAFFIC DIRECTORY>/. <DESTINATION DIRECTORY>/.
done
```

__Look for suspicious and self-signed SSL certificates:__

```
# tcpdump -s 1500 -A '(tcp[((tcp[12:1]  & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2:1] = 0x16'
```

__Get SSL Certificate:__

```
# openssl s_client -connect <URL>:443

# openssl s_client -connect <URL>:443 </dev/null 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > <CERT>.pem
```

__Examine and verify the certificate and check for self-signed:__

```
# openssl x509 -text -in <CERT>.pem

# openssl x509 -in <CERT>.pem -noout -issuer -subject -startdate -enddate -fingerprint

# openssl verify <CERT>.pem
```

__Extract Certificae Server Name:__

```
# tshark -nr <PCAP FILE NAME> -Y "ssl.handshake.ciphersuites" -Vx| grep "Server Name: " | sort | uniq -c | sort -r
```


__Extract Certificate info for analysis:__

```
# ssldump -Nr <FILE NAME>.pcap | awk 'BEGIN {c=0;} { if ($0 ~ /^[  ]+Certificate$/) {c=1; print "=================================";} if ($0 !~ /^ +/) {c=0;} if (c==1) print $0; }'
```


---------------------

#### tshark

__Get list of network interfaces:__

```
# tshark -D
```

__Listen on multiple network interfaces:__

```
# tshark -i eth1 -i eth2 -i eth3
```

__Save to pcap and disable name resolution:__

```
# tshark -nn -w <FILE NAME>.pcap
```

__Get absolute data and time stamp:__

```
# tshark -t a
```

__Get arp or icmp traffic:__

```
# tshark arp or icmp
```

__Capture traffic between to [hosts] and/or [nets]:__

```
# tshark "host <HOST 1> && host <HOST 2>"

# tshark -n "net <NET 1> && net <NET 2>"
```

__Filter just host and IPs (or not your IP):__

```
# tshark -r <FILE NAME>.pcap -q -z hosts,ipv4

# tshark not host <YOUR IP ADDRESS>
```

__Not ARP and UDP:__

```
# tshark not arp not (udp.port == 53)
```

__Replay a pcap file:__

```
# tshark -r <FILE NAME>.pcap
```

__Replay a pcap and just grab hosts and IPs:__

```
# tshark -r <FILE NAME>.pcap -q -z hosts
```

__Setup a capture session (duration = 60 sec):__

```
# tshark -n -a files:10 -a filesize:100 -a duration:60 -w <FILE NAME>.pcap
```

__Grab src/dst IPs only:__

```
# tshark -n -e ip.src -e ip.dst -T fields -E separator=, -R ip
```

__Grab IP of src DNS and DNS query:__

```
# tshark -n -e ip.src -e dns.qry.name -E separator=';' -T fields port 53
```

__Grab HTTP URL host and request:__

```
# tshark -R http.request -T fields -E separator=';' -e http.host -e http.request.uri
```

__Grab just HTTP host requests:__

```
# tshark -n -R http.request -T fields -e http.host
```

__Grab top talkers by IP dst:__

```
# tshark -n -c 150 | awk '{print $4}' | sort -n | uniq -c | sort -nr
```

__Grab top stats of protocols:__

```
# tshark -q -z io,phs -r <FILE NAME>.pcap

# tshark -r <PCAP FILE>.pcap -R http.request -T fields -e http.host -e http.request.utri | sed -e 's/?.*$//' | sed -e 's#^(.*)t(.*)$#http://12#' | sort | uniq -c | sort -rn | head

# tshark -n -c 100 -e ip.src -R "dns.flags.response eq 1" -T fields port 53

# tshark -n -c 100 -e ip.src -R "dns.flags.response eq 1" -T fields port 53

# tshark -n -e http.request.uri -R http.request -T fields | grep exe

# tshark -n -c 1000 -e http.host -R http.request -T fields port 80 | sort | uniq -c | sort -r
```


--------------------

#### Snort

__Run test on snort config file:__

```
# snort -T -c /<PATH TO SNORT>/snort/snort.conf
```

__Use snort (v=verbose, d=dump packet payload):__

```
# snort -dv -r <LOG FILE NAME>.log
```

__Replay a log file and match icmp traffic:__

```
# snort -dvr packet.log icmp
```

__Logs in ASCII:__

```
# snort -K ascii -l <LOG DIRECTORY>
```

__Logs in binary:__

```
# snort -l <LOG DIRECTORY>
```

__Send events to console:__

```
# snort -q -A console -i eth0 -c /etc/snort/snort.conf

# snort -c snort.conf -l /tmp/so/console -A console
```

__Create a single snort rule and save:__

```
# echo alert any any <SNORT RULE> > one.rule
```

__Test single rule:__

```
# snort -T -c one.rule
```

__Run single rule and output to console and logs dir:__

```
# mkdir ./logs

# snort -vd -c one.rule -r <PCAP FILE NAME>.pcap -A console -l logs
```

----------------

### Network Capture (PCAP) Tools

#### Editcap

__Use to edit a pcap file (split into 1000 packets):__

```
# editcap -F pcap -c 1000 original.pcap out_split.pcap
```

__Use to edit a pcap file (split into 1 hour each packets):__

```
# editcap -F pcap -t+3600 original.pcap out_split.pcap
```

#### Mergecap

__Use to merge multiple pcap files:__

```
# mergecap -w merged_cap.pcap cap1.pcap cap2.pcap cap3.pcap
```

-------------


### Honey Techniques

#### Windows


__Honey Ports Windows:__

Reference: [http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf](http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf)

__Step 1:__ Create a new TCP firewall Block rule on anything connecting on port 3333:

```
C:\> echo @echo off for /L $$i in (1,1,1) do @for /f "tokens=3" %%j in ('netstat -nao ^|find ^":3333^"') do@for /f "tokens=1 delims=:" %%k in ("%%j") do netsh advfirewall firewall add rulename="HONEY TOKEN RULE" dir=in remoteip=%%k localport=any protocol=TCP action=block >> <BATCH FILENAME>.bat
```

__Step 2:__ Run batch script:

```
C:\> <BATCH FILE NAME>.bat
```


__Windows Honey Ports Powershell Script:__ Ref: [https://github.com/Pwdrkeg/honeyport/blob/master/honeyport.ps1](https://github.com/Pwdrkeg/honeyport/blob/master/honeyport.ps1)


__Step 1:__ Download PowerShell script

```
C:\> "%ProgramFiles%\Internet Explorer\iexplore.exe" https://github.com/Pwdrkeg/honeyport/blob/master/honeyport.ps1
```

__Step 2:__ Run PowerShell script

```
C:\> honeyport.ps1
```

__Honey Hashes for Windows (Also for detecting mimikatz use):__ Ref: [https://isc.sans.edu/forums/diary/Detecting+Mimikatz+Use+On+Your+Network/19311/](https://isc.sans.edu/forums/diary/Detecting+Mimikatz+Use+On+Your+Network/19311/)


__Step 1:__ Create Fake Honey Hash. Note __ENTER A FAKE PASSWORD AND KEEP COMMAND PROMPS OPEN TO KEEP A PASSWORD IN MEMORY.__

```
C:\> runas /user:yourdomain.com\fakeadministratoraccount /netonly cmd.exe
```

__Step 2:__ Query for Remote Access Attempts

```
C:\> wevtutil qe System /q:"*[System[(EventID=20274)]]" /f:text /rd:true /c:1 /r:remotecomputername
```

__Step 3:__ Query for Failed Login Attempts

```
C:\> wevtutil qe System /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:text /rd:true /c:5 /r:remotecomputername
```

__Step 4:__ (Optional) Run queries in infinit loop with 30s pause

```
C:\> for /L %i in ( 1, 0, 2 ) do wevtutil qe System /q:"*[System[(EventID=20274)]]" /f:text /rd:true /c:1 /r:remotecomputername & wevtutil qe System /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:text /rd:true /c:5 /r:remotecomputername & timeout 30
```



#### Linux


__Honey Ports Linux:__

Ref: [http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf](http://securityweekly.com/wp-content/uploads/2013/06/howtogetabetterpentest.pdf)

__Step 1:__ Run a while loop to create TCP firewall rules to block any hosts connecting on port 2222

```
# while [ 1 ]; echo "started"; do IP=`nc -n -l -p 2222 2>&1 1>/dev/null | grep from | cut -d[  -f 3 | cut -d] -f 1`; iptables -A INPUT -p tcp -s ${IP} -j DROP; done
```

__Linux Honey Ports Python Script:__ 

Ref: [https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py](https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py)

__Step 1:__ Download Python Script

```
# wget https://github.com/gchetrick/honeyports/blob/master/honeyports-0.5.py
```

__Step 2:__ Run Python Script

```
# python honeyports-0.5.py -p <CHOOSE AN OPEN PORT> -h <HOST IP ADDRESS>
```

__Detect rogue scanning with Labrea Tarpit:__

```
# apt-get install labrea

# labrea -z -s -o -b -v -i eth0 2>&1 | tee -a log.txt
```

#### Netcat

__Use netcat to listen for scanning threats__

```
# nc -v -k -l 80

# nc -v -k -l 443

# nc -v -k -l 3389
```

#### Passive DNS Monitoring

__Use dnstop to monitor DNS requests at any sniffer location:__

```
# apt-get update

# apt-get install dnstop

# dnstop -l 3 <INTERFACE NAME>
```

__Step 1:__ Hit 2 key to show query names

__Use dnstop to monitor DNS requests from a pcap file:__

```
# dnstop -l 3 <PCAP FILE NAME> | <OUTPUT FILE NAME>.txt
```


---------------

### Log Auditing

#### Windows

__Increase Log size to support increased auditing__

```
C:\> reg add HKLM\Software\Policies\Microsoft\Windows\EventLog\Application /v MaxSize /t REG_DWORD /d 0x19000


C:\> reg add HKLM\Software\Policies\Microsoft\Windows\EventLog\Security /v MaxSize /t REG_DWORD /d 0x64000

C:\> reg add HKLM\Software\Policies\Microsoft\Windows\EventLog\System /v MaxSize /t REG_DWORD /d 0x19000
```

__Check settings of security log:__

```
C:\> wevtutil gl Security
```

__Check settings of audit policies:__

```
C:\> auditpol /get /category:*
```

__Set Log Auditing on Success and/or Failure on All Categories:__

```
C:\> auditpol /set /category:* /success:enable /failure:enable
```

__Set Log Auditing on Success and/or Failure on Subcategories:__

```
C:\> auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"File System" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Logon" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Logoff" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Registry" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"SAM" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"File Share" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enables

C:\> auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Kerberos Authentication Success" /success:enable /failure:enable

C:\> auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

__Check for list of available logs, size, retention limit:__

```
PS C:\> Get-EventLOg -List
```

__Partial List of Key Security Log Auditing Events monitor:__

```
PS C:\> Get-EventLog -newest 5 -logname application | Format-List
```

__Show log from remote system:__

```
PS C:\> Show-EventLog -ComputerName <SERVER NAME>
```

__Get a specific list of events based on Event ID:__

```
PS C:\> Get-EventLog Security | ? { $_.EventId -eq 4800 }  

PS C:\> Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4774}
```

__Account Logon - Audit Credential Validation Last 14 Days:__

```
PS C:\> Get-EventLog Security 4768,4771,4772,4769,4770,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633 -After ((Get-Date).addDays(-14))
```

__Account - Logon/Logoff:__

```
PS C:\> Get-EventLog Security 4625,4634,4647,4624,4625,4648,4675,6272,6273,6724,6275,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801,4802,4803,5378,5632,5633,4964 -after ((Get-Date).addDays(-1))
```

__Account Management - Audit Application Group Management:__

```
PS C:\> Get-EventLog Security 4783,4784,4785,4786,4787,4788,4789,4790,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,4759,4760,4761,4782,4793,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758,4764,4720,4722,4723,4724,4725,4726,4738,4740,4765,4766,4767,4780,4781,4794,5376,5377 -After ((Get-Date.addDays(-1))
```

__Detailed Tracking - Audit DPAPI Activity, Process Termination, RPC Events:__

```
PS C:\> Get-EventLog Security 4692,4693,4694,4695,4689,5712 -After ((Get-Date).addDays(-1))
```

__Domain Service Access - Audit Directory Service Access:__

```
PS C:\> Get-EventLog Security 4662,5136,5137,5138,5139,5141 -After ((Get-Date).addDays(-1))
```

__Object Access - Audit File Share, File System, SAM, Registry, Certifications:__

```
PS C:\> Get-EventLog Security 4671,4691,4698,4699,4700,4701,4702,5148,5149,5888,5889,5890,4657,5039,4659,4660,4661,4663,4656,4658,4690,4874,4875,4880,4881,4882,4884,4885,4888,4890,4891,4892,4895,4896,5145,5140,5142,5143,5144,5168,4664,4985,5152,5153,5031,5140,5151,5154,5155,5156,5157,5158,5159 -After ((Get-Date).addDays(-1))
```

__Policy Change - Audit Policy Change, Microsoft Protection Service, Windows Filtering Platform:__

```
PS C:\> Get-EventLog Security 4715,4719,4817,4902,4904,4905,4906,4907,4908,4912,4713,4716,4717,4718,4739,4864,4865,4866,4867,4704,4705,4706,4707,4714,4944,4945,4946,4947,4948,4949,4950,4951,4952,4953,4954,4956,4957,4958,5046,5047,5048,5449,5450,4670 -After ((Get-Date).addDays(-1))
```

__Privilege Use - Audit Non-Sensitive/Sensitive Privilege Use:__

```
PS C:\> Get-EventLog Security 4672,4673,4674 -After ((Get-Date).addDays(-1))
```

__System - Audit Security State Change, Security System Extension, System Integrity, System Events:__

```
PS C:\> Get-EventLog Security 5024,5025,5027,5028,5029,5030,5033,5034,5035,5037,5058,5058,6400,6401,6402,6403,6404,6405,6406,6407,4608,4609,4616,4621,4610,4611,4622,4697,4612,4615,4618,4816,5038,5056,5057,5060,5061,5062,6281 -After ((Get-Date).addDays(-1))
```

__Add Microsoft IIS cmdlets:__

```
PS C:\> Add-PSSnapIn WebAdministration

PS C:\> Import-Modyke WebAdministration
```

__Get IIS Website Information:__

```
PS C:\> Get-IISSite
```

__Get IIS Log Path Location:__

```
PS C:\> (Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name 'logfile.directory').Value
```


__Set variable for IIS Log Path (default path):__

```
PS C:\> $LogDirPath = "C:\inetpub\logs\LogFiles\W3SVC1"
```

__Get IIS HTTP log file list from the last 7 days:__

```
PS C:\> Get-ChildItem -Path C:\inetput\logs\LogFiles\w3svc1 -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).addDays(-7) }
```

__View IIS Logs (Using $LogDirPath variable set above):__

```
PS C:\> Get-Content $LogDirPath\*.log |%{$_ -Replace '#Fields: ',''} |?{$_ -notmatch '^#'} | ConvertFrom-Csv -Delimiter ' '
```

__View IIS logs:__

```
PS C:\> Get-Content <IIS LOG FILE NAME>.log |%{$_ -Replace '#Fields: ',''} |?{$_ -notmatch '^#'} | ConvertFrom-Csv -Delimiter ' '
```

__Find in IIS logs IP address `192.168.*.*` pattern:__

```
PS C:\> Select-String -Path $LogDirPath\*.log -Pattern '192.168.*.*'
```

__Find in IIS logs common SQL injection patterns:__


```
PS C:\> Select-String -Path $LogDirPath\*.log -Pattern '(@@version)|(sqlmap)|(Connect\(\))|(cast\()|(char\()|(bchar\()|(sys databases)|(\(select)|(convert\()|(Connect\()|(count\()|(sys objects)'
```


#### Linux

__Authentication logs in Ubuntu:__

```
# tail /var/log/auth.log

# grep -i "fail" /var/log/auth.log
```

__User login logs in Ubuntu:__

```
# tail /var/
```

__Look at Samba activity:__

```
# grep -i "samba" /var/log/syslog
```

__Look at cron activity:__

```
# grep -i "cron" /var/log/syslog
```

__Look at sudo activity:__

```
# grep -i "sudo" /var/log/syslog
```

__Look in Apache logs for 404 errors:__

```
# grep 404 <LOG FILE NAME> | grep -v -E "favicon.ico|robots.txt"
```

__Look in Apache logs for files requested:__

```
# head access_log | awk '{print $7}'
```

__Monitor for new created files every 5 minutes:__

```
# watch -n 300 -d ls -lR /<WEB DIRECTORY>
```

__Look where traffic is coming from:__

```
# cat <LOG FILE NAME> | fgrep -v <YOUR DOMAIN> | cut -d\" -f4 | grep -v ^-
```

__Monitor for TCP connections every 5 seconds:__

```
# netstat -ac 4 | grep tcp
```

__Install audit framework and review syscalls/events:__

```
# apt-get install auditd

# auditctl -a exit,always -S execve

# ausearch -m execve
```

__Get audit report summary:__

```
# aureport
```


--------------------

## __4. Respond (Analysis)__

### Live Triage - Windows

#### System Information

```
C:\> echo %DATE% %TIME%

C:\> hostname

C:\> systeminfo

C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

C:\> wmic csproduct get name

C:\> wmic bios get serialnumber

C:\> wmic computersystem list brief
```

Reference: [https://technet.microsoft.com/en-us/sysinternals/psinfo.aspx](https://technet.microsoft.com/en-us/sysinternals/psinfo.aspx)

```
C:\> psinfo -accepteula -s -h -d
```

#### User Information

```
C:\> whoami

C:\> net users

C:\> net localgroup administrators

C:\> net group administrators

C:\> wmic rdtoggle list

C:\> wmic useraccount list

C:\> wmic group list

C:\> wmic netlogin get name,lastlogon,badpasswordcount

C:\> wmic netclient list brief

C:\> doskey /history > history.txt
```

#### Network Information

```
C:\> netstat -e

C:\> netstat -naob

C:\> netstat -nr

C:\> netstat -vb

C:\> netstat -S

C:\> route print

C:\> arp -a

C:\> ipconfig /displaydns

C:\> netsh winhttp show proxy

C:\> ipconfig /allcompartments /all

C:\> netsh wlan show interfaces

C:\> netsh wlan show all

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings"

C:\> type %SYSTEMROOT%\system32\drivers\etc\hosts

C:\> wmic nicconfig get descriptions,IPaddress,MACaddress

C:\> wmic netuse get name,username,connectiontype,localname
```


#### Service Information

```
C:\> at

C:\> tasklist

C:\> tasklist /svc

C:\> tasklist /svc /fi "imagename eq svchost.exe"

C:\> schtasks

C:\> net start

C:\> sc query

C:\> wmic service list brief | findstr "Running"

C:\> wmic service list config

C:\> wmic process list brief

C:\> wmic process list status

C:\> wmic process list memory

C:\> wmic job list breif 

PS C:\> Get-Service | Where-Object { $_.Status -eq "running" }
```

__List of all processes and then all loaded modules:__


```
PS C:\> Get-Process | Select modules|ForEach-Object{$_.modules}
```


#### Policy, Patch and Settings Information


```
C:\> set

C:\> gpresult /r

C:\> gpresult /z > <OUTPUT FILE NAME>.txt

C:\> gpresult /H report.html /F

C:\> wmic qfe
```

__List GPO software installed:__

```
C:\> reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\AppMgmt"
```

#### Autorun and Autoload Information

__Startup information:__

```
C:\> wmic startup list full

C:\> wmic ntdomain list brief
```

__View directory contents of startup folder:__

```
C:\> dir "%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%SystemDrive%\Documents and Settings\All Users\Start Menu\Programs\Startup"

C:\> dir "%userprofile%\Start Menu\Programs\Startup"

C:\> dir "%ProgramFiles%\Startup"

C:\> dir "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"

C:\> dir "%ALLUSERSPROFILE%\Start Menu\Programs\Startup"

C:\> type C:\Windows\winstart.bat

C:\> type %windir%\wininit.ini

C:\> type %windir%\win.ini
```

__View autoruns, hide Microsoft files:__


Reference:  [https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx](https://technet.microsoft.com/en-us/sysinternals/bb963902.aspx)

```
C:\> autorunsc -accepteula -m

C:\> type C:\Autoexec.bat
```

__Show all autorun files, export to CSV and check with VirusTotal:__

```
C:\> autorunsc.exe -accepteula -a -c -i -e -f -l -m -v
```

__`HKEY_CLASSES_ROOT`__:

```
C:\> reg query HKCR\Comfile\Shell\Open\Command

C:\> reg query HKCR\Batfile\Shell\Open\Command

C:\> reg query HKCR\htafile\Shell\Open\Command

C:\> reg query HKCR\Exefile\Shell\Open\Command

C:\> reg query HKCR\Exefiles\Shell\Open\Command

C:\> reg query HKCR\piffile\shell\Open\Command
```

__`HKEY_CURRENT_USERS`:__

```
C:\> reg query "HKCU\Control Panel\Desktop"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Load"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows\Scripts"

C:\> reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /f run

C:\> reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /f load

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RecentDocs"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\LastVisitedMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\OpenSaveMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\LastVisitedPidlMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ComDlg32\OpenSavePidlMRU" /s

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunMRU"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Shell Folders"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\User Shell Folders"

C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit" /v LastKey

C:\> reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"

C:\> reg query "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
```

__`HKEY_LOCAL_MACHINE`:__

```
C:\> reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\User Shell Folders"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" 

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s 

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winlogon\Userinit"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\shellServiceObjectDelayLoad"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" /s

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f AppInit_DLLs

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f Shell

C:\> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f Userinit

C:\> reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts"

C:\> reg query "HKLM\SOFTWARE\Classes\batfile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Classes\comfile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Classes\exefile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Classes\htafile\shell\open\Command"

C:\> reg query "HKLM\SOFTWARE\Classes\piffile\shell\open\command"

C:\> reg query "HKLM\SOFTWARE\Woww6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s

C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"

C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"

C:\> reg query "HKLM\SYSTEM\ControlSet001\Control\Session Manager\KnownDLLs"
```

#### Logs

__Copy Event Logs:__

```
C:\> wevtutil epl Security C:\<BACK UP PATH>\mylogs.evtx

C:\> wevtutil epl System C:\<BACK UP PATH>\mylogs.evtx

C:\> wevtutil epl Application C:\<BACK UP PATH>\mylogs.evtx
```

__Get list of logs remotely:__

Reference: [https://technet.microsoft.com/en-us/sysinternals/psloglist.aspx](https://technet.microsoft.com/en-us/sysinternals/psloglist.aspx)

```
C:\> psloglist \\<REMOTE COMPUTER> -accepteula -h 12 -x
```

__Clear all logs and start a baseline log to monitor:__

```
PS C:\> wevtutil el | Foreach-Object {wevtutil cl "$_"}
```

__List log filenames and path location:__

```
C:\> wmic nteventlog get path,filename,writeable
```

__Take pre-breach log export:__

```
PS C:\> wevtutil el | ForEach-Object { Get-EventLog -Log "$_" | Export-Csv -Path C:\<BASELINE LOG>.csv -Append}
```

__Take post-breach log export:__

```
PS C:\> wevtutil el | ForEach-Object { Get-EventLog -Log "$_" | Export-Csv -Path C:\<POST BASELINE LOG>.csv -Append}
```

__Compare two files baseline and post breach log:__

```
PS C:\> Compare-Object -ReferenceObject $(Get-Content "C:\<PATH TO FILE>\<ORIGINAL BASELINE LOGS>.txt") -DifferenceObject $(Get-Content "C:\<PATH TO FILE>\<POST BASELINE LOGS>.txt") >> <DIFFERENCES LOGS>.txt
```

__This deletes all logs:__

```
PS C:\> wevtutil el | ForEach-Object { wevtutil cl "$_" }
```

#### Files, Drives and Shares Information

```
C:\> net use \\<TARGET IP ADDRESS>

C:\> net share

C:\> net session

C:\> wmic volume list brief

C:\> wmic logicaldisk get description,filesystem,name,size

C:\> wmic share get name,path
```

__Find multiple file types or a file:__

```
C:\> dir /A /S /T:A *.exe *.dll *.bat *.ps1 *.zip

C:\> dir /A /S /T:A <BAD FILE NAME>.exe
```

__Find executable (.exe) files newer than Jan 1, 2017:__

```
C:\> forfiles /p C:\ /M *.exe /S /D +1/1/2017 /C "cmd /c echo @fdate @ftime @path"
```

__Find multiple file types using loops:__

```
C:\> for %G in (.exe, .dll, .bat, .ps) do forfiles -p "C:" -m *%G -s -d +1/1/2017 -c "cmd /c echo @fdate @ftime @path"
```

__Search for files newer than date:__

```
C:\> forfiles /P C:\  /S /D +1/01/2017 /C "cmd /c echo @path @fdate"
```

__Find large files: (example <20 MB)__

```
C:\> forfiles /S /M * /C "cmd /c if @fsize GEQ 2097152 echo @path @fsize"
```

__Find files with alternate data streams:__

Reference: [https://technet.microsoft.com/en-us/sysinternals/streams.aspx](https://technet.microsoft.com/en-us/sysinternals/streams.aspx)

```
C:\> sigcheck -c -h -s  -u -nobanner <FILE OR DIRECTORY> > <OUTPUT FILENAME>.csv
```

__Find and show only unsigned files with a bad signature in C:__

```
C:\> sigcheck -e  -u -vr -s C:\
```

__List loaded unsigned DLLs:__

Reference: [https://technet.microsoft.com/en-us/sysinternals/bb896656.aspx](https://technet.microsoft.com/en-us/sysinternals/bb896656.aspx)

```
C:\> listdlls.exe -u

C:\> listdlls.exe -u <PROCESS NAME OR PID>
```

__Run Malware scan (Windows Defender) offline:__

Reference: [https://windows.microsoft.com/en-us/windows/what-is-windows-defender-offline](https://windows.microsoft.com/en-us/windows/what-is-windows-defender-offline)

```
C:\> MpCmdRun.exe -SignatureUpdate

C:\> MpCmdRun.exe -Scan
```

### Live Triage - Linux

#### System Information


```
# uname -a

# uptime

# timedatectl

# mount
```

#### User Information

__View logged in users:__

```
# w
```

__Show if a user has ever logged in remotely:__

```
# lastlog

# last
```

__View failed logins:__

```
# faillog -a
```

__View local user accounts:__

```
# cat /etc/passwd

# cat /etc/shadow
```

__View local groups:__

```
# cat /etc/group
```

__View sudo access:__

```
# cat /etc/sudoers
```

__View accounts with UID 0:__

```
# awk -F: '($3 == "0") {print}' /etc/passwd

# egrep ':0+' /etc/passwd
```

__View root authorized SSH key authentications:__

```
# cat /root/.ssh/authorized_keys
```

__List of files opened by user:__

```
# lsof -u <USER NAME>
```

__View the root user bash history:__

```
# cat /root/.bash_history
```


#### Network Information

__View network interfaces:__

```
# ifconfig
```

__View network connections:__

```
# netstat -antup

# netstat -plantux
```

__View listening ports:__

```
# netstat -nap
```

__View routes:__

```
# route
```

__View arp table:__

```
# arp -a
```

__List of processes listening to ports:__

```
# lsof -i
```

#### Service Information


__View processes:__

```
# ps -aux
```

__List of loaded modules:__

```
# lsmod
```

__List of open files:__

```
# lsof
```

__List of open files, using the network__

```
# lsof -nPi | cut -f 1 -d " " | uniq | tail -n +2
```

__List of open files on specific process:__

```
# lsof -c <SERVICE NAME>
```

__Get all open files of a specific process ID:__

```
# lsof -p <PID>
```

__List of unlinked processes running:__

```
# lsof +L1
```

__Get path of suspicious process PID:__

```
# ls -al /proc/<PID>/exe
```

__Save fle for further malware binary analysis:__

```
# cp /proc/<PID>/exe > /<SUSPICIOUS FILE NAME TO SAVE>.elf
```

__Monitor logs in real-time:__

```
# less +F /var/log/messages
```

__List services:__

```
# chkconfig --list
```

#### Policy, Patch and Settings Information

__View pam.d files:__

```
# cat /etc/pam.d/common*
```

#### Autorun and Autoload Information:

__List cron jobs:__

```
# crontab -l
```

__List cron jobs by root and other UID 0 accounts:__

```
# crontab -u root -l
```

__Review for unusual cron jobs:__

```
# cat /etc/crontab

# ls /etc/cron.*
```

#### Logs

__View root user command history:__

```
# cat /root/.*history
```

__View last logins:__

```
# last
```



#### Files, Drives and Shares Information

__View disk space:__

```
# df -ah
```


__View directory listing for /etc/init.d/:__

```
# ls -la /etc/init.d
```

__Get more info for a file:__

```
# stat -x <FILENAME>
```

__Identify file type:__

```
# file <FILENAME>
```

__Look for immutable files:__

```
# lsattr -R / | grep "\-i-"
```

__View directory listing for /root:__

```
# ls -la /root
```

__Look for files recently modified in a current directory:__

```
# ls -alt | head
```

__Look for world writeable files:__

```
# find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
```

__Look for recently created files, in this case newer than Jan 02, 2017:__

```
# find / -newermt 2017-01-02q
```

__List all files and attributes:__

```
# find / -printf "%m;%Ax;%AT;Tx;%TT;%Cx;%CT;%U;%G;%s;%p\n"
```

__Look at files in directory by most recent timestamp (could be tampered):__

```
# ls -alt | head
```

__Check for rootkits or signs of compromise:__

__Run unix-privesc-check tool:__

```
# wget https://raw.githubusercontent.com/pentestmonkey/unix-privesc-check/1_x/unix-privesc-check

# ./unix-privesc-check > output.txt
```

__Run chkrootkit:__

```
# apt-get install chkrootkit

# chkrootkit
```


__Run rkhunter:__

```
# apt-get install rkhunter

# rkhunter --update

# rkhunter --check
```

__Run tiger:__

```
# apt-get install tiger

# tiger

# less /var/log/tiger/security.report.*
```

__Run lynis:__

```
# apt-get install lynis

# lynis audit system

# less /var/logs/lynis.log
```

__Run Linux Malware Detect (LMD):__

```
# wget http://www.rfxn.com/downloads/maldetect-current.tar.gz

# tar xfz maldetect-current.tar.gz

# cd maldetect-*

# ./install.sh
```

__Get LMD updates:__

```
# maldet -u
```

__Run LMD scan on directory:__

```
# maldet -a /<DIRECTORY>
```

