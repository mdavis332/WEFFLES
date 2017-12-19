<#  Setup script for Creating an IR/Threat Hunting Console with Windows Event Forwaring and PowerBI full documentation at https://aka.ms/weffles

Should be run from an Admin PowerShell session with a domain account with permissions to add/edit GPOs, 
on the server you wish to act as the Windows Event Log Collector.
This script will create a GPO called 'COMP.WefPolicy' which should be manually linked to OU containing any computers that you want to push subscribed events to the collector.

#>

# FQDN of Server to act as Windows Event collector
#$ServerName = $env:COMPUTERNAME

<#

WEFFLES is currently hard coded to a directory, this is because of the need to have it be a fast and failproof solution for IR situations.
You can change the directory by chasing all the variables, and in the future there may be a version that allows more flexibility.
But I errored on the side of "make sure it works, as often as possible" since often times IR situations lead you to tired people and tired infrastructure.

#>
mkdir c:\weffles
Copy-Item *.* c:\weffles

#Setting WinRM Service to automatic start and running quickconfig
Set-Service -Name winrm -StartupType Automatic
winrm quickconfig -quiet

<#

Set the size of the forwarded events log to 1GB, as we'll be saving them off to .csv
you can set this bigger if you want, but remember the main performance bottleneck of WEF is the log size - you need enough memory to hold the log +5GB or so for normal OS functions
so if had a reason to make this 10GB of log, you'll need to add 10GB RAM to the base amount in your VM

#>
wevtutil sl forwardedevents /ms:1000000000


#Running quickconfig for subscription service
wecutil qc -quiet


#If you need to export any existing subscriptions, or want to export a subscription made via the gui to get SDDLs of domains
#wecutil gs "%subscriptionname%" /f:xml >>"C:\Temp\%subscriptionname%.xml"

<#

This is where we actually import the Windows Event Collector subscriptions, i.e. the events we're going to collect. WEFFLES intentionally is NOT gathering "all the things"
and instead we want to get targeted "known bad" or "possibly shady" events. The core events file looks for these item :
7045 : new service creations to look for persistence
200 and 106 : scheduled task operations, also for persistence and execution
4720: creation of local accounts, sometimes done as a malware free backdoor
1102: clearing the security event log (anywhere you see that is a machine that should automatically get deeper forensic analysis)

The "InterestingAccounts.xml subscription is one I use to specifically track either high value accounts, or known compromised accounts.
You can get laser focus on the activities you need to see, versus combing through millions of logon events to start with.

It's also incredibly useful for solving that question of "what DOES that legacy account in Domain Admins that we're afraid to remove do?" as you get logs from both
domain controllers and workstations as well as the process and logon type - and you also get 4625 logon failed events, so you can rapidly find if something does break.

#>

#Set the Windows Event Collector Service to start type automatic, it's automatic with delayed start by default, which is fine as that lets the dependencies churn in.
#it is also annoying though, as sometimes you spend a good 5+ minutes thinking WEFFLES isn't working. Be patient. :)
Set-Service -Name Wecsvc -StartupType "Automatic"
#WEC service must be running before wecutil can import subs below
net start wecsvc

#Import the core subscriptions, if you edited the "Interesting Accounts" example, uncomment that, and if you have Defender as your AV, uncomment the MalwareEvents
#If your env uses DameWare, uncomment that line for dameware login events on remote PCs
wecutil cs "Subs\InterestingAccounts.xml"
wecutil cs "Subs\AccountLockouts.xml"
wecutil cs "Subs\MalwareEvents.xml"
wecutil cs "Subs\coreevents.xml"
wecutil cs "Subs\AdminLogons.xml"
wecutil cs "Subs\DamewareEvents.xml"
wecutil cs "Subs\RDPSessions.xml"
wecutil cs "Subs\RemoteSysmon.xml"

#Creating Task Scheduler Item to restart parsing script on reboot of system.
#schtasks.exe /create /tn "WEF Parsing Task" /xml WEFFLESParsingTask.xml

# Configure a GPO with client policy to forward subscription events to the central WE Collector
$NewGPo = New-GPO -Name COMP.WefPolicy -Comment 'This is an auto-generated GPO to configure Windows Event Forwarding'
#   1. Create WinRM service and set it to start auto
# Splat parameters to pass to Set-GPPrefRegistryValue cmdlet
$parmsForSet = @{
    Guid      = "$($NewGpo.Id.toString())"
    Context   = 'Computer'
    Action    = 'Update'
    Key       = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service'
    ValueName = 'AllowAutoConfig'
    Value     = 00000001
    Type      = 'DWord'
}
# Now add the reg key to set client WinRM Service
Set-GPPrefRegistryValue @parmsForSet
# Splat parameters to pass to Set-GPPrefRegistryValue cmdlet
$parmsForSet.ValueName = 'IPv4Filter'
$parmsForSet.Value = '*'
$parmsForSet.Type = 'String'

#   2. Allow remote server mgmt through WinRM
# Now add the reg key to set client WinRM Service ipv4 filter
Set-GPPrefRegistryValue @parmsForSet
# Splat parameters to pass to Set-GPPrefRegistryValue cmdlet
$parmsForSet.ValueName = 'IPv6Filter'
# Now add the reg key to set client WinRM Service ipv6 filter
Set-GPPrefRegistryValue @parmsForSet

#   3. Provide event log reader access

#   4. Add WEF Server sub address
# Splat parameters to pass to Set-GPPrefRegistryValue cmdlet
$parmsForSet = @{
    Guid      = "$($NewGpo.Id.toString())"
    Context   = 'Computer'
    Action    = 'Update'
    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    ValueName = '1'
    Value     = "Server=http://${env:COMPUTERNAME}.${env:USERDNSDOMAIN}:5985/wsman/SubscriptionManager/WEC"
    Type      = 'String'
}
# Now add the reg key to set the collection server
Set-GPPrefRegistryValue @parmsForSet


<#

You need to reboot now, uncomment if you want to do it automatically. After reboot let the machine cook for five minutes, and then you should see a weffles.csv in the c:\weffles
directory, and then you can use the weffles.pbix PowerBI desktop to analyze it - make sure the pbix and the csv are in a directory c:\weffles on your machine and open the .pbx and then hit refresh.

 #>
#Restart-Computer
