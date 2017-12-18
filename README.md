# WEFFLES

WEFFLES is a way to build a fast, free, and effective threat hunting console using Windows Event Forwarding and PowerBI. 

Jessica Payne (https://twitter.com/jepaynemsft) originally wrote full blog post on it at https://aka.ms/weffles. 

## Purpose
This lab has been designed with defenders in mind. Its primary purpose is to allow the user to quickly build a Windows Event Collector server that comes pre-loaded with security logging configurations.

## Primary Features:
* Windows Event Collector service started and set to 'auto'
* Windows event subscriptions created for standard logging of security-related EventIDs
* Reg keys created inside GPO to configure client computers to push subscription-related events to Windows event collector
* Sysmon is installed and configured using mdavis332's open-sourced configuration, forked from ion-storm which is heavily built upon SwiftOnSecurity's

## Planned Updates
* Integrate Graylog setup/config/alerting

## Requirements
* Server 2012R2 or higher joined to domain
* User running script must do so in an elevated PowerShell session using domain creds which allow for creating/editing GPOs
## Quickstart
1. Run wefsetup.ps1 on the server you want to act as your central Windows Collector and it will turn on necessary services and import subscriptions.

## Installed Tools
  * Sysmon

## Contributing
Contributions, fixes, and improvements can be submitted directly against this project as a GitHub issue or pull request.

## License
MIT License

Copyright (c) 2017

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

# Acknowledgements
* [Graylog](https://www.graylog.org)
* [jepayneMSFT/WEFFLES](https://github.com/jepayneMSFT/WEFFLES)
* [Monitoring what matters — Windows Event Forwarding for everyone](https://blogs.technet.microsoft.com/jepayne/2015/11/23/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem/)
* [Windows Event Forwarding for Network Defense](https://medium.com/@palantir/windows-event-forwarding-for-network-defense-cb208d5ff86f)
* [palantir/windows-event-forwarding](http://github.com/palantir/windows-event-forwarding)
* [clong/DetectionLab](https://github.com/clong/DetectionLab)
* [ion-storm/sysmon-config](https://github.com/ion-storm/sysmon-config)
* [SwiftOnSecurity - Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)