# SPFarmInfo

SPFarmInfo is a PowerShell data-collection and diagnostics script for SharePoint Server 2013 and later, including SharePoint Server Subscription Edition. It gathers high-level farm configuration and reports known configuration and health findings. It is read-only and does not make changes to the SharePoint farm.

The report includes information such as the farm build and configuration database, servers, web applications and alternate access mappings, service applications, timer jobs, authentication, search, and other farm configuration. Optional switches can collect additional performance, distributed cache, TLS, and usage and reporting details.

By default, the script creates a self-contained HTML report. The HTML report also embeds a structured JSON snapshot of the collected findings, which can be copied or downloaded from the report. JSON represents the data collected by the script; it is not a complete dump of every object in the farm. The `-Text` option creates a text report instead and does not include JSON.

Treat reports as sensitive: they can contain farm configuration and server or account details. Server-name masking, when enabled, is applied to the JSON as well as the visible report.

# Usage
1. Download [Get-SPFarmInfo.ps1](./Get-SPFarmInfo.ps1) or the [latest release](https://github.com/acasilla/SPFarmInfo/releases/latest).
2. On a SharePoint farm server, open the 64-bit SharePoint Management Shell and navigate to the folder containing the script.
3. Run it with an account that has the required SharePoint permissions (farm administrator and an elevated shell are recommended):

```powershell
.\Get-SPFarmInfo.ps1
```

Use `.\Get-SPFarmInfo.ps1 -Help` for the available options. Common switches include `-Performance`, `-DistributedCache`, `-TLS`, and `-Text`. `-UsageAndReporting` requires a `-SiteUrl`, for example:

```powershell
.\Get-SPFarmInfo.ps1 -UsageAndReporting -SiteUrl "https://sharepoint.example.com"
```

# Releases
## SPSE | SP 2019 | SP 2016
For the latest release, go to: [https://github.com/acasilla/SPFarmInfo/releases/latest](https://github.com/acasilla/SPFarmInfo/releases/latest)

