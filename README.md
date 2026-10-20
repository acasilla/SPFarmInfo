# SPFarmInfo

SPFarmInfo is a PowerShell data-collection and diagnostics script for SharePoint Server 2013 and later, including SharePoint Server Subscription Edition. It gathers high-level farm configuration and reports known configuration and health findings. It is read-only and does not make changes to the SharePoint farm.

## Synopsis
`Get-SPFarmInfo.ps1` creates a point-in-time diagnostics report of a SharePoint farm so administrators can review configuration, health, and operational signals in one place. The default output is an HTML report, and the same collected dataset is embedded as JSON for export.

## What the script collects
1. Farm identity and topology: farm build, configuration database details, farm servers, and key service instance status.
2. Web and service architecture: web applications, Alternate Access Mappings, authentication and trust settings, service applications, proxies, and proxy groups.
3. Operations and health data: timer/admin service information, timer job history context, health analyzer findings, diagnostics and usage-service settings.
4. Search and content services: search service applications, content sources, topology/components, and related configuration checks.
5. Platform and integration settings: databases, certificates/settings, STS and WOPI-related data, plus optional collectors for performance, distributed cache, TLS readiness, and usage/reporting.

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
