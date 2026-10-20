<#
.SYNOPSIS
    Collects high level farm information and reports known configuration issues for SharePoint 2013+
.DESCRIPTION
    Collects information including but not limited to:
        + Farm build and configuration database location and name
        + Web application urls and alternate access mappings
        + Service applications
        + Authentication methods and configurations
        + Only collects data, makes no changes
.EXAMPLE
    PS C:\> Get-SPFarmInfo.PS1 -Performance
    This executes the Get-SPFArmInfo standard data collection process and performs additional "Performance" data collection
.INPUTS
    None at this time
.OUTPUTS
    A self-contained HTML report documenting findings, with embedded JSON in the
    script element spfarminfo-data (type application/json). Copy JSON and Download
    JSON export that same data without requiring a server or companion file.
    Copy JSON uses the asynchronous browser clipboard API; when clipboard access
    is unavailable or denied, use Download JSON. Export controls do not parse the
    embedded JSON again or insert it into a hidden text box.
    Schema 1.6 contains report metadata, summary counts, and a flat findings array
    with stable traversal IDs, parent IDs, plain-text descriptions, and records.
    Get-SPFarm captures selected public scalar settings once as property-name/value
    pairs under its properties object, from the farm
    already used for collection. Connection strings, account/contact details,
    Properties, UpgradedPersistedProperties, and object graphs are excluded.
    Its exportNotes records selected members unavailable on the installed version.
    SPColumnDefinition, SPJobHistory, and AnalysisTaskInfo objects are exported as
    { objectType, properties } using public scalar members and scalar collections.
    Member names/types are discovered at runtime for version compatibility.
    Complex members on these targeted types are not read and are listed in
    exportNotes. This avoids traversing farm/service back-references.
    Command-labeled sections also expose collected web applications, service
    applications/proxies/groups, selected timer jobs, diagnostic settings,
    and STS settings without rerunning commands.
    Records retain scope, runtime type, source finding IDs, and export notes.
    All command-labeled sections are consecutive after summary and findings.
    Additional sections cover servers, databases, search applications/content
    sources/topologies/components, usage service/definitions, distributed cache
    client settings, trust issuers/authorities, certificates/settings, and WOPI.
    Cache client settings are scoped by farm/container type, matching the query;
    Host is only an optional observation from the existing display collector.
    Failed Distributed Cache statistics queries are reported as warnings without
    preventing collection of remaining caches. Partial memory sums are labeled;
    a complete memory total is unavailable when any cache statistics are missing.
    Optional collectors retain their existing version, permission, and option gates.
    Certificate exports contain public metadata only, never key material.
    Collection status and coverage distinguish unavailable/uncollected data from
    a complete inventory. Service application inventory reuses farm enumeration;
    timer job coverage is limited to jobs inspected by existing collectors.
    Minute/hourly/daily/weekly/monthly schedules export public scalar members.
    exportNotes identifies nested objects represented as text or depth-limited,
    and unreadable properties exported as null with a warning.
    The JSON is a snapshot of collected findings, not a complete farm object dump;
    existing presentation-grouped values remain grouped. Record strings preserve
    literal content, with styling sentinels removed and line-break sentinels
    converted to newlines. Server-name masking is
    applied to the JSON when UseEncodedServerId is enabled. Treat the embedded
    data as having the same sensitivity as the visible report.
    The -Text output remains unchanged and does not include JSON.
.NOTES
    General notes
    Version 4.x

DISCLAIMER
 This script is not supported under any Microsoft standard support program or service. 
 The script is provided AS IS without warranty of any kind. Microsoft further disclaims 
 all implied warranties including, without limitation, any implied warranties of merchantability 
 or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
 the script and documentation remains with you. In no event shall Microsoft, its authors, 
 or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
 damages whatsoever (including, without limitation, damages for loss of business profits, business 
 interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
 inability to use the scripts or documentation, even if Microsoft has been advised of the 
 possibility of such damages     
#>

param(
    [Parameter(Position=10,HelpMessage="Displays the help associated with the SPFarmInfo script")]
    [switch]$Help,

    <# task:546 removing PatchInfo

    [Parameter(Position=20,HelpMessage="Queries MSI and Update Session for Patch Information related to SharePoint")]
    [switch]$PatchInfo,
    #>

    [Parameter(Position=30,HelpMessage="Performs Data Collection to assist in troubleshooting Usage Analysis and Reporting Issues. Requires -SiteUrl parameter")]
    [switch]$UsageAndReporting,

    [Parameter(Position=40,HelpMessage="SiteUrl parameter, required for UsageAndReporting check")]
    [string]$SiteUrl,

    # Task 544: Change search to an opt-in experience, search findings will no longer be collected by default
    # Task 589: Change search back to default collection

    #[Parameter(Position=50,HelpMessage="Skips the Search Check altogether")]
    #[switch]$SkipSearchCheck,
    
    #[Parameter(Position=60,HelpMessage="Skips the indepth Search Health Check")]
    #[switch]$SkipSearchHealthCheck,

    #[Parameter(Position=50,HelpMessage="Collects information and performs checks related to search")]
    #[switch]$Search,

    [Parameter(Position=70,HelpMessage="Performs checks on whether configurations necessary for TLS1.2 and ciphers necessary for connecting to Azure Front Door (M365) are done")]
    [switch]$TLS,

    [Parameter(Position=80,HelpMessage="Saves Output to TEXT format instead of HTML")]
    [switch]$Text,

    [Parameter(Position=90,HelpMessage="Performs additional Performance related checks and report server resources. Some items which may have been with the default SPFarmInfo Script run have been moved here.")]
    [switch]$Performance,

    [Parameter(Position=100,HelpMessage="Collects configuration and status information regarding distributed cache")]
    [switch]$DistributedCache,

    #Task 602: Removing ExtendedFindings switch
    #[Parameter(Position=108,HelpMessage="Includes addition detailed findings about the environment that are not included by default")]
    #[switch]$ExtendedFindings,

    #[Parameter(Position=109,HelpMessage="Some findings are only included in the report output if there is an issue found, use this switch to include information regarding to these findings regardless of whether an issue was detected or not.")]
    #[switch]$ShowHiddenFindings,

    [Parameter(Position=110,HelpMessage="Skips appending the SPFarmInfo output with errors collection")]
    [switch]$SkipErrorCollection,

    [Parameter(Position=120,HelpMessage="Skips the initial disclaimer")]
    [switch]$SkipDisclaimer,

    [Parameter(Position=130,HelpMessage="Skips the interactive menu allowing you to specify which checks to perform")]
    [switch]$SkipParameterMenu
)

if([System.IntPtr]::Size -lt 8)
{
    Write-Error "Get-SPFarmInfo Is not supported on x86 Powershell/Powershell ISE instances"
    exit
}

$ScriptVersion="4.1.2608.1600"
$script:PreviousFindingTime= Get-Date

# Retrieve parameters information
$script:parameters = $MyInvocation.MyCommand.Parameters 

$script:hiddenParams = @(
    "Verbose",
    "Debug",
    "SkipDisclaimer", #if using UI to select options this should be displayed
    "SkipErrorCollection",
    "Help",
    "SkipParameterMenu",
    "Text"
)

#region CoreFramework

## c# is used to define a core class for a finding to provide a centralized an manged framework
## the use of inline c# was decided to remove the dependency on PowerShell v.5 which is necessary for PowerShell classes
## Be very careful if making changes in this area as all individual checks call into this
$cs = @"
using System;
using System.Collections.Generic;
using System.Collections;

namespace SPDiagnostics
{
    public enum Severity
    {
        Default         = 0,
        Informational   = 1,
        Warning         = 2,
        Critical        = 4
    }

    public enum Format
    {
        Table           = 1,
        List            = 2
    }

    public enum OutputFormat
    {
        HTML = 0,
        TEXT = 1
    }
    public class Finding
    {
        public Severity Severity
        {
            get
            {
                return _severity;
            }
            set
            {
                if(value > _severity)
                {
                    _severity = value;
                }
            } 
        }
        private Severity _severity;
        public string Name;
        public List<string> Description;
        public List<string> WarningMessage;
        public List<Uri> ReferenceLink;
        public object InputObject;
        public List<object> CommandSnapshots = new List<object>();
        public bool Expand;
        public Format Format;
        public FindingCollection<Finding> ChildFindings;
    }

    public partial class FindingCollection<Finding> : List<Finding>
    {
        public new void Add(Finding item)
        {
            if(null != item)
            {
                base.Add(item);
            }
        }
    }
}
"@
$loadedFindingType = 'SPDiagnostics.Finding' -as [type]
if($null -eq $loadedFindingType)
{
    Add-Type -TypeDefinition $cs -Language CSharp
}
elseif($null -eq $loadedFindingType.GetField('CommandSnapshots'))
{
    throw 'An older SPFarmInfo diagnostic framework is already loaded. Open a fresh SharePoint PowerShell session and rerun this updated script.'
}


#cmdlet used to create new SPDiagnostics.Finding objects for eas of consumption
#use this method to create diagnostic findings that will be included in the report
function New-DiagnosticFinding
{
    <#
    .SYNOPSIS
    Creates a diagnostic finding to be used in creating html based report.
    
    .DESCRIPTION
    Use this function to generate findings....
    
    .PARAMETER Name
    The name of the finding that will be displayed in the report
    
    .PARAMETER Description
    Description that will be displayed under the name in the report, you can include html formatting here
    
    .PARAMETER Category
    The broad category that the finding falls into
    
    .PARAMETER Severity
    The severity of the finding, warning or critical findings will be promoted to the top of the report and formatted to call attention to it
    
    .PARAMETER WarningMessage
    Provides warning text in RED encapsulated in exclamations !!! Warning !!!
    
    .PARAMETER ReferenceLink
    Url link to a useful public resource describing the issue or how to resolve
    
    .PARAMETER InputObject
    The object or collection of objects representing the table or list object in the finding. This can be null to create a "shell" finding.
    
    .PARAMETER Expand
    Determines whether or not the finding will be expanded by default. 
    It is recommended to not utilize this as it quickly makes the report overwhelming.
    
    .PARAMETER Format
    Table or List to determine how the html table will be formatted. Generally individual objects should be formatted as a list.
    I.e. listing the properties of a single SPWeb object whereas Table would be used for collections of objects.
    
    .PARAMETER ChildFindings
    Other findings can be nested here to provide a hierarchy.
    
    .EXAMPLE
    $sts = Get-SPSecurityTokenServiceConfig
    $finding = New-DiagnosticFinding -Name "Security Token Service Config" -Description "Details of Get-SPSecurityTokenServiceConfig" -Category Authentication -Severity Default -InputObject $sts -Format Table
    
    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $Name,

        [Parameter()]
        [String[]]
        $Description,

        [Parameter()]
        [SPDiagnostics.Severity]
        $Severity = [SPDiagnostics.Severity]::Default,

        [Parameter()]
        [String[]]
        $WarningMessage,

        [Parameter()]
        [Uri]
        $ReferenceLink,

        [Parameter()]
        [Object]
        $InputObject,

        [Parameter()]
        [Switch]
        $Expand,

        [Parameter(Mandatory=$false)]
        [SPDiagnostics.Format]
        $Format,

        [Parameter()]
        [SPDiagnostics.FindingCollection[SPDiagnostics.Finding]]
        $ChildFindings
    )


    if($Severity -ge 2 -and [string]::IsNullOrEmpty($WarningMessage))
    {
        # As weird as it seems here, we don't want to exit execution so we'll throw so that we collect it in the script execution finding and can act on it
        try
        {
            throw (New-Object System.ArgumentException -ArgumentList @("Warning message cannot be empty for an error or warning finding"))
        }
        catch
        {
            Write-Warning "Warning message should not be empty for a warning or critical finding."
        }
    }


    #if no InputObject is specified default a value for format unless already specified
    if($null -eq $InputObject -and $null -eq $Format)
    {
        $Format = [SPDiagnostics.Format]::Table
    }
    
    #A format is required if there is an $InputObject which needs to be formatted
    if($null -eq $Format)
    {
        throw (New-Object System.ArgumentException -ArgumentList @("Format must be specified if an InputObject is present"))
    }

    $findingTime = (get-Date).ToString('yyyy-MM-dd HH:mm:ss.ffff')
    $findingDuration = [Math]::Round((((Get-Date) - $script:PreviousFindingTime).TotalMilliSeconds),0)
    $script:PreviousFindingTime = get-date

    $script:FindingTimes += [PSCustomObject]@{
        Entry = $script:FindingTimes.Count + 1
        Time = $findingTime
        Duration = $findingDuration
        Finding = $Name
    }

    #Write-Host ("{0} Generating finding -- {1}" -f $findingTime, $Name)
    Write-Host ("Generated finding -- {0}" -f $Name)

    $finding = New-Object SPDiagnostics.Finding
    $finding.Name = $Name
    $finding.Description = $Description
    $finding.Severity = $Severity
    $finding.WarningMessage = $WarningMessage
    $finding.ReferenceLink = $ReferenceLink
    $finding.InputObject = $InputObject
    $finding.Expand = [bool]$Expand
    $finding.Format = $Format
    if($null -eq $ChildFindings)
    {
        $finding.ChildFindings = New-Object SPDiagnostics.FindingCollection[SPDiagnostics.Finding]
    }
    else
    {
        $finding.ChildFindings = $ChildFindings
    }

    return $finding
}

# Creates a new FindingCollection for ease of use, TBD whether this is necessary or not
function New-DiagnosticFindingCollection
{
    [cmdletbinding()]
    Param()

    return New-Object SPDiagnostics.FindingCollection[SPDiagnostics.Finding]
}

function ConvertAndStripHTML($html)
{
    $string = $html.Replace("<br>","`r`n")
    $string = $string -replace '<[^>]+>',''
    return $string
}

# Internal method that should not be directly consumed outside of the core framework to generate the report
function Write-DiagnosticFindingFragment
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [SPDiagnostics.Finding]
        $Finding,
        [SPDiagnostics.OutputFormat]
        $OutputFormat=[SPDiagnostics.OutputFormat]::HTML,
        [switch]$ExcludeChildFindings
    )
    try
    {
        if($null -eq $Finding)
        {
            return
        }

        switch ($Finding.Severity)
        {
            Critical {$class = "error"}
            Warning {$class = "warning"}
            default {$class = [string]::Empty}
        }

        $expandStr = [string]::Empty
        if($Finding.Expand)
        {
            $expandStr = " open"
        }

        $preContent = $null

        Switch($OutputFormat)
        {
            'HTML'
            {
                $encodedFindingName = [uri]::EscapeDataString($Finding.Name)
                $preContent = "`r`n<details{0}>`r`n<summary id=`"{1}`" class=`"heading {2}`">{3}</summary>`r`n<div class=`"finding`">" -f $expandStr, $encodedFindingName, $class, $Finding.Name
            }
            'TEXT'
            {
                $preContent = "#########################################################################################`r`n"
                $preContent += "{0}`r`n" -f $Finding.Name
                $preContent += "#########################################################################################`r`n"
            }
        }

        
        foreach($desc in $finding.Description)
        {
            Switch($OutputFormat)
            {
                'HTML'
                {
                    $preContent+="`r`n<div class=`"description`">{0}</div>" -f $desc
                }
                'TEXT'
                {
                    # Strip the HTML content from descriptions
                    $description = ConvertAndStripHTML $desc
                    $preContent+= " {0}`r`n" -f $description
                }
            }
            
        }
        
        foreach($link in $Finding.ReferenceLink)
        {
            Switch($OutputFormat)
            {
                'HTML'
                {
                    $preContent+="`r`n<div>Reference: <a href=`"{0}`" target=`"_blank`">{0}</a></div><br/>" -f $link.AbsoluteUri
                }
                'TEXT'
                {
                    $preContent+= " {0}`r`n" -f $link.AbsoluteUri
                }
            }
        }

        foreach($warningMessage in $finding.WarningMessage)
        {
            Switch($OutputFormat)
            {
                'HTML'
                {
                    $preContent+="`r`n<div class=`"warning-message`"> {0} </div>" -f $warningMessage
                }
                'TEXT'
                {
                    # Strip the HTML content from Warning Messages
                    $warning = ConvertAndStripHTML $warningMessage
                    $preContent+= "Warning: {0}`r`n`r`n" -f $warning
                }
            }
        }

        $postContent = $null

        Switch($OutputFormat)
        {
            'HTML'
            {
                $postContent = "`r`n</details>`r`n"
            }
            'TEXT'
            {
                $postContent = "`r`n" 
            }
        }
        
        $htmlFragment = $null
        
        if($null -ne $Finding.InputObject -and $OutputFormat -eq [SPDiagnostics.OutputFormat]::HTML)
        {

            #Account for objects that only have a single property, ConverTo-Html does not display the property name if there is only one
            if($Finding.InputObject.GetType().FullName -match "System.Collections.Generic.Dictionary``2" -or $finding.InputObject -is [System.Collections.Hashtable])
            {
                $Finding.InputObject = $Finding.InputObject.GetEnumerator() | Select-Object Key, Value
                $Finding.Format = "Table"
            }
            if($finding.InputObject -is [System.Array] -and $finding.InputObject.Count -gt 0)
            {
                $properties = Get-Member -InputObject $Finding.InputObject[0] -MemberType Properties -ErrorAction Stop
            }
            else 
            {
                $properties = Get-Member -InputObject $Finding.InputObject -MemberType Properties -ErrorAction Stop
            }            

            # Generate a unique guid and add DIV tag for getting element in order to copy to clipboard
            $CopyToClipBoardGuid = [System.Guid]::NewGuid()
            $preContent  += "`r`n<div id=`"{0}`" class=`"copyToClipboardDiv`">" -f $CopyToClipBoardGuid

            if($properties.Count -eq 1)
            {
                $property =  $properties[0]
                $propertyName = $property.Name
                $htmlFragment += $Finding.InputObject | ConvertTo-Html -Property $propertyName -PreContent $preContent -As $Finding.Format -Fragment
            }
            else
            {
                $htmlFragment += $Finding.InputObject | ConvertTo-Html -PreContent $preContent -As $Finding.Format -Fragment
            }

            # Configure buttons for copying to the clipboard
            $htmlButton = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAACXBIWXMAAA7EAAAOxAGVKw4bAAABeElEQVRIibWWsYrCQBCGv8h1voOdL2CplcZOuMJKfQILQTB9imusEhBsBPMSygmCCr6AhQ8gRKxSiqn3iiV3SS7GTdQfhuzO7O7P/LOTRBNCCN6MwrsJAD7SgoZhJPqHwyGlUkmdRaRgNBol+kzTFK7rpm2NIDWTJFiWlXVLulwBWuYCgO+vTyCHjFnlyiOj0u1qmYtfS0On08FxHM7nc8SvJFcgUxJ5OD6fzwGYTCaR2mWqSZwwPA4fGq/ZSzJ5tDbzFVYhz0wSTz0sy0syedR4qpkUAGxbWhy6Duu10jmpyF2Te13/MpKs7y+ljvd9KV1gg4GUUddlLIBtg+OA50G3m0BiGKBpUdvtZKxYhO0WajXo92E6hesVLhdYreQaz4PZDFwXbjc4HBJILAuEiFqjkZ5hpQL7vRwvl3KehKc+v+WyfB6PsNlAu/0GEoBeD8ZjaDbvr3mapFqV9ajX/8dMU5omhPovke/LS3BvHvadTn++TCR58QMjoESxLJb7twAAAABJRU5ErkJggg=="
            $textButton = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAAACXBIWXMAAA7EAAAOxAGVKw4bAAABXUlEQVRIibWWMaoCMRRFz3x+Z2chVpZuxFL4nTCuQVDUyiaF2FoIls4GnE6wsHQJLkBBsRrQzvr9IqgzEmOizoWQ8DIvl3uTvEwgIkLO+MmbAODXNtnv943xTqdDpVJxZxELer2eMaaUkv1+b0vNwKrEhPF47Jtit+uKuloAsBz+AW/Y6GvXOzY6na66WtyaDWEYEkURh8MhE3ey62qTiTw9P5vNAJhMJpm989qTR8L0OL3o4559Rcmrb72PsAu5N8mj9LQtX1Hy6uK5Krkd4SSBIDC3OHZa6yluSkoluBb9OIb1GqbT54nPbr2VxAe+9cv5PWk2YbfT4yjSamu1e7NaaqpN87lIq2WObTYiYXiPV6si262tAjrWLoBGQ/fdLgwGrlkaXs9vsQjHI5TLOZGsVnA+w2gEw2EOJEkC7TYopW07nTSpKwIRt1+iJNF3CeBy0X2hkI1/TPIJ/gHPkoS9HAjyhAAAAABJRU5ErkJggg=="
            #$htmlFragment += "&nbsp;&nbsp;<input type=`"button`" Title=`"Copy table to clipboard as HTML`" value=`"HTML`" onclick=`"copyToClipboardHtml(document.getElementById('{0}'))`"/>&nbsp;<input type=`"button`" Title=`"Copy table to clipboard as text`"value=`"Text`" onclick=`"copyToClipboardText(document.getElementById('{0}'))`"/></div>" -f $CopyToClipBoardGuid
            $htmlFragment += "&nbsp;&nbsp;<input type=`"image`" Title=`"Copy table to clipboard as HTML`" src=`"$htmlButton`" onclick=`"copyToClipboardHtml(document.getElementById('{0}'))`"/>&nbsp;<input type=`"image`" Title=`"Copy table to clipboard as text`" src=`"$textButton`" onclick=`"copyToClipboardText(document.getElementById('{0}'))`"/></div>" -f $CopyToClipBoardGuid
        }
        elseif($null -ne $Finding.InputObject -and $OutputFormat -eq [SPDiagnostics.OutputFormat]::TEXT)
        {
            if($Finding.Format -eq 'List')
            {
                $htmlFragment = $preContent + ($finding.InputObject | Format-List * | Out-String)
            }
            else {
                $htmlFragment = $preContent + ($finding.InputObject | Format-Table * | Out-String)
            }

        }
        else
        {
            $htmlFragment = $preContent
        }

        if(!$ExcludeChildFindings)
        {
            foreach($child in $Finding.ChildFindings)
            {
                $childContent = Write-DiagnosticFindingFragment -Finding $child -OutputFormat $OutputFormat
                $htmlFragment+=$childContent
            }
        }

        $htmlFragment+=$postContent

        if($OutputFormat -eq [SPDiagnostics.OutputFormat]::HTML)
        {
            return ($htmlFragment -join "`r`n")
        }
        return $htmlFragment
    }
    catch
    {
        Write-Error $_
        return $null
    }
}

function ConvertTo-DiagnosticDataText
{
    param(
        [AllowEmptyString()][string]$Value,
        [switch]$Html
    )

    $valueText = $Value.Replace('~~~BR~~~', "`n")
    $valueText = $valueText -replace '~~~(?:POLICYSTART|POLICYEND|SETSTART|SETEND|PILLGOOD|PILLBAD|PILLWARN|PILLEND)~~~', ''
    if($Html)
    {
        $valueText = $valueText -replace '(?i)<br\s*/?>', "`n"
        $valueText = $valueText -replace '<[^>]+>', ''
        $valueText = [System.Net.WebUtility]::HtmlDecode($valueText)
    }
    if($UseEncodedServerId)
    {
        foreach($server in $script:servers)
        {
            foreach($serverName in @($server.Address, $server.Name))
            {
                if(![string]::IsNullOrEmpty($serverName))
                {
                    $valueText = [regex]::Replace($valueText, [regex]::Escape($serverName),
                        [System.Text.RegularExpressions.MatchEvaluator]{ param($match) [string]$server.EncodedServerId },
                        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                }
            }
        }
    }
    return $valueText
}

function ConvertTo-DiagnosticDataValue
{
    param(
        [AllowNull()][object]$Value,
        [System.Collections.Generic.List[string]]$Notes,
        [string]$Path = 'records',
        [int]$Depth = 0,
        [string[]]$PropertyNames
    )

    if($null -eq $Value) { return $null }
    if($Value -is [string] -or $Value -is [char])
    {
        return ConvertTo-DiagnosticDataText -Value ([string]$Value)
    }
    if($Value -is [System.Enum]) { return $Value.ToString() }
    if($Value -is [bool] -or $Value -is [byte] -or $Value -is [sbyte] -or
       $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or
       $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64] -or
       $Value -is [single] -or $Value -is [double] -or $Value -is [decimal])
    {
        return $Value
    }
    if($Value -is [datetime] -or $Value -is [datetimeoffset])
    {
        return $Value.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if($Value -is [guid] -or $Value -is [uri] -or $Value -is [version] -or $Value -is [timespan])
    {
        return ConvertTo-DiagnosticDataText -Value ($Value.ToString())
    }
    if($Value -is [type])
    {
        return ConvertTo-DiagnosticDataText -Value $Value.FullName
    }

    $targetedType = $Value.GetType().FullName -in @(
        'Microsoft.SharePoint.Administration.SPColumnDefinition',
        'Microsoft.SharePoint.Administration.SPJobHistory',
        'Microsoft.Ceres.AnalysisEngine.Shared.Services.AnalysisTaskInfo',
        'Microsoft.SharePoint.SPMinuteSchedule',
        'Microsoft.SharePoint.SPHourlySchedule',
        'Microsoft.SharePoint.SPDailySchedule',
        'Microsoft.SharePoint.SPWeeklySchedule',
        'Microsoft.SharePoint.SPMonthlySchedule',
        'Microsoft.Office.Server.Search.Administration.DailySchedule',
        'Microsoft.Office.Server.Search.Administration.WeeklySchedule',
        'Microsoft.Office.Server.Search.Administration.MonthlySchedule'
    )
    # Nested live objects are limited to selected diagnostic types, not farm object graphs.
    if($Depth -ge 6 -or ($Depth -gt 0 -and
       !$targetedType -and
       $Value -isnot [System.Collections.IDictionary] -and
       $Value -isnot [System.Collections.IEnumerable] -and
       $Value -isnot [System.Management.Automation.PSCustomObject]))
    {
        $Notes.Add(("{0}: {1} represented as text (nested object or depth limit)." -f $Path, $Value.GetType().FullName))
        return ConvertTo-DiagnosticDataText -Value ($Value.ToString()) -Html
    }
    if($Value -is [System.Collections.IDictionary])
    {
        $result = [ordered]@{}
        foreach($key in $Value.Keys)
        {
            $name = ConvertTo-DiagnosticDataText -Value ([string]$key)
            if($result.Contains($name)) { throw "Duplicate structured-data key at $Path : $name" }
            $result[$name] = ConvertTo-DiagnosticDataValue -Value $Value[$key] -Notes $Notes -Path "$Path.$name" -Depth ($Depth + 1)
        }
        return $result
    }
    if($Value -is [System.Collections.IEnumerable])
    {
        $items = New-Object 'System.Collections.Generic.List[object]'
        foreach($item in $Value)
        {
            $items.Add((ConvertTo-DiagnosticDataValue -Value $item -Notes $Notes -Path ("{0}[{1}]" -f $Path, $items.Count) -Depth ($Depth + 1)))
        }
        return ,($items.ToArray())
    }

    $properties = $Value.PSObject.Properties
    if($targetedType)
    {
        $Path = "$Path.properties"
        $properties = @(Get-DiagnosticDataTargetProperties -Value $Value -Notes $Notes -Path $Path)
    }
    elseif($null -ne $PropertyNames)
    {
        $properties = @(Get-DiagnosticDataTargetProperties -Value $Value -Notes $Notes -Path $Path -PropertyNames $PropertyNames)
    }
    $result = [ordered]@{}
    foreach($property in $properties)
    {
        $name = ConvertTo-DiagnosticDataText -Value $property.Name
        if($result.Contains($name)) { throw "Duplicate structured-data property at $Path : $name" }
        try
        {
            # PowerShell property access can suppress getter exceptions; invoke the getter explicitly.
            $propertyValue = $property.get_Value()
        }
        catch
        {
            $note = ConvertTo-DiagnosticDataText -Value ("Cannot read structured-data property {0}.{1}: {2}" -f $Path, $name, $_.Exception.Message)
            $Notes.Add($note)
            Write-Warning $note
            $result[$name] = $null
            continue
        }
        $result[$name] = ConvertTo-DiagnosticDataValue -Value $propertyValue -Notes $Notes -Path "$Path.$name" -Depth ($Depth + 1)
    }
    if($targetedType)
    {
        return [ordered]@{ objectType = $Value.GetType().FullName; properties = $result }
    }
    return $result
}

function Test-DiagnosticDataScalarType
{
    param([type]$Type)

    $underlyingType = [System.Nullable]::GetUnderlyingType($Type)
    if($null -ne $underlyingType) { $Type = $underlyingType }
    return ($Type.IsPrimitive -or $Type.IsEnum -or $Type -in @(
        [string], [decimal], [datetime], [datetimeoffset], [guid], [uri],
        [version], [timespan]
    ) -or [type].IsAssignableFrom($Type))
}

function Get-DiagnosticDataTargetProperties
{
    param(
        [object]$Value,
        [System.Collections.Generic.List[string]]$Notes,
        [string]$Path,
        [string[]]$PropertyNames
    )

    if($Value -is [System.Management.Automation.PSCustomObject] -and $null -ne $PropertyNames)
    {
        foreach($name in $PropertyNames)
        {
            $property = $Value.PSObject.Properties[$name]
            if($null -ne $property)
            {
                $property
            }
            else
            {
                $Notes.Add(("{0}.{1}: selected property is unavailable on this farm version." -f $Path, $name))
            }
        }
        return
    }

    $foundNames = @{}
    $flags = [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Instance
    foreach($member in $Value.GetType().GetMembers($flags))
    {
        if($member -isnot [System.Reflection.PropertyInfo] -and $member -isnot [System.Reflection.FieldInfo])
        {
            continue
        }
        if($null -ne $PropertyNames -and $PropertyNames -notcontains $member.Name)
        {
            continue
        }
        $foundNames[$member.Name] = $true
        if($member -is [System.Reflection.PropertyInfo])
        {
            if($null -eq $member.GetGetMethod() -or $member.GetIndexParameters().Length -gt 0)
            {
                $Notes.Add(("{0}.{1}: indexed or non-public getter omitted from targeted export." -f $Path, $member.Name))
                continue
            }
            $memberType = $member.PropertyType
        }
        elseif($member -is [System.Reflection.FieldInfo])
        {
            $memberType = $member.FieldType
        }
        $supported = Test-DiagnosticDataScalarType -Type $memberType
        if(!$supported -and $null -ne $PropertyNames -and
           $memberType.FullName -in @(
               'Microsoft.SharePoint.SPSchedule',
               'Microsoft.Office.Server.Search.Administration.Schedule',
               'Microsoft.Office.Server.Search.Administration.StartAddressCollection'
           ))
        {
            $supported = $true
        }
        if(!$supported -and $memberType.IsArray -and $memberType.GetArrayRank() -eq 1)
        {
            $supported = Test-DiagnosticDataScalarType -Type $memberType.GetElementType()
        }
        elseif(!$supported -and [System.Collections.IEnumerable].IsAssignableFrom($memberType))
        {
            foreach($interface in @($memberType) + @($memberType.GetInterfaces()))
            {
                if($interface.IsGenericType -and $interface.GetGenericTypeDefinition() -eq [System.Collections.Generic.IEnumerable``1])
                {
                    $supported = Test-DiagnosticDataScalarType -Type $interface.GetGenericArguments()[0]
                    break
                }
            }
        }
        if($supported)
        {
            $Value.PSObject.Properties[$member.Name]
        }
        else
        {
            $memberName = ConvertTo-DiagnosticDataText -Value $member.Name
            $Notes.Add(("{0}.{1}: {2} omitted from targeted export (non-scalar member)." -f $Path, $memberName, $memberType.FullName))
        }
    }
    foreach($name in $PropertyNames)
    {
        if(!$foundNames.ContainsKey($name))
        {
            $adaptedProperty = $Value.PSObject.Properties[$name]
            if($null -ne $adaptedProperty)
            {
                $adaptedProperty
            }
            else
            {
                $Notes.Add(("{0}.{1}: selected property is unavailable on this farm version." -f $Path, $name))
            }
        }
    }
}

function Get-DiagnosticFarmSettings
{
    param([object]$Farm)

    if($null -eq $Farm)
    {
        throw 'Cannot export farm settings: the farm object is not initialized.'
    }
    $propertyNames = @(
        'Id', 'Name', 'DisplayName', 'TypeName', 'BuildVersion', 'Version',
        'Status', 'EncodedFarmId', 'TraceSessionGuid', 'CanUpgrade', 'NeedsUpgrade',
        'IsBackwardsCompatible', 'ShouldDeferUpgradeActions', 'DeploymentLocked',
        'CEIPEnabled', 'DownloadErrorReportingUpdates', 'ErrorReportingAutomaticUpload',
        'ErrorReportingEnabled', 'DaysBeforePasswordExpirationToSendEmail',
        'PasswordChangeGuardTime', 'PasswordChangeMaximumTries', 'PersistedFileChunkSize',
        'EnableConfigureOrgIdNameIdIssuerMappingRule', 'EnablePreParseSecurityCheckForWorkflow',
        'IsPaired', 'OneDriveUserExperienceVersion', 'SiteCreationUserExperienceVersion',
        'SPListUserExperienceVersion', 'UseMinWidthForHtmlPicker', 'UserLicensingEnabled',
        'XsltTransformTimeOut'
    )
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $properties = ConvertTo-DiagnosticDataValue -Value $Farm -Notes $notes -Path 'Get-SPFarm.properties' -PropertyNames $propertyNames
    return [ordered]@{
        objectType = $Farm.GetType().FullName
        properties = $properties
        selection = 'allowlisted-scalar-settings'
        explicitlyExcludedMembers = @(
            'PairConnectionString', 'PasswordChangeEmailAddress', 'DefaultServiceAccount',
            'Properties', 'UpgradedPersistedProperties'
        )
        exportNotes = $notes.ToArray()
    }
}

function Add-DiagnosticDataFindings
{
    param(
        [SPDiagnostics.Finding[]]$Findings,
        [System.Collections.Generic.List[object]]$Items,
        [AllowNull()][string]$ParentId,
        [System.Collections.Generic.List[object]]$Snapshots
    )

    foreach($finding in $Findings)
    {
        if($null -eq $finding) { continue }
        $id = 'finding-{0:D6}' -f ($Items.Count + 1)
        foreach($snapshot in $finding.CommandSnapshots)
        {
            $Snapshots.Add([pscustomobject]@{ findingId = $id; snapshot = $snapshot })
        }
        $notes = New-Object 'System.Collections.Generic.List[string]'
        $records = New-Object 'System.Collections.Generic.List[object]'
        if($null -ne $finding.InputObject)
        {
            foreach($record in $finding.InputObject)
            {
                $records.Add((ConvertTo-DiagnosticDataValue -Value $record -Notes $notes -Path ("{0}.records[{1}]" -f $id, $records.Count)))
            }
        }
        $Items.Add([ordered]@{
            id = $id
            parentId = $(if([string]::IsNullOrEmpty($ParentId)) { $null } else { $ParentId })
            name = ConvertTo-DiagnosticDataText -Value $finding.Name -Html
            severity = $finding.Severity.ToString()
            descriptions = @($finding.Description | ForEach-Object { ConvertTo-DiagnosticDataText -Value $_ -Html })
            warnings = @($finding.WarningMessage | ForEach-Object { ConvertTo-DiagnosticDataText -Value $_ -Html })
            referenceLinks = @($finding.ReferenceLink | ForEach-Object { ConvertTo-DiagnosticDataText -Value $_.AbsoluteUri })
            format = $finding.Format.ToString()
            records = $records.ToArray()
            exportNotes = $notes.ToArray()
        })
        if($finding.ChildFindings.Count -gt 0)
        {
            Add-DiagnosticDataFindings -Findings $finding.ChildFindings -Items $Items -ParentId $id -Snapshots $Snapshots
        }
    }
}

function Add-DiagnosticCommandSnapshot
{
    param(
        [SPDiagnostics.Finding]$Finding,
        [string]$CommandName,
        [object[]]$Records,
        [System.Collections.IDictionary]$Scope = ([ordered]@{}),
        [string]$Source,
        [string]$Coverage,
        [string[]]$PropertyNames,
        [string[]]$IdentityProperties = @('Id'),
        [string[]]$Notes = @()
    )

    $Finding.CommandSnapshots.Add([pscustomobject]@{
        commandName = $CommandName
        records = $Records
        scope = $Scope
        source = $Source
        coverage = $Coverage
        propertyNames = $PropertyNames
        identityProperties = $IdentityProperties
        notes = $Notes
    })
}

function Add-DiagnosticTimerJobSnapshot
{
    param(
        [SPDiagnostics.Finding]$Finding,
        [object[]]$Jobs,
        [System.Collections.IDictionary]$Scope,
        [string]$Source,
        [string]$Coverage
    )

    Add-DiagnosticCommandSnapshot -Finding $Finding -CommandName 'Get-SPTimerJob' -Records $Jobs -Scope $Scope -Source $Source -Coverage $Coverage -PropertyNames @(
        'Id', 'Name', 'DisplayName', 'TypeName', 'Status', 'IsDisabled',
        'LockType', 'LastRunTime', 'Schedule'
    )
}

function Get-DiagnosticCommandData
{
    param([System.Collections.Generic.List[object]]$Snapshots)

    $sections = [ordered]@{}
    foreach($name in @(
        'Get-SPWebApplication', 'Get-SPServiceApplication', 'Get-SPServiceApplicationProxy',
        'Get-SPServiceApplicationProxyGroup', 'Get-SPTimerJob', 'Get-SPDiagnosticConfig',
        'Get-SPSecurityTokenServiceConfig',
        'Get-SPServer', 'Get-SPDatabase', 'Get-SPEnterpriseSearchServiceApplication',
        'Get-SPEnterpriseSearchCrawlContentSource', 'Get-SPUsageService', 'Get-SPUsageDefinition',
        'Get-SPDistributedCacheClientSetting', 'Get-SPEnterpriseSearchTopology',
        'Get-SPEnterpriseSearchComponent', 'Get-SPTrustedIdentityTokenIssuer',
        'Get-SPTrustedSecurityTokenIssuer', 'Get-SPTrustedRootAuthority',
        'Get-SPCertificate', 'Get-SPCertificateSettings', 'Get-SPWopiBinding',
        'Get-SPWopiZone', 'Get-SPWOPISuppressionSetting'
    ))
    {
        $sections[$name] = @{
            records = New-Object 'System.Collections.Generic.List[object]'
            coverage = New-Object 'System.Collections.Generic.List[string]'
            sources = New-Object 'System.Collections.Generic.List[string]'
            notes = New-Object 'System.Collections.Generic.List[string]'
            seen = @{}
            snapshotCount = 0
        }
    }
    foreach($entry in $Snapshots)
    {
        $snapshot = $entry.snapshot
        $name = $snapshot.commandName
        if(!$sections.Contains($name)) { throw "Unsupported diagnostic command snapshot: $name" }
        $section = $sections[$name]
        $section.snapshotCount++
        foreach($pair in @(@('coverage', $snapshot.coverage), @('sources', $snapshot.source)))
        {
            $text = ConvertTo-DiagnosticDataText -Value $pair[1]
            if(!$section[$pair[0]].Contains($text)) { $section[$pair[0]].Add($text) }
        }
        $scopeNotes = New-Object 'System.Collections.Generic.List[string]'
        $scope = ConvertTo-DiagnosticDataValue -Value $snapshot.scope -Notes $scopeNotes -Path "$name.scope"
        foreach($note in @($snapshot.notes) + $scopeNotes.ToArray())
        {
            $text = ConvertTo-DiagnosticDataText -Value $note
            if(!$section.notes.Contains($text)) { $section.notes.Add($text) }
        }
        foreach($record in $snapshot.records)
        {
            if($null -eq $record) { continue }
            $notes = New-Object 'System.Collections.Generic.List[string]'
            $path = '{0}.records[{1}].properties' -f $name, $section.records.Count
            $arguments = @{ Value = $record; Notes = $notes; Path = $path }
            if($null -ne $snapshot.propertyNames) { $arguments.PropertyNames = $snapshot.propertyNames }
            $properties = ConvertTo-DiagnosticDataValue @arguments
            if($properties -isnot [System.Collections.IDictionary])
            {
                throw "Diagnostic command snapshot records must be property objects: $name"
            }
            $identity = [ordered]@{}
            $missingIdentity = $false
            foreach($property in $snapshot.identityProperties)
            {
                if(!$properties.Contains($property) -or $null -eq $properties[$property])
                {
                    $missingIdentity = $true
                    $notes.Add(("{0}: identity property {1} is unavailable; record retained without deduplication." -f $path, $property))
                }
                else
                {
                    $identity[$property] = $properties[$property]
                }
            }
            $key = ConvertTo-Json -InputObject ([ordered]@{ scope = $scope; identity = $identity }) -Depth 16 -Compress -ErrorAction Stop
            if($missingIdentity) { $key += '|{0}' -f $section.records.Count }
            if($section.seen.ContainsKey($key))
            {
                $target = $section.seen[$key]
                $targetPath = '{0}.records[{1}].properties' -f $name, $section.records.IndexOf($target)
                for($index = 0; $index -lt $notes.Count; $index++) { $notes[$index] = $notes[$index].Replace($path, $targetPath) }
                foreach($property in $properties.Keys) { $target.properties[$property] = $properties[$property] }
            }
            else
            {
                $target = [ordered]@{
                    objectType = $record.GetType().FullName
                    scope = $scope
                    properties = $properties
                    sourceFindingIds = New-Object 'System.Collections.Generic.List[string]'
                    exportNotes = New-Object 'System.Collections.Generic.List[string]'
                }
                $section.seen[$key] = $target
                $section.records.Add($target)
            }
            if(!$target.sourceFindingIds.Contains($entry.findingId)) { $target.sourceFindingIds.Add($entry.findingId) }
            foreach($note in $notes)
            {
                if(!$target.exportNotes.Contains($note)) { $target.exportNotes.Add($note) }
            }
        }
    }
    $result = [ordered]@{}
    foreach($name in $sections.Keys)
    {
        $section = $sections[$name]
        foreach($record in $section.records)
        {
            $record.sourceFindingIds = $record.sourceFindingIds.ToArray()
            $record.exportNotes = $record.exportNotes.ToArray()
        }
        $status = if($section.snapshotCount -eq 0) { 'notCollected' } elseif($section.records.Count -eq 0) { 'noRecordsCaptured' } else { 'captured' }
        $result[$name] = [ordered]@{
            collectionStatus = $status
            coverage = $section.coverage.ToArray()
            sources = $section.sources.ToArray()
            records = $section.records.ToArray()
            exportNotes = $section.notes.ToArray()
        }
    }
    return $result
}

function Get-DiagnosticReportJson
{
    param([SPDiagnostics.Finding[]]$Findings)

    $items = New-Object 'System.Collections.Generic.List[object]'
    $snapshots = New-Object 'System.Collections.Generic.List[object]'
    Add-DiagnosticDataFindings -Findings $Findings -Items $items -ParentId $null -Snapshots $snapshots
    $data = [ordered]@{
        schemaVersion = '1.6'
        generatedAtUtc = [datetime]::UtcNow.ToString('o')
        scriptVersion = $ScriptVersion
        product = ConvertTo-DiagnosticDataText -Value $build
        farmBuild = $script:SPFarmBuild.ToString()
        serverNamesMasked = [bool]$UseEncodedServerId
        summary = [ordered]@{
            totalFindings = $items.Count
            critical = @($items | Where-Object { $_.severity -eq 'Critical' }).Count
            warning = @($items | Where-Object { $_.severity -eq 'Warning' }).Count
            informational = @($items | Where-Object { $_.severity -eq 'Informational' }).Count
        }
        findings = $items.ToArray()
    }
    $data['Get-SPFarm'] = Get-DiagnosticFarmSettings -Farm $script:SPFarm
    $commandData = Get-DiagnosticCommandData -Snapshots $snapshots
    foreach($name in $commandData.Keys) { $data[$name] = $commandData[$name] }
    $json = ConvertTo-Json -InputObject $data -Depth 32 -ErrorAction Stop
    # JSON escapes keep HTML raw-text parsing and the legacy whole-report replacements out of the payload.
    return $json.Replace('&', '\u0026').Replace('<', '\u003c').Replace('>', '\u003e').Replace('~', '\u007e')
}

#Core function to write html report
function Write-DiagnosticReport
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [SPDiagnostics.Finding[]]
        $Findings, 
        [Parameter(Mandatory=$false)]
        [SPDiagnostics.OutputFormat]$OutputFormat=[SPDiagnostics.OutputFormat]::HTML
    )

    $reportJson = $null
    if($OutputFormat -eq [SPDiagnostics.OutputFormat]::HTML)
    {
        $reportJson = Get-DiagnosticReportJson -Findings $Findings
    }

    #Defining CSS to be applied to the report
    $globalCss = @"
    <style>
        * {
            box-sizing: border-box;
        }

        :root {
            --bg: #1a1a2e;
            --panel: #16213e;
            --panel-2: #1e2a4a;
            --panel-3: #0f3460;
            --line: #2a2a4a;
            --text: #eef3fb;
            --muted: #a8b2c1;
            --accent: #00d4ff;
            --accent-2: #60a5fa;
            --critical: #f87171;
            --critical-bg: #3d1f1f;
            --warning: #fbbf24;
            --warning-bg: #2d1f00;
            --success: #4ade80;
        }

        body {
            margin: 0;
            padding: 24px;
            background:
                radial-gradient(circle at top left, rgba(0, 212, 255, 0.16), transparent 34rem),
                linear-gradient(135deg, #101729 0%, var(--bg) 45%, #111827 100%);
            color: var(--text);
            font-family: 'Segoe UI', Tahoma, sans-serif;
            line-height: 1.45;
        }

        .container {
            width: 96%;
            max-width: 2000px;
            margin: 0 auto;
        }

        #topInfo {
            background: linear-gradient(135deg, rgba(22, 33, 62, 0.98), rgba(15, 52, 96, 0.88));
            border: 1px solid rgba(0, 212, 255, 0.35);
            border-left: 5px solid var(--accent);
            border-radius: 14px;
            box-shadow: 0 18px 44px rgba(0, 0, 0, 0.28);
            margin-bottom: 24px;
            padding: 22px 26px;
        }

        h1 {
            color: var(--accent);
            font-size: 2rem;
            margin: 0 0 12px 0;
            padding-bottom: 12px;
            border-bottom: 2px solid var(--accent);
            letter-spacing: 0.01em;
        }

        #topInfo p {
            color: var(--muted);
            margin: 4px 0;
        }

        a {
            color: var(--accent);
        }

        #expAll {
            display: inline-block;
            margin-top: 16px;
            padding: 8px 14px;
            color: #061827;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            border-radius: 999px;
            font-weight: 700;
            text-decoration: none;
            box-shadow: 0 8px 20px rgba(0, 212, 255, 0.20);
        }

        #ieWarning {
            color: var(--warning);
            margin-top: 12px;
        }

        .summary {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 20px 0 4px 0;
        }

        .summary-card {
            min-width: 145px;
            padding: 18px 26px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 10px 24px rgba(0, 0, 0, 0.22);
        }

        .summary-card.critical {
            background: linear-gradient(135deg, #d13438, #8f1f24);
        }

        .summary-card.warning {
            background: linear-gradient(135deg, #ffb900, #cc9400);
            color: #1a1a2e;
        }

        .summary-card.info {
            background: linear-gradient(135deg, #0078d4, #005a9e);
        }

        .summary-card.total {
            background: linear-gradient(135deg, #107c10, #0a5c0a);
        }

        .summary-card .count {
            font-size: 2.35rem;
            font-weight: 800;
            line-height: 1;
        }

        .summary-card .label {
            font-size: 0.88rem;
            margin-top: 7px;
            opacity: 0.92;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }

        table {
            width: 100%;
            margin: 15px 0;
            overflow: hidden;
            border: 1px solid var(--line);
            border-collapse: separate;
            border-spacing: 0;
            border-radius: 10px;
            background: var(--panel);
            color: var(--text);
            font-family: 'Segoe UI', Tahoma, sans-serif;
            box-shadow: 0 10px 24px rgba(0, 0, 0, 0.18);
        }

        th {
            padding: 12px 10px;
            background: var(--panel-3);
            color: var(--accent);
            font-weight: 700;
            text-align: left;
            border-bottom: 1px solid rgba(0, 212, 255, 0.22);
        }

        td {
            padding: 10px;
            border-bottom: 1px solid var(--line);
            color: var(--text);
            vertical-align: top;
        }

        tbody tr:nth-child(even) {
            background: rgba(255, 255, 255, 0.035);
        }

        tbody tr:hover {
            background: rgba(0, 212, 255, 0.08);
        }

        tr:last-child td {
            border-bottom: none;
        }

        details {
            margin: 16px 0;
        }

        details > summary {
            cursor: pointer;
            list-style: none;
        }

        details > summary::-webkit-details-marker {
            display: none;
        }

        details > summary::before {
            content: '>';
            display: inline-block;
            margin-right: 9px;
            color: var(--accent);
            transition: transform 0.2s ease;
        }

        details[open] > summary::before {
            transform: rotate(90deg);
        }

        .review-section {
            margin: 18px 0;
            padding: 5px 12px 12px 12px;
            background: rgba(22, 33, 62, 0.88);
            border: 1px solid var(--line);
            border-left: 5px solid var(--accent-2);
            border-radius: 12px;
            box-shadow: 0 12px 28px rgba(0, 0, 0, 0.20);
        }

        .review-section.critical {
            border-left-color: var(--critical);
        }

        .review-section.warning {
            border-left-color: var(--warning);
        }

        .review-section.info {
            border-left-color: var(--accent-2);
        }

        .error {
            color: var(--critical);
        }

        .warning {
            color: var(--warning);
        }

        .warning-message {
            margin: 12px 0;
            padding: 13px 15px;
            color: #ffd7d7;
            background: var(--critical-bg);
            border-left: 4px solid var(--critical);
            border-radius: 0 8px 8px 0;
        }

        .description {
            margin: 10px 0;
            padding: 12px 15px;
            color: var(--muted);
            background: rgba(15, 52, 96, 0.55);
            border-left: 3px solid var(--accent-2);
            border-radius: 6px;
        }

        .finding {
            padding: 8px 0 8px 26px;
            font-size: 13px;
        }

        .heading {
            color: var(--text);
            font-size: 1.15rem;
            font-weight: 700;
            padding-top: 10px;
            padding-bottom: 10px;
            border-radius: 5px;
        }

        .heading:hover {
            color: var(--accent);
        }

        .code {
            display: block;
            margin: 10px 0;
            padding: 12px 14px;
            overflow-x: auto;
            color: var(--accent);
            background: #0b1220;
            border: 1px solid var(--line);
            border-radius: 8px;
            font-size: 0.875rem;
            font-family: Consolas, 'Courier New', monospace;
            white-space: pre-wrap;
        }

        .copyToClipboardDiv input[type='image'] {
            margin: 8px 4px 0 0;
            padding: 4px;
            background: #ffffff;
            border-radius: 5px;
            opacity: 0.9;
        }

        /* URLs (http/https) found anywhere in object data */
        .url {
            color: #ffd700;
            font-weight: 600;
            white-space: nowrap;
        }

        /* Quoted object names highlighted within finding headings */
        .obj {
            color: #7ee787;
            font-weight: 600;
            border-bottom: 1px dotted rgba(126, 231, 135, 0.55);
        }

        /* Horizontally scrollable wrapper injected around result tables */
        .table-wrap {
            max-width: 100%;
            margin: 8px 0;
            overflow-x: auto;
            border-radius: 10px;
        }

        .table-tools {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 6px;
        }

        .table-expand-btn {
            display: none;
            cursor: pointer;
            border: none;
            border-radius: 999px;
            padding: 4px 14px;
            font-size: 0.78rem;
            font-weight: 700;
            color: #061827;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            box-shadow: 0 4px 12px rgba(0, 212, 255, 0.18);
        }

        .table-expand-btn:hover {
            filter: brightness(1.1);
        }

        .table-wrap--full {
            position: relative;
            z-index: 5;
            max-width: none;
            box-shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
        }

        .table-wrap table {
            margin: 0;
        }

        /* Console-style transcript used by the Kerberos configuration finding */
        .kconsole {
            font-family: Consolas, 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            background: #012456;
            color: #d6e9ff;
            padding: 16px 18px;
            margin: 4px 0;
            border: 1px solid #0a3d7a;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre;
        }
        .kconsole .k-head  { color: #34e2e2; font-weight: 600; }
        .kconsole .k-white { color: #ffffff; }
        .kconsole .k-acct  { color: #f4d35e; font-weight: 600; }
        .kconsole .k-ok    { color: #5dd55d; }
        .kconsole .k-bad   { color: #ff6b6b; }
        .kconsole .k-info  { color: #3fd0e0; }
        .kconsole .k-dim   { color: #b9b9b9; }
        .kconsole .k-ddim  { color: #8a8a8a; }
        .kconsole .k-warn  { color: #e0b020; }
        .kconsole .k-err2  { color: #c04040; }
        .kconsole .k-sep   { color: #6f8fbf; }

        /* Search Application Topology grid (mimics the Central Admin topology view) */
        .searchtopo {
            border-collapse: collapse;
            width: 100%;
            margin: 10px 0;
            background: #ffffff;
            color: #333333;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 0.9rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.35);
            border-radius: 4px;
            overflow: hidden;
        }
        .searchtopo thead th {
            background: #e6e6e6;
            color: #555555;
            font-weight: 400;
            padding: 14px 12px;
            text-align: center;
            vertical-align: middle;
            border: none;
            white-space: nowrap;
        }
        .searchtopo thead th.stp-srv {
            text-align: left;
        }
        .searchtopo .stp-part {
            display: block;
            margin-top: 4px;
            color: #888888;
            font-size: 0.85rem;
        }
        .searchtopo tbody td {
            padding: 10px 12px;
            text-align: center;
            border: none;
        }
        .searchtopo tbody td.stp-srv {
            text-align: left;
            font-weight: 600;
            color: #222222;
        }
        .searchtopo tbody tr:nth-child(odd)  { background: #ffffff; }
        .searchtopo tbody tr:nth-child(even) { background: #f3f3f3; }
        .searchtopo .stp-chk {
            color: #4f8a4f;
            font-weight: bold;
            font-size: 1rem;
        }
        .searchtopo .stp-pri {
            color: #2e7d32;
            font-weight: 600;
            font-size: 0.8rem;
        }

        /* Horizontal scroll guard so very wide topologies (up to 25 index partitions) never break the page layout */
        .searchtopo-wrap {
            width: 100%;
            overflow-x: auto;
        }

        /* Density tiers applied dynamically based on the number of index partitions */
        .searchtopo.density-compact thead th { padding: 9px 7px; font-size: 0.8rem; }
        .searchtopo.density-compact tbody td { padding: 7px 7px; font-size: 0.8rem; }
        .searchtopo.density-compact .stp-part { font-size: 0.75rem; }
        .searchtopo.density-compact .stp-chk  { font-size: 0.9rem; }
        .searchtopo.density-compact .stp-pri  { font-size: 0.7rem; }

        .searchtopo.density-tiny thead th { padding: 6px 5px; font-size: 0.68rem; }
        .searchtopo.density-tiny tbody td { padding: 5px 5px; font-size: 0.68rem; }
        .searchtopo.density-tiny .stp-part { font-size: 0.62rem; margin-top: 2px; }
        .searchtopo.density-tiny .stp-chk  { font-size: 0.8rem; }
        .searchtopo.density-tiny .stp-pri  { font-size: 0.6rem; }

        /* Grouped "Index Partition" header (spans all partition columns) with ordinals beneath */
        .searchtopo .stp-partgroup {
            text-align: center;
            border-bottom: 1px solid #d6d6d6;
        }
        .searchtopo .stp-partnum {
            font-weight: 400;
            color: #888888;
            padding-top: 6px;
            padding-bottom: 10px;
        }

        /* Component state icons inside the topology grid */
        .searchtopo .stp-ico { vertical-align: middle; }
        .searchtopo .stp-ico-wrap { display: inline-block; line-height: 1; }

        /* Legend shown above the grid (sits on the report's dark panel) */
        .stp-legend { margin-top: 8px; color: #cfe0f5; font-size: 0.85rem; }
        .stp-legend .stp-ico { vertical-align: middle; }
        .stp-legend .stp-chk { color: #5dd55d; font-weight: bold; vertical-align: middle; }
    </style>
"@

# https://stackoverflow.com/questions/74838274/copy-html-rich-text-using-navigator-clipboard
$copyToClipboardJs = @"
function getStructuredReportJson() {
    var data = document.getElementById('spfarminfo-data');
    if (!data) {
        throw new Error('The embedded JSON data could not be found.');
    }
    return data.textContent;
}

function downloadStructuredReportJson() {
    try {
        var blob = new Blob([getStructuredReportJson()], { type: 'application/json;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = 'SPFarmInfo-data.json';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    } catch (error) {
        alert('Could not download structured data: ' + error.message);
    }
}

async function copyStructuredReportJson(button) {
    if (button.disabled) { return; }
    var originalLabel = button.textContent;
    try {
        if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
            throw new Error('Clipboard access is not available in this browser or context.');
        }
        button.disabled = true;
        button.textContent = 'Copying JSON...';
        await navigator.clipboard.writeText(getStructuredReportJson());
    } catch (error) {
        alert('Could not copy structured data: ' + error.message + ' Use Download JSON instead.');
    } finally {
        button.disabled = false;
        button.textContent = originalLabel;
    }
}

function copyToClipboardText(str) {
    function listener(e) {
      const newstr = str.getElementsByTagName("table")[0];

      e.clipboardData.setData("text/html", newstr.outerText);
      e.clipboardData.setData("text/plain", newstr.outerText);
      e.preventDefault();
    }
    document.addEventListener("copy", listener);
    document.execCommand("copy");
    document.removeEventListener("copy", listener);
  };

  function copyToClipboardHtml(str) {
    function listener(e) {
      const newstr = str.getElementsByTagName("table")[0];

      e.clipboardData.setData("text/html", newstr.outerHTML);
      e.clipboardData.setData("text/plain", newstr.outerHTML);
      e.preventDefault();
    }
    document.addEventListener("copy", listener);
    document.execCommand("copy");
    document.removeEventListener("copy", listener);
  };

"@

$expandAllJS = "// Reference the toggle link
    const xa = document.getElementById('expAll');

    // Register link on click event
    xa.addEventListener('click', function(e) {

    /* Toggle the two classes that represent `"state`"
    || determined when link is clicked
    */
    e.currentTarget.classList.toggle('exp');
    e.currentTarget.classList.toggle('col');

    // Collect all <details> into a NodeList
    const details = document.querySelectorAll('details');

    /* Convert NodeList into an array then iterate
    || through it...
    */
    Array.from(details).forEach(function(obj, idx) {

        /* If the link has the class .exp...
        || make each <detail>'s open attribute true
        */
        if (e.currentTarget.classList.contains('exp')) {
        obj.open = true;
        // Otherwise remove [open]
        } else {
        obj.removeAttribute('open');
        }

    });

    }, false);"

# Post-render colorizer: golds URLs in object data and highlights quoted object
# names inside finding headings. Operates on text nodes only so hrefs, embedded
# images, scripts, and code blocks are never touched.
$colorizeJs = @"
(function () {
    function colorize() {
        var skipTags = { A: 1, SCRIPT: 1, STYLE: 1, INPUT: 1, TEXTAREA: 1, BUTTON: 1 };
        function isSkipped(el) {
            while (el && el.nodeType === 1) {
                if (skipTags[el.tagName]) { return true; }
                if (el.classList && el.classList.contains("code")) { return true; }
                el = el.parentNode;
            }
            return false;
        }
        var urlRe = /(https?:\/\/[^\s'"()<>\]]+)/g;
        var quoteRe = /('[^']+')/g;
        var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        var nodes = [];
        while (walker.nextNode()) { nodes.push(walker.currentNode); }
        nodes.forEach(function (node) {
            var parent = node.parentNode;
            if (!parent || isSkipped(parent)) { return; }
            var text = node.nodeValue;
            var inHeading = !!(parent.closest && parent.closest(".heading"));
            var hasUrl = urlRe.test(text); urlRe.lastIndex = 0;
            var hasQuote = inHeading && quoteRe.test(text); quoteRe.lastIndex = 0;
            if (!hasUrl && !hasQuote) { return; }
            var html = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            if (inHeading) {
                html = html.replace(quoteRe, '<span class="obj">`$1</span>');
            }
            html = html.replace(urlRe, '<span class="url">`$1</span>');
            var wrap = document.createElement("span");
            wrap.innerHTML = html;
            parent.replaceChild(wrap, node);
        });
    }
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", colorize);
    } else {
        colorize();
    }
})();
"@

# Wraps each result table in a horizontally scrollable container and adds an
# "Expand width" toggle so wide tables stay inside their section but can be
# popped out to full viewport width on demand.
$enhanceTablesJs = @"
(function () {
    function applyState(wrap, btn) {
        var overflow = wrap.scrollWidth > wrap.clientWidth + 2;
        if (!wrap.classList.contains('table-wrap--full')) {
            btn.style.display = overflow ? 'inline-block' : 'none';
        }
    }
    function enhanceTables() {
        var tables = document.querySelectorAll('.finding table');
        Array.prototype.forEach.call(tables, function (tbl) {
            if (tbl.parentNode && tbl.parentNode.classList && tbl.parentNode.classList.contains('table-wrap')) { return; }
            var wrap = document.createElement('div');
            wrap.className = 'table-wrap';
            var tools = document.createElement('div');
            tools.className = 'table-tools';
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'table-expand-btn';
            btn.textContent = 'Expand width';
            btn.addEventListener('click', function () {
                var full = wrap.classList.toggle('table-wrap--full');
                if (full) {
                    var rect = wrap.getBoundingClientRect();
                    var vw = document.documentElement.clientWidth;
                    var target = Math.min(vw - 24, 2400);
                    wrap.style.width = target + 'px';
                    wrap.style.marginLeft = ((vw - target) / 2 - rect.left) + 'px';
                    btn.textContent = 'Collapse width';
                } else {
                    wrap.style.width = '';
                    wrap.style.marginLeft = '';
                    btn.textContent = 'Expand width';
                }
            });
            tools.appendChild(btn);
            tbl.parentNode.insertBefore(wrap, tbl);
            wrap.appendChild(tools);
            wrap.appendChild(tbl);
            applyState(wrap, btn);
        });
        window.addEventListener('resize', function () {
            document.querySelectorAll('.table-wrap').forEach(function (wrap) {
                var btn = wrap.querySelector('.table-expand-btn');
                if (btn) { applyState(wrap, btn); }
            });
        });
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', enhanceTables);
    } else {
        enhanceTables();
    }
})();
"@

    $html = $null;

    # Identify "Critical" and "Warning" findings so that they can be promoted
    $criticalFindings = Get-DiagnosticErrorFindings -Findings $Findings -Severity Critical
    $warningFindings = Get-DiagnosticErrorFindings -Findings $Findings -Severity Warning
    $informationalFindings = Get-DiagnosticErrorFindings -Findings $Findings -Severity Informational

    if($OutputFormat -eq [SPDiagnostics.OutputFormat]::HTML)
    {
        $html = "<!DOCTYPE html>`r`n<html>`r`n<head>`r`n<meta charset=`"utf-8`">`r`n<Title>SPFarmInfo - {0}</Title>`r`n" -f $build
        $html+=$globalCss
        $html += ("`r`n<script type=`"text/javascript`">{0}</script>`r`n</head>`r`n<body>`r`n<div class=`"container`">`r`n" -f $copyToClipboardJs)
        $html+="<div id=`"topInfo`">`r`n"
        $html+="<h1>SPFarmInfo - {0} [{1}]</h1>`r`n" -f $build, [Microsoft.SharePoint.Administration.SPFarm]::Local.BuildVersion.ToString()
        $html+="<p style=`"font-style: italic;`">Generated at {0} UTC</p>`r`n" -f [datetime]::UtcNow.ToString("MM/dd/yyyy hh:mm:ss tt")
        $html+="<p style=`"font-style: italic;`">ScriptVersion: {0} (Published on 08-16-2026)</p>`r`n" -f $ScriptVersion
        $html+="<div class=`"summary`">`r`n"
        $html+="    <div class=`"summary-card critical`">`r`n        <div class=`"count`">{0}</div>`r`n        <div class=`"label`">Critical</div>`r`n    </div>`r`n" -f $criticalFindings.Count
        $html+="    <div class=`"summary-card warning`">`r`n        <div class=`"count`">{0}</div>`r`n        <div class=`"label`">Warnings</div>`r`n    </div>`r`n" -f $warningFindings.Count
        $html+="    <div class=`"summary-card info`">`r`n        <div class=`"count`">{0}</div>`r`n        <div class=`"label`">Info</div>`r`n    </div>`r`n" -f $informationalFindings.Count
        $html+="    <div class=`"summary-card total`">`r`n        <div class=`"count`">{0}</div>`r`n        <div class=`"label`">Total Findings</div>`r`n    </div>`r`n" -f (Get-TotalFindingCount -Findings $Findings)
        $html+="</div>`r`n"
        $html+="<a href='#/' id='expAll' class='col'>Expand All</a>`r`n"
        $html+="<p><button type=`"button`" onclick=`"copyStructuredReportJson(this)`">Copy JSON</button> <button type=`"button`" onclick=`"downloadStructuredReportJson()`">Download JSON</button></p>`r`n"
        $html+="<p>Machine-readable findings are embedded as JSON in the spfarminfo-data element. The exported data has the same sensitivity as this report.</p>`r`n"
        $html+=("<script id=`"spfarminfo-data`" type=`"application/json`">`n{0}`n</script>`r`n" -f $reportJson)
        $html+="<div id=`"ieWarning`" />
        <script type=`"text/javascript`">
            var isIe = navigator.userAgent.indexOf(`"Trident`") > -1;
            if(isIe){
                document.getElementById(`"expAll`").style.display = `"none`";
                document.getElementById(`"ieWarning`").innerHTML = `"This report is not optimized for IE for best results open this report in Microsoft Edge.`";
            }
        </script>"
        $html+="`r`n</div>`r`n"
    }


    # If there are critical findings create a "review-section" for critical findings at the top of the report
    if($criticalFindings.Count -ge 1)
    {
        Switch($OutputFormat)
        {
            'HTML'
            {
                $html+="<div class=`"review-section critical`">`r`n<details open=`"true`">`r`n<summary class=`"error heading`">Critical Findings</summary>`r`n"
                $html+="<div style=`"padding-left: 30px`">`r`n"
            }
            'TEXT'
            {
                $html+="!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`r`n"
                $html+="Critical Findings`r`n"
                $html+="!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`r`n"
            }
        }
        
        foreach($finding in $criticalFindings)
        {
            try
            {
                $expand = $finding.Expand
                $finding.Expand = $true
                $fragment = Write-DiagnosticFindingFragment -Finding $finding -ExcludeChildFindings -OutputFormat $OutputFormat
                $html+=$fragment
                $finding.Expand = $expand
            }
            catch
            {
                Write-Warning $_
            }
        }
        Switch($OutputFormat)
        {
            'HTML'
            {
                $html+="`r`n</div>`r`n</details>`r`n</div>`r`n<br>`r`n"
            }
            'TEXT'
            {
                $html+="!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`r`n"
            }
        }

    }

    # Similar to critical findings promote any warnings that may be present
    if($warningFindings.Count -ge 1)
    {
        Switch($OutputFormat)
        {
            'HTML'
            {
                $html+="<div class=`"review-section warning`">`r`n<details>`r`n<summary class=`"warning heading`">Review Items</summary>`r`n"
                $html+="<div style=`"padding-left: 30px`">`r`n"
            }
            'TEXT'
            {
                $html+="*****************************************************************************************`r`n"
                $html+="Review Items`r`n"
                $html+="*****************************************************************************************`r`n"
            }
        }

        
        foreach($finding in $warningFindings)
        {
            try
            {
                $fragment = Write-DiagnosticFindingFragment -Finding $finding -ExcludeChildFindings -OutputFormat $OutputFormat
                $html+=$fragment
            }
            catch
            {
                Write-Warning $_
            }
        }

        Switch($OutputFormat)
        {
            'HTML'
            {
                $html+="`r`n</div>`r`n</details>`r`n</div>`r`n<br>`r`n"
            }
            'TEXT'
            {
                $html+="*****************************************************************************************`r`n"
            }
        }
    }


    # Similar to critical findings promote any warnings that may be present
    if($informationalFindings.Count -ge 1)
    {
        Switch($OutputFormat)
        {
           'HTML'
            {
                $html+="<div class=`"review-section info`">`r`n<details>`r`n<summary class=`"heading`">Informational Items</summary>`r`n"
                $html+="<div style=`"padding-left: 30px`">`r`n"
            }
            'TEXT'
            {
                $html+="#########################################################################################`r`n"
                $html+="Informational Items`r`n"
                $html+="#########################################################################################`r`n"
            }
        }
        
        foreach($finding in $informationalFindings)
        {
            try
            {
                $fragment = Write-DiagnosticFindingFragment -Finding $finding -ExcludeChildFindings -OutputFormat $OutputFormat
                $html+=$fragment
            }
            catch
            {
                Write-Warning $_
            }
        }

        Switch($OutputFormat)
        {
            'HTML'
            {
                $html+="`r`n</div>`r`n</details>`r`n</div>`r`n<br>`r`n"
            }
            'TEXT'
            {
                $html+="#########################################################################################`r`n"
            }
        }
    }
    
    foreach($finding in $Findings)
    {
        if($null -eq $finding)
        {
            continue
        }
        try
        {
            $fragment = Write-DiagnosticFindingFragment -Finding $finding -OutputFormat $OutputFormat
            $html+=$fragment
        }
        catch
        {
            Write-Warning $_
        }
    }

    Switch($OutputFormat)
    {
        'HTML'
        {
            $html+=("`r`n<script type=`"text/javascript`">{0}</script>`r`n" -f $expandAllJS)
            $html+=("<script type=`"text/javascript`">{0}</script>`r`n" -f $colorizeJs)
            $html+=("<script type=`"text/javascript`">{0}</script>`r`n" -f $enhanceTablesJs)
            $html+="</div>`r`n</body>`r`n</html>`r`n"
        }
        'TEXT'
        {
            $html+="#########################################################################################`r`n"
        }
    }

    # Decode the ~~~BR~~~ line-break sentinel used by findings that stack multiple values within a single table cell
    # ~~~POLICYSTART~~~ / ~~~POLICYEND~~~ wrap a label (e.g. a policy name) so it renders bold in HTML output.
    # ~~~SETSTART~~~ / ~~~SETEND~~~ wrap a value (e.g. a security setting) so it renders in a light-blue color in HTML output.
    # ~~~PILLGOOD~~~ / ~~~PILLBAD~~~ / ~~~PILLWARN~~~ ... ~~~PILLEND~~~ wrap a value in a colored status pill (green/red/amber) in HTML output.
    # These sentinels are used because ConvertTo-Html encodes raw markup; replacing them after conversion keeps the styling intact.
    if($OutputFormat -eq [SPDiagnostics.OutputFormat]::HTML)
    {
        $html = $html.Replace('~~~BR~~~','<br/>')
        $html = $html.Replace('~~~POLICYSTART~~~','<strong>')
        $html = $html.Replace('~~~POLICYEND~~~','</strong>')
        $html = $html.Replace('~~~SETSTART~~~','<span style="color:#9ecbff;padding-left:1.6em">')
        $html = $html.Replace('~~~SETEND~~~','</span>')
        $html = $html.Replace('~~~PILLGOOD~~~','<span style="background:#1a7f37;color:#fff;padding:1px 8px;border-radius:10px;font-size:12px;display:inline-block">')
        $html = $html.Replace('~~~PILLBAD~~~','<span style="background:#b62324;color:#fff;padding:1px 8px;border-radius:10px;font-size:12px;display:inline-block">')
        $html = $html.Replace('~~~PILLWARN~~~','<span style="background:#9e6a03;color:#fff;padding:1px 8px;border-radius:10px;font-size:12px;display:inline-block">')
        $html = $html.Replace('~~~PILLEND~~~','</span>')
    }
    else
    {
        $html = $html.Replace('~~~BR~~~',' | ')
        $html = $html.Replace('~~~POLICYSTART~~~','')
        $html = $html.Replace('~~~POLICYEND~~~','')
        $html = $html.Replace('~~~SETSTART~~~','')
        $html = $html.Replace('~~~SETEND~~~','')
        $html = $html.Replace('~~~PILLGOOD~~~','')
        $html = $html.Replace('~~~PILLBAD~~~','')
        $html = $html.Replace('~~~PILLWARN~~~','')
        $html = $html.Replace('~~~PILLEND~~~','')
    }

    return $html
}

function Get-DiagnosticErrorFindings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [SPDiagnostics.Finding[]]
        $Findings,

        [Parameter(Mandatory=$true)]
        [SPDiagnostics.Severity]
        $Severity
    )
    
    $returnFindings = New-DiagnosticFindingCollection #New-Object SPDiagnostics.FindingCollection
    foreach($finding in $Findings)
    {
        if($null -ne $finding)
        {
            if($finding.Severity -eq $Severity)
            {
                $returnFindings+=$finding
            }
            foreach($ChildFinding in $finding.ChildFindings)
            {
                if($null -ne $ChildFinding)
                {
                    $returnFindings+=(Get-DiagnosticErrorFindings -Findings $ChildFinding -Severity $Severity -ErrorAction SilentlyContinue)
                }
            }
        }
    }
    return $returnFindings
}

# Recursively counts all findings including nested child findings, so the
# "Total Findings" summary reflects the entire tree rather than just top-level items.
function Get-TotalFindingCount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [SPDiagnostics.Finding[]]
        $Findings
    )

    $count = 0
    foreach($finding in $Findings)
    {
        if($null -ne $finding)
        {
            $count++
            if($null -ne $finding.ChildFindings -and $finding.ChildFindings.Count -gt 0)
            {
                $count += Get-TotalFindingCount -Findings $finding.ChildFindings
            }
        }
    }
    return $count
}

#endregion

## setting 'script servers varaible here and replacing it in 13 locations where we call 'get spserver'''

## moving this line within main as it is called outside of any function, from there methods can call it
##$script:servers = Get-SPServer

#region SPVersion Function

function Get-SPVersion
{
    [CmdletBinding()]
    param ()

    #moving global assigment to main
    #$farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    #$script:SPFarm = $farm
    #$Script:SPFarmBuild = $script:SPFarm.BuildVersion

    # Task 518: Account for case where $script:SPFarm may be null
    # Additionally this may already have been determined, if $script:SPBuild is already set just return that
    if(![string]::IsNullOrEmpty($Script:Build))
    {
        return $Script:Build
    }

    if($null -eq $script:SPFarm)
    {
        $script:SPFarm = Get-SPFarm
    }
    $farm = $script:SPFarm

    <#
        .SYNOPSIS
        Returns a SharePoint Product Version such as 2013, 2016, 2019, SPSE

        .DESCRIPTION
        Returns a SharePoint Product Version such as 2013, 2016, 2019, SPSE

        .OUTPUTS
        System.String. Get-SPVersion returns a string with the product version
    #>

    if($farm.BuildVersion.Major -eq 16)
    {
        if($farm.BuildVersion.Build -ge 14326)
        {
            $retval = "SPSE"
        }
        elseif($farm.BuildVersion.Build -ge 10337 -and $farm.BuildVersion.Build -lt 14320)
        {
            $retval = "2019"
        }
        else
        {
            $retval = "2016"
        }
    }
    Elseif($farm.BuildVersion.Major -eq 15)
    {
        Write-Warning "The support for SharePoint 2013 has ended, please update this farm to a newer version of SharePoint"
        $retval = "2013"
    }
    elseIf($farm.BuildVersion.Major -eq 14)
    {
        Write-Warning "The support for SharePoint 2010 has ended a long time ago, please update this farm to a newer version of SharePoint.. Aborting Script"
        exit
    }
    else
    {
        Write-Warning "Unsupported Version of SP... Aborting script"
        exit
    }
    $Script:Build=$retval
    return $retval
}
#endregion # SPVersion Function

#region SupportServicePolicy
function Get-ServicingPolicy ($ServicingPolicies)
{
    $farmBuild = (get-spfarm).BuildVersion.Build
    foreach ($ServicingPolicy in $ServicingPolicies)
    {
        $ServBuildParts = $ServicingPolicy.BuildVersionMin.split('.')
        if ($farmbuild -ge $ServBuildParts[2])
        {
            if ((get-date) -lt $ServicingPolicy.SupportEndDate)
            {
                return $true
            } else {
                return $false
            }
        }
    }
    return $false
}

function Get-SecondTuesday ($Year, $Month)
{
    # Second Tuesday of the given month — the SPSE PU support-end convention.
    $first = [DateTime]::new($Year, $Month, 1)
    $daysUntilTuesday = ([int][System.DayOfWeek]::Tuesday - [int]$first.DayOfWeek + 7) % 7
    return $first.AddDays($daysUntilTuesday + 7)
}

Function Get-SPSESupportServicePolicy
{
    <#
        SharePoint Server Subscription Edition servicing policy:
        each Public Update (PU) is supported for one year from its release date,
        ending on the second Tuesday of the same month in the following year.
        Ref: https://learn.microsoft.com/en-us/sharepoint/product-servicing-policy/updated-product-servicing-policy-for-sharepoint-server-se

        Dynamic model (no per-CU table to maintain):
          Anchor = a known PU build and its release month/year.
            - Farm build newer than the anchor  -> supported (newer than anything tracked; never false-alarm).
            - Farm build <= anchor AND today is past the anchor's 1-year mark -> out of policy (certain).
          Bump the anchor below occasionally (a few times a year); no monthly edits required.
    #>

    # ---- Anchor: update occasionally (set to the oldest build you consider "still supported") ---- #
    $anchorBuild        = [version]"16.0.18526.20518"   # August 2025 PU
    $anchorReleaseYear  = 2025
    $anchorReleaseMonth = 08 
    # ---------------------------------------------------------------------------------------------

    $farmVersion = (Get-SPFarm).BuildVersion                 # authoritative farm build (fixes prior undefined $farm bug)
    $farmBuild   = [version]$farmVersion.ToString()

    # Newer than anything this script knows about -> treat as supported.
    if ($farmBuild -gt $anchorBuild)
    {
        return
    }

    # Support end for the anchor build's release month, one year later (2nd Tuesday).
    $anchorSupportEnd = Get-SecondTuesday -Year ($anchorReleaseYear + 1) -Month $anchorReleaseMonth

    # Any build <= anchor ends no later than the anchor; if we're past that date it is certainly unsupported.
    if ((Get-Date) -lt $anchorSupportEnd)
    {
        return
    }

    $ServicePolicyFinding = New-DiagnosticFinding -Name "SharePoint SE Product Servicing Policy" -InputObject $null -Format List
    $ServicePolicyFinding.WarningMessage += " - This build of SharePoint Server Subscription Edition ($($farmVersion.ToString())) is no longer within the product servicing policy.</br> - Each Public Update is supported for one year from its release date. </br> - Please install a recent Public Update to remain fully supported."
    $ServicePolicyFinding.ReferenceLink  += "https://learn.microsoft.com/en-us/sharepoint/product-servicing-policy/updated-product-servicing-policy-for-sharepoint-server-se"
    $ServicePolicyFinding.Severity = [SPDiagnostics.Severity]::Warning
    return $ServicePolicyFinding
}

Function Get-SP2019SupportServicePolicy
{
    #ToDo:Adjust values after November 2023 CU of SP 2019
    $ServiceingPolicies = @()
    
    
    # Nov 2023
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2026,07,14)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10404.20003"
    $ServiceingPolicies += $ServicingPolicy
    
    # Nov 2022
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,10,31)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10392.20000"
    $ServiceingPolicies += $ServicingPolicy

    # Dec 2021
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2023,10,31)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10381.20001"
    $ServiceingPolicies += $ServicingPolicy

    # Nov 2020
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2022,10,31)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10368.20022"
    $ServiceingPolicies += $ServicingPolicy

    $ServicePolicyFinding = New-DiagnosticFinding -Name "SharePoint 2019 Product Servicing Policy" -InputObject $null -Format List
    if (Get-ServicingPolicy  $ServiceingPolicies)
    {
        return
        #$ServicePolicyFinding.Description +="SharePoint farm is in Product Servicing Policy"
    }
    else
    {
        $ServicePolicyFinding.WarningMessage += "This Version of SharePoint 2019 is no longer supported. You must install a later Cumulative Update to be fully supported again."
        $ServicePolicyFinding.ReferenceLink+="https://learn.microsoft.com/en-us/SharePoint/product-servicing-policy/updated-product-servicing-policy-for-sharepoint-2019"
        $ServicePolicyFinding.Severity = [SPDiagnostics.Severity]::Critical
    }
    return $ServicePolicyFinding
}

Function Get-SP2016SupportServicePolicy
{
    $ServiceingPolicies = @()
    #ToDo:Adjust values after November 2023 CU of SP 2016
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2026,07,14)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.5161.1000"
    $ServicePolicyFinding = New-DiagnosticFinding -Name "SharePoint 2016 Product Servicing Policy" -InputObject $null -Format List
    $ServiceingPolicies += $ServicingPolicy
    if (Get-ServicingPolicy  $ServiceingPolicies)
    {
        return
        #$ServicePolicyFinding.Description +="SharePoint farm is in Product Servicing Policy"
    }
    else
    {
        $ServicePolicyFinding.WarningMessage += "This Version of SharePoint 2016 is no longer supported. You must install a later Cumulative Update to be fully supported again."
        $ServicePolicyFinding.ReferenceLink +="https://learn.microsoft.com/en-us/sharepoint/product-servicing-policy/updated-product-servicing-policy-for-sharepoint-server-2016"
        $ServicePolicyFinding.Severity = [SPDiagnostics.Severity]::Critical
    }
    return $ServicePolicyFinding
}
#endregion

function Get-SPDiagnosticSupportDateFinding
{
    [cmdletbinding()]
    Param()
    $supportDateFinding = New-DiagnosticFinding -Name "Microsoft Support Lifecycle Information" -InputObject $null -Format Table -Expand
    
    $adminWebApp = [Microsoft.SharePoint.Administration.SPAdministrationWebApplication]::Local
    $adminSite = $adminWebApp.sites["/"]
    $build = Get-SPVersion

    if($build -eq "SPSE")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri "https://go.microsoft.com/fwlink/?LinkId=2198657").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2199, 12, 1), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2199, 12, 1), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $spseServicePolicy = Get-SPSESupportServicePolicy
        if ($null -ne $spseServicePolicy)
        {
            $supportDateFinding.ChildFindings.add($spseServicePolicy)
        }
    }
    elseif($build -eq "2019")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri "https://go.microsoft.com/fwlink/?LinkId=2198656").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2024, 1, 9), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2026, 7,14), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        #$supportDateFinding.ChildFindings.add((Get-SP2019SupportServicePolicy))

    }
    elseIf($build -eq "2016")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri  "https://go.microsoft.com/fwlink/?LinkId=2198655").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2021, 7, 13), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2026, 7, 14), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        #$supportDateFinding.ChildFindings.add((Get-SP2016SupportServicePolicy))
    }
    elseif($build -eq "2013")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri "https://go.microsoft.com/fwlink/?LinkId=2198654").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2018, 4, 10), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2023, 4, 11), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
    }
    else
    {
        Write-Warning "It appears that this script is running a pre-SharePoint 2013 environment, experiences may be inconsistent"
        return
    }
    
    $endOfSupportInfo = $null

    #SPSE had no end of support, omit this information
    if($build -ne "SPSE")
    {
        # Re-assign as PSCustomObject
        $endOfSupportInfo = [PSCustomObject]@{
        }

        $endOfSupportSeverityLevel = "   None   "

        $endOfSupportDateInfo = $endOfSupportDate.AddYears(-2)
        $endOfSupportDateWarning = $endOfSupportDate.AddMonths(-18)

        $mainstreamSupportDateInfo = $mainstreamSupportDate.AddMonths(-12)
        $mainstreamSupportDateWarning = $mainstreamSupportDate.AddMonths(-6)

        $endOfSupportDateString = [Microsoft.SharePoint.Utilities.SPUtility]::FormatDate($adminSite.RootWeb, $endOfSupportDate, [Microsoft.SharePoint.Utilities.SPDateFormat]::DateOnly)
        $mainstreamSupportDateString = [Microsoft.SharePoint.Utilities.SPUtility]::FormatDate($adminSite.RootWeb, $mainstreamSupportDate, [Microsoft.SharePoint.Utilities.SPDateFormat]::DateOnly)

        $currentDate = [System.DateTime]::UtcNow.AddDays(-1)

        # not used  Todo: Remove
        #$mainstreamDateWarning = ($currentDate -gt $mainstreamSupportDateWarning) -and ($currentDate -lt $mainstreamSupportDate) 

        if( [System.DateTime]::Compare($currentDate, $endOfSupportDate) -gt 0)
        {
            $endOfSupportSeverityLevel = "Alert";
            $supportDateFinding.Severity = [SPDiagnostics.Severity]::Critical
            $supportDateFinding.WarningMessage += "This version of SharePoint Server is no longer supported.</br> Microsoft does not accept requests for fixes, design changes, or new features when a product is no longer supported.</br> Microsoft will not release any updates for this product, not even 'Security' related updates."   

        }
        elseif([System.DateTime]::Compare($currentDate, $endOfSupportDateInfo) -gt 0)
        {
            if([System.DateTime]::Compare($currentDate, $endOfSupportDateWarning) -lt 0)
            {
                $endOfSupportSeverityLevel = "Attention";
                $supportDateFinding.Severity = [SPDiagnostics.Severity]::Informational
            }

            elseif([System.DateTime]::Compare($currentDate, $endOfSupportDate) -lt 0)
            {
                $endOfSupportSeverityLevel = "Warning";
                $supportDateFinding.Severity = [SPDiagnostics.Severity]::Warning
                $supportDateFinding.WarningMessage += "This version of SharePoint Server is nearing the end of 'Mainstream' support.</br> Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' phase.</br> Microsoft will only release 'Security' related updates in the patching cycle." }
            else
            {
                $endOfSupportSeverityLevel = "Alert";
                $supportDateFinding.Severity = [SPDiagnostics.Severity]::Critical
                $supportDateFinding.WarningMessage += "This version of SharePoint Server is in 'Extended' Support.</br> Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' phase.</br> Microsoft will only release 'Security' related updates in the patching cycle."}   
        }
        else
        {
            If([System.DateTime]::Compare($currentDate, $mainstreamSupportDateInfo) -gt 0)
            {
                if([System.DateTime]::Compare($currentDate, $mainstreamSupportDateWarning) -gt 0)
                {
                    $endOfSupportSeverityLevel = "Attention";
                    $supportDateFinding.Severity = [SPDiagnostics.Severity]::Informational
                }

                elseif([System.DateTime]::Compare($currentDate, $mainstreamSupportDate) -lt 0)
                {
                    $endOfSupportSeverityLevel = "Warning";
                    $supportDateFinding.Severity = [SPDiagnostics.Severity]::Warning
                    $supportDateFinding.WarningMessage += "This version of SharePoint Server is nearing the end of 'Mainstream' support.</br> Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' phase.</br> Microsoft will only release 'Security' related updates in the patching cycle."
                }
                else
                {
                    $endOfSupportSeverityLevel = "Alert";
                    $supportDateFinding.Severity = [SPDiagnostics.Severity]::Critical
                    $supportDateFinding.WarningMessage += "This version of SharePoint Server is in 'Extended' Support.</br> Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' phase.</br> Microsoft will only release 'Security' related updates in the patching cycle."
                }   
            }
        }
    
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "SPFarm Build" -Value $build
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Alert" -Value $endOfSupportSeverityLevel
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Mainstream End Date" -Value $mainstreamSupportDateString
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Extended End Date" -Value $endOfSupportDateString
    } # no spse
    #$endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Information" -Value $endOfSupportNotificationLink
    $supportDateFinding.ReferenceLink += $endOfSupportNotificationLink
    
    $supportDateFinding.InputObject =  $endOfSupportInfo
    return $supportDateFinding              
}


#region FarmFindings
Function Get-SPDiagnosticFarmFindings
{
    [cmdletbinding()]
    Param()
        $farmFindings = New-DiagnosticFinding -Name "Farm configuration" -InputObject $null
        $farmFindings.ChildFindings.Add((Get-SPDiagnosticFarmBuildInfo))
        $farmFindings.ChildFindings.Add((Get-FarmUpdateHistory))
        $farmFindings.ChildFindings.Add((Get-ConfigDbVersionsTable))
        $farmFindings.ChildFindings.Add((Get-SPUpgradeSessionsFinding))
        #Farm Services finding - only show when one or more services are not "Online"
        $farmServicesFinding = Get-SPDiagnosticFarmServicesFinding
        if($null -ne $farmServicesFinding)
        {
            $farmFindings.ChildFindings.Add(($farmServicesFinding))
        }
        $farmFindings.ChildFindings.Add((Get-SPDiagnosticServersInFarm))
        $farmFindings.ChildFindings.Add((Get-SPDiagnosticSQLFindings))
        $farmFindings.ChildFindings.Add((Get-SPManagedAcountsWithPwdProps))
    
    # Task 532: Remove farm admins finding
    #$farmFindings.ChildFindings.Add((Get-FarmAdmins))  

    #Task 529: Move behind extended findings switch
    #Task 602: Removing ExtendedFindings switch
    #if($ExtendedFindings)
    #{
    #
    #}
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServiceAppInfo))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServicesOnServer))
    $farmFindings.ChildFindings.Add((Get-SPDatabasesInFarm))
    
    #Task 531: Hide finding unless there is something to report.
    #$farmFindings.ChildFindings.Add((Get-SPDiagnosticTimerAndAdminServiceFinding))
    $timerAndAdminSvcFinding = Get-SPDiagnosticTimerAndAdminServiceFinding
    if(($timerAndAdminSvcFinding.ChildFindings | Where-Object{$_.Severity -ge [SPDiagnostics.Severity]::Warning}).Count -ge 1)
    {
        $farmFindings.ChildFindings.Add(($timerAndAdminSvcFinding))
    }
    else
    {
        foreach($child in $timerAndAdminSvcFinding.ChildFindings)
        {
            foreach($snapshot in $child.CommandSnapshots) { $farmFindings.CommandSnapshots.Add($snapshot) }
        }
    }

    $farmFindings.ChildFindings.Add((Get-SPDiagnosticHealthAnalyzerFinding))
    # Moving this finding as a child finding to "Timer Information"
    #$farmFindings.ChildFindings.Add((Get-SPDiagnosticTimerJobHistoryFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsWebAppsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsFarmSolutionsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsFarmFeaturesFinding))
    #Task 529: Move behind extended findings switch
    #Task 602: Removing ExtendedFindings switch
    #if($ExtendedFindings)
    #{
    #    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsFarmFeaturesFinding))
    #}

    $farmFindings.ChildFindings.Add((Get-SPDiagnosticCertificateFindings -SnapshotFinding $farmFindings))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsDeveloperDashboardSettingsFinding))
    
    #Task 529: Move behind extended findings switch
    #Task 602: Removing ExtendedFindings switch
    if($Performance)
    {
        $farmFindings.ChildFindings.Add((Get-FarmAVSettings))
    }

    #Task 529: Move behind extended findings switch
    #Task 602: Removing ExtendedFindings switch
    if($Performance)
    {
        $farmFindings.ChildFindings.Add((Get-SPSessionStateServiceFinding))
    }
    # Moving dcache to top level finding and only to be included by use of dcache switch.
    #$farmFindings.ChildFindings.Add((Get-SPDiagnosticsDCacheFinding))
    $farmFindings.ChildFindings.Add((Get-OfficeOnlineServerFindings -SnapshotFinding $farmFindings))
    $farmFindings.ChildFindings.Add((Get-ContentDeploymentFindings))

    #Task 471: move to Servers
    #$farmFindings.ChildFindings.Add((Get-SPDiagnosticFarmNetworkLatency))
    return $farmFindings
}

function Get-SPConfigurationDatabase
{
    [cmdletbinding()]
    Param()

    if($null -ne $script:configDb)
    {
        return $script:configDb
    }
    
    # Task 521: Remove reliance on English named objects
    $script:configDb = $script:spDatabases  | Where-Object{$_.GetType().FullName -eq "Microsoft.SharePoint.Administration.SPConfigurationDatabase"}
    return $script:configDb
}


function Get-SPDiagnosticFarmBuildInfo
{
    [cmdletbinding()]
    Param()
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $configDb = Get-SPConfigurationDatabase
    $SPDiagnosticConfig = Get-SPDiagnosticConfig
    $LogLevel = Get-SPLogLevel
    $countOfVerboseEx = ($LogLevel | Where-Object{$_.TraceSeverity -eq "VerboseEx" -and $_.TraceSeverity -ne $_.DefaultTraceSeverity}| measure-object | select-object Count).Count
    $license = Get-SPFarmLicenseString


    $retObj = [PSCustomObject]@{
        FarmBuildVersion = $farm.BuildVersion.ToString()
        CurrentLicense = $license
        "ULS Log Location" = $SPDiagnosticConfig.LogLocation
        DaysToKeepLogs = $SPDiagnosticConfig.DaysToKeepLogs
        LogMaxDiskSpaceUsageEnabled = $SPDiagnosticConfig.LogMaxDiskSpaceUsageEnabled
        LogDiskSpaceUsageGB = $SPDiagnosticConfig.LogDiskSpaceUsageGB
        "VerboseEx LogLevel Count" = $countOfVerboseEx
        ConfigDbName = $($configDb.Name)
        ConfigDbId = $configDb.Id
        ConfigDBAuthMode = $configDb.ServiceInstance.AuthMode
        ConfigDbSql = $($configDb.ServiceInstance.Server.Address)
        ConfigDbInstance = $($configDb.ServiceInstance.Instance)
    }
    $finding = New-DiagnosticFinding -Name "Farm Info" -Description "Farm build, ULS Location, and config db" -InputObject $retObj -Format List
    $commandScope = [ordered]@{ farmId = $farm.Id }
    Add-DiagnosticCommandSnapshot -Finding $finding -CommandName 'Get-SPDiagnosticConfig' -Records $SPDiagnosticConfig -Scope $commandScope -Source 'Get-SPDiagnosticConfig' -Coverage 'Selected logging configuration already read by the farm collector.' -IdentityProperties @() -PropertyNames @(
        'LogLocation', 'DaysToKeepLogs', 'LogMaxDiskSpaceUsageEnabled', 'LogDiskSpaceUsageGB'
    )

    if($countOfVerboseEx -gt 0 -or $countOfVerboseEx -gt 0 -or $countOfVerboseEvents)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "TraceSeverity is set to 'VerboseEx' on $countOfVerboseEx LogLevel(s). This may cause performance issues. </br> If this logging is not necessary, reset the logging to default either from 'Central Administration > Monitoring > Configur Diagnostic Logging' </br> OR by running the 'Clear-SPLogLevel' command from the SharePoint management shell."
    }
    $Finding.ChildFindings.Add((Get-SPDiagnosticsSideBySidePathcingFinding))
    return $finding

}

function Get-SPFarmLicenseString
{
    [cmdletbinding()]
    param()

    $page = [Microsoft.Office.Server.Internal.UI.ConversionPage]::new()
    $type = $page.GetType()
    $bflags = [System.Reflection.BindingFlags]"NonPublic", "Instance"

    $identProducts = $type.GetMethod("IdentifyCurrentInstalledProduct", $bflags)
    $identProducts.Invoke($page, $null) | Out-Null

    $licenstStrMethod = $type.GetMethod("GetCurrentProductLicenseString", $bflags)
    $licenseStr =  $licenstStrMethod.Invoke($page, $null)

    return $licenseStr
}

function Get-FarmUpdateHistory
{
    $FarmUpdateHistory = New-DiagnosticFinding -Name "Installed Updates" -InputObject $null -Format Table -Description "Updates installed in SharePoint Farm"

    $configDb = Get-SPConfigurationDatabase
    $query = "
        select ServerId, obj.Name as ServerName, Product, svi.Version, PatchableUnit, PatchableUnitName, PatchName, PatchUrl
        from dbo.ServerVersionInformation svi
        cross apply TVF_Objects_NoLock_Id (svi.ServerId) as obj
        where (Flags &(1) <> 0) --RequiredOnAllServers
        and (Flags &(8) <> 0) --IsPatch
        and (Flags &(16) = 0) --PatchSuperseded
        order by ServerName
    "
    $installedUpdates = Invoke-SPSqlCommand -spDatabase $configDb -query $query

    ## determine the newest applied updated for each "PatchableUnit" and ensure that all servers have that update applied
    $uniquePatchableUnits = $installedUpdates | Select-Object -Property "PatchableUnit" -Unique
    $uniqueServerIds = $installedUpdates | Select-Object -Property "ServerId" -Unique

    $latestPatches = @()
    foreach($uniquePatchableUnit in $uniquePatchableUnits)
    {
        $highestPatchLevel = ($installedUpdates | Where-Object{$_.PatchableUnit -eq $uniquePatchableUnit.PatchableUnit} | Measure-Object -Property Version -Maximum).Maximum
        $highestPatchUrl = ($installedUpdates | Where-Object{$_.PatchableUnit -eq $uniquePatchableUnit.PatchableUnit -and $_.Version -eq $highestPatchLevel} | Select-Object -Property PatchUrl -Unique).PatchUrl
        $latestPatches += $highestPatch

        foreach($uniqueServerId in $uniqueServerIds)
        {
            $appliedPatch = $installedUpdates | Where-Object{$_.ServerId -eq $uniqueServerId.ServerId -and $_.PatchableUnit -eq $uniquePatchableUnit.PatchableUnit}

            # This fixes a VERY rare scenario when two or more private patches have been applied in a test environment with the same version #
            if($null -ne $appliedPatch -and $appliedPatch.Count -gt 1)
            {
                $appliedPatch = $appliedPatch[0]
            }

            if($null -eq $appliedPatch -or [version]::Parse($appliedPatch.Version) -lt [version]::Parse($highestPatchLevel))
            {
                ##Server is at a lower patch level, flag this patch as missing
                $FarmUpdateHistory.WarningMessage += ("Server {0} is missing latest applied patch for {1}" -f $appliedPatch.ServerName, $appliedPatch.PatchableUnitName)
                $FarmUpdateHistory.WarningMessage += ("Please install update {0}" -f $highestPatchUrl)
                $FarmUpdateHistory.WarningMessage += "If this update is already installed run 'Get-SPProduct -Local' on the affected server(s) and re-run this script."
                $FarmUpdateHistory.WarningMessage += ""
                $FarmUpdateHistory.Severity = [SPDiagnostics.Severity]::Critical
            }
        }
    }

    # Consolidate to one row per server (server shown once); stack each patch's columns in parallel
    # using the ~~~BR~~~ sentinel (<br/> in HTML, " | " in text), matching "Service Instances on Server(s)".
    $updatesReport = $installedUpdates | Select-Object @{l="ServerName"; e={$_.ServerName}}, PatchableUnitName, Version, PatchUrl
    $groupedUpdates = @()
    foreach($updGroup in ($updatesReport | Group-Object ServerName))
    {
        $groupedUpdates += [PSCustomObject]@{
            ServerName        = $updGroup.Name
            PatchableUnitName = (($updGroup.Group | ForEach-Object {$_.PatchableUnitName}) -join '~~~BR~~~')
            Version           = (($updGroup.Group | ForEach-Object {$_.Version})           -join '~~~BR~~~')
            PatchUrl          = (($updGroup.Group | ForEach-Object {$_.PatchUrl})          -join '~~~BR~~~')
        }
    }
    $FarmUpdateHistory.InputObject = $groupedUpdates

    $orphanedSviQuery = "
        select count (1) as NumRows
        from dbo.ServerVersionInformation svi
        left join dbo.Objects obj
        on svi.ServerId = obj.Id
        where obj.Id is null
    "
    $orphanedSviResults = Invoke-SPSqlCommand -spDatabase $configDb -query $orphanedSviQuery
    if($orphanedSviResults.NumRows -ge 1)
    {
        ## There are orphaned records in dbo.ServerVersionInformation pertaining to removed/defunct servers objects.
        ## Fixing this requires direct db modification and a support case to be opened.

        $FarmUpdateHistory.WarningMessage += "Orphaned records found in ServerVersionInformation, please open a support case with Microsoft for assistance"
        $FarmUpdateHistory.Severity = [SPDiagnostics.Severity]::Critical
    }

    return $FarmUpdateHistory
}

function Get-ConfigDbVersionsTable
{

    $configDBVersions = New-DiagnosticFinding -Name "ConfigDB Versions" -InputObject $null -Format Table -Description "Versions table from the Config DB"

    $configDb = Get-SPConfigurationDatabase
    $query = "
        select * from versions
    "
    $versionsTable = Invoke-SPSqlCommand -spDatabase $configDb -query $query
    # Invoke-SPSqlCommand returns DataRow objects; selecting the actual table columns
    # strips DataRow metadata (RowError, RowState, Table, ItemArray, HasErrors).
    if ($versionsTable)
    {
        $cols = @($versionsTable)[0].Table.Columns | ForEach-Object { $_.ColumnName }
        $versionsTable = $versionsTable | Select-Object $cols
    }
	$configDBVersions.InputObject = $versionsTable
	return $configDBVersions
}

function Get-SPUpgradeSessionsFinding
{
    $spUpgradeSessionFinding = New-DiagnosticFinding -Name "SPUpgrade Sessions" -InputObject $null -Format Table -Description "Should contain info similar to '/_admin/UpgradeStatus.aspx' in Central Admin </br>"

    $configDb = Get-SPConfigurationDatabase

    # Query to pull SPUpgradeSession objects
    $query = @"
SELECT [Properties]
FROM [Objects]
WHERE [Properties] LIKE '<object type="Microsoft.SharePoint.Upgrade.SPUpgradeSession,%'
"@

    # Load SQL client
    Add-Type -AssemblyName "System.Data"

    $connString = $configDb.databaseConnectionString
    $conn = New-Object System.Data.SqlClient.SqlConnection $connString
    $cmd  = New-Object System.Data.SqlClient.SqlCommand $query, $conn

    $conn.Open()
    $reader = $cmd.ExecuteReader()

    $spUpgradeSessions = @()

    while ($reader.Read()) {

        $xmlString = $reader["Properties"]

        # Parse XML
        $xml = [xml]$xmlString

        # Create output object
        $obj = [PSCustomObject]@{}

        # Extract <sFld> and <fld> nodes
        foreach ($node in $xml.object.ChildNodes)
        {

            $name = $node.name
            $value = $null

            switch ($node.LocalName)
            {

                "sFld"
                {
                    # Simple typed field
                    $value = $node.'#text'
                }

                "fld"
                {
                    # Could be null or typed
                    if ($node.type -eq "null")
                    {
                        $value = $null
                    }
                    else {
                        $value = $node.'#text'
                    }
                }
            }

            # Add property dynamically
            if($name)
            {
                $name = $name.TrimStart("m_")
                Add-Member -InputObject $obj -MemberType NoteProperty -Name $name -Value $value -Force
            }
        }

        $spUpgradeSessions += $obj
    }

    $conn.Close()
    $spUpgradeSessions = @($spUpgradeSessions | Sort-Object -Property server, LastUpdatedTime)

    # Consolidate to one row per server (server shown once); stack each session's columns in parallel
    # using the ~~~BR~~~ sentinel (<br/> in HTML, " | " in text), matching "Installed Updates".
    if ($spUpgradeSessions.Count -gt 0)
    {
        # Columns are built dynamically from the SPUpgradeSession XML, so derive them from the objects.
        $stackColumns = $spUpgradeSessions[0].PSObject.Properties.Name | Where-Object {$_ -ne 'server'}

        $groupedSessions = @()
        foreach ($sessGroup in ($spUpgradeSessions | Group-Object server))
        {
            $row = [ordered]@{server = $sessGroup.Name}
            foreach ($col in $stackColumns)
            {
                $row[$col] = (($sessGroup.Group | ForEach-Object {$_.$col}) -join '~~~BR~~~')
            }
            $groupedSessions += [PSCustomObject]$row
        }
        $spUpgradeSessionFinding.InputObject = $groupedSessions
    }
    else
    {
        $spUpgradeSessionFinding.InputObject = $spUpgradeSessions
    }

    return $spUpgradeSessionFinding
}

function Get-SPManagedAcountsWithPwdProps
{
    $ManagedAccountData = Get-SPManagedAccount
    $ManagedAccountInfo = @()
    foreach ($ma in $ManagedAccountData)
    {
        $maInfo = New-Object psobject
        $maInfo | Add-Member -MemberType NoteProperty -Name Username -value $($ma.Username)
        $maInfo | Add-Member -MemberType NoteProperty -Name Displayname  -value $($ma.Displayname)
        $maInfo | Add-Member -MemberType NoteProperty -Name AutomaticChange  -value $ma.AutomaticChange
        $maInfo | Add-Member -MemberType NoteProperty -Name EnableEmailBeforePasswordChange  -value $ma.EnableEmailBeforePasswordChange
        $maInfo | Add-Member -MemberType NoteProperty -Name DaysBeforeChangeToEmail  -value $ma.DaysBeforeChangeToEmail
        $maInfo | Add-Member -MemberType NoteProperty -Name DaysBeforeExpiryToChange  -value $ma.DaysBeforeExpiryToChange
        $maInfo | Add-Member -MemberType NoteProperty -Name CanChangePassword  -value $ma.CanChangePassword
        $maInfo | Add-Member -MemberType NoteProperty -Name PasswordLastChanged  -value $ma.PasswordLastChanged
        $maInfo | Add-Member -MemberType NoteProperty -Name PasswordExpiration  -value $ma.PasswordExpiration
        $maInfo | Add-Member -MemberType NoteProperty -Name MinPasswordLen  -value $ma.MinPasswordLen
        $maInfo | Add-Member -MemberType NoteProperty -Name ChangeSchedule  -value $ma.ChangeSchedule
        $ManagedAccountInfo += $maInfo
    }
    $ManagedAccountData = $Null;
    return New-DiagnosticFinding -Name "Managed Accounts " -InputObject $ManagedAccountInfo -Format Table 
}

function Get-FarmAVSettings
{
    $AVfinding = New-DiagnosticFinding -Name "SharePoint AntiVirus settings" -Severity Default -InputObject $null -Format List 
 
    # Get a reference to the Administration
    $adminService = [Microsoft.SharePoint.Administration.SPWebService]::ContentService

    # get  antivirus settings
    $AVSettings = $adminService.AntivirusSettings | Select-Object AllowDownload,AllowQuarantinedFileDownload,CleaningEnabled,DownloadScanEnabled,GuestUserDownloadScanEnabled,MaxScanFileSize,MaxGuestUserDownloadScanFileSize,NumberOfThreads,Timeout,UploadScanEnabled,VendorUpdateCount,SkipSearchCrawl,VendorId,AutomaticUpdateSchedule 
    if ($AVSettings.VendorId -eq 0)
    {
        return
        #$AVfinding.Description +="No AntiVirus software is used for SharePoint."
    } else {
        if ($AVSettings.CleaningEnabled)
        {
            $AVfinding.WarningMessage +="An attempt to clean viruses from files is made by the AV scanner. This can result in corruptions in the files."
            $AVfinding.Severity = [SPDiagnostics.Severity]::Informational
        }
        if ($AVSettings.AllowQuarantinedFileDownload)
        {
            $AVfinding.WarningMessage +="Users are allowed to download files that are quarantined by the SharePoint Virus scanner."
            $AVfinding.Severity = [SPDiagnostics.Severity]::Warning
        }
        if (!$AVSettings.UploadScanEnabled)
        {
            $AVfinding.WarningMessage +="A SharePoint Virus scanner is enabled, but items are not scanned when they are uploaded to SharePoint."
            $AVfinding.Severity = [SPDiagnostics.Severity]::Warning
        }
        if (!$AVSettings.DownloadScanEnabled)
        {
            $AVfinding.WarningMessage +="A SharePoint Virus scanner is enabled, but items are not scanned when they are downloaded from SharePoint."
            $AVfinding.Severity = [SPDiagnostics.Severity]::Warning
        }
        if (!$AVSettings.GuestUserDownloadScanEnabled)
        {
            $AVfinding.WarningMessage +="A SharePoint Virus scanner is enabled, but items are not scanned when they are downloaded from SharePoint by guest users."
            $AVfinding.Severity = [SPDiagnostics.Severity]::Warning
        }
        $AVSettings.MaxScanFileSize = $AVSettings.MaxScanFileSize.ToString('N0')
        $AVSettings.MaxGuestUserDownloadScanFileSize=$AVSettings.MaxGuestUserDownloadScanFileSize.ToString('N0')
        $AVfinding.InputObject = $AVSettings
    }
    return  $AVfinding
}

function Get-SPDiagnosticsSqlAlias
{
    $servers = $script:servers | Where-Object {$_.role -ne "Invalid"}
    $serverAliases = @()
    foreach($server in $servers)
    {
        try
        {
            $registryHive  = [Microsoft.Win32.RegistryHive]::LocalMachine
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($registryHive, $server.Name)
            $key = $reg.OpenSubKey("SOFTWARE\\Microsoft\\MSSQLServer\\Client\\ConnectTo")
            if($null -ne $key)
            {
            $aliases = $key.GetValueNames()
                foreach($alias in $aliases)
                {
                    $serverAliases += [PSCustomObject]@{
                        Server = $($server.Name)
                        ServerAlias = $($alias)
                        ConnectionString = $(($key.GetValue($alias).ToString().Replace("DBMSSOCN,", "").Replace("DBNMPNTW,","")))
                     }
                }
            }
        }
        catch
        {
        }
    }
    if($serverAliases.Count -ge 1)
    {
        # Consolidate to one row per server (server shown once); stack alias columns in parallel
        # using the ~~~BR~~~ sentinel (<br/> in HTML, " | " in text), matching "Service Instances on Server(s)".
        $groupedAliases = @()
        foreach($aliasGroup in ($serverAliases | Group-Object Server))
        {
            $groupedAliases += [PSCustomObject]@{
                Server           = $aliasGroup.Name
                ServerAlias      = (($aliasGroup.Group | ForEach-Object {$_.ServerAlias})      -join '~~~BR~~~')
                ConnectionString = (($aliasGroup.Group | ForEach-Object {$_.ConnectionString}) -join '~~~BR~~~')
            }
        }
        return New-DiagnosticFinding -Name "Sql Aliases" -InputObject $groupedAliases -Format Table -Description "SQL Server aliases that are currently configured in cliconfg"
    }
}

function Get-SPDiagnosticServersInFarm
{
    $serverColl = @()
    $servers = $script:servers
    $spProduct = Get-SPProduct
    foreach($svr in $servers)
    {
        $productStatus = $null
        if($svr.Role -ne "Invalid")
        {
            $productStatus = $spProduct.GetStatus($svr.DisplayName) | Select-Object -Unique


            if($productStatus -ine "NoActionRequired" -and $productStatus -ine "UpgradeAvailable")
            {
                #$message = "'" + $productStatus.ToString() + "'" + " has been detected on server: " + $svr.DisplayName + ". This puts the farm\server in an 'UNSUPPORTED' and unstable state and patching\psconfig needs to be completed before any further troubleshooting. Support cannot provided until this is resolved"
                #Write-Warning -Message $message
                $productStatusBool = $true
                if ($productStatusLevel -ne [SPDiagnostics.Severity]::Critical) {$productStatusLevel = [SPDiagnostics.Severity]::Warning }
                if($productStatus -ieq "UpgradeBlocked" -or $productStatus -ieq "InstallRequired" -or $productStatus -ieq "UpgradeInProgress" )
                {
                    $productStatusLevel = [SPDiagnostics.Severity]::Critical
                }
            }

        }

        $osInfo = Get-SPDiagnosticsOsInfo $svr

        $serverCollItem =  [PSCustomObject]@{
            Name = $($svr.DisplayName)
            Role = $svr.Role
            RoleCompliant = $svr.CompliantWithMinRole
            Id = $svr.Id
            EncodedServerId = $svr.EncodedServerId
            Status = $svr.Status
            ProductStatus = $productStatus
			OperatingSystem = $osInfo.OSName
			ServicePack = $osInfo.ServicePack
			Model = $osInfo.Model
			Processors = $osInfo.ProcessorCount
			Cores = $osInfo.ProcessorCoreCount
			TotalRAM = $osInfo.TotalRAM
			TimeZone = $osInfo.TimeZone
        }
        
        $serverColl+=$serverCollItem

         #Task 501: Moving OSInfo to only be included if -Performance is specified during script execution due to perf hit
         #if($Performance)
         #{
         #   $osInfo = Get-SPDiagnosticsOsInfo $svr
		 #
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $osInfo.OSName
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name ServicePack -Value $osInfo.ServicePack
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name Model -Value $osInfo.Model
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name Processors -Value $osInfo.ProcessorCount
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name Cores -Value $osInfo.ProcessorCoreCount
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name TotalRAM -Value $osInfo.TotalRAM
         #   $serverCollItem | Add-Member -MemberType NoteProperty -Name TimeZone -Value $osInfo.TimeZone
		 #
         #}
    }
    
    $finding = New-DiagnosticFinding -Name "Servers in Farm" -Severity Default -InputObject $serverColl -Format Table
    Add-DiagnosticCommandSnapshot -Finding $finding -CommandName 'Get-SPServer' -Records $servers -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Cached Get-SPServer inventory' -Coverage 'Servers returned during initialization; selected identity, role, and status properties.' -PropertyNames @(
        'Id', 'Name', 'DisplayName', 'Address', 'Role', 'Status'
    )

    #Servers in Custom Role
    $CustomRoleServers =@()
    foreach ($spserver in $servercoll)
    {
        if ($spserver.role -eq "Custom")
        {
            $CustomRoleServers += $spServer.Name
        }
    }
    if ($CustomRoleServers.Count -gt 0)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Informational
        $customRoleNotes = "- This server role is typically used to run services that do not integrate with MinRole. The farm administrator has full control over which service instances can run on servers assigned to the Custom server role. </br>- MinRole will not attempt to manage servers assigned to this role."
        if ($CustomRoleServers.count -eq 1)
        {
            $finding.WarningMessage += "- The server $($($CustomRoleServers[0])) is running in MinRole: 'Custom'. </br>- Servers in the 'Custom' MinRole are not self healing. </br>$customRoleNotes"
        } else {
            $finding.WarningMessage += "- The servers '$($($CustomRoleServers -join "', '"))' are running in MinRole: 'Custom'. </br>- Servers in the 'Custom' MinRole are not self healing. </br>$customRoleNotes" 
        }
        $finding.ReferenceLink +="https://learn.microsoft.com/en-us/SharePoint/install/overview-of-minrole-server-roles-in-sharepoint-server#how-does-minrole-improve-performance-and-reliability"
    } 

    #Servers not role compliant
    if ($SCript:Build -ne "2013")
    {
        $NonRoleCompliantServers =@()
        foreach ($spserver in $servercoll)
        {
            if (!(($spserver.role -eq "Invalid" ) -or ($SPServer.Role -eq "Custom")))
            {
                if (!($spserver.RoleCompliant ))
                {
                    $NonRoleCompliantServers += $spServer.Name
                }
            }
        }
        if ($NonRoleCompliantServers.Count -gt 0)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            if ($NonRoleCompliantServers.count -eq 1)
            {
                $finding.WarningMessage += "The server $($($NonRoleCompliantServers[0])) is not Role Compliant in the Farm. Make sure that all required services are running and that no extra services are running on the servers."
            } else {
                $finding.WarningMessage += "The servers $($($NonRoleCompliantServers -join ",")) are not Role Compliant in the Farm. Make sure that all required services are running and that no extra services are running on the servers."
            }
            $finding.WarningMessage += "Validate in the Services on Server page in Central Administration what service is in an incorrect state and try to fix this service."
            $finding.ReferenceLink +="https://learn.microsoft.com/en-us/SharePoint/administration/description-of-minrole-and-associated-services-in-sharepoint-server-2016"
        } 
    }
    
    <# task:546 removing PatchInfo
    if($PatchInfo)
    {
        $patchInfoServerList = $servers | Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
        foreach($server in $patchInfoServerList)
        {
            $finding.ChildFindings.Add((Get-SPPatchInfo $server))
        }
    }
    #>

    if($productStatusBool)
    {
        $finding.Severity = $productStatusLevel
        $finding.WarningMessage = "Inconsistent patch or upgrade state identified, please complete relevant actions on the identified servers"
        $finding.Expand = $false
    }

    #Task: FIPS check. Only surfaces when FIPS is actually enabled on a server; otherwise the helper
    #returns $null and the finding is omitted from the report entirely.
    $fipsFinding = Get-SPDiagnosticFIPSFinding
    if($null -ne $fipsFinding)
    {
        $finding.ChildFindings.Add($fipsFinding)
    }

    $finding.ChildFindings.Add((Get-MissingPatches))
    $finding.ChildFindings.Add((Get-WindowsSerivcesOnServer))
    $finding.ChildFindings.Add((Get-ServerLocalGroupMemberships))
    $finding.ChildFindings.Add((Get-UserRightsAssignments))
    $finding.ChildFindings.Add((Get-HDDiskStatistics))
    #Task 528: Move SQL Alias finding to SQL servers
    #Reverted: SQL Alias finding moved back under "Servers in Farm"
    $sqlAliasFinding = Get-SPDiagnosticsSqlAlias
    if($sqlAliasFinding.InputObject.Count -ge 1)
    {
        $finding.ChildFindings.Add($sqlAliasFinding)
    }
    #Task 529: Move behind extended findings switch
    #Task 602: Removed extendedfindings switch
    #if($ExtendedFindings)
    #{
    #    $finding.ChildFindings.Add((Get-WindowsSerivcesOnServer))
    #    $finding.ChildFindings.Add((Get-ServerLocalGroupMemberships))
    #}
    #if($ExtendedFindings -or $Performance)
    #{
    #    $finding.ChildFindings.Add((Get-UserRightsAssignments))
    #    $finding.ChildFindings.Add((Get-HDDiskStatistics))
    #}

    #Task 471: move from Farm Finding so Server sub finding
    #Task 501: Moving to only call if -Performance switch is used
    if($Performance)
    {
        $finding.ChildFindings.Add((Get-SPDiagnosticFarmNetworkLatency))
    }

    return $finding
}

function Get-SPDiagnosticFIPSFinding
{
    # Checks whether FIPS (Federal Information Processing Standard) mode is enabled on any farm
    # server by reading HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled via the
    # remote registry (same approach used by the Kerberos findings). FIPS is NOT supported by
    # SharePoint Server, so if it is enabled anywhere a Critical finding is raised. The finding is
    # only returned when FIPS is detected on at least one server; otherwise $null is returned and the
    # caller omits it, keeping it out of the report when it is not present.
    $FipsKeyPath = "SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    $fipsServers = @()

    $FarmServers = Get-SPServer | Where-Object { $_.Role -ne "Invalid" } | Sort-Object Name
    foreach ($Server in $FarmServers)
    {
        $enabledValue = $null
        $regKey = $null
        try
        {
            $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $Server.Name,
                [Microsoft.Win32.RegistryView]::Registry64)

            $subKey = $regKey.OpenSubKey($FipsKeyPath)
            if ($subKey)
            {
                try   { $enabledValue = $subKey.GetValue("Enabled") }
                finally { $subKey.Close() }
            }
        }
        catch
        {
            # Unable to read the remote registry (e.g. the Remote Registry service is stopped or the
            # server is unreachable). Skip this server rather than raising a false FIPS finding.
            $enabledValue = $null
        }
        finally
        {
            if ($regKey) { $regKey.Close() }
        }

        if ($null -ne $enabledValue -and [int]$enabledValue -eq 1)
        {
            $fipsServers += [PSCustomObject]@{
                Server         = $Server.Name
                "FIPS Enabled" = "Yes"
                "Registry Key" = "HKLM\$FipsKeyPath\Enabled = 1"
            }
        }
    }

    if ($fipsServers.Count -eq 0)
    {
        # FIPS is not enabled on any server, so there is nothing to report; omit the finding.
        return $null
    }

    $fipsFinding = New-DiagnosticFinding -Name "FIPS Enabled (Not Supported)" -InputObject $fipsServers -Format Table

    $fipsFinding.WarningMessage += " - FIPS (Federal Information Processing Standard) compliant algorithms are ENABLED on one or more servers. </br> - FIPS is NOT supported by SharePoint Server and can cause a wide range of failures (for example in search, User Profile synchronization, and workflows).</br> - To remediate, you <strong>must</strong> disable the 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' security policy (or the FipsAlgorithmPolicy registry value) on the affected server(s) and restart them."
    $fipsFinding.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/federal-information-processing-standard-security-standards"
    # Set Critical only after the WarningMessage is populated. New-DiagnosticFinding warns (and logs to
    # the Script Execution finding) if a Warning/Critical finding is created with an empty message.
    $fipsFinding.Severity = [SPDiagnostics.Severity]::Critical

    return $fipsFinding
}

function Get-SPDiagnosticsOsInfo
{
    [CmdletBinding()]
    Param([Microsoft.SharePoint.Administration.SPServer]$server)

    try {
        $timeZone = (Get-CimInstance -ClassName Win32_TimeZone -ComputerName $server.DisplayName -OperationTimeoutSec 5 -ErrorAction Stop).Description

        $sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem -Namespace "root\CIMV2" -ComputerName $server.DisplayName -OperationTimeoutSec 5 -ErrorAction Stop
        $os      = Get-CimInstance -ClassName Win32_OperatingSystem -Namespace "root\CIMV2" -ComputerName $server.DisplayName -OperationTimeoutSec 5 -ErrorAction Stop
        $procs   = Get-CimInstance -ClassName Win32_Processor -Namespace "root\CIMV2" -ComputerName $server.DisplayName -OperationTimeoutSec 5 -ErrorAction Stop
        #$mem    = Get-CimInstance -ClassName Win32_PhysicalMemory -Namespace "root\CIMV2" -ComputerName $server.DisplayName -OperationTimeoutSec 5 -ErrorAction Stop

        if (![string]::IsNullOrEmpty($os.Name)) {
            $osName = $os.Name.Substring(0, $os.Name.IndexOf("|"))
            $osName = $osName.Replace("Microsoft Windows", "")
        } else {
            $osName = [string]::Empty
        }

        if (![string]::IsNullOrEmpty($os.ServicePackMajorVersion)) {
            $servicePack = "SP $($os.ServicePackMajorVersion)"
        } else {
            $servicePack = [string]::Empty
        }

        $model      = [string]$sysInfo.Model
        $procCount  = @($procs).Count
        $coreCount  = $procs[0].NumberOfLogicalProcessors
        $totalRAM   = "$([Math]::Round($sysInfo.TotalPhysicalMemory / 1GB, 2)) GB"
    }
    catch {
        return $null
    }

    [PSCustomObject]@{
        TimeZone          = $timeZone
        OsName            = $osName
        ServicePack       = $servicePack
        Model             = $model
        ProcessorCount    = $procCount
        ProcessorCoreCount= $coreCount
        TotalRAM          = $totalRAM
    }
}

<# task:546 removing PatchInfo
function Get-SPPatchInfo
{
    [cmdletbinding()]
    Param([Microsoft.SharePoint.Administration.SPServer]$server)

    $patchInfoScriptBlk = {
        $ErrorActionPreference = 'SilentlyContinue' 
        #Install MSI module
        Install-Module -Name MSI -SkipPublisherCheck
    
        $Session = New-Object -ComObject "Microsoft.Update.Session"
        $Searcher = $Session.CreateUpdateSearcher()
    
        $historyCount = $Searcher.GetTotalHistoryCount()
    
        $results = @{}
    
        #List SP MSI's, these SP patches are the ones installed manually 
        $msiInfo = Get-MsiPatchInfo | Where-Object {$_.DisplayName -match "SharePoint"}
        $msiInfo | ForEach-Object{
            $KBNumber = $_.DisplayName.Substring($_.DisplayName.IndexOf("(")+1,( $_.DisplayName.IndexOf(")") - $_.DisplayName.IndexOf("(")-1))
            $URI = New-Object System.Uri "https://support.microsoft.com/en-us/Search/results?query=$KBNumber"
    
            $result = New-Object PSObject
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Source" -Value "MSI"
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Title" -Value $_.DisplayName
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Install Date" -Value $_.InstallDate
            Add-Member -InputObject $result -MemberType NoteProperty -Name "KB" -Value $KBNumber
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Url" -Value $URI
    
            $results.add($KBNumber, $result)
        }
        
        #Add WSUS SP updates, installed via windows update
       $searchResults = $Searcher.QueryHistory(0, $historyCount) | Where-Object{$_.Operation -eq 1 -and $_.Title -match "SharePoint"} | Select-Object Title, Date 
       $searchResults | ForEach-Object{
            $KBNumber = $_.Title.Substring($_.Title.IndexOf("(")+1,( $_.Title.IndexOf(")") - $_.Title.IndexOf("(")-1))
            $URI = New-Object System.Uri "https://support.microsoft.com/en-us/Search/results?query=$KBNumber"
        
            $result = New-Object PSObject
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Source" -Value "WSUS"
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Title" -Value $_.Title
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Install Date" -Value $_.Date
            Add-Member -InputObject $result -MemberType NoteProperty -Name "KB" -Value $KBNumber
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Url" -Value $URI
           
            $results.add($KBNumber, $result) 
        }
    
        $newResults = @()
        foreach($key in $results.Keys)
        {
            $result = $results[$key]
            $newResults += $result
        }
    
        $ErrorActionPreference = $currenAction
    
        #Pick up top 2 results, either this will be WSUS or MSI's
        return ($newResults | sort-object "Install Date" -Descending | Select-Object -First 4)
    }

    $output = Invoke-Command -ComputerName $server.DisplayName -ScriptBlock $patchInfoScriptBlk
    $refined = $output | select-object Source, Title, "Install Date", KB, Url

    if($null -ne $refined)
    {
        $patchFinding = New-DiagnosticFinding -Name $server.DisplayName -Severity Default -InputObject $refined -format Table -Description "Patching Information"
        return $patchFinding
    }

    return $null

}
    #>

function Get-MissingPatches
{
    if ($Script:Build -eq "2013")
    {
        [void][System.Reflection.Assembly]::Load("Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c")
    } else {
        [void][System.Reflection.Assembly]::Load("Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c")
    }
    
    $InstalledProducts=@()

    $MissingPatchesFindings = New-DiagnosticFinding -Name "Missing Patches" -Severity Default -InputObject $null -format List
    $foundMissingPatch = $false

    try
    {
        $SPServers =  $script:servers | Where-Object {$_.role -ne "invalid"}
        $ServerNum = $SPServers.Count


        $ServerCount = $ServerNum 
        $ProdsCount, $ProdInfosCount = 0,0

        [Microsoft.SharePoint.Administration.SPProductVersions] $versions = [Microsoft.SharePoint.Administration.SPProductVersions]::GetProductVersions()
        $infos = New-Object 'System.Collections.Generic.List[Microsoft.SharePoint.Administration.SPServerProductInfo]' (,$versions.ServerInformation)
        
        foreach ($prodInfo in $infos)
        {
            $ProdsCount = 0;
            $ProdInfosCount = 0;
            $products = New-Object 'System.Collections.Generic.List[System.String]' (,$prodInfo.Products)
            $products.Sort()
            #
            #$serverProducts[$ServerCount, $ProdsCount, $ProdInfosCount] = $prodInfo.ServerName
            foreach ($str in $products)
            {
                $ProdsCount++
                $singleProductInfo = $prodInfo.GetSingleProductInfo($str)
                $patchableUnitDisplayNames = New-Object 'System.Collections.Generic.List[System.String]' (,$singleProductInfo.PatchableUnitDisplayNames)
                $patchableUnitDisplayNames.Sort()
                foreach ($str2 in $patchableUnitDisplayNames)
                {
                    $patchableUnitInfoByDisplayName = New-Object 'System.Collections.Generic.List[Microsoft.SharePoint.Administration.SPPatchableUnitInfo]' (,$singleProductInfo.GetPatchableUnitInfoByDisplayName($str2))
                    foreach ($info in $patchableUnitInfoByDisplayName)
                    {
                        $pi = New-Object psobject 
                        $pi | Add-Member -MemberType NoteProperty -Name "server" -Value  $($prodInfo.ServerName)
                            #"Product" = $str
                        $pi | Add-Member -MemberType NoteProperty -Name "ProductName" -Value $info.DisplayName
                        $pi | Add-Member -MemberType NoteProperty -Name "ProductVersion" -Value $info.LatestPatchOnServer($prodInfo.ServerId).Version.ToString() 
                        
                        $InstalledProducts+=$pi
                     }
                }
                $ProdInfosCount = 0
            }
            $ServerCount--
        }
    }
    catch [System.Exception] 
    {
		
    }

    $UniqeProducts =  ($InstalledProducts).ProductName | Select-Object -Unique

    foreach ($prod in $UniqeProducts)
    {
        $pvs = $InstalledProducts | Where-Object {$_.ProductName -eq $prod} | select-Object ProductVersion -Unique
        if ($pvs.count -gt 1)
        {
            $ppis = $InstalledProducts | Where-Object {$_.ProductName -eq $prod} | select-Object ProductName, Server, ProductVersion 
            $MissingPatchFinding = New-DiagnosticFinding -Name " Missing Patches - $prod" -Severity Default -InputObject $ppis -format Table -Description "Installed Patches"

            $PatchMissingOnServers=@()
            $MaxVersion = (($pvs.ProductVersion | Sort-Object -Descending)[0])
            foreach ($ppi  in $ppis)
            {
                if ($ppi.ProductVersion -ne $MaxVersion)
                {
                    $PatchMissingOnServers += $ppi.Server
                }
            }
            $MissingPatchFinding.WarningMessage += "Patch for $($ppi.ProductName) is missing on Server(s) $($PatchMissingOnServers -join ', ')"
            $MissingPatchFinding.Severity=[SPDiagnostics.Severity]::Warning
            $MissingPatchesFindings.ChildFindings.Add($MissingPatchFinding)
        }
           
    }
    if ($foundMissingPatch)
    {
        $MissingPatchesFindings.Description ="Make sure you install all SharePoint Patches on all SharePoint Servers and run the SharePoint Products Configuration Wizard"

    }
    else
    {
        return
        #$MissingPatchesFindings.Description ="All SharePoint Servers are on the same patch level for all SharePoint Products"
    }
    return $MissingPatchesFindings
}

function Get-WindowsSerivcesOnServer
{
    $WindowsSerivcesOnServerfinding = New-DiagnosticFinding -Name "Windows Services on Server(s)" -InputObject $null -Description "State of SharePoint related Windows Services on SharePoint Servers" -Format Table

    if ($Build -eq "SPSE")
    {
        $ServicesList = @("SPCache", "w3svc","AppFabricCachingService","SPTimerV4","SPUserCodeV4", "SPSEarchHostController","SPAdminV4", "SPWriterV4","OSearch16", "SPTraceV4") #c2wts
    } else {
        $ServicesList = @("AppFabricCachingService", "w3svc","AppFabricCachingService","SPTimerV4","SPUserCodeV4", "SPSEarchHostController","SPAdminV4", "SPWriterV4","OSearch16","SPTraceV4")
    }

    $WServiceInfos=@()
    $servers = $script:servers | Where-Object {$_.role -ne "Invalid"}
    foreach ($server in $servers)
    {
        $Services =  Get-WmiObject "Win32_Service" -ComputerName $server.name | Where-Object {$_.name -in $ServicesList} | Sort-Object DisplayName
        foreach ($s in $services)
        {
            $wServiceInfo = new-object psobject
            $wServiceInfo | Add-Member -MemberType NoteProperty -Name "Computer" -value $($s.systemname)
            $wServiceInfo | Add-Member -MemberType NoteProperty -Name "DisplayName" -value $s.displayname
            $wServiceInfo | Add-Member -MemberType NoteProperty -Name "Name" -value $s.name
            $wServiceInfo | Add-Member -MemberType NoteProperty -Name "Service Account" -value $($s.startname)
            $wServiceInfo | Add-Member -MemberType NoteProperty -Name "State" -value $s.state
            $wServiceInfo | Add-Member -MemberType NoteProperty -Name "StartMode" -value $s.startmode
            $WServiceInfos += $wServiceInfo

            # This needs to be tested with French/Spanish system. The term "runnning" could be translated
            if ($s.State -ne "Running" -and $s.StartMode -eq "Auto")
            {
                $WindowsSerivcesOnServerfinding.WarningMessage += "The service '"+ $s.Displayname + "' is configured to start automatically on Server '" +  $($s.systemname) + "' is not running."
                $WindowsSerivcesOnServerfinding.Severity = [SPDiagnostics.Severity]::Critical
            }

            if ($s.State -eq "Running" -and $s.StartMode -eq "Disabled")
            {
                $WindowsSerivcesOnServerfinding.WarningMessage += "The service '"+ $s.Displayname + "' is disabled on Server '" +  $($s.systemname) + "' but it is running."
                $WindowsSerivcesOnServerfinding.Severity = [SPDiagnostics.Severity]::Informational
            }
            if ($s.State -ne "Running" -and ($s.Name -eq "SPTimerV4" -or $s.name -eq "SPAdminV4"))
            {
                $WindowsSerivcesOnServerfinding.WarningMessage += "The critical service '"+ $s.Displayname + "' is not running on Server '" +  $($s.systemname) + "'."
                $WindowsSerivcesOnServerfinding.Severity = [SPDiagnostics.Severity]::Informational
            }
        
            #Check if SPAdminV4is running with Local System Account
            if ($s.Name -eq "SPAdminV4")
            {
                if ($s.Startname -notmatch "LocalSystem")
                {
                    $WindowsSerivcesOnServerfinding.WarningMessage += "The service '" + $s.Displayname + "' is not running in the 'Local System' account on server " +  $($s.systemname) + "."
                    $WindowsSerivcesOnServerfinding.Severity = [SPDiagnostics.Severity]::Warning

                }
            }
            #Check if SPTraceV4 is running with Local Service Account
            if ($s.Name -eq "SPTraceV4")
            {
                $objUser = New-Object System.Security.Principal.NTAccount($s.StartName)
                $objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value.ToString()
               
                if ($objSID -ne "S-1-5-19")
                {
                    $WindowsSerivcesOnServerfinding.WarningMessage += "The service '"+ $s.Displayname + "' is not running in the 'Local Service' account  on server " +  $($s.systemname) + "."
                    $WindowsSerivcesOnServerfinding.Severity = [SPDiagnostics.Severity]::Warning

                }
            }
        }
    }
    # Consolidate to one row per server (server shown once); stack each service's columns in parallel
    # using the ~~~BR~~~ sentinel (<br/> in HTML, " | " in text), matching "Service Instances on Server(s)".
    $groupedWServices = @()
    foreach($wsGroup in ($WServiceInfos | Group-Object Computer))
    {
        $groupedWServices += [PSCustomObject]@{
            Computer          = $wsGroup.Name
            DisplayName       = (($wsGroup.Group | ForEach-Object {$_.DisplayName})       -join '~~~BR~~~')
            Name              = (($wsGroup.Group | ForEach-Object {$_.Name})              -join '~~~BR~~~')
            'Service Account' = (($wsGroup.Group | ForEach-Object {$_.'Service Account'}) -join '~~~BR~~~')
            State             = (($wsGroup.Group | ForEach-Object {$_.State})             -join '~~~BR~~~')
            StartMode         = (($wsGroup.Group | ForEach-Object {$_.StartMode})         -join '~~~BR~~~')
        }
    }
    $WindowsSerivcesOnServerfinding.InputObject = $groupedWServices
    return $WindowsSerivcesOnServerfinding
}

function Get-HDDiskStatistics 
{
    $ServerHarddDisks = New-DiagnosticFinding -Name "Disk Usage on Servers" -InputObject $null -Format Table
    $DiskUsageInfos=@()
    $servers = $script:servers | Where-Object {$_.role -ne "Invalid"}
    foreach ($server in $servers)
    {
        $ServerDiskInfos = get-wmiObject -query "select * from win32_LogicalDisk where DriveType=3" -ComputerName $Server.Name

        # Collect each drive as a single line and accumulate per-server totals so all disks for a server land on one row
        $driveLines = @()
        $totalSizeBytes = 0
        $totalFreeBytes = 0
        $totalUsedBytes = 0

        foreach ($serverDiskInfo in $ServerDiskInfos)
        {
            $sizeGB = [math]::Round($serverDiskInfo.Size/1GB,1)
            $freeGB = [math]::Round($serverDiskInfo.FreeSpace/1GB,1)
            $usedGB = [math]::Round(($serverDiskInfo.Size - $serverDiskInfo.FreeSpace)/1GB,1)

            $totalSizeBytes += $serverDiskInfo.Size
            $totalFreeBytes += $serverDiskInfo.FreeSpace
            $totalUsedBytes += ($serverDiskInfo.Size - $serverDiskInfo.FreeSpace)

            $volumeName = $serverDiskInfo.VolumeName
            if([string]::IsNullOrEmpty($volumeName)) { $volumeName = "(no label)" }

            $driveLines += ("{0} ({1}) - {2} / {3} / {4} GB" -f $serverDiskInfo.DeviceID, $volumeName, $freeGB, $sizeGB, $usedGB)

            if ($serverDiskInfo.FreeSpace -lt 1GB )
            {
                $ServerHarddDisks.WarningMessage += "The Disk "+ $serverDiskInfo.DeviceID + " on server " + $server.Name +" has less than 1 GB free space"
                $ServerHarddDisks.Severity = [SPDiagnostics.Severity]::Warning

            } elseif ($serverDiskInfo.FreeSpace -lt 5GB )
            {
                $ServerHarddDisks.WarningMessage += "The Disk "+ $serverDiskInfo.DeviceID + " on server " + $server.Name +" has less than 5 GB free space"
                $ServerHarddDisks.Severity = [SPDiagnostics.Severity]::Informational
            }
        }

        # One consolidated row per server. Drive lines are joined with the ~~~BR~~~ sentinel which the
        # report writer converts to <br/> for HTML output (or " | " for text output).
        $sdi = new-object PSObject
        $sdi | Add-Member -MemberType NoteProperty -Name "Computer" -Value $($server.name)
        $sdi | Add-Member -MemberType NoteProperty -Name "Disks (Drive - Volume - Free / Size / Used GB)" -Value ($driveLines -join '~~~BR~~~')
        $sdi | Add-Member -MemberType NoteProperty -Name "Total Size (GB)" -Value $([math]::Round($totalSizeBytes/1GB,1))
        $sdi | Add-Member -MemberType NoteProperty -Name "Total Free (GB)" -Value $([math]::Round($totalFreeBytes/1GB,1))
        $sdi | Add-Member -MemberType NoteProperty -Name "Total Used (GB)" -Value $([math]::Round($totalUsedBytes/1GB,1))
        $DiskUsageInfos += $sdi
    }
    $ServerHarddDisks.InputObject = $DiskUsageInfos
    return $ServerHarddDisks
}

function Get-ServerLocalGroupMemberships
{
    $ServerLocalGroupMembers = New-DiagnosticFinding -Name "Local group members on servers" -InputObject $null -Format Table

    $spServers = $script:servers | where-object {$_.role -ne "Invalid"}
    #Task 578: Local "Administrators" group is localized, get the name from the well known SID
    $localAdminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $groups =@("WSS_WPG","WSS_ADMIN_WPG","WSS_RESTRICTED_WPG_V4",$localAdminGroup.Name,"IIS_IUSRS", "Performance Log Users", "Performance Monitor Users")
    $LocalGroupMemberships=@()

    foreach ($s in $spservers)
    {
        $serverName = $s.Name
        foreach ($g in $groups)
        {
            $GroupMembers = @()
            try {
                $ADSI = [ADSI]("WinNT://$serverName,Computer")
                $Group = $ADSI.PSBase.Children.Find($g,'Group')
                $GroupMembers=$Group.PSBase.Invoke('Members').Foreach{ $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null) }   

            } catch {}

            $members = @($GroupMembers) | Sort-Object
            if ($members.Count) { $memberStr = [string]::Join(" || ", $members) } else { $memberStr = "(none)" }
            $gmo = New-Object psobject
            $gmo | add-member -MemberType NoteProperty -Name "Server" -Value $($serverName)
            $gmo | add-member -MemberType NoteProperty -Name "Group" -Value $g
            $gmo | add-member -MemberType NoteProperty -Name "Members" -Value $memberStr
            $gmo | add-member -MemberType NoteProperty -Name "Count" -Value $members.Count
            $LocalGroupMemberships += $gmo
        }
    }

    #ToDo: Add validation

    # Consolidate to one row per server (server shown once); stack each group's columns in parallel
    # using the ~~~BR~~~ sentinel (<br/> in HTML, " | " in text), matching "Service Instances on Server(s)".
    $groupedLocalGroups = @()
    foreach($lgGroup in ($LocalGroupMemberships | Group-Object Server))
    {
        $groupedLocalGroups += [PSCustomObject]@{
            Server  = $lgGroup.Name
            Group   = (($lgGroup.Group | ForEach-Object {$_.Group})   -join '~~~BR~~~')
            Members = (($lgGroup.Group | ForEach-Object {$_.Members}) -join '~~~BR~~~')
            Count   = (($lgGroup.Group | ForEach-Object {$_.Count})   -join '~~~BR~~~')
        }
    }
    $ServerLocalGroupMembers.InputObject = $groupedLocalGroups
    return $ServerLocalGroupMembers
}

function Get-UserRightsAssignments
{
    $userRightsAssignment = New-DiagnosticFinding -Name "GPO - 'User Rights Assignment' Policies" -InputObject $null -Format Table
    # Get all SharePoint servers with valid roles
    $servers = $script:servers | Where-Object {$_.role -ne "Invalid"}

    # Map of privilege keys to gpedit.msc display names
    $RightDisplayMap = @{
        # Existing entries...
        SeNetworkLogonRight                  = "Access this computer from the network"
        SeBackupPrivilege                    = "Back up files and directories"
        SeChangeNotifyPrivilege              = "Bypass traverse checking"
        SeSystemtimePrivilege                = "Change the system time"
        SeCreatePagefilePrivilege            = "Create a pagefile"
        SeDebugPrivilege                     = "Debug programs"
        SeRemoteShutdownPrivilege            = "Force shutdown from a remote system"
        SeAuditPrivilege                     = "Generate security audits"
        SeIncreaseQuotaPrivilege             = "Adjust memory quotas for a process"
        SeIncreaseBasePriorityPrivilege      = "Increase scheduling priority"
        SeAssignPrimaryTokenPrivilege        = "Replace a process level token"
        SeRestorePrivilege                   = "Restore files and directories"
        SeShutdownPrivilege                  = "Shut down the system"
        SeTcbPrivilege                       = "Act as part of the operating system"
        SeServiceLogonRight                  = "Log on as a service"
        SeInteractiveLogonRight              = "Allow log on locally"
        SeDenyInteractiveLogonRight          = "Deny log on locally"
        SeDenyNetworkLogonRight              = "Deny access to this computer from the network"
        SeDenyServiceLogonRight              = "Deny log on as a service"
        SeBatchLogonRight                    = "Log on as a batch job"
        SeDenyBatchLogonRight                = "Deny log on as a batch job"
        SeRemoteInteractiveLogonRight        = "Allow log on through Remote Desktop Services"
        SeDenyRemoteInteractiveLogonRight    = "Deny log on through Remote Desktop Services"
        SeImpersonatePrivilege               = "Impersonate a client after authentication"
        SeLoadDriverPrivilege                = "Load and unload device drivers"
        SeLockMemoryPrivilege                = "Lock pages in memory"
        SeTakeOwnershipPrivilege             = "Take ownership of files or other objects"
        SeTimeZonePrivilege                  = "Change the time zone"
        SeMachineAccountPrivilege            = "Add workstations to domain"
        SeSecurityPrivilege                  = "Manage auditing and security log"
        SeProfileSingleProcessPrivilege      = "Profile single process"
        SeSystemProfilePrivilege             = "Profile system performance"
        SeUndockPrivilege                    = "Remove computer from docking station"
        SeTrustedCredManAccessPrivilege      = "Access Credential Manager as a trusted caller"
        SeCreateSymbolicLinkPrivilege        = "Create symbolic links"
        SeDelegateSessionUserImpersonatePrivilege = "Delegate session user impersonate"
        SeIncreaseWorkingSetPrivilege        = "Increase a process working set"
        SeManageVolumePrivilege              = "Perform volume maintenance tasks"
        SeSystemEnvironmentPrivilege         = "Modify firmware environment values"
        SeCreateGlobalPrivilege              = "Create global objects"
    }

    $scriptBlock = {
        param($RightDisplayMap)

        function Resolve-Principal
        {
            param([string]$Token)

            $t = $Token.Trim()
            if ($t.StartsWith('*'))
            {
                $t = $t.Substring(1).Trim()
            }

            if ($t -match '^S-1-\d+(-\d+)+$')
            {
                try
                {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($t)
                    return ($sid.Translate([System.Security.Principal.NTAccount])).Value
                }
                catch
                {
                    return $t
                }
            }
            return $t
        }

        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            secedit /export /cfg $tempFile /areas USER_RIGHTS | Out-Null
            $content = Get-Content -LiteralPath $tempFile -Encoding Unicode

            foreach ($line in $content) {
                if ($line -match '^(?<Right>[^=]+)=(?<Accounts>.*)$') {
                    $rightKey = $matches['Right'].Trim()
                    $rawAccounts = ($matches['Accounts'] -split ',') | Where-Object { $_.Trim() }
                    $resolved = foreach ($a in $rawAccounts) { Resolve-Principal $a }
                    $display = $RightDisplayMap[$rightKey]; if (-not $display) { $display = $rightKey }

                    [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        Policy        = $display
                        SecuritySettings   = ($resolved -join '  ||  ')
                    }
                }
            }
        }
        finally { Remove-Item $tempFile -ErrorAction SilentlyContinue }
    }

    # Run across all servers
    $results = foreach ($server in $servers)
    {
        Invoke-Command -ComputerName $server.Address -ScriptBlock $scriptBlock -ArgumentList $RightDisplayMap
    }

    # Consolidate to a single row per server. All policies for a server are stacked in one cell, joined with the
    # ~~~BR~~~ sentinel (rendered as <br/> in HTML, " | " in text). The policy name is wrapped in the
    # ~~~POLICYSTART~~~/~~~POLICYEND~~~ sentinels so it renders bold, separating it from the settings.
    # The security setting is wrapped in ~~~SETSTART~~~/~~~SETEND~~~ so it renders in light-blue.
    $consolidated = @()
    foreach ($group in ($results | Group-Object ComputerName | Sort-Object Name))
    {
        $policyLines = foreach ($row in ($group.Group | Sort-Object Policy))
        {
            "~~~POLICYSTART~~~{0}:~~~POLICYEND~~~ ~~~SETSTART~~~{1}~~~SETEND~~~" -f $row.Policy, $row.SecuritySettings
        }

        $uraRow = New-Object PSObject
        $uraRow | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $group.Name
        $uraRow | Add-Member -MemberType NoteProperty -Name "  Policy :  Security Setting" -Value ($policyLines -join '~~~BR~~~')
        $consolidated += $uraRow
    }

    # Display nicely
    $userRightsAssignment.InputObject = $consolidated
    return $userRightsAssignment
}

function Get-SPDiagnosticServicesOnServer
{
    [cmdletbinding()]
    Param()
    $finding = New-DiagnosticFinding -Name "Service Instances on Server(s)" -InputObject $null -Description "This should be equivalent to what we see in Central Admin on page '/_admin/FarmServices.aspx'<br/>" -Format Table
    $runningServices = @()
    $servers = $script:servers #| Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    foreach($server in $servers)
    {
        $services = $server.ServiceInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Disabled}
        foreach ($service in $services)
        {
            if($service.DisplayName -match "Search Data Acces")
            {
                $runningServices+=[PSCustomObject]@{
                Server = $($server.Address)
                Service = $service.DisplayName
                Status = $service.Status
                Id = $service.Id
                }
            }
            else
            {
                $runningServices+=[PSCustomObject]@{
                Server = $($server.Address)
                Service = $service.TypeName
                Status = $service.Status
                Id = $service.Id
                }
            }
        }
    }
    $runningServices = $runningServices | sort-object Server, Service, status

    # Consolidate to one row per server (server shown once). Each instance's Service/Status/Id is
    # stacked in parallel using the ~~~BR~~~ line-break sentinel (rendered as <br/> in HTML, " | " in
    # text), matching the "Disk Usage on Servers" presentation. The flat $runningServices list is kept
    # for the warning detection below.
    $groupedServices = @()
    foreach($svcGroup in ($runningServices | Group-Object Server))
    {
        $groupedServices += [PSCustomObject]@{
            Server  = $svcGroup.Name
            Service = (($svcGroup.Group | ForEach-Object {$_.Service}) -join '~~~BR~~~')
            Status  = (($svcGroup.Group | ForEach-Object {$_.Status})  -join '~~~BR~~~')
            Id      = (($svcGroup.Group | ForEach-Object {$_.Id})       -join '~~~BR~~~')
        }
    }
    $finding.InputObject = $groupedServices
    
    $troubleServices = $runningServices | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    if($null -ne $troubleServices)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "One or more services identified in a starting or stopping state"
    }
    $finding.ChildFIndings.add((Get-SPRequestManagementServiceFinding))
    return $finding
}

function Get-SPDatabasesInFarm
{	
	$spDatabasesInFarm = $script:spDatabases | Select Name, TypeName, Id, NormalizedDataSource, @{N="DB Size(GB)"; E={$(([System.Math]::Round($_.DiskSizeRequired/1gb,2)))}}, Status, BuildVersion, IsReadOnly, Encrypt, IsSqlAzure, Exists, Username, NeedsUpgrade, NeedsUpgradeIncludeChildren
    $dbCount = $spDatabasesInFarm.Count
	$spDatabasesInFarmFinding = New-DiagnosticFinding -Name "Databases in Farm: ($dbCount)" -Format Table -InputObject $null -Description "Shows the databases registered in Farm, per 'Get-SPDatabase' command <BR>"
    foreach($spDatabase in $spDatabasesInFarm)
    {
        if($spDatabase.NeedsUpgrade -eq $True -or $spDatabase.NeedsUpgradeIncludeChildren -eq $True)
        {
            $spDatabasesInFarmFinding.Severity = [SPDiagnostics.Severity]::Warning
            $spDatabasesInFarmFinding.WarningMessage = "The following database(s) have 'NeedsUpgrade' and\or 'NeedsUpgradeIncludeChildren' set to 'True'. <BR> These databases could have misaligned schemas and cause various issues within SharePoint"
        }
    }
	$spDatabasesInFarmFinding.inputObject = $spDatabasesInFarm
    Add-DiagnosticCommandSnapshot -Finding $spDatabasesInFarmFinding -CommandName 'Get-SPDatabase' -Records $script:spDatabases -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Cached Get-SPDatabase inventory' -Coverage 'Registered databases; selected identity, SQL source, build, and upgrade flags. Credentials and connection strings excluded.' -PropertyNames @(
        'Id', 'Name', 'TypeName', 'NormalizedDataSource', 'Status', 'BuildVersion',
        'IsReadOnly', 'Encrypt', 'IsSqlAzure', 'Exists', 'NeedsUpgrade'
    )
	return $spDatabasesInFarmFinding
}

function Get-SPRequestManagementServiceFinding()
{
    $RMInstances = get-spserviceinstance | Where-Object {$_.typename -eq "Request Management" }  | Select-Object Typename, @{l="Server";e={$_.Server.Address}}, Status, Id 
    foreach ($rmi in $RMInstances)
    {
        $rmi.Server = $($rmi.server)
    }
    $NonDisabledRMInstances = @()
    foreach ($rmInstance in $rmInstances)
    {
        if ($rmInstance.Status -ne "Disabled")
        {
            $NonDisabledRMInstances += $rmInstance
        }
    }
    if ($NonDisabledRMInstances.count -gt 0)
    {
        $RMFinding = New-DiagnosticFinding -Name "Request Management Service" -InputObject $NonDisabledRMInstances -Format Table
        $RMFinding.severity = [SPDiagnostics.Severity]::Critical
        $RMFinding.WarningMessage +="The Request Management Service in a SharePoint Farm should not be used when a Load Balancer is used for the farm"
        $RMFinding.ReferenceLink +="https://learn.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/configure-request-manager-in-sharepoint-server"
        $RMFinding.ReferenceLink +="http://www.harbar.net/articles/sp2013rm1.aspx"
        return $RMFinding
    }
    return $null
}
 
function Get-SPDiagnosticHealthAnalyzerFinding
{
    #Task 501: Changing call to retireve Central Admin web to be more performant
    #$CAWebUrl= ( Get-SPWebApplication -IncludeCentralAdministration | Where-Object { $_.IsAdministrationWebApplication -eq $true}).Url
    $w = [Microsoft.SharePoint.Administration.SPAdministrationWebApplication]::Local.Sites["/"].RootWeb    
    #$l = $w.lists | Where-Object {$_.basetemplate.value__ -eq 1221}
    $l = $w.GetList("/Lists/HealthReports")
    $query = New-Object Microsoft.SharePoint.SPQuery
    $query.RowLimit = 100
    $query.ViewAttributes = "Scope=`"Recursive`""
    $query.Query = "<Where><Neq><FieldRef Name='HealthReportSeverity' /><Value Type='Choice'>4 - Success</Value></Neq></Where>"
    $items = $l.GetItems($query)
    
    $MinSeverity="9"
    $HealthAnalyzerEntries = @()
    foreach ($HALe in $items)
    {
        $HAEntry = new-object PSObject
        $HAEntry | Add-Member -membertype NoteProperty -Name "Severity" -value $HALe["Severity"]
        $HAEntry | Add-Member -membertype NoteProperty -Name "Category" -value $HALe["Category"]
        $HAEntry | Add-Member -membertype NoteProperty -Name "Description" -Value $HALe.Title 
        $HAEntry | Add-Member -membertype NoteProperty -Name "Failing Servers" -Value $($HALe["ows_HealthReportServers"])
        $HAEntry | Add-Member -membertype NoteProperty -Name "Failing Services" -Value $HALe["ows_HealthReportServices"] 
        $HAEntry | Add-Member -membertype NoteProperty -Name "Remedy" -Value ($HALe["Remedy"]).Replace($w.Url,$($w.Url))
        $HAEntry | Add-Member -membertype NoteProperty -Name "Modified" -Value $HALe["Modified"]

        if ($HALe["Severity"].SubString(0,1) -le $MinSeverity)
        {
            $MinSeverity = $HALe["Severity"].SubString(0,1)
        }
        $HealthAnalyzerEntries += $HAEntry
    }
    if ($HealthAnalyzerEntries.Count -gt 0)
    {
        $HealthAnalyzerFinding = New-DiagnosticFinding -Name "SharePoint Health Analyzer " -InputObject ($HealthAnalyzerEntries | Sort-Object -Property Category, Severity)  -Format Table
        #if ($MinSeverity -eq 1) { $HealthAnalyzerFinding.Severity = [SPDiagnostics.Severity]::Critical}
        #elseif ($MinSeverity -eq 2) { $HealthAnalyzerFinding.Severity = [SPDiagnostics.Severity]::Warning}
        #else { $HealthAnalyzerFinding.Severity = [SPDiagnostics.Severity]::Informational}
        if ($MinSeverity -in 1,2) {$HealthAnalyzerFinding.Severity = [SPDiagnostics.Severity]::Informational}
        else {$HealthAnalyzerFinding.Severity = [SPDiagnostics.Severity]::Default}

        $HealthAnalyzerFinding.Description += "The following findings are in the SharePoint Health Analyzer"

        return $HealthAnalyzerFinding
    }
    return $null
}

function Get-SPDiagnosticTimerAndAdminServiceFinding
{
    [cmdletbinding()]
    Param()
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $timerInstances = $farm.TimerService.Instances | Select-Object @{l="Server";e={$_.Server.Address}}, Status, AllowServiceJobs, AllowContentDatabaseJobs, Id
    $problemTimerInstances = $timerInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    
    foreach ($ti in $timerInstances)
    {
        $ti.Server = $($ti.server)
    }
    
    $timerFinding = New-DiagnosticFinding -Name "Timer Service Instances" -InputObject $timerInstances -Format Table

    if($null -ne $problemTimerInstances)
    {
        $timerFinding.Severity = [SPDiagnostics.Severity]::Critical
        $timerFinding.WarningMessage += "One or more Timer Service Instances is not online"
        $timerFinding.Description+=("Example PowerShell to set the 'Timer Service Instance' object back online.<br/><div class=`"code`">`[Microsoft.SharePoint.Administration.SPFarm]::Local.TimerService.Instances | where{`$_.Status -ne `"Online`"} | foreach{`$_.Status = `"Online`"; `$_.Update()}</div>")
        $timerFinding.Description+="Once the above PowerShell is performed the 'SharePoint Timer Service' service on that server must be restarted (within services.msc console)"
        $timerFinding.ReferenceLink += "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"       
    }

    #Task 591: report if there are no servers that allow service or content db jobs
    $allowContentDbJobs = !(($timerInstances | Where-Object{$_.AllowContentDatabaseJobs}).Count -eq 0 -or $null -eq ($timerInstances | Where-Object{$_.AllowContentDatabaseJobs}))
    $allowServiceJobs = !(($timerInstances | Where-Object{$_.AllowServiceJobs}).Count -eq 0 -or $null -eq ($timerInstances | Where-Object{$_.AllowServiceJobs}))

    if(!$allowContentDbJobs)
    {
        $timerFinding.Severity = [SPDiagnostics.Severity]::Critical
        $timerFinding.WarningMessage += "There are no servers in the farm that are configured to run jobs with a `"Content Database`" lock type. <br>Steps to correct this can be found in the below blog post."
        $timerFinding.ReferenceLink += "https://joshroark.com/sharepoint-2016-2019-timer-jobs-with-contentdatabase-lock-type-do-not-run/"
    }

    if(!$allowServiceJobs)
    {
        $timerFinding.Severity = [SPDiagnostics.Severity]::Critical
        $timerFinding.WarningMessage += "There are no servers in the farm that are configured to run jobs with a `"Job`" lock type. <br>Steps to correct this can be found in the below blog post."
        $timerFinding.ReferenceLink += "https://joshroark.com/sharepoint-2016-2019-timer-jobs-with-job-lock-type-do-not-run/"
    }

    
    $adminSvc = $farm.Services | Where-Object{$_.TypeName -eq "Microsoft SharePoint Foundation Administration"}
    $adminInstances = $adminSvc.Instances | Select-Object @{l="Server";e={$_.Server.Address}}, Status, Id
    $problemAdminInstances = $adminInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    
     foreach ($ai in $adminInstances)
     {
         $ai.Server = $($ai.server)
     }
 
    $adminFinding = New-DiagnosticFinding -Name "Administration Service Instances" -InputObject $adminInstances -Format Table

    if($null -ne $problemAdminInstances)
    {
        $adminFinding.Severity = [SPDiagnostics.Severity]::Critical
        $adminFinding.WarningMessage = "One or more Admin Service Instances is not online"
        $adminFinding.Description +=("Example PowerShell to set the 'Admin Service Instance' object back online.<br/><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guid of disabled object')<br/>`$obj.Status = [Microsoft.SharePoint.Administration.SPObjectStatus]::Online<br/>`$obj.Update()</div>")
        $adminFinding.Description += "Once the above PowerShell is performed the 'SharePoint Administration' service on that server must be restarted (within services.msc console)<br/>"
        $adminFinding.ReferenceLink += "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"
    }


    $finding = New-DiagnosticFinding -Name "Timer and Admin Service Information" -InputObject $null -Format Table
    $finding.Description += "The 'Timer' and 'Admin' Service Instances are critical for proper SP functionality. They are *not* to be confused with the 'Timer' and 'SP Admin' services within 'services.msc' console."
    $finding.Description += "'Services' in the console can be 'running' fine, but if these 'instances' are not Online, then the execution of one-time timer jobs will not function."
    $finding.Description += "This can prevent other service instances from 'provisioning' properly."
    $finding.ChildFindings.Add($timerFinding)
    $finding.ChildFindings.Add($adminFinding)
    $finding.ChildFindings.Add((Get-SPDiagnosticTimerJobHistoryFinding))

    return $finding
}


function Get-SPDiagnosticFarmServicesFinding
{
    [cmdletbinding()]
    Param()
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $notOnlineServices = $farm.Services | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}

    #Only surface this finding when one or more farm services are not "Online"
    if($null -eq $notOnlineServices)
    {
        return $null
    }

    $servicesReport = $notOnlineServices | Select-Object @{l="TypeName";e={$_.TypeName}}, @{l="DisplayName";e={$_.DisplayName}}, Status, Id

    $finding = New-DiagnosticFinding -Name "Farm Services" -InputObject $servicesReport -Format Table
    $finding.Severity = [SPDiagnostics.Severity]::Critical
    $finding.WarningMessage += " - One or more Farm Services (`$farm.Services) are not 'Online'.</br> - The Farm Services listed above are in a status other than 'Online'. Farm Services that are not Online can prevent proper provisioning and functionality within the farm.</br> - Example PowerShell to set the Farm Service object(s) back to 'Online'.<br/><div class=`"code`">`$farm = Get-SPFarm<br/>`$farm.Services | Where-Object{`$_.Status -ne `"Online`"} | foreach{`$_.Status = [Microsoft.SharePoint.Administration.SPObjectStatus]::Online; `$_.Update()}</div>"

    return $finding
}


function Get-SPDiagnosticServiceAppInfo
{
    [cmdletbinding()]
    Param()
    # Build a combined Service Applications view mirroring Central Admin's
    # ServiceApplications.aspx: each service application followed by its connected
    # proxies (indented), then any proxies not connected to a service application.
    # Ported from the FillDataTable logic; the farm-admin gate is intentionally omitted.
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local

    # Gather all service applications, sorted by name (case-insensitive)
    $serviceApplications = @()
    foreach($service in $farm.Services)
    {
        foreach($app in $service.Applications)
        {
            $serviceApplications += $app
        }
    }
    $serviceApplications = @($serviceApplications | Sort-Object { $_.Name })

    # Gather all service application proxies
    $remainingProxies = [System.Collections.ArrayList]::new()
    foreach($serviceProxy in $farm.ServiceProxies)
    {
        foreach($appProxy in $serviceProxy.ApplicationProxies)
        {
            [void]$remainingProxies.Add($appProxy)
        }
    }
    $allProxies = $remainingProxies.ToArray()
    $observedProxyApplications = @{}
    $connectionNotes = New-Object 'System.Collections.Generic.List[string]'

    # Non-breaking spaces survive HTML rendering, so they indent connected proxy rows.
    $indent = ([char]0x00A0).ToString() * 10

    # Each row carries a hidden composite SortKey so the table can be sorted while
    # keeping every proxy grouped beneath its parent application:
    #   "0|<appName>|0|"            -> the service application row (sorts first in its group)
    #   "0|<appName>|1|<proxyName>" -> its connected proxies (sort after the app, by proxy name)
    #   "1|<proxyName>|0|"          -> proxies with no parent application (listed last)
    $serviceAppRows = @()
    foreach($application in $serviceApplications)
    {
        $serviceAppRows += [PSCustomObject]@{
            Name    = $application.DisplayName
            Type    = $application.TypeName
            Status  = $application.Status
            SortKey = "0|{0}|0|" -f $application.Name
        }

        # Identify proxies connected to this service application
        $connected = @()
        foreach($appProxy in @($remainingProxies))
        {
            $isConnected = $false
            try { $isConnected = $application.IsConnected($appProxy) }
            catch
            {
                $note = "Could not check service application $($application.Id) against proxy $($appProxy.Id): $($_.Exception.Message)"
                $connectionNotes.Add($note)
                Write-Warning $note
            }
            if($isConnected) { $connected += $appProxy }
        }

        # Add connected proxies indented beneath the application, and remove them
        # so they aren't matched again or listed as un-connected.
        foreach($appProxy in $connected)
        {
            $observedProxyApplications[[string]$appProxy.Id] = $application.Id
            $serviceAppRows += [PSCustomObject]@{
                Name    = "$indent$($appProxy.DisplayName)"
                Type    = $appProxy.TypeName
                Status  = $appProxy.Status
                SortKey = "0|{0}|1|{1}" -f $application.Name, $appProxy.Name
            }
            $remainingProxies.Remove($appProxy)
        }
    }

    # Any proxies not connected to a service application
    foreach($appProxy in @($remainingProxies))
    {
        $serviceAppRows += [PSCustomObject]@{
            Name    = $appProxy.DisplayName
            Type    = $appProxy.TypeName
            Status  = $appProxy.Status
            SortKey = "1|{0}|0|" -f $appProxy.Name
        }
    }

    # Sort by the composite key so children always stay grouped under their parent,
    # then drop the helper column before rendering.
    $serviceAppRows = @($serviceAppRows | Sort-Object SortKey | Select-Object Name, Type, Status)

    $serviceAppFinding = New-DiagnosticFinding -Name "Service Applications" -InputObject $serviceAppRows -Format Table
    $commandScope = [ordered]@{ farmId = $farm.Id }
    Add-DiagnosticCommandSnapshot -Finding $serviceAppFinding -CommandName 'Get-SPServiceApplication' -Records $serviceApplications -Scope $commandScope -Source 'SPFarm.Services.Applications (existing command-equivalent farm enumeration)' -Coverage 'Service application inventory; selected identity and status properties, not all subtype settings.' -PropertyNames @(
        'Id', 'Name', 'DisplayName', 'TypeName', 'Status'
    )
    $proxyCommandRecords = @($allProxies | ForEach-Object {
        [pscustomobject]@{
            Id = $_.Id
            Name = $_.Name
            DisplayName = $_.DisplayName
            TypeName = $_.TypeName
            Status = $_.Status
            ObservedServiceApplicationId = $observedProxyApplications[[string]$_.Id]
        }
    })
    Add-DiagnosticCommandSnapshot -Finding $serviceAppFinding -CommandName 'Get-SPServiceApplicationProxy' -Records $proxyCommandRecords -Scope $commandScope -Source 'SPFarm.ServiceProxies.ApplicationProxies (existing command-equivalent farm enumeration)' -Coverage 'Proxy inventory. ObservedServiceApplicationId reflects existing first-match connection checks; null does not prove there is no connection.' -Notes $connectionNotes.ToArray()
    $serviceAppFinding.Description += "- This finding should be similar to 'Central Admin > Applications > Manage Service Applications' page. </br>- Most service applications should have a 'connected' proxy right under it. </br>- If for example, Search Service Application, does not have a proxy right below, but you do see a 'Search Proxy' on the page, then this would indicate that proxy is rogue and search functionality is not working properly. </br>- In this type of scenario, you want to delete the Proxy, then recreate it so it reassociates with the Service App."

    $notOnline = $serviceAppRows | Where-Object{$null -ne $_.Status -and $_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    if($null -ne $notOnline)
    {
        $warningMessage = [string]::Empty
        $warningMessage = "One or more service applications or proxies were found not to be in a `"started`" state, the below PowerShell should be used to attempt to start them. After attempting to provision them this should be rechecked."
        $warningMessage += "`r`n<br><div class=`"code`">Get-SPServiceApplication | Where-Object{`$_.Status -ne `"Online`"} | Foreach-Object{`$_.Provision()}<br>Get-SPServiceApplicationProxy | Where-Object{`$_.Status -ne `"Online`"} | Foreach-Object{`$_.Provision()}</div>"

        $serviceAppFinding.Severity = [SPDiagnostics.Severity]::Warning
        $serviceAppFinding.WarningMessage += $warningMessage
    }

    ## As a child finding dump out the service application associations
    $proxyGroups = Get-SPServiceApplicationProxyGroup
    $proxyGroupObjects = @()
    $proxyGroupCommandRecords = @()
    foreach($proxyGroup in $proxyGroups)
    {
        $proxyIds = New-Object 'System.Collections.Generic.List[object]'
        foreach($proxy in $proxyGroup.Proxies)
        {
            $proxyIds.Add($proxy.Id)
            $proxyGroupObjects += [PSCustomObject]@{
                ProxyGroup = $proxyGroup.FriendlyName
                Proxy = $proxy.DisplayName
            }
        }
        $proxyGroupCommandRecords += [pscustomobject]@{
            Id = $proxyGroup.Id
            Name = $proxyGroup.Name
            FriendlyName = $proxyGroup.FriendlyName
            ProxyIds = $proxyIds.ToArray()
        }
    }
    $proxyGroupObjects = $proxyGroupObjects | Sort-Object ProxyGroup, Proxy
    $proxyGroupFinding = New-DiagnosticFinding -Name "Proxy Group Associations" -InputObject $proxyGroupObjects -Format Table
    Add-DiagnosticCommandSnapshot -Finding $proxyGroupFinding -CommandName 'Get-SPServiceApplicationProxyGroup' -Records $proxyGroupCommandRecords -Scope $commandScope -Source 'Get-SPServiceApplicationProxyGroup' -Coverage 'Proxy groups returned by the existing collector, including empty groups and proxy ID membership.'

    $serviceAppFinding.ChildFindings.Add($proxyGroupFinding)

    $serviceAppFinding.ChildFindings.Add((Get-SPDiagnosticsUserProfileFinding))

    $TempserviceAppPool =  get-SPServiceApplicationPool | Select-Object Id, DisplayName, ProcessAccountName
    $ServieAppPools = @()
    foreach ($ap in $TempserviceAppPool)
    {
        $Apo = new-object PSObject
        
        $apo | add-member -MemberType NoteProperty -Name "DisplayName" -Value $ap.DisplayName
        $apo | add-member -MemberType NoteProperty -Name "ID" -Value $ap.id
        $apo | add-member -MemberType NoteProperty -Name "ServiceAccount" -Value $ap.ProcessAccountName
        $ServieAppPools += $apo
    }
    $ServieAppPools = $ServieAppPools | sort-object DisplayName | Select 
    $spServiceAppPoolFinding = New-DiagnosticFinding -Name "Service Application Pools" -InputObject $ServieAppPools -Format Table
    $serviceAppFinding.ChildFindings.add($spServiceAppPoolFinding)


    return $serviceAppFinding
}

function Get-SPDiagnosticsTrustedRootAuthority
{
    $TrustedRootAuthFindings = New-DiagnosticFinding -Name "Trusted Root Authorities" -InputObject $null -Format Table
    $SPTrustedRootAuthorities = Get-SPTrustedRootAuthority | Sort-Object Name
    $TrustedRootAuthoritiesReport = @()
    foreach ($SPTrustedRootAuthority in $SPTrustedRootAuthorities)
    {
        $tra = new-object psobject
        $tra | add-member -MemberType NoteProperty -Name "Name" -Value $($SPTrustedRootAuthority.Name)
        $tra | add-member -MemberType NoteProperty -Name "DisplayName" -Value $($SPTrustedRootAuthority.DisplayName)
        $tra | add-member -MemberType NoteProperty -Name "Status" -Value $SPTrustedRootAuthority.Status
        $tra | add-member -MemberType NoteProperty -Name "Id" -Value $SPTrustedRootAuthority.Id
        $tra | add-member -MemberType NoteProperty -Name "Certificate Subject" -Value $($SPTrustedRootAuthority.Certificate.Subject)
        $tra | add-member -MemberType NoteProperty -Name "Certificate Valid from" -Value $SPTrustedRootAuthority.Certificate.Notbefore
        $tra | add-member -MemberType NoteProperty -Name "Certificate Valid until" -Value $SPTrustedRootAuthority.Certificate.NotAfter 
        $tra | add-member -MemberType NoteProperty -Name "Certificate Thumbprint" -Value $($SPTrustedRootAuthority.Certificate.Thumbprint)
        $TrustedRootAuthoritiesReport+=$tra
    }
    $TrustedRootAuthFindings.InputObject = $TrustedRootAuthoritiesReport
    Add-DiagnosticCommandSnapshot -Finding $TrustedRootAuthFindings -CommandName 'Get-SPTrustedRootAuthority' -Records $TrustedRootAuthoritiesReport -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPTrustedRootAuthority curated public certificate report' -Coverage 'Root authorities and public certificate identity, validity, and thumbprint; no private key material.'
    return $TrustedRootAuthFindings
}

function Get-SPDiagnosticsUserProfileFinding
{
    [CmdletBinding()]
    param ()

    $upaService = [Microsoft.SharePoint.Administration.SPFarm]::Local.Services | Where-Object{$_.TypeName -match "User Profile Service"}
    if($upaService.Applications.Count -eq 0)
    {
        return
    }
    foreach($upa in $upaService.Applications)
    {
        $serviceContext = [Microsoft.SharePoint.SPServiceContext]::GetContext($upa.ServiceApplicationProxyGroup, [guid]::Empty)
        
        $configManager = New-Object -TypeName "Microsoft.Office.Server.UserProfiles.UserProfileConfigManager" -ArgumentList $serviceContext

        $syncConnections = @()
        foreach($connection in $configManager.ConnectionManager)
        {
            if($configManager.ConnectionManager.Type -ne "ActiveDirectoryImport")
            {
                ##Not AD import, skip
                ##Perhaps add as a finding for customers using FIM, however this would only affect SP13 which is nearly out of support.
                continue
            }
            # this would only return for ADImport
            $adConnection = [Microsoft.Office.Server.UserProfiles.ActiveDirectoryImportConnection]$connection
            
            $flags = [System.Reflection.BindingFlags]"Instance","NonPublic"
            $type = $adConnection.GetType()
            $field = $type.GetField("namingContexts", $flags)
            $namingContexts = $field.GetValue($adConnection)

            $ousStr = [string]::Empty
            foreach($namingContext in $namingContexts)
            {
                foreach($ou in $namingContext.ContainersIncluded)
                {
                    [string]$ousStr += $ou + "; "
                }
            }
            $adConnection_OUs = $ousStr.TrimEnd("; ")

            $field = $type.GetField("server", $flags)
            $adConnection_server = $field.GetValue($adConnection)

            $field = $type.GetField("useSSL", $flags)
            $adConnection_useSSL = $field.GetValue($adConnection)

            $field = $type.GetField("useDisabledFilter", $flags)
            $adConnection_useDisabledFilter = $field.GetValue($adConnection)

            $field = $type.GetField("ldapFilter", $flags)
            $adConnection_ldapFilter = $field.GetValue($adConnection)


            #Get connection properties (claim provider type, id, and claim mapping)
            $m = $type.GetMethod("ADImportPropertyMappings", $flags)
            $mappings = $m.Invoke($adConnection, @())

            $adConnectionProperties = [System.Collections.HashTable]::new()
            foreach($mapping in $mappings.GetEnumerator())
            {
                $type = $mapping.GetType()

                $p = "get_ADAttribute"
                $m = $type.GetMethod($p, $flags)
                $adAttribute = $m.Invoke($mapping, @())

                $p = "get_ProfileProperty"
                $m = $type.GetMethod($p, $flags)
                $profileProperty = $m.Invoke($mapping, @())

                $p = "get_ConstantMappingValue"
                $m = $type.GetMethod($p, $flags)
                $constantMappingValue = $m.Invoke($mapping, @())

                switch ($profileProperty)
                {
                    "SPS-ClaimID" {$adConnectionProperties.Add($profileProperty, $adAttribute)}
                    "SPS-ClaimProviderID" {$adConnectionProperties.Add($profileProperty, $constantMappingValue)}
                    "SPS-ClaimProviderType" {$adConnectionProperties.Add($profileProperty, $constantMappingValue)}
                    default {}
                }

            }

            $syncConnections += [PSCustomObject]@{
                Name = $($adConnection.DisplayName)
                Server = $($adConnection_server)
                UseSSL = $adConnection_useSSL
                SelectedOUs = $($adConnection_OUs)
                UseDisabledFilter = $adConnection_useDisabledFilter
                LdapFilter = $($adConnection_ldapFilter)
                ClaimProviderType = $adConnectionProperties["SPS-ClaimProviderType"]
                ClaimProviderID = $($adConnectionProperties["SPS-ClaimProviderID"])
                ClaimID = $adConnectionProperties["SPS-ClaimID"]
                #ClaimProviderId = $adConnection_spsClaimProviderIdValue
            }
        }

        $syncConnectionFinding = New-DiagnosticFinding -Name ("Sync Connections: {0}" -f $upa.DisplayName) -InputObject $syncConnections -Format Table
    }
    $upaJobs = $upaService.JobDefinitions | Select-Object Name, Schedule, LastRunTime
    $upaFinding = New-DiagnosticFinding -Name "User Profile Service" -InputObject $upaJobs -Format table
    $upaFinding.ChildFindings.Add($syncConnectionFinding)
    return $upaFinding
}

#region HelperFunctions
function Invoke-SPSqlCommand
{
    [cmdletbinding()]
    Param
    (
        [Parameter(mandatory=$true,position=0)]
        [Microsoft.SharePoint.Administration.SPDatabase]
        $spDatabase,

        [Parameter(mandatory=$true,position=0)]
        [string]
        $query
    )

    $dataTable = New-Object System.Data.DataTable
    $connectionString = $spDatabase.DatabaseConnectionString
    $conn = New-Object System.Data.SqlClient.SqlConnection $connectionString
    try
    {
        $conn.Open()
        $command = New-Object System.Data.SqlClient.SqlCommand
        $command.Connection = $conn
        $command.CommandText = $query
        $reader = $command.ExecuteReader()
        $dataTable.Load($reader)
    }
    catch
    {
        Write-Error $_
    }
    finally
    {
        $conn.Close()
    }
    return $dataTable    
}


function IsElevated
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $winPrincipal =  New-Object Security.Principal.WindowsPrincipal $user
    return $winPrincipal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

#region ExecutionInfo
Function GetDBServerRoles 
{
    $DBServerRoles =@()

    $sqlQuery = " SELECT roles.name as Role FROM sys.server_role_members AS server_role_members `
        INNER JOIN sys.server_principals AS roles ON server_role_members.role_principal_id = roles.principal_id `
        INNER JOIN sys.server_principals AS members ON server_role_members.member_principal_id = members.principal_id `
        where members.name = '" + $env:USERDOMAIN + "\" + $env:USERNAME + "'"

    $configDb = Get-SPConfigurationDatabase
    $result = Invoke-SPSqlCommand -spDatabase $configDb -query $sqlquery -ErrorAction SilentlyContinue
    foreach ($row in $result)
    {
        $dbServerRoles+=($row[0])
    }
    return $DBServerRoles -join ','

}

function IsCurrentUserSPFarmAdmin
{
    $domUser = $env:USERDOMAIN + "\" + $env:USERNAME
    $IsFarmAdmin = $false
    Try {
        $CAWebApp = Get-SPWebApplication -IncludeCentralAdministration | where-object {$_.DisplayName -eq "SharePoint Central Administration v4"}

        #Get Central Admin site
        $caSite = Get-SPSite -Identity $CAWebApp.Url
        if ($caSite)
        {
            $CAWeb = $caSite.RootWeb
            $admgroup = $CAWeb.groups | Where-Object { $_.Name -eq $_.Owner}
            if ($admgroup)
            {
                $IsFarmAdmin = $admgroup.CanCurrentUserManageGroup
            }
        }

    } catch {
        #write-host "Can't access CA web App"
        return $false
    }

    if (!$IsFarmAdmin)
    {
        $builtInAdminGroup = get-localgroup | Where-Object {$_.sid -eq "S-1-5-32-544"}

        $builtInAdminGroupInFarmAdmins = $admgroup.Users | Where-Object {$_.Userlogin -match $builtInAdminGroup.Name}

        $LocalAdmin = Get-LocalGroupMember -Group $builtInAdminGroup -Member $domUser
    
        if ($LocalAdmin -and $builtInAdminGroupInFarmAdmins)
        {
            $IsFarmAdmin=$true
            #write-host "LocalAdmin"
        }
    } 

    #write-host "$domuser is FarmAdmin $IsFarmAdmin"
    return $IsFarmAdmin
} 

Function Get-ScriptExecutionInfo
{
    # Information about server, server role, time user and if script is executed elevated.
    $execInfo = New-Object psobject
    $execInfo | Add-Member -MemberType NoteProperty -Name ScriptVersion -Value $ScriptVersion
    $execInfo | Add-Member -MemberType NoteProperty -Name Computer -Value ($env:COMPUTERNAME)
    $execInfo | Add-Member -MemberType NoteProperty -Name ServerRole -Value (Get-SPServer -Identity $env:Computername).Role

    $execInfo | Add-Member -MemberType NoteProperty -Name "DataCollection Start" $Script:RunStartTime
    $execInfo | Add-Member -MemberType NoteProperty -Name Time -Value (Get-Date)
    $execInfo | Add-Member -MemberType NoteProperty -Name UTCTime -Value ([DateTime]::UtcNow.ToString('u'))
    $CollectionTime = new-Timespan  -start $Script:RunStartTime -end (Get-Date)
    $execInfo | Add-Member -MemberType NoteProperty -Name "Script Duration" -Value ( "$([int]$CollectionTime.TotalSeconds) seconds" )

    $execInfo | Add-Member -MemberType NoteProperty -Name User -Value (($env:USERDNSDOMAIN + "\" + $env:USERNAME))
    $execInfo | Add-Member -MemberType NoteProperty -Name DBServerRoles -Value (GetDBServerRoles)
    $execInfo | Add-Member -MemberType NoteProperty -Name FarmAdmin -Value (IsCurrentUserSPFarmAdmin)
    $execInfo | Add-Member -MemberType NoteProperty -Name Elevated -Value (isElevated)

    $ScriptExecutionFindings = New-DiagnosticFinding -Name "Script Execution Info" -InputObject $execInfo -Format List
 
    # Task 517 dynamically build script execution info
    $hiddenParams = @(
        "Verbose",
        "Debug",
        "ErrorAction",
        "WarningAction",
        "InformationAction",
        "ErrorVariable",
        "WarningVariable",
        "InformationVariable",
        "OutVariable",
        "OutBuffer",
        "PipelineVariable"
    )    

    $params = $script:MyInvocation.MyCommand.Parameters.Values 
    $params = $params.GetEnumerator() | Where-Object{$_.Name -notin $hiddenParams}
    $paramCollection = @()
    foreach($param in $params)
    {
        $paramCollection += [PSCustomObject]@{
            Parameter = $param.Name
            Value = (Get-Variable $param.Name -Scope Script | Select-Object Value).Value
        }
    }
 
    $ScriptExecutionParamsFindings = New-DiagnosticFinding -Name "Script Execution Parameters" -InputObject $paramCollection -Format Table
    $ScriptExecutionFindings.ChildFIndings.Add(($ScriptExecutionParamsFindings))


    # Add finding times to the script diagnostic findings. 
    if($Script:FindingTimes.Count -gt 0)
    {
        $findingTimesFinding = New-DiagnosticFinding -Name "Finding Times" -InputObject $script:FindingTimes -Format Table
        $ScriptExecutionFindings.ChildFindings.Add($findingTimesFinding)
    }

    return $ScriptExecutionFindings
}
#endregion

#endregion HelperFunctions

function Get-SPDiagnosticTimerJobHistoryFinding
{
    [cmdletbinding()]
    Param()
    $servers = $script:servers | Where-Object{$_.Role -ne "Invalid"}
    $warningRowCount = 2000000*$servers.Count
    $configDb = Get-SPConfigurationDatabase
    
    #Task 501: modifying query to improve performance when executed against large tables.
    #$result = Invoke-SPSqlCommand -spDatabase $configDb -query "select count(1) from dbo.TimerJobHistory with(nolock)" -ErrorAction SilentlyContinue
    $rowCountQuery = "SELECT SUM(p.rows) FROM sys.partitions AS p
        INNER JOIN sys.tables AS t
        ON p.[object_id] = t.[object_id]
        INNER JOIN sys.schemas AS s
        ON s.[schema_id] = t.[schema_id]
        WHERE t.name = N'TimerJobHistory'
        AND s.name = N'dbo'
        AND p.index_id IN (0,1);"
    $result = Invoke-SPSqlCommand -spDatabase $configDb -query $rowCountQuery -ErrorAction SilentlyContinue
    $rowCount = $result.Column1[0]

    #Task 501: modifying query to improve performance when executed against large tables.
    #$result2 = Invoke-SPSqlCommand -spDatabase $configDb -query "Select MIN(EndTime) as Oldest, MAX(EndTime) as Newest from TimerJobHistory with(nolock)" -ErrorAction SilentlyContinue
    $minMaxQuery = "Select MIN(StartTime) as Oldest, MAX(StartTime) as Newest from TimerJobHistory with(nolock, INDEX(IX_TimerJobHistory_StartTime_Id))"
    $result2 = Invoke-SPSqlCommand -spDatabase $configDb -query $minMaxQuery -ErrorAction SilentlyContinue

    $job = Get-SPTimerJob job-delete-job-history

    <#
    $finding.Description+=("<li>Job LastRunTime: {0}</li>" -f $job.LastRunTime)
    $finding.description+=("<li>Oldest record: {0}</li>" -f $result2.Oldest[0])
    $finding.description+=("<li>Newest record: {0}</li>" -f $result2.Newest[0])
    $finding.Description+=("<li>DaysToKeepHistory: {0}</li></ul>" -f $job.DaysToKeepHistory)
    #>

    $finding = New-DiagnosticFinding -Name "TimerJobHistory" -InputObject $null -Format List
    Add-DiagnosticTimerJobSnapshot -Finding $finding -Jobs $job -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPTimerJob job-delete-job-history' -Coverage 'The delete-job-history timer job inspected by the existing collector; not all farm timer jobs.'
    $uri = New-Object System.Uri('https://blog.stefan-gossner.com/2018/04/12/changes-in-the-timerjobhistory-table-maintenance-introduced-in-april-2018-cu-for-sharepoint-2013/')
    $finding.ReferenceLink += $uri

    if($rowCount -ge $warningRowCount)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage += ("Timer job history table has {0} rows, make sure that timer job history is being properly cleaned up" -f $rowCount.ToString('N0'))
        $finding.ReferenceLink += "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"
    }

    if($null -eq $job)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+=("`nThe timer job `"{0}}`" does not exist, take steps to reprovision the job" -f $job.DisplayName)
    }
    else
    {
        if($job.IsDisabled)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            $finding.WarningMessage+=("`nThe timer job `"{0}}`" is disabled, please enable the timer job" -f $job.DisplayName)
        }
        elseif($job.LastRunTime -lt [datetime]::Now.AddDays(-3))
        {
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            $finding.WarningMessage+=("`nThe timer job `"{0}`" has not run since {1}, please ensure that the job is enabled and it is running" -f $job.DisplayName, $job.LastRunTime.ToShortDateString())
        }

        $retObj = [PSCustomObject]@{
            TimerjobHistoryCount = "{0}" -f $rowCount.ToString('N0')
            LastRunTime = $job.LastRunTime
            "Oldest Record" = $result2.Oldest[0]
            "Newest Record" = $result2.Newest[0]
            DaysToKeepHistory = $job.DaysToKeepHistory
            Disabled = $job.IsDisabled
        }

        $finding.InputObject = $retObj
    }


   

   
    return $finding
}

function Get-SPDiagnosticWebAppObjectCacheUserFinding($webapp)
{
    if ($webapp.IsAdministrationWebApplication)
    {
        return $Null
    }

    $objectCacheName = "Object Cache Users" + " ( " + $($webapp.Url) + " ) "
	$ObjectCacheUserfinding = New-DiagnosticFinding -Name $objectCacheName -Description $null -InputObject $null -Format Table

	$ObjectCacheUsers=@()
	$PSR = new-object psobject
	$PSU = new-Object PSObject

	$webAppProperties = $webapp.Properties
	$webAppPolicies = $webapp.Policies

	$PSR | Add-Member -MemberType NoteProperty -Name "Name" -Value "PortalSuperReader"
	$PSR | Add-Member -MemberType NoteProperty -Name "WebAppProperty" -Value $($webapp.Properties["portalsuperreaderaccount"])
	$psr | Add-Member -MemberType NoteProperty -Name "DenyAll" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "DenyWrite" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "FullRead" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "FullControl" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "Permissions Correct?" -value $false

	$PSU | Add-Member -MemberType NoteProperty -Name "Name" -Value "PortalSuperUser"
	$PSU | Add-Member -MemberType NoteProperty -Name "WebAppProperty" -Value $($webapp.Properties["portalsuperuseraccount"])
	$PSU | Add-Member -MemberType NoteProperty -Name "DenyAll" -Value $false
	$PSU | Add-Member -MemberType NoteProperty -Name "DenyWrite" -Value $false
	$PSU | Add-Member -MemberType NoteProperty -Name "FullRead" -Value $false
	$PSU | Add-Member -MemberType NoteProperty -Name "FullControl" -Value $false
	$PSU | Add-Member -MemberType NoteProperty -Name "Permissions Correct?" -value $false

	if ($webAppProperties.Keys -contains "portalsuperreaderaccount" -and `
		$webAppProperties.Keys -contains "portalsuperuseraccount")
	{
		if ($psr -and $psu)
		{
			$psrPolicies = $webAppPolicies | Where-Object {$_.Username -eq $webapp.Properties["portalsuperreaderaccount"]}
			$psuPolicies = $webAppPolicies | Where-Object {$_.Username -eq $webapp.Properties["portalsuperuseraccount"]}


			foreach ($psrPolicy in $psrPolicies)
			{
				foreach  ($psrPolicybinding in $psrPolicy.PolicyRoleBindings)
				{
					$pn =  ($psrPolicybinding.Type).ToString()
					$psr.psobject.Properties[$Pn].Value =$true
				}
			}

			foreach ($psuPolicy in $psuPolicies)
			{
				foreach  ($psuPolicybinding in $psuPolicy.PolicyRoleBindings)
				{
					$pn =  ($psuPolicybinding.Type).ToString()
					$psu.psobject.Properties[$Pn].Value =$true
                }
			}
        	if ($PSR.FullRead -and !$PSR.DenyAll -and !$PSR.DenyWrite -and !$PSR.FullControl)
	        {
		        $psr.psobject.Properties["Permissions Correct?"].Value =$true   
	        } 
            else 
            {
		        $ObjectCacheUserfinding.WarningMessage += "The permissions for the Portal Super Reader Account are not set correct"  
		        $ObjectCacheUserFinding.Severity = [SPDiagnostics.Severity]::Warning    
	        }

	        if ($PSU.FullControl -and !$PSU.DenyAll -and !$PSU.DenyWrite)
	        {
		        $psu.psobject.Properties["Permissions Correct?"].Value =$true
	        } 
            else 
            {
		        $ObjectCacheUserfinding.WarningMessage += "The permissions for the Portal Super User Account are not set correct"       
		        $ObjectCacheUserFinding.Severity = [SPDiagnostics.Severity]::Warning    
	        }

	        $ObjectCacheUsers += $psr
	        $ObjectCacheUsers += $PSU 
        }
        else 
        {
            $ObjectCacheUserfinding.WarningMessage += "WebApplication property for portalsuperreaderaccount and/or portalsuperuseraccount missing."           
        }
	} 
    else 
    {
		$SuperOOB = $true
        If($webapp.Policies["NT AUTHORITY\LOCAL SERVICE"].UserName -eq "NT AUTHORITY\LOCAL SERVICE" -and $($webapp.Policies["NT AUTHORITY\LOCAL SERVICE"].PolicyRoleBindings | Where-Object {$_.type -eq "FullRead"}))
        {
            #this check is for making sure the OOB SR has Full Read for the User Policy of the web application.
            $ObjectCacheUserfinding.Description +="No Portal Super User and Portal Super User are configured. Using the Default users for this:"
            $ObjectCacheUserfinding.Description +="Site's System Account as Portal Super User and NT Authority\Local Service as the Portal Super Reader."
        }
        Else
        {
            $ObjectCacheUserfinding.WarningMessage += "NT AUTHORITY\LOCAL SERVICE does not have the proper permissions for the web application." 
            $ObjectCacheUserFinding.Severity = [SPDiagnostics.Severity]::Warning                
        }
	}



	if ($ObjectCacheUserfinding.WarningMessage.Count -gt 0)
	{
		$ObjectCacheUserfinding.ReferenceLink += "https://joshroark.com/sharepoint-the-complete-guide-to-portalsuperuseraccount-and-portalsuperreaderaccount/"
	}

	If(!$SuperOOB)
    {
        $ObjectCacheUserfinding.InputObject = $ObjectCacheUsers
    }
	return $ObjectCacheUserfinding								  
}

function Get-SPDiagnosticsWebAppsFinding
{
    [cmdletbinding()]
    Param()
    $webAppsFinding = New-DiagnosticFinding -Name "Web Applications & AAMs"

    #Task 529: Move behind extended findings switch
    if($ExtendedFindings)
    {
        $webAppsFinding.ChildFindings.Add((Get-SPDiagnosticsWebConfigModificationsFinding))
    }

    $webApps = Get-SPWebApplication -IncludeCentralAdministration
    $webAppList = @()
    foreach($webApp in $webApps)
    {
        $webAppSiteCount = $null
        $webAppSiteCount = $webApp.Sites.Count
        # Task 535: Add table for webapps similar to Central Admin
        # get the default zone port:
        $dfltSettings = $webApp.IisSettings[[Microsoft.SharePoint.Administration.SPUrlZone]::Default]
        if($null -ne $dfltSettings.ServerBindings[0].Port)
        {
            $port = $dfltSettings.ServerBindings[0].Port
        }
        else
        {
            $port = $dfltSettings.SecureBindings[0].Port
        }
        
        $webAppList += [PSCustomObject]@{
            Name = ($webApp.DisplayName)
            Url = ($webApp.Url)
            Port = $port
            ContentDatabaseCount = $webApp.ContentDatabases.Count
            SiteCount = ($webApp.ContentDatabases | Measure-Object -Property CurrentSiteCount -Sum).Sum
        }
        
        $webAppName = "Web Application: '" + ($webApp.DisplayName) + "' (" + ($webApp.Url) + ")"

        #Remove  $_ -like "*throttle*" -or $_ -like "*max*" -or  because this is collected separate and returns objects
        #$webAppDetails = $WebApp | Select-Object ($webApp.PSObject.Properties.Name.Where({ $_ -like "ExternalUrlZone" -or $_ -like "UseExternalUrlZoneForAlerts" -or $_ -like "IncomingEmailServerAddress" -or $_ -like "OutboundMailServiceInstance" -or $_ -like "OutboundMailPort" -or $_ -like "OutboundMailEnableSsl" -or $_ -like "RecycleBinEnabled" -or $_ -like "RecycleBinCleanupEnabled" -or $_ -like "RecycleBinRetentionPeriod" -or $_ -like "SecondStageRecycleBinQuota" -or $_ -like "SharePoint2010WorkflowsEnabled" -or $_ -like "DisableCoauthoring"}) | Sort-Object)  -ErrorAction SilentlyContinue
        $webAppDetails = $WebApp | Select-Object ExternalUrlZone, UseExternalUrlZoneForAlerts, RecycleBinEnabled, RecycleBinCleanupEnabled, RecycleBinRetentionPeriod, SecondStageRecycleBinQuota, SharePoint2010WorkflowsEnabled, DisableCoauthoring, AllowDesigner, RequiredDesignerVersion | Sort-Object -ErrorAction SilentlyContinue
        #separate finding for mail settings
        #$webAppDetails = $WebApp | Select-Object ExternalUrlZone, UseExternalUrlZoneForAlerts, IncomingEmailServerAddress, @{N='OutboundMailServiceInstance'; E={$_.OutboundMailServiceInstance.Server.DisplayName}}, OutboundMailPort, OutboundMailEnableSsl, RecycleBinEnabled, RecycleBinCleanupEnabled, RecycleBinRetentionPeriod, SecondStageRecycleBinQuota, SharePoint2010WorkflowsEnabled, DisableCoauthoring, AllowDesigner, RequiredDesignerVersion | Sort-Object -ErrorAction SilentlyContinue
        # The above is a squirrely way to avoid errors finding their way into the errors collection due to duplicate properties being selected because of *throttle* and *max* matching a few of the same property names
        # Otherwise we end up with a lot of these
        # select-object : The property cannot be processed because the property "MaxItemsPerThrottledOperationWarningLevel" already exists.
        # At line:1 char:14
        # + $webapp777 | select-object *max*,*throttle*
        # +              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # + CategoryInfo          : InvalidOperation: (SPWebApplication Name=SharePoint - 7777:PSObject) [Select-Object], PSArgumentException
        # + FullyQualifiedErrorId : AlreadyExistingUserSpecifiedPropertyNoExpand,Microsoft.PowerShell.Commands.SelectObjectCommand
        
        $WebAppPropertiesFinding = New-DiagnosticFinding -Name "WebApp Properties" -InputObject $webAppDetails -Format List
       
        $aams = $webApp.AlternateUrls | Select-Object -Property IncomingUrl, Zone, PublicUrl | Sort-Object -Property Zone

        $DisplayAAMs=@()
        foreach ($aam in $aams)
        {
            $DisplayAAM = new-object PSObject
            $DisplayAAM | Add-Member -MemberType NoteProperty -Name "Incoming Url" -Value $($aam.IncomingUrl)
            $DisplayAAM | Add-Member -MemberType NoteProperty -Name "Zone" -Value $aam.Zone
            $DisplayAAM | Add-Member -MemberType NoteProperty -Name "PublicURL" -value $($aam.PublicUrl)
            $DisplayAAMs += $DisplayAAM
        }

        $webAppFinding = New-DiagnosticFinding -Name $webAppName -InputObject $DisplayAAMs -Format Table
        Add-DiagnosticCommandSnapshot -Finding $webAppFinding -CommandName 'Get-SPWebApplication' -Records $webApp -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPWebApplication -IncludeCentralAdministration' -Coverage 'Web applications returned by the existing collector, including Central Administration. Selected identity and configuration properties; source findings contain zone and threshold details.' -PropertyNames @(
            'Id', 'Name', 'DisplayName', 'Url', 'IsAdministrationWebApplication',
            'ExternalUrlZone', 'UseExternalUrlZoneForAlerts', 'RecycleBinEnabled',
            'RecycleBinCleanupEnabled', 'RecycleBinRetentionPeriod', 'SecondStageRecycleBinQuota',
            'SharePoint2010WorkflowsEnabled', 'DisableCoauthoring', 'AllowDesigner', 'RequiredDesignerVersion'
        )
        $webAppFinding.Description += " Site Count: (" +$webAppSiteCount +")"


        # itterate through aams to get zones to check to be sure to not miss manually created aams
        # if there are manually created AAMs call them out
        foreach($aam in $aams)
        {
            if($aam.IncomingUrl -eq $aam.PublicUrl)
            {
                $iisSettings = $webApp.IisSettings[$aam.Zone]
                if($null -eq $iisSettings)
                {
                    $WebAppFinding.Severity = "Warning"
                    $WebAppFinding.WarningMessage += "The [{0}] Zone Url is manually created." -f $aam.Zone
                    $WebAppFinding.WarningMessage += "The manually created aam should be removed and the web application properly extended into the zone"
                }
                else
                {
                    $iisSettingName = "IIS Settings: " + " -- Zone: " + $aam.Zone + " | Url:  " + $($aam.PublicUrl)
                    $iisSettingsFinding = New-DiagnosticFinding -Name $iisSettingName -InputObject $null -Format List
                    $iisSettingsObj = $iisSettings | Select-Object ServerComment, iispath, PreferredInstanceId, AuthenticationMode, MembershipProvider, RoleManager, AllowAnonymous, EnableClientIntegration, UseWindowsIntegratedAuthentication, UseBasicAuthentication,UseClaimsAuthentication,UseFormsClaimsAuthenticationProvider,UseTrustedClaimsAuthenticationProvider,UseWindowsClaimsAuthenticationProvider, DisableKerberos, ClaimsAuthenticationRedirectionUrl, ClientObjectModelRequiresUseRemoteAPIsPermission
                    $iisSettingsObj.iisPath = $($IIsSettings.Path)
                    $iisSettingsObj.ClaimsAuthenticationRedirectionUrl = $($IIsSettings.ClaimsAuthenticationRedirectionUrl)

                    # Check for debug flag
                    $compilationDebug = Confirm-DebugCompilationDisabled $iisSettingsObj.ServerComment

                    if([Bool]::TryParse($compilationDebug, [ref]$compilationDebug) -and $compilationDebug)
                    {
                        $iisSettingsFinding.WarningMessage += "Compilation Debug is True in the Web.Config. This will have performance repercussions. "
                        $iisSettingsFinding.Severity = "Warning"
                    }

                    $iisSettingsObj | Add-Member -MemberType NoteProperty -Name "Web.Config Compilation Debug" -Value $compilationDebug

                    $iisSettingsObj.ServerComment = $($iisSettingsObj.ServerComment)
                    $iisSettingsFinding.InputObject = $iisSettingsObj

                    $iisBindingFinding = New-DiagnosticFinding -Name "IIS Bindings" -InputObject $null -Format List

                    $IISBindingsReport = @()
                    $Sbs = $iisSettings.ServerBindings                    
                    foreach ($sb in $Sbs)
                    {
                        $sbr = new-object PSObject
                        $sbr | Add-Member -MemberType NoteProperty -Name "path" -value $sb.Path
                        $sbr | Add-Member -MemberType NoteProperty -Name "port" -value $sb.Port 
                        $sbr | Add-Member -MemberType NoteProperty -Name "hostheader" -value  $($sb.HostHeader)
                        $IISBindingsReport += $sbr

                    }

                    $Sbs = $iisSettings.SecureBindings                    
                    foreach ($sb in $Sbs)
                    {
                        $sbr = new-object PSObject
                        $sbr | Add-Member -MemberType NoteProperty -Name "path" -value $sb.Path
                        $sbr | Add-Member -MemberType NoteProperty -Name "port" -value $sb.Port 
                        $sbr | Add-Member -MemberType NoteProperty -Name "hostheader" -value  $($sb.HostHeader)
                        if ($Script:Build -eq "SPSE")
                        {
                            $sbr | Add-Member -MemberType NoteProperty -Name "UseServerNameIndication" -value $sb.UseServerNameIndication 
                            $sbr | Add-Member -MemberType NoteProperty -Name "Certificate" -value $($sb.Certificate)
                            $sbr | Add-Member -MemberType NoteProperty -Name "DisableHTTP2" -value $sb.DisableHTTP2 
                            $sbr | Add-Member -MemberType NoteProperty -Name "DisableQuic" -value $sb.DisableQuic 
                            $sbr | Add-Member -MemberType NoteProperty -Name "DisableLegacyTls" -value $sb.DisableLegacyTls 
                        }
                        $IISBindingsReport += $sbr
                    }
                    $iisBindingFinding.InputObject = $IISBindingsReport
                    $iisSettingsFinding.ChildFindings.Add($iisBindingFinding)
                    $IISSettingsFinding.ChildFindings.Add((Get-SPDiagnosticsExtraBindingsOnIIS $webapp $aam.Zone))
                    $WebAppFinding.ChildFindings.Add($iisSettingsFinding)
                }
            }
        }
        
        $WebAppFinding.ChildFindings.Add((Get-WebAppContentDBsFinding $webapp))
        $WebAppFinding.ChildFindings.Add((Get-SPWebAppApplicationPool $webapp))
        
        if(!$webApp.IsAdministrationWebApplication)
        {
            $WebAppFinding.ChildFindings.Add((Get-SPWebAppServiceAppProxiesFinding $webapp))
            $webAppFinding.ChildFindings.Add((Get-SPDiagnosticPeoplePickerSettings $webApp))
            $webAppFinding.ChildFindings.Add($WebAppPropertiesFinding)
            $webAppFinding.ChildFindings.Add($peoplePickerFindings)
            $webAppFinding.ChildFindings.Add((Get-SPDiagnosticsBlobCache $webApp))
            
            #Task 531: Hide findings unless there is something reportable:
            #$WebAppFinding.ChildFindings.Add((Get-SPDiagnosticsWebAppChangeLogFinding $webApp))
            $changeLogFinding = Get-SPDiagnosticsWebAppChangeLogFinding $webApp
            if($changeLogFinding.Severity -ge [SPDiagnostics.Severity]::Informational)
            {
                $WebAppFinding.ChildFindings.Add(($changeLogFinding))
            }
            
            #Task 531: Hide findings unless there is something reportable:
            #$WebAppFinding.ChildFindings.Add((Get-SPDiagnosticsMissingSTSHeader $webapp))
            $stsHeaderFinding = Get-SPDiagnosticsMissingSTSHeader $webapp
            if($stsHeaderFinding.Severity -ge [SPDiagnostics.Severity]::Warning)
            {
                $WebAppFinding.ChildFindings.Add(($stsHeaderFinding))
            }
            
            #Task 531: Hide findings unless there is something reportable:
            #$WebAppFinding.ChildFindings.Add((Get-SPDiagnosticWebAppObjectCacheUserFinding $webapp))
            $objectCacheUserFinding = Get-SPDiagnosticWebAppObjectCacheUserFinding $webapp
            if($objectCacheUserFinding.Severity -ge [SPDiagnostics.Severity]::Warning)
            {
                $WebAppFinding.ChildFindings.Add(($objectCacheUserFinding))
            }

            #Task 531: Hide findings unless there is something reportable:
            #$WebAppFinding.ChildFindings.Add((Get-SPDiagnosticsWebAppThrottlingFinding $webapp))
            $webAppThrottlingFinding = Get-SPDiagnosticsWebAppThrottlingFinding $webapp
            if($webAppThrottlingFinding.Severity -ge [SPDiagnostics.Severity]::Informational `
                -or ($webAppThrottlingFinding.ChildFindings | Where-Object{$_.Severity -ge [SPDiagnostics.Severity]::Informational}).Count -ge 1 `
            )
            {
                $WebAppFinding.ChildFindings.Add(($webAppThrottlingFinding))
            }

            $WebAppFinding.ChildFindings.Add((Get-SPWebApplicationBlockedFileExtensions $webapp))
            $WebAppFinding.ChildFindings.Add((Get-SelfSiteCreationFinding $webapp))
            $WebAppFinding.ChildFindings.Add((Get-ManagedPathFinding $webapp))
            $WebAppFinding.ChildFindings.Add((Get-OutGoingMailServerFinding $webapp))
            $WebAppFinding.ChildFindings.Add((Get-WebAppPolicyFinding $webapp))
        }


        ## Check if web app is missing root site collection
        $rootSite = Get-SPSite -Identity $webApp.Url -ErrorAction SilentlyContinue

        if(!$rootSite)
        {
            $webAppFinding.Severity = [SPDiagnostics.Severity]::Warning
            $webAppFinding.WarningMessage += " - No root site collection present in web application.<br/> - Web applications must have a site collection present at their root url.<br/> - Please create a site collection at $($($webApp.Url))"
        }
        else 
        {
            $rootsite.Close()
            $rootSite.Dispose()
        }

        #Task 561: Check for AMSI feature and report if not active, this should be active after Sept 2023 PU, build
        $amsiMinVer = switch($script:build)
        {
            "SPSE" {[version]::Parse("16.0.16731.20180")}
            "SP19" {[version]::Parse("16.0.10402.20016")}
            "SP16" {[version]::Parse("16.0.5413.1001")}
        }
        if($Script:Build -ge $amsiMinVer)
        {
            $amsiFeatureId = [guid]::Parse("4cf046f3-38c7-495f-a7da-a1292d32e8e9")
            if($null -eq $webApp.Features[$amsiFeatureId])
            {
                $webAppFinding.Severity = [SPDiagnostics.Severity]::Warning
                $webAppFinding.WarningMessage += "Antimalware Scan Interface (AMSI) is disabled for this web application, this is an important cyber security feature and is recommended to have enabled."
                $webAppFinding.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/configure-amsi-integration"
            }
        }
        
        $webAppsFinding.ChildFindings.Add($webAppFinding)
    }

    # Consolidated content database file size and growth finding across all web applications.
    # Previously this was emitted once per web application (as a child of each web app's Content
    # Database(s) finding), which caused one "Content Database file size and growth Information"
    # block per web app to be promoted into the Informational Items section. It is now a single
    # finding with a leading "Web Application" column.
    $webAppsFinding.ChildFindings.Add((Get-ContentDBFileSizeAndGrowthFinding $webApps))

    $webAppsFinding.InputObject = $webAppList
    $webAppsFinding.Format = [SPDiagnostics.Format]::Table
    
    return $webAppsFinding
}

Function Get-ContentDBFileSizeAndGrowthFinding ($webApps)
{
    # Single consolidated finding for content database file size and growth across every web
    # application. Builds one flat table keyed by a leading "Web Application" column so the
    # Informational Items section shows a single block instead of one per web application.
    $DBFileAndSizefinding = New-DiagnosticFinding -Name "Content Database file size and growth Information" -Severity Default -InputObject $null -Format Table
    $DBFileInfosReport = @()

    # Farm-level flags: track whether any web application / database exhibits each growth issue so a
    # single generic warning can be emitted after the loop instead of one message per web application.
    $anyGrowthLtMax = $false
    $anyRowsBadGrowth = $false
    $anyTlPercentGrowth = $false

    foreach ($webApp in $webApps)
    {
        if($webApp.IsAdministrationWebApplication)
        {
            continue
        }

        $webAppLabel = "$($webApp.DisplayName) ($($webApp.Url))"

        foreach ($db in $webapp.ContentDatabases)
        {
            $SQLQuery=" SELECT   'Database Name' = DB_NAME(db.database_id), 'FileName' = mf.NAME, 'CurrentSize' = CONVERT(BIGINT, size /128),
                'maxsize' = (
                CASE max_size
                WHEN - 1
                THEN N'Unlimited'
                ELSE CONVERT(NVARCHAR(15), CONVERT(BIGINT, max_size) /128)
                END
                )
                ,Freespace = CONVERT(BIGINT,(size/128.0 - CAST(FILEPROPERTY(mf.name, 'SpaceUsed') AS INT)/128.0 ))
                ,'growth' = (
                CASE is_percent_growth
                WHEN 1
                THEN growth
                ELSE CONVERT(BIGINT, growth) /128
                END
                )
                , is_percent_growth as GrowInPercent
                ,'type_desc' = type_desc
                FROM sys.master_files mf (NOLOCK)
                inner join sys.databases db (NOLOCK) on db.database_id = mf.database_id
                where db.name = '" + $db.Name +"' ORDER BY file_id
            "

            $dbFileInfos = Invoke-SPSqlCommand -spDatabase $db -query $sqlQuery -ErrorAction SilentlyContinue

            foreach ($dbfileInfo in $dbFileInfos)
            {
                if ($dbfileInfo.GrowInPercent -eq $false -and $dbfileInfo.growth -lt $webApp.MaximumFileSize)
                {
                    $anyGrowthLtMax = $true
                }
                if ($dbfileInfo.type_desc -eq "ROWS" -and $dbfileInfo.growth -eq 1)
                {
                    $anyRowsBadGrowth = $true
                }
                if ($dbfileInfo.type_desc -eq "LOG" -and $dbfileInfo.GrowInPercent)
                {
                    $anyTlPercentGrowth = $true
                }

                #build object for report
                $dbfileInfoReport = New-Object PSObject
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "Web Application" -value $webAppLabel
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "Database Name" -value $($dbfileInfo.'Database Name')
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "FileName" -value $($dbfileInfo.FileName)
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "CurrentSize" -value $($dbfileInfo.CurrentSize.ToString() + " MB")
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "Maxsize" -value $dbfileInfo.maxsize
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "Freespace" -value $($dbfileInfo.Freespace.ToString() + " MB")
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "Growth" -value $($dbfileInfo.growth.ToString() + " MB")
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "GrowInPercent" -value $dbfileInfo.GrowInPercent
                $dbfileInfoReport | add-member -MemberType NoteProperty -name "Type_Desc" -value $dbfileInfo.type_desc

                $DBFileInfosReport += $dbfileInfoReport
            }
        }
    }

    # Emit a single, generic warning (no per-web-app repetition and no web app / database names,
    # since the table below already lists them). Only the explanation lines that actually apply are
    # included, and the reference link is added once.
    if ($anyGrowthLtMax -or $anyRowsBadGrowth -or $anyTlPercentGrowth)
    {
        $DBFileAndSizefinding.Severity = [SPDiagnostics.Severity]::Informational
        $DBFileAndSizefinding.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/administration/best-practices-for-sql-server-in-a-sharepoint-server-farm#proactively-manage-the-growth-of-data-and-log-files"

        $growthMessage = " - One or more content database or transaction log files listed below have a sub-optimal auto-growth configuration. Review the 'Growth' and 'GrowInPercent' columns in the table for the affected files."
        if ($anyGrowthLtMax)
        {
            $growthMessage += "<BR>- The growth increment on one or more files is smaller than the web application's maximum upload file size, which can trigger multiple database or transaction log file growth operations when a large file is uploaded."
        }
        if ($anyRowsBadGrowth)
        {
            $growthMessage += "<BR> - One or more data files are configured to grow by only 1 MB, which can cause many small file growth operations."
        }
        if ($anyTlPercentGrowth)
        {
            $growthMessage += "<BR> - One or more transaction log files are configured to grow by a percentage, which causes small growths when the log is small and unnecessarily large growths when it is big, briefly interrupting the database while the file grows."
        }
        $growthMessage += "<BR> - Configure a fixed, appropriately sized auto-growth increment to reduce the number of file growth operations."
        $DBFileAndSizefinding.WarningMessage += $growthMessage
    }

    $DBFileAndSizefinding.InputObject = $DBFileInfosReport
    return $DBFileAndSizefinding
}

Function Get-WebAppContentDBsFinding ($webapp)
{
    $dbInfo = $webApp.ContentDatabases | Select-Object  @{N='Name'; E={$($_.Name)}} , @{N='SiteCount'; E={$_.CurrentSiteCount}}, Id, Status, BuildVersion,  @{N='DB Server' ; E={$($_.NormalizedDataSource)}} ,@{N="DB Size(GB)"; E={$(([System.Math]::Round($_.DiskSizeRequired/1gb,2)))}}, IsReadOnly, IsAttachedToFarm, @{N='AuthMode'; E={$_.ServiceInstance.AuthMode}}, IsSqlAzure, @{N='PreferredTimerServer'; E={$_.PreferredTimerServiceInstance.Id.Guid}}, @{N='Rbs Enabled'; E={$_.RemoteBlobStorageSettings.Enabled}},  @{N='Rbs Provider'; E={$_.RemoteBlobStorageSettings.ActiveProviderName}}
    $dbInfoCount = $webApp.ContentDatabases.Count
    $cdbfinding = New-DiagnosticFinding -Name "Content Database(s) - ($($webApp.Name)) - (Count:$dbInfoCount)" -Severity Default -InputObject $dbInfo -Format Table

    $totalSiteCount = ($webApp.ContentDatabases | Measure-Object  -Property CurrentSiteCount -Sum).Sum
    $maxSiteCount = ($webApp.ContentDatabases | Measure-Object  -Property MaximumSiteCount -Sum).Sum

    if($totalSiteCount -ge $maxSiteCount)
    {
        $cdbfinding.Severity = "Warning"
        $cdbfinding.WarningMessage += "Content database(s) have reached their maximum site count, either increase the maximum site count on one or more databases or add new databases to add capacity for new sites to be created. New site collections will not be able to be created in this web application unless addressed."
    }

    #Check DB Size
    $HugeDBs = @()
    $LargeDBs=@()
    $HugeSingleSiteDBs=@()
    $LargeSingleSiteDBs=@()
    $ReadOnlyDBs=@()
    foreach ($db in $dbInfo)
    {
        if ($db.'DB Size(GB)' -gt 4000)
        {
            if ($Db.SiteCount -gt 1)
            {
                $HugeDBs +=$DB.Name
            } else {
                $HugeSingleSiteDBs +=$DB.Name
            }
        } elseif ($db.'DB Size(GB)' -gt 200)
        {
            if ($Db.SiteCount -gt 1)
            {
                $largeDBs +=$db.Name
            } else {
                $LargeSingleSiteDBs +=$db.Name
            }               
        }
        if ($db.IsReadOnly)
        {
            $ReadOnlyDBs +=$db.Name
        }
    }
    if ($LargeDBs)
    {
        $cdbfinding.Severity = [SPDiagnostics.Severity]::Informational
        $cdbfinding.WarningMessage += "The following databases are large, you should consider moving sites to other databases. <BR>" + $($LargeDBs -join ',')   
    }
    if ($LargeSingleSiteDBs)
    {
        $cdbfinding.Severity = [SPDiagnostics.Severity]::Warning
        $cdbfinding.WarningMessage += "The following databases are large single site databases, you should consider changing the Information architecture for this site because SharePoint Site collections can't be split over multiple content databases. <BR>" + $($LargeSingleSiteDBs -join ',')   
    }
    if ($HugeDBs)
    {
        $cdbfinding.Severity = [SPDiagnostics.Severity]::Warning
        $cdbfinding.WarningMessage += "The following databases are huge, you should consider moving sites to other databases. Running huge databases can prevent you from meeting disaster recovery targets.. <BR>" + $($HugeDBs -join ',')     
    }
    if ($HugeSingleSiteDBs)
    {
        $cdbfinding.Severity = [SPDiagnostics.Severity]::Warning
        $cdbfinding.WarningMessage += "The following databases are huge single site databases, you should consider changing the Information architecture for the site collection because SharePoint Site collections can't be split over multiple content databases. Running huge databases can prevent you from meeting disaster recovery targets.. <BR>" + $($HugeSingleSiteDBs -join ',')     
    }

    if ($ReadOnlyDBs)
    {
        $cdbfinding.Severity = [SPDiagnostics.Severity]::Warning
        $cdbfinding.WarningMessage += "The following databases are readonly databases, Data in SharePoint can't be modified when the database is ReadOnly on the SQL server <BR>" + $($ReadOnlyDBs -join ',')     
    }

    
    return $cdbfinding
}


function Get-SPWebAppApplicationPool ($webapp)
{
    $webAppAppPoolFinding = New-DiagnosticFinding -name "Application Pool" -severity default -Format List
    
    # Initialize child collection
    #$webAppAppPoolFinding.ChildFindings = New-Object System.Collections.Generic.List[object]

    # Build the base application pool info
    $AppPoolInfo = New-Object PsObject @{
        "AppPool Name"        = $($webapp.ApplicationPool.Name)
        "AppPool DisplayName" = $($webapp.ApplicationPool.DisplayName)
        "Status"              = $webapp.ApplicationPool.Status
        "AppPool User"        = $($webapp.ApplicationPool.Username)
    }

    # Determine which servers to target
    if ($webapp.IsAdministrationWebApplication)
    {
        # Central Admin Web App Ã¢â€ â€™ look for servers running the CA service instance
        $servers = Get-SPServiceInstance |
            Where-Object {
                $_.TypeName -eq "Central Administration" -and
                $_.Status -eq "Online"
            } |
            Select-Object -ExpandProperty Server |
            Select-Object -ExpandProperty Address
    }
    else
    {
        # Regular Web App Ã¢â€ â€™ look for servers running the Web Application service
        $servers = Get-SPServiceInstance |
            Where-Object {
                $_.TypeName -eq "Microsoft SharePoint Foundation Web Application" -and
                $_.Status -eq "Online"
            } |
            Select-Object -ExpandProperty Server |
            Select-Object -ExpandProperty Address
    }

    # Script block to query IIS App Pool settings
    $scriptBlock = {
        param($AppPoolName)

        Import-Module WebAdministration

        $config = Get-Item "IIS:\AppPools\$AppPoolName"

        [PSCustomObject]@{
            ServerName         = $env:COMPUTERNAME
            AppPoolName        = $AppPoolName
            State              = $config.state
            startMode          = $config.startMode
            autoStart          = $config.autoStart
            PrivateMemoryLimit = $config.recycling.periodicRestart.privateMemory
            VirtualMemoryLimit = $config.recycling.periodicRestart.memory
            IdleTimeout        = $config.processModel.idleTimeout
            PingingEnabled     = $config.processModel.pingingEnabled
            managedRuntimeVersion = $config.managedRuntimeVersion
            passAnonymousToken = $config.passAnonymousToken
        }
    }

    # Collect IIS settings from each server
    $iisResults = foreach ($server in $servers) {
        Invoke-Command -ComputerName $server -ScriptBlock $scriptBlock -ArgumentList $webapp.ApplicationPool.Name
    }

    # Create a subÃ¢â‚¬â€˜finding for IIS settings
    $IISAppPoolFinding = New-DiagnosticFinding `
        -name "IIS App Pool Settings" `
        -severity default `
        -InputObject ($iisResults | Select ServerName, AppPoolName, State, startMode, autoStart, PrivateMemoryLimit, VirtualMemoryLimit, IdleTimeout, PingingEnabled, managedRuntimeVersion, passAnonymousToken) `
        -Format Table

    # Attach child finding
    $webAppAppPoolFinding.InputObject = $AppPoolInfo
    $webAppAppPoolFinding.ChildFindings.Add($IISAppPoolFinding)

    return $webAppAppPoolFinding
}

function Get-SPWebApplicationBlockedFileExtensions ($webapp)
{
    if ($webapp.BlockedFileExtensions )
    {
        $BlockedFileTypes= ($webapp.BlockedFileExtensions) -join ','
        
        $bf = new-object PSObject
        $bf | add-Member -MemberType NoteProperty -Name "Blocked File Extensions" -Value $BlockedFileTypes
        $BlockedFileExtensionsFinding = New-DiagnosticFinding  -Name ("Blocked File Extensions ({0})" -f $($WebApp.Url))  -InputObject $bf  -Format List

        if ($Script:SPFarmBuild.Major -eq "16" -and !$webapp.IsAdministrationWebApplication )
        {

            #ashx,asmx,json,soap,svc,xamlx   # false positive for 2016
            if (!(($BlockedFileTypes -eq "ashx,asmx,json,soap,svc,xamlx") -and ($build -eq "2016")))
            {
                #$BlockedFileExtensionsFinding.Severity = [SPDiagnostics.Severity]::Informational
                $BlockedFileExtensionsFinding.Description ="SharePoint 2016 or higher does not have any Blocked File Extensions by default. Please review the Blocked File Extensions for this web application."
                return  $BlockedFileExtensionsFinding
            }
        }
    }
}

Function Get-SelfSiteCreationFinding ($webapp)
{
    $selfSiteInfo = $webapp | Select-Object *self*
    $SelfSiteCreationFinding = New-DiagnosticFinding  -Name ("Self Site Creation ({0})" -f $($WebApp.Url))  -InputObject $selfSiteInfo  -Format List
    return  $SelfSiteCreationFinding
}

Function Get-ManagedPathFinding ($webapp)
{
    $ManagedPaths = Get-SPManagedPath -WebApplication $webapp | Select-Object Type, Name
    $ManagedPathFinding = New-DiagnosticFinding  -Name ("Managed Paths ({0})" -f $($WebApp.Url))  -InputObject $ManagedPaths -Format Table
    return  $ManagedPathFinding
}

Function Get-OutGoingMailServerFinding ($webapp)
{
    $WebAppMailSettings = new-object psobject
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "IncomingEmailServerAddress" -value $($webapp.IncomingEmailServerAddress)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailServiceInstance" -value $($webapp.OutboundMailServiceInstance.Server.Address)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailSenderAddress" -value $($webapp.OutboundMailSenderAddress)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailReplyToAddress" -value $($webapp.OutboundMailReplyToAddress)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailCodePage" -value $webapp.OutboundMailCodePage
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailPort" -value $($webapp.OutboundMailPort)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailEnableSsl" -value $webapp.OutboundMailEnableSsl
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailCertificateThumbprint" -value $($webapp.OutboundMailCertificateThumbprint)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "OutboundMailOverrideEnvelopeSender" -value $($webapp.OutboundMailOverrideEnvelopeSender)
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "EmailToNoPermissionWorkflowParticipantsEnabled" -value $webapp.EmailToNoPermissionWorkflowParticipantsEnabled
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "SendSiteUpgradeEmails" -value $webapp.SendSiteUpgradeEmails
    $WebAppMailSettings | Add-Member -MemberType NoteProperty -Name "SendLoginCredentialsByEmail" -value $webapp.SendLoginCredentialsByEmail

    if ($webapp.IsAdministrationWebApplication)
    {
        #Farm Email Settings
        $FarmMailSettingsFinding = New-DiagnosticFinding  -Name "Farm Email Settings" -InputObject $WebAppMailSettings -Format List
        $farmFindings.ChildFindings.Add(($FarmMailSettingsFinding))
    } else {       
        #WebApp email settings
        $WebAppMailSettingsFinding = New-DiagnosticFinding  -Name ("Email Settings({0})" -f $($WebApp.Url))  -InputObject $WebAppMailSettings -Format List
        return  $WebAppMailSettingsFinding
    }
}

#region WebAppPolicies
Function Get-WebAppPolicyFinding ($webapp)
{
    $WebAppPolicies = $webapp.Policies
    $wpsReport = @()
    foreach ($wp in $WebAppPolicies)
    {
        $wpReport = new-object PSObject
        $wpReport | Add-Member -MemberType NoteProperty -Name "Display Name" -value $($wp.DisplayName)
        $wpReport | Add-Member -MemberType NoteProperty -Name "IsSystemUser" -value $wp.IsSystemUser
        $wpReport | Add-Member -MemberType NoteProperty -Name "PolicyRoleBindings" -value $wp.PolicyRoleBindings
        $wpReport | Add-Member -MemberType NoteProperty -Name "UserName" -value $($wp.UserName)
        $wpsReport += $wpReport
    }
    $WebAppPoliciesFinding = New-DiagnosticFinding  -Name ("User Policy for web application: {0}" -f $($WebApp.Url))  -InputObject $wpsReport -Format Table
    # NO Todo: Policy for Default content access account is validated in Search Content Source

    $NumFullControlPolicies=0
    foreach ($wp in $wpsReport)
    {
        if ($wp.PolicyRolebindings.DenyRightsMask.value__ -gt 0)
        {
            $DenyPolicyFound=$true
        }
        if ($wp.RoleBinding.Name -match "Full Control")
        {
            $NumFullControlPolicies+=1
        }
    }
    if ($DenyPolicyFound)
    {
        $WebAppPoliciesFinding.WarningMessage +="At least one deny policy is configured on the Web Application. Please validate if this is desired."
        $WebAppPoliciesFinding.Severity = [SPDiagnostics.Severity]::Informational 
    }
    if ($NumFullControlPolicies -gt 10)
    {
        $WebAppPoliciesFinding.WarningMessage +="More than 10 accounts are configured with 'Full Control' on the Web Application. Please validate if this is desired."
        $WebAppPoliciesFinding.Severity = [SPDiagnostics.Severity]::Informational 
    }

    return  $WebAppPoliciesFinding
}
#endregion #WebApp Policies


function Get-SPWebAppServiceAppProxiesFinding($webapp)
{
    # Service Application ProxyGroup and Proxies
    [string]$Proxies=""
    $ServiceProxy = New-Object PSObject
    If ($webapp.ServiceApplicationProxyGroup.name -eq "")
    {  
        $serviceProxy | Add-Member -MemberType NoteProperty -name ProxyGroupName -Value "Default" 
    } else {
        $serviceProxy | Add-Member -MemberType NoteProperty -name ProxyGroupName -Value $webapp.ServiceApplicationProxyGroup.name
    }
    $webapp.ServiceApplicationProxyGroup.Proxies | ForEach-Object { $Proxies += $_.Displayname + ", " }
    $Proxies=$Proxies.TrimEnd(', ')
    $serviceProxy | Add-Member -MemberType NoteProperty -name Proxies -Value $($Proxies)


    $WebAppServiceAppProxies = New-DiagnosticFinding -name "Service Application Proxies" -severity default -input $ServiceProxy -Format List 
    return $WebAppServiceAppProxies
}

function Get-SPDiagnosticsExtraBindingsOnIIS ($webapp, $zone)
{
    #search for extra IIS Bindings on local IIS 
    $IIS_Bindingfinding = New-DiagnosticFinding -Name "IIS Binding on IIS server '$($env:COMPUTERNAME)'" -Severity Default -InputObject $null -Format Table

    if ((IsElevated))
    {
        if (!($Script:Build -eq "2013"))
        {
            if ($webapp.IisSettings.Keys -contains $zone)
            {
                $iisSettings = $webApp.IisSettings[$zone]
                if($null -ne $iisSettings)
                {

                    $bis = @()
                    $IIS_Bindings = (Get-IISSite  $iisSettings.ServerComment).Bindings | Select-Object protocol,BindingInformation
                    $IIS_Bindings | ForEach-Object {$_.BindingInformation = $_.BindingInformation}

                    $bhelper =@()
                    foreach ($b in $IIS_Bindings)
                    {                           
                        $bx = $b.Protocol
                        $u= $b.bindingInformation.split(':')[2]
                        # if ([String]::IsNullOrEmpty($u)) {$u = $env:COMPUTERNAME}
                        $bx = $b.Protocol +"://" + $u
                        $ip = $b.BindingInformation.split(":")[0]
                        $p =$b.bindingInformation.split(':')[1]
                        if (!($p -eq "80" -or $p -eq "443"))
                        {
                            $bx += ":" + $p
                        }

                        $bi = new-object PSObject 
                        $bi | Add-Member -MemberType NoteProperty -name "Protocol" -value $b.Protocol
                        $bi | Add-Member -MemberType NoteProperty -name "IPAddress" -value $($ip)
                        $bi | Add-Member -MemberType NoteProperty -name "port" -value $($p)
                        $bi | Add-Member -MemberType NoteProperty -name "Hostname" -value $($u)
                        $bis += $bi
                        $bhelper +=$bx

                    }
                    $IIS_Bindingfinding.InputObject = $bis 

                    $aams = Get-SPAlternateURL -WebApplication $webApp -zone $zone
                    foreach ($aam in $AAMs)
                    {
                        $IIS_BindingExistsAsAAM=$false
                        foreach ($bx in $bhelper)
                        {
                            if ($aam.IncomingUrl -eq $bx)
                            {
                                $IIS_BindingExistsAsAAM = $true
                                #break
                            } 

                            $bxHostName = $bx.Substring($bx.IndexOf("://")+3).Split(":")[0]
                            # $bxProtocol = $bx.Split(":")[0]
                            if([string]::IsNullOrEmpty($bxHostName)) ## empty host header binding, evaluate if protocol and port match
                            {
                                $IIS_BindingExistsAsAAM = Get-AamBindingAndPortMatch -aamUri $aam.IncomingUrl -bindingUri $bx
                            }

                        }
                        if (!$IIS_BindingExistsAsAAM)
                        {
                            $IIS_Bindingfinding.WarningMessage += "In WebApplication  $($($WebApp.Name)) in the $zone zone, the AAM '$($aam.IncomingUrl)' does not exist as an IISBinding"
                            $IIS_Bindingfinding.Severity = [SPDiagnostics.Severity]::Warning 
                            break
                        } 
                    }


                    foreach ($bx in $bhelper)
                    {
                        $AAM_Exists_as_IIS_Binding = $false
                        foreach ($aam in $AAMs)
                        {
                            if ($aam.IncomingUrl -eq $bx)
                            {
                               $AAM_Exists_as_IIS_Binding = $true
                                #break
                            }
                            
                            $bxHostName = $bx.Substring($bx.IndexOf("://")+3).Split(":")[0]
                            # $bxProtocol = $bx.Split(":")[0]
                            if([string]::IsNullOrEmpty($bxHostName)) ## empty host header binding, evaluate if protocol and port match
                            {
                                $AAM_Exists_as_IIS_Binding = Get-AamBindingAndPortMatch -aamUri $aam.IncomingUrl -bindingUri $bx
                            }

                        }
                        if (!$AAM_Exists_as_IIS_Binding)
                        {
                            $IIS_Bindingfinding.WarningMessage += "In WebApplication $($($WebApp.Name)) in the $Zone zone, the IIS Binding '$($($b.BindingInformation))' is not known in SharePoint as AAM`n"       
                            $IIS_Bindingfinding.Severity = [SPDiagnostics.Severity]::Warning 
                            break
                        }
                    }
                } 
            }
            else 
            {
                $IIS_Bindingfinding.Description += "This data can't be collected on SharePoint Server 2013"
            }
        }
        else 
        {
            $iis_BindingFinding.Description += "This data can only be collected when the Script is executed with 'Run as Administrator'"
        }
    }
    return $IIS_Bindingfinding
}

function Get-AamBindingAndPortMatch
{
    [CmdletBinding()]
    param (
        [string]$aamUri,
        [string]$bindingUri
    )
    
    $protocolMatch = $false
    $portsMatch = $false

    $bx = $bindingUri

    $bxHostName = $bx.Substring($bx.IndexOf("://")+3).Split(":")[0]
    if([string]::IsNullOrEmpty($bxHostName)) ## empty host header binding, evaluate if protocol and port match
    {
        $protocolMatch = $false
        $portsMatch = $false

        [uri]$aamUri = [uri]$aam.IncomingUrl
        
        $bxProtocol = $bx.Split(":")[0]
        $bxPort = $bx.Split(":")[2]

        # does protocol match?
        $protocolMatch = [string]::Equals($aamUri.Scheme, $bxProtocol, [StringComparison]::InvariantCultureIgnoreCase)
        
        # does the port match?
        if($null -ne $bxPort -and $bxPort -eq $aamUri.Port)
        {
            $portsMatch = $true
        }
        elseif($null -eq $bxPort -and (($aamUri.Port -eq 80 -and $aamUri.Scheme -eq "http") -or ($aamUri.Port -eq 443 -and $aamUri.Scheme -eq "https")))
        {
            # default port is used for protocol so match
            $portsMatch = $true
        }

        # if both port and protocol match then this is a match
        if($protocolMatch -and $portsMatch)
        {
            return $true
        }
    }

    return $false
}

function Get-SPDiagnosticsWebAppChangeLogFinding
{
    [cmdletbinding()]
    param(
        [Microsoft.SharePoint.Administration.SPwebApplication]$WebApp
    )

    #ChangeLog
    $changeLogObject = [PSCustomObject]@{
        ChangeLogExpirationEnabled = $WebApp.ChangeLogExpirationEnabled
        ChangeLogRetentionPeriod = ($WebApp.ChangeLogRetentionPeriod.days.ToString() + " days")
    }
    
    $ChangeLogFinding = New-DiagnosticFinding `
        -Name ("Change log Configuration ({0})" -f $($WebApp.Url)) `
        -Severity Default `
        -InputObject $changeLogObject `
        -Format List
    
    if ($WebApp.ChangeLogExpirationEnabled -eq $false)
    {
        $ChangeLogFinding.WarningMessage += ("ChangeLog Expiration is not enabled for this web application. This can have an impact on database size. To enable change log expiration use the below PowerShell.")
        $ChangeLogFinding.WarningMessage += ("<div class=`"code`">`$webApp = Get-SPWebApplication -Identity `"{0}`"<br>`$webApp.ChangeLogExpirationEnabled = `$true<br>`$webApp.Update()</div>" -f $($WebApp.Url))
        $ChangeLogFinding.Severity = [SPDiagnostics.Severity]::Warning
    }
    if ($WebApp.ChangeLogRetentionPeriod.days -lt 14)
    {
        $ChangeLogFinding.WarningMessage += ("The change log in the databases for this web application is only kept for $($WebApp.ChangeLogRetentionPeriod.days) days. This can result in problems with alerts and incremental crawls. To change this use the below PowerShell to set to the desired timeframe (recommended minimum of 14 days).")
        $ChangeLogFinding.WarningMessage += ("<div class=`"code`">`$webApp = Get-SPWebApplication -Identity `"{0}`"<br>`$webApp.ChangeLogRetentionPeriod = New-TimeSpan -Days 30<br>`$webApp.Update()</div>" -f $($WebApp.Url))
        $ChangeLogFinding.Severity = [SPDiagnostics.Severity]::Warning
    }
    
    return $ChangeLogFinding
}

function Get-SPDiagnosticsWebAppThrottlingFinding
{
    [cmdletbinding()]
    param(
        [Microsoft.SharePoint.Administration.SPwebApplication]$WebApp
    )   
    if ($WebApp.IsAdministrationWebApplication)
    {
        return $null  #Do not collect for Central Admin 
    }

        $WebAppThrottleSettings = New-Object psObject
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxItemsPerThrottledOperation (List View Threshold)" -Value $webApp.MaxItemsPerThrottledOperation.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxItemsPerThrottledOperationOverride (List View Threshold for auditors and administrators)" -Value $webApp.MaxItemsPerThrottledOperationOverride.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxItemsPerThrottledOperationWarningLevel" -Value $webApp.MaxItemsPerThrottledOperationWarningLevel.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "AllowOMCodeOverrideThrottleSettings" -Value $webApp.AllowOMCodeOverrideThrottleSettings
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "UnthrottledPrivilegedOperationWindowEnabled" -Value $webApp.UnthrottledPrivilegedOperationWindowEnabled
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "DailyStartUnthrottledPrivilegedOperationsHour" -Value $webApp.DailyStartUnthrottledPrivilegedOperationsHour
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "DailyStartUnthrottledPrivilegedOperationsMinute" -Value $webApp.DailyStartUnthrottledPrivilegedOperationsMinute
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "DailyUnthrottledPrivilegedOperationsDuration" -Value $webApp.DailyUnthrottledPrivilegedOperationsDuration
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "SyncSiteProvisioningThrottle" -Value $webApp.SyncSiteProvisioningThrottle
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxQueryLookupFields" -Value $webApp.MaxQueryLookupFields
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxListItemRowStorage" -Value $webApp.MaxListItemRowStorage

        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "AlertsMaximum" -Value $webApp.AlertsMaximum.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "AlertsMaximumQuerySet" -Value $webApp.AlertsMaximumQuerySet.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxSizePerCellStorageOperation" -Value $webApp.MaxSizePerCellStorageOperation
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxUniquePermScopesPerList" -Value $webApp.MaxUniquePermScopesPerList.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "CascadeDeleteMaximumItemLimit" -Value $webApp.CascadeDeleteMaximumItemLimit.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaximumFileSize" -Value $webApp.MaximumFileSize.ToString('N0')

        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxAuditLogTrimmingRetention" -Value $webApp.MaxAuditLogTrimmingRetention
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "UserDefinedWorkflowMaximumComplexity" -Value $webApp.UserDefinedWorkflowMaximumComplexity.ToString('N0')
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxSizeForSelfServiceEvalSiteCreationMB" -Value $webApp.MaxSizeForSelfServiceEvalSiteCreationMB.ToString('N0')

        $WebAppThrottlingFinding = New-DiagnosticFinding -Name ("WebAppThrottling ({0})" -f $($WebApp.Url))  -InputObject $WebAppThrottleSettings -Format List

        if ( $webApp.MaxItemsPerThrottledOperation -gt 5000)
        {
            $WebAppThrottlingFinding.WarningMessage +="The list view Threshold was increased above 5000. This can cause Performance problems when accessing large lists."
        }

        if ( $webApp.MaxItemsPerThrottledOperationOverride -gt 20000)
        {
            $WebAppThrottlingFinding.WarningMessage +="The list view Threshold for Administrators and Authors was increased above 20000. This can cause Performance problems when accessing large lists."
        }
        if ( $WebApp.DailyUnthrottledPrivilegedOperationsDuration -gt 2 -and $WebApp.UnthrottledPrivilegedOperationWindowEnabled)
        {
            $WebAppThrottlingFinding.WarningMessage +="More than 2 hours are allowed every day for unthrottled list operations"
        }        
        
        if ( $WebApp.MaxQueryLookupFields -gt 12)
        {
            $WebAppThrottlingFinding.WarningMessage +="The number of Lookup fields in lists is increased over 12. This can add a lot of load on the system and can cause delays when opening lists."
        }
        
        if ( $WebApp.MaxUniquePermScopesPerList -gt 50000)
        {
            $WebAppThrottlingFinding.WarningMessage +="The MaxUniquePermScopesPerList is increased over 50000. This can add a lot of load on the system and can cause delays when opening lists or permissions not applied correctly."
        }

        if ($WebAppThrottlingFinding.WarningMessage.Count -gt 0)
        {
            $WebAppThrottlingFinding.Severity = [SPDiagnostics.Severity]::Warning
            $WebAppThrottlingFinding.ReferenceLink +="https://social.technet.microsoft.com/wiki/contents/articles/53460.sharepoint-troubleshooting-5000-list-view-threshold-limit-issue.aspx"
            $WebAppThrottlingFinding.ReferenceLink +="https://support.microsoft.com/en-us/office/manage-large-lists-and-libraries-b8588dae-9387-48c2-9248-c24122f07c59?ui=en-us&rs=en-us&ad=us"
        } else {
            $WebAppThrottlingFinding.Severity = [SPDiagnostics.Severity]::Default
        }

        #Todo:  Add more tests
        
        # Task 532: Removing site upgrade finding
        #$suts = new-object PSObject
        #$suts | Add-Member -MemberType NoteProperty -Name "AppPoolConcurrentUpgradeSessionLimit" -Value $webapp.SiteUpgradeThrottleSettings.AppPoolConcurrentUpgradeSessionLimit
        #$suts | Add-Member -MemberType NoteProperty -Name "UsageStorageLimit" -Value $webapp.SiteUpgradeThrottleSettings.UsageStorageLimit
        #$suts | Add-Member -MemberType NoteProperty -Name "SubwebCountLimit" -Value $webapp.SiteUpgradeThrottleSettings.SubwebCountLimit
        #$suts | Add-Member -MemberType NoteProperty -Name "Id" -Value $webapp.SiteUpgradeThrottleSettings.Id
        #$suts | Add-Member -MemberType NoteProperty -Name "Status" -Value $webapp.SiteUpgradeThrottleSettings.Status
        #$suts | Add-Member -MemberType NoteProperty -Name "DeploymentLocked" -Value $webapp.SiteUpgradeThrottleSettings.DeploymentLocked
        #$SiteUpgradeThrottleSettingsFinding = New-DiagnosticFinding -Name "  Site Upgrade Throttling" -Severity Default -InputObject $suts -Format List
        #$webAppThrottlingFinding.ChildFindings.Add(($SiteUpgradeThrottleSettingsFinding))

        $WebAppThrottle = $webapp.HttpThrottleSettings
        $HTTPthrottleSettings = New-Object psobject
        $HTTPthrottleSettings | Add-Member -MemberType NoteProperty -Name "RefreshInterval" -Value $WebAppThrottle.RefreshInterval
        $HTTPthrottleSettings | Add-Member -MemberType NoteProperty -Name "NumberOfSamples" -Value $WebAppThrottle.NumberOfSamples
        $HTTPthrottleSettings | Add-Member -MemberType NoteProperty -Name "PerformThrottle" -Value $WebAppThrottle.PerformThrottle
        $HTTPthrottleSettings | Add-Member -MemberType NoteProperty -Name "UnclassifiedRequestThrottleLevel" -Value $WebAppThrottle.UnclassifiedRequestThrottleLevel
        $WebAppHTTPThrottlingFinding = New-DiagnosticFinding -Name "  HTTP Throttling" -Severity Default -InputObject $HTTPthrottleSettings -Format Table

        $WebAppHTTPThrottlingFindingPerfs = New-DiagnosticFinding -Name "   Performance Counters" -Severity Default -InputObject ($WebAppThrottle.PerformanceMonitors | select-Object Category, Counter, Instance, AssociatedHealthScoreCalculator ) -Format Table
 
        #Calculation of Buckets for Health throttling on local server
        [double[]]$BucketModifiers = (1e-6,1.0,2.0,4.0,8.0,16.0,32.0,64.0,82.0,100.0)
        $NumProcs = [System.Environment]::Processorcount
        [double[]]$buckets=new-object double[] 10
            $buckets[0] = 6.0 * $NumProcs
            $buckets[1] = 8.0 * $NumProcs
            $buckets[2] = 10.0 * $NumProcs
            $buckets[3] = 12 * $NumProcs

            for ($i = 4; $i -lt $BucketModifiers.Length; $i++)
            {
                $buckets[$i] = $buckets[3] + $BucketModifiers[$i];
            }

            $buckets[9] = [Math]::Max(500, $buckets[9]); 

        $BucketString="["
        $BucketString += $Buckets | ForEach-Object {($_.ToString()).Trim() +".0,"}
        $BucketString= $BucketString.TrimEnd(',') +']'
        $BucketString=$BucketString.Replace(' ','')

        $counterDefault = new-Object PsObject @{
            "Available Mbytes"="[1000.0,500.0,400.0,300.0,200.0,100.0,80.0,60.0,40.0,20.0]"
            "Requests Current"=$BucketString
        }
        
        foreach ($pm in $WebAppThrottle.PerformanceMonitors)
        {
            if ($counterDefault[$pm.counter] -ne $pm.AssociatedHealthScoreCalculator) 
            {
                $WebAppHTTPThrottlingFindingPerfs.Description += "HTTP Throttling Performance Counters are not default $($counterDefault[$pm.counter]) for counter '$($pm.Counter)' on server ' $($($env:COMPUTERNAME))'"
                $WebAppHTTPThrottlingFindingPerfs.Description += "This information is shown when SharePoint servers have a different number of CPUs. And the sever the script is running on has a different number of CPUs than the number of CPUs on the server the Web Application was originally created on."
                $WebAppHTTPThrottlingFindingPerfs.Severity = [SPDiagnostics.Severity]::Informational
                $WebAppHTTPThrottlingFindingPerfs.ReferenceLink ="https://www.wictorwilen.se/blog/sharepoint-2013-sharepoint-health-score-and-throttling-deep-dive"
            }
        }

        $WebAppHTTPThrottlingFinding.Childfindings.Add(($WebAppHTTPThrottlingFindingPerfs))
        
        $WebAppHTTPThrottlingFindingClassifiers = New-DiagnosticFinding -Name "   Throttling Classifiers" -Severity Default -InputObject ($WebAppThrottle.ThrottleClassifiers | Select-Object ThrottleLevel) -Format List
        $WebAppHTTPThrottlingFinding.Childfindings.Add(($WebAppHTTPThrottlingFindingClassifiers))

        $webAppThrottlingFinding.ChildFindings.Add(($WebAppHTTPThrottlingFinding))
    
        return $WebAppThrottlingFinding
}

function Get-SPDiagnosticsWebConfigModificationsFinding
{
    [cmdletbinding()]
    Param()

    $finding = New-DiagnosticFinding -Name "Web Config Modifications"

    $webSvcMods = [Microsoft.SharePoint.Administration.SPWebService]::ContentService.WebConfigModifications
    $webSvcModsFinding = New-DiagnosticFinding `
        -Name "Web Config Modifications: Content Service" `
        -Description "Web config modifications applied to the content service will be applied to all web applications (except central administration)." `
        -InputObject $webSvcMods `
        -Format Table
    if($webSvcMods.Count -eq 0)
    {
        $webSvcModsFinding.Description += "No SPWebConfigModifications identified."
    }
    else
    {
        $dupModCOunt = Get-SPDuplicateWebConfigModifications $webSvcMods
        if($dupModCOunt)
        {
            $webSvcModsFinding.Severity = [SPDiagnostics.Severity]::Warning
            $webSvcModsFinding.WarningMessage += "$($dupModCOunt) duplicate web config modification(s) found, these duplicate(s) are unnecessary and may cause problems. Please remove the duplicate(s)"
        }
    }
    $finding.ChildFindings.Add($webSvcModsFinding)
    
    $webApps = Get-SPWebApplication -IncludeCentralAdministration
    foreach($webApp in $webApps)
    {
        $webAppMods = $webApp.WebConfigModifications
        $webAppFinding = New-DiagnosticFinding -Name ("Web Config Modifications : {0}" -f $($webApp.Url)) -InputObject $webAppMods -Format Table
        if($webAppMods.Count -eq 0)
        {
            $webAppFinding.Description += "No SPWebConfigModifications identified."
        }
        else
        {
            $dupModCOunt = Get-SPDuplicateWebConfigModifications $webAppMods
            if($dupModCOunt)
            {
                $webAppFinding.Severity = [SPDiagnostics.Severity]::Warning
                $webAppFinding.WarningMessage += "$($dupModCOunt) duplicate web config modification(s) found, these duplicate(s) are unnecessary and may cause problems. Please remove the duplicate(s)"
            }
        }
        $finding.ChildFindings.Add($webAppFinding)
    }
    return $finding
}

function Get-SPDuplicateWebConfigModifications
{
    [cmdletbinding()]
    Param($WebConfigModifications)

    #$foundDuplicateMods = $false
    #$dupFindings = $null
    $dupCount = 0
    
    for($i=0; $i -lt $WebConfigModifications.Count; $i++)
    {
        for($j=$i+1; $j-lt $WebConfigModifications.Count; $j++)
        {
            if ( ($WebConfigModifications[$i]).path -eq ($WebConfigModifications[$j]).path `
            -and ($WebConfigModifications[$i]).Name -eq ($WebConfigModifications[$j]).Name `
            -and ($WebConfigModifications[$i]).type -eq ($WebConfigModifications[$j]).type `
            -and ($WebConfigModifications[$i]).value -eq ($WebConfigModifications[$j]).value
            )
            {
                $dupCount++
                #$foundDuplicateMods = $true
                #$dupFindings += "<BR>" + $WebConfigModifications[$i].Name -join ';'
                #if ($dupFindings -notmatch $dupfinding)
                #{
                #    $dupFindings += $dupfinding
                #}
            }

        }
    }

    #return $dupFindings
    return $dupCount
}


Function Get-SPDiagnosticsMissingSTSHeader ($webapp)
{
    #Missing STS Header
    $MissingSTSHeaderFinding = New-DiagnosticFinding -name "MicrosoftSharePointTeamServices HTTP response header" -severity default -input $null -Format Table 
    if ($Script:Build -ne "2013")
    {
        if (!(IsElevated))
        {
            $MissingSTSHeaderFinding.Description +="This data can only be collected when the script is 'Run as Administrator'"
        } 
        else 
        {
            $HeaderMissing = $false
            $SPTeamServicesHeaderValues = @()

            foreach($zone in [enum]::GetNames("Microsoft.SharePoint.Administration.SPUrlZone"))
            {
                if ($webapp.IisSettings.Keys -contains $zone)
                {
                    $iisSettings = $webapp.IisSettings[$zone]
                    $WebSiteName = $iisSettings.ServerComment

                    $SiteConfiguredOnThisServer = $false
                    if ($WebSiteName)
                    {
                        $IISSite = Get-IISSite -Name $WebSiteName #-ea SilentlyContinue
                        if ($IISSite)
                        {
                            $SiteConfiguredOnThisServer = $true
                            $IISConfigSection = Get-IISConfigSection -SectionPath system.webServer/httpProtocol -CommitPath $WebSiteName | Get-IISConfigCollection -CollectionName "customHeaders";
                            $Header = Get-IISConfigCollectionElement -ConfigCollection $IISConfigSection  | Where-Object {$_["name"] -eq "MicrosoftSharePointTeamServices"}
        
                            $SPTeamServicesHeaderValue=New-Object psobject
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Server" -Value ($env:Computername)
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "WebApplication" -Value $($webapp.Name)
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Zone" -Value $Zone
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "SiteName" -Value $($WebSiteName)
                            if ($header)
                            {
                                $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Header" -Value "MicrosoftSharePointTeamServices"
                                $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Value" -Value $Header["Value"]
                            } 
                            else 
                            { 
                                $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Header" -Value ""
                                $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Value" -Value ""        
                                $headerMissing = $true
                            }
                            $SPTeamServicesHeaderValues += $SPTeamServicesHeaderValue
                        } else {
                            $SiteConfiguredOnThisServer = $false
                            $MissingSTSHeaderFinding.Description +="The Website $($webapp.Name) is not configured on server $($($env:Computername))"
                        }
                    }
                }
            }
            if ($headerMissing -and $SiteConfiguredOnThisServer)
            {
                $MissingSTSHeaderFinding.Severity = [SPDiagnostics.Severity]::Warning
                $MissingSTSHeaderFinding.WarningMessage +=("Missing IIS ResponseHeader 'MicrosoftSharePointTeamServices'")
                $MissingSTSHeaderFinding.Description += "If this HTTP Response Header is missing, it will prevent the crawler from discovering that the site is SharePoint and will not use the 'sitedata.asmx' web service to enumerate the SP Content.<br/>"
                $MissingSTSHeaderFinding.Description += "Office Client integration can be impacted as well when this header is missing.<br/>"
                $MissingSTSHeaderFinding.Description += "This is often removed manually, in the web.config, or 'Client Integration' is turned off within 'Central Admin > Web Apps > Auth provider'<br/>"
            } 
            $MissingSTSHeaderFinding.inputObject = $SPTeamServicesHeaderValues
        }
    }
    else 
    {
        $MissingSTSHeaderFinding.Description +="This data can't be collected on SharePoint Server 2013"
    }
    return $MissingSTSHeaderFinding
}

function Confirm-DebugCompilationDisabled ($servercomment)
{
    $debug = "Unknown"

    try{
        if(!(IsElevated))
        {
            throw("Requires Elevation")
        }
    
        if($serverComment)
        {
            $webconfigFilePath=(Get-WebFilePath "IIS:\Sites\$ServerComment\web.config")
    
            if (test-path $webconfigFilePath) 
            {
                $doc = (Get-Content $webconfigFilePath) -as [Xml]
    
                $debug = $doc.configuration.'system.web'.compilation.debug
            }
        }
    
        return $debug
    }
    catch{
        # Swallow any exceptions. Can check the Error Finding for details
    }

    return "There was a problem accessing the debug attribute on the compilation element. This could be due to elevation requirements"
    
}

function Get-SPDiagnosticsBlobCache($webapp)
{
    if($Performance)
    {
        # don't do anything for Central Admin Web App
        if ($webapp.IsAdministrationWebApplication)
        {
            return
        }
        #Blob cache settings in Web.config on local IIS 
        $BlobCachefindings = New-DiagnosticFinding -Name "BlobCache Settings" -Severity Default -InputObject $null -Format list -ReferenceLink "https://learn.microsoft.com/en-us/sharepoint/administration/cache-settings-operations#blob-cache"
        if (!(IsElevated))
        {
            $BlobCachefindings.Description += "This data can only be collected when the Script is executed with 'Run as Administrator'"
        } 
        else
        {
            if (!($Script:Build -eq "2013"))
            {
                if (!($webapp.IsAdministrationWebApplication))
                {
                    foreach($zone in [enum]::GetNames("Microsoft.SharePoint.Administration.SPUrlZone"))
                    {
                        $servercomment = $webapp.IisSettings[$zone].ServerComment
                        if ($servercomment)
                        {
                            $webconfigFilePath=(Get-WebFilePath "IIS:\Sites\$ServerComment\web.config")
                            if (test-path $webconfigFilePath) 
                            {
                                $doc = (Get-Content $webconfigFilePath) -as [Xml]

                                $bc=$doc.configuration.SharePoint.BlobCache
                                $bc = $bc | Select-Object Location, Path, MaxSize, Enabled,ImageRenditionMaxFileSize,ImageRenditionMaxSourcePixels
                                $BlobCachefinding = New-DiagnosticFinding -Name "BlobCache Setting - Web Application: '$($($webapp.name))' -- Zone: '$Zone' -- Server:  '$($env:COMPUTERNAME)'" -Severity Default -InputObject $bc -Format list

                                if ($bc.Enabled -eq "False")
                                {
                                    $BlobCachefinding.Severity = [SPDiagnostics.Severity]::Informational
                                    $BlobCachefinding.Description +="BlobCache is not 'Enabled' for this web application and zone"
                                    $BlobCachefinding.Description += " -- A PowerShell script to manage the BlobCache Settings can be downloaded from https://github.com/rainerasbach/ManageBlobCache/blob/main/ManageBlobCache.ps1 "    
                                }
                                $BlobCachefindings.ChildFIndings.Add(($BlobCachefinding))
                            }
                        }
                    }
                }
            }
            else
            {
                $BlobCachefindings.Description += "This data can't be collected on SharePoint Server 2013"
            }
        }
        return $BlobCachefindings
    }
}
function Get-SPDiagnosticPeoplePickerSettings($webApp)
{
    $SearchActiveDirectoryDomains = [System.String]::Empty
    $DistributionListSearchDomains = [System.String]::Empty
    $ServiceAccountDirectoryPaths = [System.String]::Empty

    #Task 395  - expanding SearchActiveDirectoryDomains
    foreach($key in $WebApp.PeoplePickerSettings.SearchActiveDirectoryDomains)
    {
        $SearchActiveDirectoryDomains += $key.DomainName + "; "
    }
    foreach($value in $WebApp.PeoplePickerSettings.DistributionListSearchDomains)
    {
        $DistributionListSearchDomains += "'" + $value + "'; "
    }
    foreach($value in $WebApp.PeoplePickerSettings.ServiceAccountDirectoryPaths)
    {
        $ServiceAccountDirectoryPaths += "'" + $value + "'; "
    }

    $retObj = [PSCustomObject]@{
        #SearchActiveDirectoryDomains need to be expanded since there are properties for each.
        SearchActiveDirectoryDomains = $($SearchActiveDirectoryDomains)
        ActiveDirectoryCustomQuery = $WebApp.PeoplePickerSettings.ActiveDirectoryCustomQuery
        ActiveDirectoryCustomFilter = $WebApp.PeoplePickerSettings.ActiveDirectoryCustomFilter
        OnlySearchWithinSiteCollection = $WebApp.PeoplePickerSettings.OnlySearchWithinSiteCollection
        PeopleEditorOnlyResolveWithinSiteCollection = $WebApp.PeoplePickerSettings.PeopleEditorOnlyResolveWithinSiteCollection
        DistributionListSearchDomains = $($DistributionListSearchDomains)
        ActiveDirectorySearchTimeout = $WebApp.PeoplePickerSettings.ActiveDirectorySearchTimeout
        NoWindowsAccountsForNonWindowsAuthenticationMode = $WebApp.PeoplePickerSettings.NoWindowsAccountsForNonWindowsAuthenticationMode
        ServiceAccountDirectoryPaths = $($ServiceAccountDirectoryPaths)
        ReferralChasingOption = $WebApp.PeoplePickerSettings.ReferralChasingOption
        ActiveDirectoryRestrictIsolatedNameLevel = $WebApp.PeoplePickerSettings.ActiveDirectoryRestrictIsolatedNameLevel
        NoUpnResolveWhenResolvingEmailAddress = $WebApp.PeoplePickerSettings.NoUpnResolveWhenResolvingEmailAddress
        #Hashtable that is not resolved in the table. If important it should be a separate child finding 
        UpgradedPersistedProperties = $WebApp.PeoplePickerSettings.UpgradedPersistedProperties
    }

    $peoplePickerFindings = New-DiagnosticFinding -Name "People Picker Settings" -Severity Default -InputObject $retObj -Format List
    Foreach($SADD in $WebApp.PeoplePickerSettings.SearchActiveDirectoryDomains)
    {
        $DN = $($SADD.DomainName)

        $SADDProps = [PSCustomObject] @{
            DomainName = $DN
            ShortDomainName = $($SADD.ShortDomainName)
            LoginName = $($SADD.LoginName)
            CustomFilter = $($SADD.CustomFilter)
            }
        $SADDFinding = New-DiagnosticFinding -Name $DN -Severity Default -InputObject $SADDProps -Format List
        $peoplePickerFindings.childfindings.add($SADDFinding)
    }
    return $peoplePickerFindings
}

function Get-SPDiagnosticsSideBySidePathcingFinding
{
    [cmdletbinding()]
    Param()

    $contentSvc = [Microsoft.SharePoint.Administration.SPWebService]::ContentService
    ##SBS is only relevant in SP2016 or greater
    $farmBuild = [Microsoft.SharePoint.Administration.SPFarm]::Local.BuildVersion
    if($farmBuild.Major -lt 16 -or !$contentSvc.EnableSideBySide)
    {
        return $null
    }
    
    $sbsToken = $contentSvc.SideBySideToken
    #Task 577: SPFarm.BuildVersion is not the authoritative source
    #$farmBuildToken = $farmBuild.ToString()
    $latestPatchVersion = Get-SPLatestPatchVersion
    $sbsTokenIsCurrent = $null
    if(![string]::IsNullOrEmpty($sbsToken))
    {
        $sbsTokenIsCurrent = $sbsToken -eq $latestPatchVersion
    }

    $retObj = [PSCustomObject]@{
        EnableSideBySide = $contentSvc.EnableSideBySide
        SideBySideToken = $sbsToken
        LatestPatchVersion = $latestPatchVersion
        SideBySideTokenMatchesLatestPatchVersion = $sbsTokenIsCurrent
    }

    $finding = New-DiagnosticFinding `
        -Name "Side by Side Patching"  `
        -ReferenceLink "https://blog.stefan-gossner.com/2017/01/10/sharepoint-server-2016-patching-using-side-by-side-functionality-explained/" `
        -InputObject $retObj `
        -Format List
    if(!($sbsTokenIsCurrent) -and $contentSvc.EnableSideBySide)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage = "SideBySideToken is not the current latest installed patch version, consider updating the side by side value to the current farm build or disabling side by side functionality. This can be accomplished by running Copy-SPSideBySideFiles or by running the configuration wizard."
    }

    return $finding
}

function Get-SPLatestPatchVersion
{
    [cmdletbinding()]
    param ()

    $t = [Microsoft.SharePoint.Administration.SPServerProductInfo]
    $flags = [System.Reflection.BindingFlags]("NonPublic", "Static")
    $m = $t.GetMethod("DetectLocalProductVersions", $flags, $null, [type[]]([Microsoft.SharePoint.Administration.SPProductVersions]), $null)

    $prodVer = [Microsoft.SharePoint.Administration.SPProductVersions]::GetProductVersions()
    $prodInfo = $m.Invoke($null, @($prodVer))

    $products = $prodInfo.Products

    [version]$latestPatchVersion = [version]::new()

    $contentSvc = [Microsoft.SharePoint.Administration.SPWebService]::ContentService
    if($null -eq $contentSvc)
    {
        return
    }

    foreach($product in $products)
    {
        $singleProd = $prodInfo.GetSingleProductInfo($product)
        $patchableUnitNames = $singleProd.PatchableUnitDisplayNames
        if($null -eq $patchableUnitNames -or $patchableUnitNames.Count -eq 0)
        {
            continue
        }

        foreach($unitName in $patchableUnitNames)
        {
            $units = $singleProd.GetPatchableUnitInfoByDisplayName($unitName)
            if($null -eq $units -or $units.Count -eq 0)
            {
                continue
            }

            foreach($unit in $units)
            {
                if($null -eq $unit -or $null -eq $unit.LatestPatch)
                {
                    continue
                }
                if($unit.LatestPatch.Version -gt $latestPatchVersion)
                {
                    $latestPatchVersion = $unit.LatestPatch.Version
                }
            }
        }
    }

    return $latestPatchVersion.ToString()
}


function Get-SPDiagnosticsFarmSolutionsFinding 
{
    [cmdletbinding()]
    param ()
   
    $farm = Get-SPFarm
    $webServices = [Microsoft.SharePoint.Administration.SPWebServiceCollection]::new($farm)
    $webAppCount = 0
    foreach($webService in $webServices)
    {
        $webAppCount+=$webService.WebApplications.Count
    }
    $globalDeployServers = $script:servers | Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    $wfeDeployServers = @()
    foreach($server in $globalDeployServers)
    {
        $webAppInstance = $server.ServiceInstances | Where-Object{$_.TypeName -match "Microsoft SharePoint Foundation Web Application"}
        if($webAppInstance.Status -eq [Microsoft.SharePoint.Administration.SPObjectStatus]::Online)
        {
            $wfeDeployServers += $server
        }
    }

    $solutions = Get-SPSolution

    $farmSolutionsFinding = New-DiagnosticFinding `
        -Name "Farm Solutions ($($solutions.Count))" `
        -InputObject $null

    if($solutions.Count -eq 0)
    {
        #$farmSolutionsFinding.Description += "No farm solutions present"
        return #$farmSolutionsFinding
    }
    $solutions = $solutions | sort-object "Name"
    foreach($solution in $solutions)
    {
        $Sol = $solution | Select-Object Farm, Name, Deployed, DeploymentSTate, SolutionFile,  `
                ContainsGlobalAssembly,ContainsCasPolicy,ContainsWebApplicationResource, SolutionId, IsWebPartPackage, LanguagePacks, `
                Added,LastOperationResult, JobStatus, JobExists, CanSelectForBackup, CanSelectForRestore, TypeName, `
                Displayname, id, Status, Parent, Version, CanBAckupRestoreAsConfiguration, DiskSizeRequired,CanRenameOnrestore, LastOperationDetails

        $solutionFinding = New-DiagnosticFinding `
            -Name ("Farm Solution: {0}" -f $($solution.Name)) `
            -InputObject $Sol `
            -Format List
        
    
    
        if(!$Solution.Deployed -and $Solution.DeployedServers.Count -ge 1)
        {
            ##Incomplete solution deployment, this solution should be flagged
            $type = [type][Microsoft.SharePoint.Administration.SPSolution]
            $flags = [System.Reflection.BindingFlags]"Instance", "NonPublic"
            $prop = $type.GetProperty("DeploymentServerType", $flags)
            $deploymentServerType = $prop.GetValue($solution)
            $missingDeploymentServers = $null

            if($deploymentServerType -eq [Microsoft.SharePoint.Administration.SPServerRole]::WebFrontEnd)
            {
                ## Should be deployed to all servers running web application service
                ## identify servers running web app service that are not in deployed servers
                foreach($deployServer in $wfeDeployServers)
                {
                    if($deployServer -notin $solution.DeployedServers)
                    {
                        $missingDeploymentServers+=$deployServer
                        
                    }
                }   
            }
            else
            {
                ## Should be deployed globally
                foreach($deployServer in $globalDeployServers)
                {
                    if($deployServer -notin $solution.DeployedServers)
                    {
                        $missingDeploymentServers += $deployServer
                    }
                }
            }

            $missingServerStr = @()
            foreach($missingDeploymentServer in $missingDeploymentServers)
            {
                $missingServerNames +=$($missingDeploymentServer.Name)
                #$missingServerStr += $missingDeploymentServer.Name -join ","
            }

            $installCmd = "Install-SPSolution -Identity "  + $solution.Name + " -Local"
            if($solution.ContainsCasPolicy){$installCmd += " -CASPolicies"}
            if($solution.ContainsGlobalAssembly){$installCmd += " -GACDeployment"}
            if($solution.ContainsWebApplicationResource){$installCmd += " -FullTrustBinDeployment"}
            
            if($solution.DeployedWebApplications.Count -eq $webAppCount){$installCmd += " -AllWebApplications"}
            elseif($solution.DeployedWebApplications.Count -ge 1)
            {
                $baseCmd = $installCmd
                $installCmd = [string]::Empty

                foreach ($webApp in $solution.DeployedWebApplications)
                {
                    $installCmd += $baseCmd + " -WebApplication `"" + $($webApp.Url) + "`" [-Force]" -join "<BR>"
                }
            }
            else
            {
                $installCmd += " [-Force]"
            }
            

            $solutionFinding.Severity = [SPDiagnostics.Severity]::Critical
            $solutionFinding.WarningMessage += ("Solution is not deployed to {0} server(s), incomplete solution deployment can cause issues. Please deploy this solution to the mentioned servers. To deploy this solution use the Install-SPSolution with the -Local switch on the server(s) where it is missing." -f $missingDeploymentServers.Count, $missingServerStr)
            $solutionFinding.WarningMessage += ("Missing on {0} server(s): {1}" -f $missingDeploymentServers.Count, [string]::Join(", ", $missingServerNames))
            $solutionFinding.ReferenceLink += "https://learn.microsoft.com/en-us/powershell/module/sharepoint-server/install-spsolution?view=sharepoint-server-ps"
            #$solutionFinding.WarningMessage += $installCmd
        }
        
        $deployedServerNames = @()
        foreach($deployedServer in $solution.DeployedServers)
        {
            $deployedServerNames += $($deployedServer.Name)
        }
        $solutionFinding.Description += ("Deployed to {0} server(s): {1}" -f $solution.DeployedServers.Count, [string]::Join(", ", $deployedServerNames))

        $farmSolutionsFinding.ChildFindings.Add($solutionFinding)
    }
    return $farmSolutionsFinding
}

Function Get-SPDiagnosticsFarmFeaturesFinding
{

        $FeaturesFinding = New-DiagnosticFinding -Name "Features" -InputObject $null -Format List 
        $culture = [System.Globalization.CultureInfo]::CurrentCulture

        ### Farm Features ###
        
        $farmFeatures = get-spfeature | where-object {$_.scope -eq "Farm"}
        $farmFeatureResults = @()
        foreach($farmFeature in $farmFeatures)
        {
            $farmFeatureObj = New-Object PSObject
            $farmFeatureObj | Add-Member -MemberType NoteProperty -Name Title -Value $farmFeature.GetTitle($culture)
            $farmFeatureObj | Add-Member -MemberType NoteProperty -Name Id -Value $farmFeature.Id
            $farmFeatureObj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $farmFeature.DisplayName
            $farmFeatureObj | Add-Member -MemberType NoteProperty -Name SolutionId -Value $farmFeature.SolutionId
            $farmFeatureObj | Add-Member -MemberType NoteProperty -Name CompatibilityLevel -Value $farmFeature.CompatibilityLevel
            $farmFeatureObj | Add-Member -MemberType NoteProperty -Name Version -Value $farmFeature.Version
            #$farmFeatureObj | Add-Member -MemberType NoteProperty -Name RootDirectory -Value $farmFeature.RootDirectory
            $farmFeatureResults += $farmFeatureObj

        }

        $FarmFeaturesFinding = New-DiagnosticFinding -Name "  Farm Features ($($FarmFeatures.Count))" -InputObject $farmFeatureResults -Format Table 
        $FeaturesFinding.ChildFindings.Add(($FarmFeaturesFinding))

        ### WebApp Features ###
        $webAppFeatures = get-spfeature | where-object {$_.scope -eq "webApplication"}
        $waFeatureResults = @()
        foreach($waFeature in $webAppFeatures)
        {
            $waFeatureObj = New-Object PSObject
            $waFeatureObj | Add-Member -MemberType NoteProperty -Name Title -Value $waFeature.GetTitle($culture)
            $waFeatureObj | Add-Member -MemberType NoteProperty -Name Id -Value $waFeature.Id
            $waFeatureObj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $waFeature.DisplayName
            $waFeatureObj | Add-Member -MemberType NoteProperty -Name SolutionId -Value $waFeature.SolutionId
            $waFeatureObj | Add-Member -MemberType NoteProperty -Name CompatibilityLevel -Value $waFeature.CompatibilityLevel
            $waFeatureObj | Add-Member -MemberType NoteProperty -Name Version -Value $waFeature.Version
            #$waFeatureObj | Add-Member -MemberType NoteProperty -Name RootDirectory -Value $waFeature.RootDirectory
            $waFeatureResults += $waFeatureObj

        }

        $WebAppFeaturesFinding = New-DiagnosticFinding -Name "  WebApplication Features ($($webAppFeatures.Count))" -InputObject $waFeatureResults -Format Table 
        $FeaturesFinding.ChildFindings.Add(($WebAppFeaturesFinding))

        ### SiteCollection Features ###
        $siteFeatures = get-spfeature | where-object {$_.scope -eq "Site"}
        $scFeatureResults = @()
        foreach($siteFeature in $siteFeatures)
        {
            $scFeatureObj = New-Object PSObject
            $scFeatureObj | Add-Member -MemberType NoteProperty -Name Title -Value $siteFeature.GetTitle($culture)
            $scFeatureObj | Add-Member -MemberType NoteProperty -Name Id -Value $siteFeature.Id
            $scFeatureObj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $siteFeature.DisplayName
            $scFeatureObj | Add-Member -MemberType NoteProperty -Name SolutionId -Value $siteFeature.SolutionId
            $scFeatureObj | Add-Member -MemberType NoteProperty -Name CompatibilityLevel -Value $siteFeature.CompatibilityLevel
            $scFeatureObj | Add-Member -MemberType NoteProperty -Name Version -Value $siteFeature.Version
            #$scFeatureObj | Add-Member -MemberType NoteProperty -Name RootDirectory -Value $siteFeature.RootDirectory
            $scFeatureResults += $scFeatureObj

        }
        $SiteFeaturesFinding = New-DiagnosticFinding -Name "  Site Features ($($SiteFeatures.Count))" -InputObject $scFeatureResults -Format Table 
        $FeaturesFinding.ChildFindings.Add(($SiteFeaturesFinding))

        ### Web Features ###
        $webFeatures = get-spfeature | where-object {$_.scope -eq "Web"}
        $webFeatureResults = @()
        foreach($webFeature in $webFeatures)
        {
            $webFeatureObj = New-Object PSObject
            $webFeatureObj | Add-Member -MemberType NoteProperty -Name Title -Value $webFeature.GetTitle($culture)
            $webFeatureObj | Add-Member -MemberType NoteProperty -Name Id -Value $webFeature.Id
            $webFeatureObj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $webFeature.DisplayName
            $webFeatureObj | Add-Member -MemberType NoteProperty -Name SolutionId -Value $webFeature.SolutionId
            $webFeatureObj | Add-Member -MemberType NoteProperty -Name CompatibilityLevel -Value $webFeature.CompatibilityLevel
            $webFeatureObj | Add-Member -MemberType NoteProperty -Name Version -Value $webFeature.Version
            #$webFeatureObj | Add-Member -MemberType NoteProperty -Name RootDirectory -Value $webFeature.RootDirectory
            $webFeatureResults += $webFeatureObj

        }
        $WebFeaturesFinding = New-DiagnosticFinding -Name "  Web Features ($($WebFeatures.Count))" -InputObject $webFeatureResults -Format Table 
        $FeaturesFinding.ChildFindings.Add(($WebFeaturesFinding))

        $FeaturesFinding.Description += "Installed Features in the farm"
        return $FeaturesFinding
}

function Get-SPDiagnosticsDeveloperDashboardSettingsFinding
{
    [cmdletbinding()]
    param()

    $dds = [Microsoft.SharePoint.Administration.SPWebService]::ContentService.DeveloperDashboardSettings | Select-Object UseDisplayLevelForEnabled, DisplayLevel, TraceEnabled, AutoLaunchEnabled, RequiredPermissions, MaximumSQLQueriesToTrack, MaximumCriticalEventsToTrack
    
    if($dds.DisplayLevel -ne [Microsoft.SharePoint.Administration.SPDeveloperDashboardLevel]::Off)
    {
        return (
            New-DiagnosticFinding `
                -Name "Developer Dashboard" `
                -Severity Critical `
                -WarningMessage "Developer dashboard can have an impact on performance, it is not recommended to have developer dashboard enabled in production environments. To disable developer dashboard you can use the below PowerShell" `
                -Description "<div class=`"code`">`$dds = [Microsoft.SharePoint.Administration.SPWebService]::ContentService.DeveloperDashboardSettings<br>`$dds.DisplayLevel = `"Off`"<br>`$dds.Update()</div>" `
                -ReferenceLink "https://learn.microsoft.com/en-us/sharepoint/dev/general-development/optimize-page-performance-in-sharepoint#developer-dashboard" `
                -InputObject $dds `
                -Format List
        )
    }
}

function Get-SPSessionStateServiceFinding
{
    [cmdletbinding()]
    param()

    $sss = Get-SPSessionStateService | Select-Object -Property SessionStateEnabled, Timeout, ServerName, CatalogName, DatabaseId
    if($sss.SessionStateEnabled -eq $False)
    {
        return
    }
    else
    {
    $sss.Servername = $($sss.Servername)
    
    $SSSFinding =  New-DiagnosticFinding `
            -Name "ASP.Net Session State Service" `
            -Severity Default `
            -Description "Session state service as configured by [Dis\En]able-SPSessionStateService cmdlets" `
            -ReferenceLink "https://learn.microsoft.com/en-us/powershell/module/sharepoint-server/enable-spsessionstateservice?view=sharepoint-server-ps" `
            -InputObject ($sss) `
            -Format List

    if ($sss.CatalogName -match " ")
    {
        $SSSFinding.Severity = [SPDiagnostics.Severity]::Warning
        $SSSFinding.WarningMessage+="In multiple SharePoint builds it is not possible to add a new server to a SharePoint farm when the name of the Secure Store Database contains a blank/space character. It might be necessary to disable the Session State Service and enable it again with a new database having a name without a blank/space."
    }
    return $SSSFinding
    }
}

#endregion

#region Auth

function Get-SPDiagnosticAuthFindings
{
    [cmdletbinding()]
    param()


    # Task 543: Move this from a child finding to top level Auth finding object
    #$authFindings.ChildFindings.Add((Get-SPDiagnosticsWebAppAuthSettingsFinding))
    $was = Get-SPWebApplication -IncludeCentralAdministration
    $webAppAuthSettings = @()
    $noWindowsInDefaultZone = $false
    $basicAuthUsed = $false
    foreach($wa in $was)
    {   
        foreach($zone in [enum]::GetNames("Microsoft.SharePoint.Administration.SPUrlZone"))
        {
            $iisSettings = $wa.IisSettings[$zone]
            if($null -ne $iisSettings)
            {
                $aam = $wa.AlternateUrls.GetResponseUrl($zone)

                $providers = @()
                foreach($provider in $iisSettings.ClaimsAuthenticationProviders)
                {
                    ##Check if this is a trusted provider or not
                    if($provider.GetType().Name -eq "SPTrustedAuthenticationProvider")
                    {
                        $tokenIssuer = Get-SPTrustedIdentityTokenIssuer -Identity $provider.LoginProviderName
                        if($tokenIssuer.TrustedLoginMethod -eq "OpenIdConnect")
                        {
                            $providers += $provider.DisplayName + " [OIDC]"
                        }
                        else
                        {
                            $providers += $provider.DisplayName + " [SAML]"
                        }
                    }
                    else
                    {
                        $providers += $provider.DisplayName
                    }
                }

                $waAuthEntry = [PSCustomObject]@{
                    WebApplication = $($wa.DisplayName)
                    Zone = $zone
                    Url = $($aam.IncomingUrl)
                    ClaimsAuthentication = $iisSettings.UseClaimsAuthentication
                    WindowsAuthEnabled = $iisSettings.UseWindowsIntegratedAuthentication
                    Kerberos = !$iisSettings.DisableKerberos
                    BasicAuthEnabled = $iisSettings.UseBasicAuthentication
                    Anonymous =  $iisSettings.AllowAnonymous
                    LoginPage = $iisSettings.ClaimsAuthenticationRedirectionUrl
                    ClaimsAuthenticationProviders = [string]::Join(", ", $providers)
                }

                if($iisSettings.UseBasicAuthentication)
                {
                    $basicAuthUsed = $true
                }

                #Avoid running Kerberos checks when no webapp uses Kerberos
                $script:SPUsesKerberos = $script:SPUsesKerberos -bor $waAuthEntry.Kerberos

                if($zone -eq "Default" -and !$iisSettings.UseWindowsIntegratedAuthentication)
                {
                    $noWindowsInDefaultZone = $true
                }

                $webAppAuthSettings+=$waAuthEntry
            }
        }
    }
    
    $authFindings = New-DiagnosticFinding -Name "Authentication" -Severity Default -InputObject $webAppAuthSettings -Format Table
    if($noWindowsInDefaultZone)
    {
        $authFindings.Severity = [SPDiagnostics.Severity]::Warning
        $authFindings.WarningMessage += "Windows Authentication is not enabled in the default zone of one or more web applications, this is required for search crawl to work correctly"
        $authFindings.ReferenceLink += "https://docs.microsoft.com/en-us/sharepoint/search/best-practices-for-crawling"
    }
    
    #Task 515: Additional callout for basic authentication
    if($basicAuthUsed)
    {
        $authFindings.Severity = [SPDiagnostics.Severity]::Warning
        $authFindings.WarningMessage += "Basic authentication detected in one or more web applications. Basic authentication is inherently insecure as it sends user credentials in plain text."
        $authFindings.WarningMessage += "Basic authentication is now blocked by Microsoft 365 apps by default, while this can be allowed as described in below article it is recommended to use a more secure method of authentication."
        $authFindings.ReferenceLink += "https://learn.microsoft.com/en-us/DeployOffice/security/basic-authentication-prompts-blocked"
    }


    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPSecurityTokenServiceConfigFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsTrustedRootAuthority))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPTrustedIdentityTokenIssuerFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPTrustedSecurityTokenIssuerFinding -SnapshotFinding $authFindings))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPClaimProviderFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticKerberosFindings)) 
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsTokenTimeoutFinding)) 


    return $authFindings
}


function Get-SPDiagnosticsTokenTimeoutFinding
{
    [cmdletbinding()]
    Param()

    $cs = [Microsoft.SharePoint.Administration.SPWebService]::ContentService
    if($cs.TokenTimeout -ne [System.TimeSpan]::new(0, 1440, 0))
    {
        $finding =  New-DiagnosticFinding -Name "Token-timeout is set to non-standard value"  -WarningMessage "When the token timeout is set to a non-standard value unexpected issues can occur, this should be set to the default value of 24 hours (1440 minutes).<br><div class=`"code`">`$cs = [Microsoft.SharePoint.Administration.SPWebService]::ContentService<br>`$cs.TokenTimeout = New-TimeSpan -Minutes 1440<br>`$cs.Update()</div>" -Severity Critical
        return $finding
    }
}


function Get-SPDiagnosticsSPSecurityTokenServiceConfigFinding
{
    [cmdletbinding()]
    Param()
    
    $stsConfig = Get-SPSecurityTokenServiceConfig
    $stsFindingObj = $stsConfig | Select-Object -Property `
    DisplayName,`
    NameIdentifier,`
    AllowMetadataOverHttp,`
    UseSessionCookies,`
    WindowsTokenLifetime,`
    FormsTokenLifetime,`
    CookieLifetime,`
    SessionCookieLifetime,`
    SessionCookieLifetimeRefreshWindow,`
    CookieLifetimeRefreshWindow,`
    ServiceTokenLifetime,`
    MaxLogonTokenCacheItems,`
    MaxLogonTokenOptimisticCacheItems,`
    LogonTokenCacheExpirationWindow,`
    MaxServiceTokenCacheItems,`
    MaxServiceTokenOptimisticCacheItems,`
    ServiceTokenCacheExpirationWindow,`
    ApplicationTokenLifetime,`
    AuthenticatorTokenLifetime,`
    MinApplicationTokenCacheItems,`
    MaxApplicationTokenCacheItems,`
    ApplicationTokenCacheExpirationWindow,`
    ImplicitFlowTokenLifetime,`
    LoopbackTokenLifetime,`
    ProofTokenLifetime,`
    IdentityTokenLifetime,`
    SuppressModernAuthForOfficeClients,`
    AllowOAuthOverHttp,`
    BypassIdentityProviderForAppWebs,`
    PidEnabled,`
    HybridStsSelectionEnabled,`
    WindowsModeIgnoreCache
    
    $finding = New-DiagnosticFinding -Name "Security Token Service Config" -ReferenceLink "https://joshroark.com/sharepoint-users-forced-to-re-authenticate-unexpectedly/" -InputObject $stsFindingObj -Format List
    Add-DiagnosticCommandSnapshot -Finding $finding -CommandName 'Get-SPSecurityTokenServiceConfig' -Records $stsFindingObj -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPSecurityTokenServiceConfig' -Coverage 'The existing curated STS lifetime, cache, cookie, and authentication settings; no signing keys or credentials.' -IdentityProperties @()

    #Check the size of the MaxLogonTokenCacheItems if trusted issuers are present
    $maxLogonTokenCacheItemsThreshold = 2000
    $trustedIdentityTokenIssuers = Get-SPTrustedIdentityTokenIssuer
    if($trustedIdentityTokenIssuers.Count -ge 1 -and $stsConfig.MaxLogonTokenCacheItems -le $maxLogonTokenCacheItemsThreshold)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage+="MaxLogonTokenCacheItems may be too low when SAML authentication is used, review the documentation and make necessary adjustments to avoid unnecessary reauthentication"
        $finding.Description+=("Example PowerShell to set the MaxLogonTokenCacheItems<div class=`"code`">`$sts = Get-SPSecurityTokenServiceConfig<br>`$sts.MaxLogonTokenCacheItems = 3000<br>`$sts.Update()</div>Once the above PowerShell is performed an IISReset must be done on ALL servers in the farm.<br>")
    }
    $cert = $stsConfig.LocalLoginProvider.SigningCertificate  
    $finding.ChildFindings.add((Get-SPDiagnosticFindingCertInfo $cert "Security Token Service" "STS"))

    # Task 534: Ensure that STS is running as the farm account.
    $farmAcc = $script:SPFarm.TimerService.ProcessIdentity.ProcessAccount
    $stsApp = Get-SPServiceApplication | Where-Object {$_.GetType().Name -eq "SPSecurityTokenServiceApplication"}
    if($stsApp.ApplicationPool.ProcessAccount.Name -ine $farmAcc.Name)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+=("The application pool servicing the security token service MUST be running as the farm account. Please correct this by navigating to Central Administration > Security > Configure Service Accounts and setting `"Service Application Pool - {0}`" to use the account `"{1}`"" -f $stsApp.ApplicationPool.Name, $farmAcc.Name)
    }

    return $finding
}

function Get-SPDiagnosticFindingCertInfo
{
    [CmdletBinding()]
    param (
     [Parameter(Mandatory=$true)]
        [Object]
        $cert,
        $SName,
        $certtype
    )
    $stsURL = "https://learn.microsoft.com/en-us/sharepoint/administration/replace-the-sts-certificate"
    $tipURL = "https://joshroark.com/sharepoint-quick-troubleshooting-tip-check-saml-token-signing-certificate/"
    $tipWFM = "https://techcommunity.microsoft.com/t5/microsoft-sharepoint-blog/wfm-certificate-renewal-process-for-sharepoint-2013-2016/ba-p/1332162"
    $tipwfm2 = "https://techcommunity.microsoft.com/t5/microsoft-sharepoint-blog/sharepoint-2013-2016-2019-how-to-replace-expired-workflow/ba-p/1148650"
    
    $Certinfo = $cert | select-object Subject, @{N='Thumbprint';E={$($_.thumbprint)}}, NotBefore, NotAfter
    $certinfo.Subject = $($cert.Subject)
    $findingName = $sname
    $certfinding = New-DiagnosticFinding -Name $findingName -InputObject $Certinfo -Format Table
    $CertLifeTime =  $Certinfo.NotAfter  - (get-date)
    If($CertLifeTime.days -le 180 -and $CertLifeTime.days -gt 0 -and $certType -eq "WFM")
    {
        $certfinding.severity = [SPDiagnostics.severity]::Warning
        $certfinding.WarningMessage+="Workflow Manager Certificate is going to expire in $($CertLifeTime.days) days. When this certificate expires workflows will stop in your farm."
        $certfinding.ReferenceLink+=$tipwfm
    }
    ElseIf($CertLifeTime.days -le 180 -and $CertLifeTime.days -gt 0)
    {
        $certfinding.severity = [SPDiagnostics.severity]::Warning
        $certfinding.WarningMessage+="Certificate is going to expire in $($CertLifeTime.days) days"
    }
    ElseIf($CertLifeTime.days -lt 1 -and $certtype -eq "TIP" )
    {
        $certfinding.severity = [SPDiagnostics.severity]::critical
        $certfinding.WarningMessage+="Certificate has expired.  Please replace this expired certificate."
        $certfinding.ReferenceLink+=$tipURL
    }
    ElseIf($CertLifeTime.days -lt 1 -and $certtype -eq "STS" )
    {
        $certfinding.severity = [SPDiagnostics.severity]::critical
        $certfinding.WarningMessage+="Certificate has expired.  Please replace this expired certificate. "
        $certfinding.ReferenceLink+=$stsURL
    }
    ElseIf($CertLifeTime.days -lt 1 -and $certtype -eq "WFM" )
    {
        $certfinding.severity = [SPDiagnostics.severity]::critical
        $certfinding.WarningMessage+="Workflow manager certificate has expired.  Please replace this expired certificate."
        $certfinding.ReferenceLink+=$tipwfm2
    }
    ElseIf($CertLifeTime.days -lt 1 )
    {
        $certfinding.severity = [SPDiagnostics.severity]::critical
        $certfinding.WarningMessage+="Certificate has expired.  Please replace this expired certificate."
    }
   return $certfinding
}

function Get-SPDiagnosticsSPTrustedIdentityTokenIssuerFinding
{
    [cmdletbinding()]
    Param()

    $TrustedIssuerFindings = New-DiagnosticFinding -Name "Trusted Identity Providers" -InputObject $null -Format Table
    #$TrustedIssuerFindings = New-DiagnosticFindingCollection
    $trustedIdentityTokenIssuers = Get-SPTrustedIdentityTokenIssuer
    Add-DiagnosticCommandSnapshot -Finding $TrustedIssuerFindings -CommandName 'Get-SPTrustedIdentityTokenIssuer' -Records $trustedIdentityTokenIssuers -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPTrustedIdentityTokenIssuer' -Coverage 'Selected issuer identity, authentication behavior, and public endpoints; certificates and property bags excluded.' -PropertyNames @(
        'Id', 'Name', 'DisplayName', 'Status', 'Description', 'ProviderUri',
        'ProviderSignOutUri', 'DefaultProviderRealm', 'ClaimProviderName',
        'UseStateToRedirect', 'UseWReplyParameter', 'UseWHomeRealmParameter',
        'RegisteredIssuerName', 'DefaultClientIdentifier', 'AuthorizationEndPointUri',
        'TrustedLoginMethod', 'MetadataEndpoint', 'IsAutomaticallyUpdated'
    )
    foreach($tokenIssuer in $trustedIdentityTokenIssuers)
    {
        $tiProps = $tokenIssuer | Select-Object -Property `
            UseStateToRedirect,
            ProviderUri,
            @{l="ProviderSignOutUri";e={$_.ProviderSignOutUri}},
            DefaultProviderRealm,
            ProviderRealms,
            HasClaimTypeInformation,
            ClaimProviderName,
            UseWReplyParameter,
            UseWHomeRealmParameter,
            GroupClaimType,
            @{l="RegisteredIssuerName";e={RegisteredIssuerName}},
            DefaultClientIdentifier,
            @{l="AuthorizationEndPointUri";e={$_.AuthorizationEndPointUri}},
            TrustedLoginMethod,
            Scope,
            @{l="IdentityClaim";e={$_.ClaimTypeInformation.DisplayName}},
            Description,
            SigningCertificate,
            @{l="MetadataEndpoint";e={$_.MetadataEndpoint}},
            IsAutomaticallyUpdated,
            Name,
            DisplayName,
            Id,
            Status            
            
        $findingName = "Trusted Identity Provider: {0}" -f $($tokenIssuer.Name)
        if($tokenIssuer.TrustedLoginMethod -eq "OpenIdConnect")
        {
            $findingName += " [OIDC]"
        }
        else
        {
            $findingName += " [SAML]"
        }
        
        

        $finding = New-DiagnosticFinding -Name $findingName -Severity Default -InputObject $tiProps -Format List
        $claimTypes = $tokenIssuer.ClaimTypeInformation | Select-Object DisplayName, InputClaimType, MappedClaimType, IsIdentityClaim
        $claimMappings = New-DiagnosticFinding -Name "Claim mappings" -InputObject $claimTypes -Format Table
        $cert = $tokenIssuer.SigningCertificate
        $finding.ChildFindings.Add($claimMappings)

        #Task 586: For OIDC log the "Kid" and the certificate they map to:
        $finding.ChildFindings.Add((Get-SPDiagnosticOIDCKidCertificateMapFinding -TokenIssuer $tokenIssuer))

        $finding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ("Certificate: " + $tokenIssuer.name) "TIP"))
        foreach($additionalCert in $tokenIssuer.AdditionalSigningCertificates)
        {
            $finding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $additionalCert  ("Certificate: " + $tokenIssuer.name + " [additional cert]")  "TIP"))
        }
        $TrustedIssuerFindings.ChildFindings.Add($finding)
    }

    # #463
    # If there's not Trusted Identifiy Providers call this out instead of leaving an empty trusted providers finding
    if($null -eq $trustedIdentityTokenIssuers)
    {
        $TrustedIssuerFindings.Description = "There are no Trusted Identity Providers"
    }

    return $TrustedIssuerFindings
}


function Get-SPDiagnosticOIDCKidCertificateMapFinding
{
    [cmdletbinding()]
    Param([Microsoft.SharePoint.Administration.Claims.SPTrustedLoginProvider]$TokenIssuer)

    #This finding only relevant if OIDC is used
    if($TokenIssuer.TrustedLoginMethod -ne "OpenIdConnect")
    {
        return
    }

    $type = [Microsoft.SharePoint.Administration.Claims.SPTrustedProviderBase]
    $bflags = [System.Reflection.BindingFlags]("NonPublic", "Instance")
    $field = $type.GetField("m_SigningCertificateRawDataWithKid", $bflags)
    $certsWithKid = $field.GetValue($TokenIssuer)

    $certMappings = @()
    foreach($certWithKid in $certsWithKid.GetEnumerator())
    {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certWithKid.Value)
        $certMappings += ([pscustomobject]@{
            Kid = $certWithKid.Key
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            FriendlyName = $cert.FriendlyName
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            #Extensions = $cert.Extensions
        })
    }

    $finding = New-DiagnosticFinding -Name "Kid mappings for certificates" -InputObject $certMappings -Format Table
    return $finding
}

function Get-SPDiagnosticsSPTrustedSecurityTokenIssuerFinding
{
    [cmdletbinding()]
    Param([SPDiagnostics.Finding]$SnapshotFinding)

    $trustedSecurityTokenIssuers = Get-SPTrustedSecurityTokenIssuer
    $issuerSnapshotFinding = if($null -ne $SnapshotFinding) { $SnapshotFinding } else { New-DiagnosticFinding -Name 'Trusted Security Token Issuers' -InputObject $null -Format Table }
    Add-DiagnosticCommandSnapshot -Finding $issuerSnapshotFinding -CommandName 'Get-SPTrustedSecurityTokenIssuer' -Records $trustedSecurityTokenIssuers -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPTrustedSecurityTokenIssuer' -Coverage 'Selected identity and public endpoint settings; signing certificates, credentials, and object graphs excluded.' -PropertyNames @(
        'Id', 'Name', 'TypeName', 'DisplayName', 'Status', 'IsSelfIssuer', 'NameId',
        'RegisteredIssuerName', 'AuthorizationEndPointUri', 'TokenEndPointUri',
        'DefaultClientIdentifier', 'Description', 'MetadataEndPoint', 'IsAutomaticallyUpdated'
    )
    if($trustedSecurityTokenIssuers.Count -ge 1)
    {
        $Findings = New-DiagnosticFinding -Name "Trusted Security Token Issuers" -InputObject $null -Format Table
        if($null -eq $SnapshotFinding)
        {
            foreach($snapshot in $issuerSnapshotFinding.CommandSnapshots) { $Findings.CommandSnapshots.Add($snapshot) }
        }
        foreach($tokenIssuer in $trustedSecurityTokenIssuers)
        {
            $tokenIssuerReport = New-Object PSObject @{
                "IsSelfIssuer" = $tokenIssuer.IsSelfIssuer
                "NameId" = $tokenIssuer.NameId
                "RegisteredIssuerName" = $($tokenIssuer.RegisteredIssuerName)
                "AuthorizationEndPointUri" = $($tokenIssuer.AuthorizationEndPointUri)
                "TokenEndPointUri" = $($tokenIssuer.TokenEndPointUri)
                "DefaultClientIdentifier" = $tokenIssuer.DefaultClientIdentifier
                # "ScopedClientIdentifier" = $tokenIssuer.ScopedClientIdentifier #Dictionary, not displayed in table
                "IdentityClaimTypeInformation" = $tokenIssuer.IdentityClaimTypeInformation
                "Description" = $tokenIssuer.Description
                "SigningCertificate" = $tokenIssuer.SigningCertificate
                "AdditionalSigningCertificates" = $tokenIssuer.AdditionalSigningCertificates
                "MetadataEndPoint" = $($tokenIssuer.MetadataEndPoint)
                "IsAutomaticallyUpdated" = $tokenIssuer.IsAutomaticallyUpdated
                "Name" = $($tokenIssuer.Name)
                "TypeName" = $tokenIssuer.TypeName
                "DisplayName" = $($tokenIssuer.DisplayName)
                "Id" = $tokenIssuer.Id
                "Status" = $tokenIssuer.Status
                "Parent" = $tokenIssuer.Parent
                "Version" = $tokenIssuer.Version
                "DeploymentLocked" = $tokenIssuer.DeploymentLocked
                # "Properties" = $tokenIssuer.Properties #Hashtable
                "Farm" = $($tokenIssuer.Farm)
                # "UpgradedPersistedProperties" = $tokenIssuer.UpgradedPersistedProperties #hashable
            }
            

            $tokenIssuerFinding = New-DiagnosticFinding -Name $tokenIssuer.Name -InputObject $tokenIssuerReport -Format List
            
            #check Cert
            $cert = $tokenIssuer.SigningCertificate
            if ($tokenIssuer.Name -eq "00000005-0000-0000-c000-000000000000")
            {
                $tokenIssuerFinding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ( $($tokenIssuer.Name)) "WFM"))
            } else {
                $tokenIssuerFinding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ( $($tokenIssuer.Name)) ""))
            }
            
            $Findings.ChildFindings.Add($tokenIssuerFinding)
        }
        return $Findings
    }
    else
    {
        return $null
    }
}


function  Get-SPDiagnosticsSPClaimProviderFinding
{
    [cmdletbinding()]
    Param()

    $claimProviders = Get-SPClaimProvider | Select-Object DisplayName, IsEnabled, IsUsedByDefault, IsVisible, AssemblyName
    $finding = New-DiagnosticFinding -Name "Claim providers" -InputObject $claimProviders -Format Table
    if($null -eq $claimProviders)
    {
        $finding.Severity =  [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage += "There are no SharePoint Claim Providers Registered"
    }
    return $finding
}


#endregion 

#region Kerberos

$Script:missingAES = $false

Function New-KConsoleLine($CssClass, $Text)
{
    $encodedText = [System.Security.SecurityElement]::Escape([string]$Text)
    return ('<span class="{0}">{1}</span>' -f $CssClass, $encodedText)
}

Function Show-KerberosEncTypes
{
    param(
        [Parameter(Mandatory = $true)] $Value,
        [string] $Indent = "      "
    )

    $lines = @()
    $encValue = [int]$Value
    $hexString = "0x{0:X}" -f $encValue
    $lines += New-KConsoleLine 'k-dim' ("{0}Value: {1} ({2})" -f $Indent, $encValue, $hexString)

    if ($encValue -band 1)  { $lines += New-KConsoleLine 'k-ddim' ("{0}  -> DES-CBC-CRC Enabled" -f $Indent) }
    if ($encValue -band 2)  { $lines += New-KConsoleLine 'k-ddim' ("{0}  -> DES-CBC-MD5 Enabled" -f $Indent) }
    if ($encValue -band 4)  { $lines += New-KConsoleLine 'k-bad'  ("{0}  -> RC4_HMAC_MD5 Enabled" -f $Indent) }
    if ($encValue -band 8)  { $lines += New-KConsoleLine 'k-ok'   ("{0}  -> AES128_HMAC_SHA1 Enabled" -f $Indent) }
    if ($encValue -band 16) { $lines += New-KConsoleLine 'k-ok'   ("{0}  -> AES256_HMAC_SHA1 Enabled" -f $Indent) }

    return $lines
}

Function Get-RemoteEncTypeValue
{
    param(
        [Parameter(Mandatory = $true)] [Microsoft.Win32.RegistryKey] $BaseKey,
        [Parameter(Mandatory = $true)] [string] $SubKeyPath
    )

    $result = [PSCustomObject]@{
        Value = $null
        Lines = @()
    }

    $subKey = $BaseKey.OpenSubKey($SubKeyPath)
    if (-not $subKey)
    {
        $result.Lines += New-KConsoleLine 'k-warn' ("      -> SUBKEY NOT FOUND: {0}" -f $SubKeyPath)
        return $result
    }

    try
    {
        $names = $subKey.GetValueNames()
        $result.Lines += New-KConsoleLine 'k-dim' ("      -> Subkey opened. Values present: [{0}]" -f ($names -join ', '))
        $result.Value = $subKey.GetValue("SupportedEncryptionTypes")
    }
    finally
    {
        $subKey.Close()
    }

    return $result
}

Function New-KPill($State, $Text)
{
    # Emits a colored status pill using the ~~~PILL...~~~ sentinels decoded in Write-DiagnosticReport
    # (green/red/amber in HTML, plain text in the TEXT report). State: 'good' | 'bad' | 'warn'.
    switch ($State)
    {
        'good'  { return "~~~PILLGOOD~~~$Text~~~PILLEND~~~" }
        'bad'   { return "~~~PILLBAD~~~$Text~~~PILLEND~~~" }
        'warn'  { return "~~~PILLWARN~~~$Text~~~PILLEND~~~" }
        default { return [string]$Text }
    }
}

Function Get-KAesCell([bool]$On)
{
    # AES columns: enabled is good (green), missing is bad (red).
    if ($On) { return (New-KPill 'good' 'Yes') } else { return (New-KPill 'bad' 'No') }
}

Function Get-KWeakCell([bool]$On)
{
    # Weak-cipher columns (RC4/DES): enabled is bad (red), disabled is good (green).
    if ($On) { return (New-KPill 'bad' 'Yes') } else { return (New-KPill 'good' 'No') }
}

Function Get-KerberosEncTypeLabel($Value)
{
    # Decodes a msDS-SupportedEncryptionTypes / SupportedEncryptionTypes bitmask into a friendly label
    # plus the raw hex value, e.g. "AES256, AES128 (0x18)".
    $v = [int]$Value
    $parts = @()
    if ($v -band 16) { $parts += 'AES256' }
    if ($v -band 8)  { $parts += 'AES128' }
    if ($v -band 4)  { $parts += 'RC4' }
    if ($v -band 2)  { $parts += 'DES-MD5' }
    if ($v -band 1)  { $parts += 'DES-CRC' }
    if ($parts.Count -eq 0) { $label = 'None' } else { $label = ($parts -join ', ') }
    return ("{0} (0x{1:X})" -f $label, $v)
}

Function Get-SPDiagnosticKerberosFindings
{
    $KerberosFindings = New-DiagnosticFinding -Name "Kerberos configuration" -InputObject $null -Format List

    if (!(IsElevated))
    {
        $KerberosFindings.Description += "Kerberos Diagnostics can only be executed when the script is executed with 'Run as Administrator'."
        return $KerberosFindings
    }

    $Separator = "\"
    $option = [System.StringSplitOptions]::RemoveEmptyEntries
    $PolicyKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $LsaKeyPath = "SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    $warn = $false

    $accountRows = @()   # one row per managed account (encryption types)
    $serverRows  = @()   # one row per farm server (OS Kerberos policy)
    $spnGroups   = @()   # one row per owner (account/server), SPNs stacked

    $accountsChecked    = 0
    $accountsMissingAes = 0
    $serversChecked     = 0
    $serversWeak        = 0
    $policyLsaMismatch  = 0

    # ---------------------------------------------------------------------------------------------
    # [1/2] SharePoint Managed Accounts: AES support (msDS-SupportedEncryptionTypes) and SPNs
    # ---------------------------------------------------------------------------------------------
    foreach ($ManagedAccount in (Get-SPManagedAccount))
    {
        $accountsChecked++
        $acctName = $ManagedAccount.Username
        $samAccountNameParts = $acctName.Split($Separator, 2, $option)
        $samAccountName = if ($samAccountNameParts.Count -gt 1) { $samAccountNameParts[1] } else { $samAccountNameParts[0] }

        $aes256 = $false; $aes128 = $false; $rc4 = $false; $des = $false
        $encLabel = ""
        $statusState = "good"; $statusText = "OK"
        $acctSpns = @()

        try
        {
            $searcher = [adsisearcher]"samAccountName=$samAccountName"
            $searcher.PropertiesToLoad.Add("msds-supportedencryptiontypes") | Out-Null
            $searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
            $userobj = $searcher.FindOne()
        }
        catch
        {
            $userobj = $null
        }

        if ($userobj)
        {
            $EncryptionTypes = $userobj.properties.Item('msds-supportedencryptiontypes')[0]
            if ($null -ne $EncryptionTypes)
            {
                $v = [int]$EncryptionTypes
                $aes256 = [bool]($v -band 16)
                $aes128 = [bool]($v -band 8)
                $rc4    = [bool]($v -band 4)
                $des    = [bool](($v -band 1) -or ($v -band 2))
                $encLabel = (Get-KerberosEncTypeLabel $v)

                if ($aes128 -and $aes256)
                {
                    $statusState = "good"; $statusText = "OK"
                }
                elseif ($aes128 -or $aes256)
                {
                    $statusState = "warn"; $statusText = "Partial AES"; $warn = $true; $accountsMissingAes++
                }
                else
                {
                    $statusState = "bad"; $statusText = "No AES"; $warn = $true; $accountsMissingAes++
                }
            }
            else
            {
                # Not set: Windows defaults to RC4/DES unless the OS overrides.
                $encLabel = "Not Set"
                $rc4 = $true; $des = $true
                $statusState = "warn"; $statusText = "Not Set"; $warn = $true; $accountsMissingAes++
            }

            $SPNs = $userobj.properties.Item('serviceprincipalname')
            if ($SPNs)
            {
                foreach ($spn in $SPNs) { $acctSpns += [string]$spn }
            }
        }
        else
        {
            $encLabel = "Account not found in AD"
            $statusState = "bad"; $statusText = "Not Found"; $warn = $true; $accountsMissingAes++
        }

        $accountRows += [PSCustomObject]@{
            Account = $acctName
            AES256  = (Get-KAesCell $aes256)
            AES128  = (Get-KAesCell $aes128)
            RC4     = (Get-KWeakCell $rc4)
            DES     = (Get-KWeakCell $des)
            "msDS-SupportedEncryptionTypes" = $encLabel
            SPNs    = $acctSpns.Count
            Status  = (New-KPill $statusState $statusText)
        }

        if ($acctSpns.Count -gt 0)
        {
            $spnGroups += [PSCustomObject]@{
                Scope = "Account"
                Owner = $acctName
                Count = $acctSpns.Count
                SPN   = ($acctSpns -join '~~~BR~~~')
                Type  = (($acctSpns | ForEach-Object { ($_ -split '/')[0] }) -join '~~~BR~~~')
            }
        }
    }

    # ---------------------------------------------------------------------------------------------
    # [2/2] Farm Servers: computer-object SPNs and the OS Kerberos encryption policy (Policy vs LSA)
    # ---------------------------------------------------------------------------------------------
    $FarmServers = Get-SPServer | Where-Object { $_.Role -ne "Invalid" } | Sort-Object Name

    foreach ($Server in $FarmServers)
    {
        $serversChecked++
        $srvSpns = @()
        $serverSam = "$($Server.Name)$"

        try
        {
            $serverSearcher = [adsisearcher]"samAccountName=$serverSam"
            $serverSearcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
            $serverObj = $serverSearcher.FindOne()
        }
        catch
        {
            $serverObj = $null
        }

        if ($serverObj)
        {
            $ServerSPNs = $serverObj.properties.Item('serviceprincipalname')
            if ($ServerSPNs)
            {
                foreach ($sSpn in $ServerSPNs) { $srvSpns += [string]$sSpn }
            }
        }
        else
        {
            $warn = $true
        }

        if ($srvSpns.Count -gt 0)
        {
            $spnGroups += [PSCustomObject]@{
                Scope = "Server"
                Owner = $serverSam.TrimEnd("$")
                Count = $srvSpns.Count
                SPN   = ($srvSpns -join '~~~BR~~~')
                Type  = (($srvSpns | ForEach-Object { ($_ -split '/')[0] }) -join '~~~BR~~~')
            }
        }

        # Local Kerberos encryption policy via remote registry (GPO Policy key + effective LSA key)
        $configuredLabel = "Unable to read"
        $paes256 = $false; $paes128 = $false; $prc4 = $false; $pdes = $false
        $matchState = "warn"; $matchText = "Unknown"
        $regKey = $null

        try
        {
            $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $Server.Name,
                [Microsoft.Win32.RegistryView]::Registry64)

            $PolicyResult = Get-RemoteEncTypeValue -BaseKey $regKey -SubKeyPath $PolicyKeyPath
            $LsaResult    = Get-RemoteEncTypeValue -BaseKey $regKey -SubKeyPath $LsaKeyPath
            $PolicyEncTypes = $PolicyResult.Value
            $LsaEncTypes    = $LsaResult.Value

            # Effective value: prefer the LSA (runtime) key, fall back to the GPO Policy key.
            if ($null -ne $LsaEncTypes) { $effective = [int]$LsaEncTypes }
            elseif ($null -ne $PolicyEncTypes) { $effective = [int]$PolicyEncTypes }
            else { $effective = $null }

            if ($null -ne $effective)
            {
                $paes256 = [bool]($effective -band 16)
                $paes128 = [bool]($effective -band 8)
                $prc4    = [bool]($effective -band 4)
                $pdes    = [bool](($effective -band 1) -or ($effective -band 2))
                $configuredLabel = (Get-KerberosEncTypeLabel $effective)
                if ($prc4 -or $pdes) { $warn = $true; $serversWeak++ }
            }
            else
            {
                $configuredLabel = "Not Defined (OS defaults)"
            }

            if (($null -ne $PolicyEncTypes) -and ($null -ne $LsaEncTypes))
            {
                if ([int]$PolicyEncTypes -eq [int]$LsaEncTypes)
                {
                    $matchState = "good"; $matchText = "Yes"
                }
                else
                {
                    $matchState = "bad"; $matchText = "No"; $warn = $true; $policyLsaMismatch++
                }
            }
            elseif (($null -eq $PolicyEncTypes) -and ($null -eq $LsaEncTypes))
            {
                $matchState = "warn"; $matchText = "Neither set"
            }
            else
            {
                $matchState = "warn"; $matchText = "Partial"
            }
        }
        catch
        {
            $configuredLabel = "Registry unreachable"
            $matchState = "bad"; $matchText = "Error"
            $warn = $true
        }
        finally
        {
            if ($regKey) { $regKey.Close() }
        }

        $serverRows += [PSCustomObject]@{
            Server = $Server.Name
            "Configured Value (LSA Effective)" = $configuredLabel
            AES256 = (Get-KAesCell $paes256)
            AES128 = (Get-KAesCell $paes128)
            RC4    = (Get-KWeakCell $prc4)
            DES    = (Get-KWeakCell $pdes)
            "Policy = LSA" = (New-KPill $matchState $matchText)
        }
    }

    # ---------------------------------------------------------------------------------------------
    # Warning banner (kept from the original console version) + reference link
    # ---------------------------------------------------------------------------------------------
    $KerberosFindings.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/troubleshoot/security/configuration-to-support-kerberos-aes-encryption"

    if ($warn)
    {
        $KerberosFindings.Severity = [SPDiagnostics.Severity]::Warning
        $warnHtml  = '<div class="warning-message">'
        $warnHtml += 'One or more Kerberos issues were detected (an account missing AES, a server allowing RC4/DES, or a Policy/LSA mismatch). Review the highlighted rows below. Since the November 2022 Security Updates, Windows enforces AES128/AES256 encryption of Kerberos tickets; this must be explicitly allowed for each account that authenticates with Kerberos.'
        $warnHtml += '</div>'
        $KerberosFindings.Description += $warnHtml
    }

    # ---------------------------------------------------------------------------------------------
    # Summary (key/value) + detail tables as child findings
    # ---------------------------------------------------------------------------------------------
    if ($accountsMissingAes -gt 0) { $accMissingCell  = New-KPill 'bad' $accountsMissingAes } else { $accMissingCell  = New-KPill 'good' '0' }
    if ($serversWeak -gt 0)        { $serversWeakCell = New-KPill 'bad' $serversWeak }         else { $serversWeakCell = New-KPill 'good' '0' }
    if ($policyLsaMismatch -gt 0)  { $mismatchCell    = New-KPill 'bad' $policyLsaMismatch }   else { $mismatchCell    = New-KPill 'good' '0' }
    if ($warn)                     { $overallCell     = New-KPill 'warn' 'Review recommended' } else { $overallCell    = New-KPill 'good' 'Healthy' }

    $summaryRows = @(
        [PSCustomObject]@{ Metric = 'Managed Accounts Checked';     Value = [string]$accountsChecked }
        [PSCustomObject]@{ Metric = 'Accounts Missing / Unset AES'; Value = $accMissingCell }
        [PSCustomObject]@{ Metric = 'Farm Servers Checked';         Value = [string]$serversChecked }
        [PSCustomObject]@{ Metric = 'Servers Allowing RC4 / DES';   Value = $serversWeakCell }
        [PSCustomObject]@{ Metric = 'Policy vs LSA Mismatches';     Value = $mismatchCell }
        [PSCustomObject]@{ Metric = 'Overall Assessment';           Value = $overallCell }
    )

    $summaryFinding = New-DiagnosticFinding -Name "Kerberos Summary" -InputObject $summaryRows -Format Table
    $KerberosFindings.ChildFindings.Add($summaryFinding)

    $acctFinding = New-DiagnosticFinding -Name "Managed Account Encryption Types" -InputObject $accountRows -Format Table
    $KerberosFindings.ChildFindings.Add($acctFinding)

    $srvFinding = New-DiagnosticFinding -Name "Server OS Kerberos Encryption Policy (Registry)" -InputObject $serverRows -Format Table
    $KerberosFindings.ChildFindings.Add($srvFinding)

    if ($spnGroups.Count -gt 0)
    {
        $spnFinding = New-DiagnosticFinding -Name "Service Principal Names (SPNs)" -InputObject $spnGroups -Format Table -Description "Grouped one row per owner (account or server); each owner's SPNs are stacked in a single cell, matching the 'Service Instances on Server(s)' presentation."
        $KerberosFindings.ChildFindings.Add($spnFinding)
    }

    return $KerberosFindings
}

#endregion Kerberos

#region SearchTopologyBoundaries
Function Get-SPDiagnosticsSearchTopologyLimits
{
    param([SPDiagnostics.Finding]$SnapshotFinding)

    $AllSearchComponents = @()
    $topologyCommandSnapshots = New-Object 'System.Collections.Generic.List[object]'

    $ssas = Get-SPEnterpriseSearchServiceApplication
    foreach ($ssa in $ssas)
    {
        $topo = Get-SPEnterpriseSearchTopology -Active -SearchApplication $ssa
        $comps = Get-SPEnterpriseSearchComponent -SearchTopology $topo
        $topologyCommandSnapshots.Add([pscustomobject]@{ applicationId = $ssa.Id; topology = $topo; components = @($comps) })
        foreach ($comp in $comps)
        {
            $SearchComponent = New-Object psobject
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "SSA" $($ssa.Name)
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "Server" $($comp.ServerName)
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "ComponentName" $comp.Name
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "ComponentType" $comp.GetType().Name
            $AllSearchComponents +=$SearchComponent
        }
    }

    $searchTopologyLimitsFindings = New-DiagnosticFinding -Name "Search Topology Limits" -Severity Default -InputObject $null -Format Table
    $topologySnapshotFinding = if($null -ne $SnapshotFinding) { $SnapshotFinding } else { $searchTopologyLimitsFindings }
    foreach($snapshot in $topologyCommandSnapshots)
    {
        $topologyScope = [ordered]@{ farmId = $script:SPFarm.Id; serviceApplicationId = $snapshot.applicationId }
        Add-DiagnosticCommandSnapshot -Finding $topologySnapshotFinding -CommandName 'Get-SPEnterpriseSearchTopology' -Records $snapshot.topology -Scope $topologyScope -Source 'Get-SPEnterpriseSearchTopology -Active' -Coverage 'Active search topology per application inspected by the existing limits collector.' -IdentityProperties @('TopologyId') -PropertyNames @(
            'TopologyId', 'State', 'CreationDate', 'ComponentCount'
        )
        $componentScope = [ordered]@{ farmId = $script:SPFarm.Id; serviceApplicationId = $snapshot.applicationId; topologyId = $snapshot.topology.TopologyId }
        Add-DiagnosticCommandSnapshot -Finding $topologySnapshotFinding -CommandName 'Get-SPEnterpriseSearchComponent' -Records $snapshot.components -Scope $componentScope -Source 'Get-SPEnterpriseSearchComponent -SearchTopology' -Coverage 'Components of the active topology; runtime type distinguishes component roles.' -IdentityProperties @('ComponentId') -PropertyNames @(
            'ComponentId', 'Name', 'ServerId', 'ServerName'
        )
    }

    $ComponentTypes = @("AdminComponent","CrawlComponent","ContentProcessingComponent","AnalyticsProcessingComponent","IndexComponent")
    $MaxCompPerServer = @(1,1,1,1,4)
    $BoundaryPerServer=@("recommended","supported","supported","supported","supported","supported")

    for ($i = 0; $i -lt $ComponentTypes.Count;$i++)
    {
        $tempComps = $AllSearchComponents | Where-Object {$_.ComponentType -eq $ComponentTypes[$i]}
        $compServers = $tempComps.Server | Sort-Object | Get-unique
        foreach ($s in $Compservers)
        {
            $CompsPerServer =0
            for ($j = 0; $j -lt $tempComps.count; $j++)
            {       
                if ($tempComps[$j].server -eq $s)
                {
                    $CompsPerServer ++
                }
            }
            if ($CompsPerServer -gt $MaxCompPerServer[$i])
            {
                $message = "More than the " + $BoundaryPerServer[$i].ToString() + " number of " + $ComponentTypes[$i] + "s are running on server " + $s +". "
                $message +=   $MaxCompPerServer[$i].ToString() +" "+ $ComponentTypes[$i] + " is " + $BoundaryPerServer[$i] + " currently active are " + $CompsPerServer.ToString() + " " +  $ComponentTypes[$i] +" components."               
                $searchTopologyLimitsFindings.WarningMessage += $message
            }
        }
    }
    if ($searchTopologyLimitsFindings.WarningMessage)
    {
        $searchTopologyLimitsFindings.Description +="Microsoft has tested search with a limited set of topologies and documented these. If you are running more than 1 Search Service Application you must ensure that the components are distributed among servers."
        $searchTopologyLimitsFindings.Severity = [SPDiagnostics.Severity]::Warning

        $searchTopologyLimitsFindings.InputObject = $AllSearchComponents
        return $searchTopologyLimitsFindings

    } else {
        $searchTopologyLimitsFindings.Description +="The number of search components per server is within supported boundaries."
    }
    $searchTopologyLimitsFindings.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/install/software-boundaries-limits-2019#search-topology-limits"
    #return $searchTopologyLimitsFindings
}
#endregion

Function Get-SPDiagnosticsSearchLinksStoreLimit
{
    [CmdletBinding()]
    param (
     [Parameter(Mandatory=$true)]
        [Object]
        $linkStore
    )

    $resultFinding = $null

    $result = Invoke-SPSqlCommand -spDatabase $linkstore.Database -query "SELECT AVG(DailyCount) AS AverageQueriesPerDay FROM (SELECT CAST(SearchTime AS DATE) AS SearchDate, COUNT(*) AS DailyCount FROM MSSQLogPageImpressionQuery GROUP BY CAST(SearchTime AS DATE)) AS x;"

    if($null -ne $result)
    {
        $resultFinding = New-DiagnosticFinding -Name "LinksDB - AverageQueriesPerDay" -InputObject $null
        $resultFinding.Description += "Average Queries PerDay Check"

        $linkStoreInfo = [pscustomobject]@{
            ID = $linkStore.Id
            Name = $linkStore.Name
            DatabaseServer = $($linkStore.Database.Server.Name)
            DatabaseType = "Linkstore Database"
            DatabaseName = $($linkStore.Database.Name)
            AverageQueriesPerDay = $result.AverageQueriesPerDay
        }

        $resultFinding.InputObject = $linkStoreInfo
        [int]$avg = 0
        if ([int]::TryParse($result.AverageQueriesPerDay, [ref]$avg))
        {
            if ($avg -gt 9000000)
            {
                $resultFinding.WarningMessage += ("AverageQueriesPerDay is high at {0}. This could result in blocked queries and/or rapid TempDB growth due to proc_MSS_GetPopularQueries or other search related stores procs" -f $result.AverageQueriesPerDay)
                $resultFinding.Description += "Consider lowering the QueryLogSettings.CleanupDays on this SSA if experiencing any of these symptoms."
                $resultFinding.Description += "Then monitor for improvement. The Query Logging timerjob will cleanup the linksdb every 24 hours based on this value."
                $resultFinding.Description += "The 'correct' value is environmentally dependent on farm use and sql performance."
                $resultFinding.Severity = [SPDiagnostics.Severity]::Warning
            }
        }

    }
    return $resultFinding
}

#region search

function Get-SPDiagnosticSearchFindings
{

    $SSAs = Get-SPEnterpriseSearchServiceApplication  | Sort-Object Name 

    $searchFindings = New-DiagnosticFinding -Name "Search Information" -Severity Default -InputObject $null
    Add-DiagnosticCommandSnapshot -Finding $searchFindings -CommandName 'Get-SPEnterpriseSearchServiceApplication' -Records $SSAs -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPEnterpriseSearchServiceApplication' -Coverage 'Search applications returned by the existing collector; selected scalar settings only.' -PropertyNames @(
        'Id', 'Name', 'DisplayName', 'Status', 'CloudIndex', 'SearchCenterUrl',
        'DiscoveryMaxRowLimit', 'AlertsEnabled', 'AllowPartialResults', 'CrawlLogCleanupIntervalInDays', 'NeedsUpgrade'
    )
    $searchFindings.Description += "Some findings may not show up if things are 'Ok'<br/> Ex: Search\HC instances, Server Name Mappings, Crawl Rules.<br/> If we do not find any values, then we will not report the finding."

    # Accumulator for content sources (across every SSA) that have no scheduled or continuous crawl.
    # Populated by Get-SPDiagnosticsSSAContentSources and rendered once as a single consolidated
    # finding after the SSA loop below. Reset here so repeat runs in the same session start clean.
    $script:NoScheduledCrawlContentSources = @()
    if($null -eq $SSAs -or $SSAs.Count -eq 0)
    {
        $searchFindings.Description+="There are no SSA's in this farm"
        return $searchFindings
    }

    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSASearchService))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSearchTopologyLimits -SnapshotFinding $searchFindings))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSASearchInstances -searchApps $SSAs))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSPJobInstances -searchApps $SSAs))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsCheckForRoot -searchApps $SSAs))
    $searchFindings.ChildFindings.Add((VerifyHostControllerRepository))
    $ssaCount = 0
    foreach($ssa in $SSAs)
    {
        $ssaCount++
        $crawlAccount = (New-Object Microsoft.Office.Server.Search.Administration.Content $ssa).DefaultGatheringAccount
        $ssaName = "SSA " + $ssaCount + ": '" + $($ssa.Name) + "'" + " || CrawlAccount: '" + $($crawlAccount) + "'"
        $ssaFindings = New-DiagnosticFinding -Name $ssaName -Severity Default -InputObject $null
        if($ssa.NeedsUpgradeIncludeChildren -eq $true -or $ssa.NeedsUpgrade -eq $true)
        {
            $ssaName = $ssa.DisplayName
            $ssaFindings.Severity = [SPDiagnostics.Severity]::Warning
            $ssaFindings.WarningMessage+="<li style='color:red'>We have detected that the 'SSA' needs to be upgraded!</li>"
            $ssaFindings.WarningMessage+="<li>In order to perform this action, please run the following command: </li>" 
            $ssaFindings.WarningMessage+="<ul style='color:#ffd700'><div class=`"code`">`Upgrade-SPEnterpriseSearchServiceApplication '$ssaName'</div></ul>"
        }
        if($ssa.CloudIndex -eq $True)
        {
            $spoProxy = Get-SPServiceApplicationProxy | Where-Object{$_.TypeName -match "SharePoint Online Application Principal Management Service"}
            $spoTenantUri = $spoProxy.OnlineTenantUri.AbsoluteUri
            $ssaFindings.Description+="<li style='color:#ffffff'>We have detected this is a Cloud SSA.</li>"
            $ssaFindings.Description+="<li style='color:#ffffff'>The SPO Tenant is: </li>"
            $ssaFindings.Description+="<ul style='color:#ffd700'>  $spoTenantUri</ul>"
        }

        # Task 544: change search to opt-in experience
        # with search an opt-in experience the skip healthcheck is unnecessary, it will be called whenever Search is included
        #if(!$SkipSearchHealthCheck)
        #{
        #    $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSearchHealthCheck -searchApplication $ssa))
        #} 
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSearchHealthCheck -searchApplication $ssa))


        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAObject -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAProxyPartition -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSATimerJobs -searchapplication $ssa))
        #$ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSATopology -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSADatabases -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-MSSCrawlStatHistory -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSATLegacyAdmin -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSACDProp -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAContentSources -searchapplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSASchemaMappings -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAServerNameMappings -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSACrawlRules -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnostictsSSAQueryAuthority -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSACrawlPolicies -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAEndpoints -searchApplication $ssa))
        #$ssaFindings.ChildFindings.Add((Get-SPDiagnosticsIndexDiskSpace -searchApplication $SSA))
        $searchFindings.ChildFindings.Add($ssaFindings) 
    }

    # Consolidated finding: content sources across all SSAs that have no scheduled or continuous
    # crawl. Previously each such content source produced its own Informational "Crawl Schedule ..."
    # finding that was promoted individually into the Informational Items section. They are now
    # collapsed into a single finding that calls out the Search Service Application and content source.
    if($script:NoScheduledCrawlContentSources -and $script:NoScheduledCrawlContentSources.Count -gt 0)
    {
        $noScheduledCrawlFinding = New-DiagnosticFinding -Name "Content Sources without a scheduled crawl" -Severity Default -InputObject $script:NoScheduledCrawlContentSources -Format Table
        $noScheduledCrawlFinding.Severity = [SPDiagnostics.Severity]::Informational
        $noScheduledCrawlFinding.Description += "The content sources listed below have no scheduled crawl and do not have continuous crawls enabled. Without a valid crawl schedule, their content will not be indexed or kept up to date. The Search Service Application and content source are identified for each."
        $noScheduledCrawlFinding.ReferenceLink += [uri]"https://learn.microsoft.com/en-us/sharepoint/search/add-edit-or-delete-a-content-source"
        $searchFindings.ChildFindings.Add($noScheduledCrawlFinding)
    }

    return $searchFindings

}

function Get-SPDiagnosticsSSAObject
{
    [CmdletBinding()]
    param (
     [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    #Todo: Remove this object
    #Todo: Format large numbers with Thousands Separator
        $ssaObjectInfo = $searchApplication | select-object DisplayName, Id, ApplicationName, ApplicationPool, SearchCenterUrl, CloudIndex, DiscoveryMaxRowLimit, AlertsEnabled, AllowPartialResults, CrawlLogCleanupIntervalInDays, DefaultQueryTimeout, MaxQueryTimeout, IndexedSchemaQueryTimeout, IisVirtualDirectoryPath, QuerySuggestionsEnabled, PersonalQuerySuggestionsEnabled, QueryLoggingEnabled, @{N='QLogEnabled'; E={$_.QueryLogSettings.QLogEnabled}}, @{N='QLogCleanupDays'; E={$_.QueryLogSettings.CleanupDays}}, ScsAuthRealm, ScsFlows, HybridTenantMaxQuota, HybridTenantMinQuota, HybridTenantQuotaBufferPercent, Status
        $findings = New-DiagnosticFinding -Name "SSA Object Info" -InputObject $ssaObjectInfo -format list
        return $findings
}

function Get-SPDiagnosticsSSAProxyPartition
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )

    if (($Script:Build -eq "2016") -or ($Script:Build -eq "2013"))
    {
        $finding = New-DiagnosticFinding -Name "SSA Partition Info" -InputObject $null -format list
        
        $proxyAppGuid = $searchapplication.id -replace "-", "" 
        $ssaProxy = Get-SPEnterpriseSearchServiceApplicationProxy | Where-Object{$_.ServiceEndpointuri -like ("*$proxyAppGuid*")}
        $ssaProxyPropertiesProperty = $ssaProxy.Properties["Microsoft.Office.Server.Utilities.SPPartitionOptions"]
        $ssaPropertiesProperty = $searchapplication.Properties["Microsoft.Office.Server.Utilities.SPPartitionOptions"]
        $ssaDisplayName = $searchApplication.DisplayName
        if($null -eq $ssaProxy)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage+="There is no proxy associated with this SSA:  " + $ssaDisplayName
            $finding.Description+=("In order to create a proxy for this ssa, the following can be executed: </br>")
            $finding.Description+=("<ul style='color:#ffd700'><div class=`"code`">`New-SPEnterpriseSearchServiceApplicationProxy -Name '$ssaDisplayName' -SearchApplication '$ssaDisplayName'<br></div></ul>")
            return $finding
        }
        if($ssaPropertiesProperty -ne "UnPartitioned")
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage +="This SSA, $ssaDisplayName, is not set to 'UnPartitioned'."
            $finding.Description += (" If the SSA is partitioned ( this would have been done at creation time ), URLMapping does not take place and will break contextual searches on Web Apps that have been extended to another zone. ( This can impact queries on extended zone URLs, among other search functions) ")
            $finding.Description += 'In order to correct this, either recreate the SSA or set the SSA to "IgnoreTenatization" with the following: '
            $finding.Description += "<ul><div style='color:#ffd700' class=`"code`">`$ssa = Get-SPEnterpriseSearchServiceApplication '$ssaDisplayName'<br>`$ssa.SetProperty('IgnoreTenantization', 1)<br>`$ssa.Update()</div><br/></ul>"
        }
        if($ssaProxyPropertiesProperty -ne "UnPartitioned")
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage +="The Search Proxy for this SSA is not set to 'UnPartitioned'. "
            $ssaProxyName = $ssaProxy.DisplayName
            $finding.Description +=(" If the proxy is partitioned ( this would have been done at creation time ), URLMapping does not take place and will break contextual searches on Web Apps that have been extended to another zone Property for 'searchProxy.Properties' is set to:  '$ssaProxyPropertiesProperty' ( This can impact queries on extended zone URLs, among other search functions) ")
            $finding.Description += 'In order to correct this, Is is recommended to delete the SSA Proxy and recreate it with the following: '
            $finding.Description += "<ul><div style='color:#ffd700' class=`"code`">`Remove-SPEnterpriseSearchServiceApplicationProxy '$ssaProxyName' -Confirm:$false<br>`New-SPEnterpriseSearchServiceApplicationProxy -Name '$ssaDisplayName' -SearchApplication '$ssaDisplayName'<br></div></ul>"
        }
        
        else
        {
            return $null
        }   
        return $finding
    } 
    else
    {
        return $null
    }

}

function Get-SPDiagnosticsSSATimerJobs
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $build = Get-SPVersion
    $ssaJobNames = "Application " + $searchApplication.Id
    $ssaDispName = $searchApplication.DisplayName
    $ssaJobs = Get-SPTimerJob | Where-Object{$_.Name -match $ssaJobNames}
    $finding = New-DiagnosticFinding -Name "SSA Related Timer Jobs" -InputObject ($ssaJobs | Select-Object DisplayName, Id, Status, isDisabled, LockType, LastRunTime, Schedule) -format Table
    Add-DiagnosticTimerJobSnapshot -Finding $finding -Jobs $ssaJobs -Scope ([ordered]@{ farmId = $script:SPFarm.Id; serviceApplicationId = $searchApplication.Id }) -Source 'Get-SPTimerJob filtered by search service application job-name prefix' -Coverage 'Jobs matched to this search service application by the existing collector; not all farm timer jobs.'
    if(($build -eq "SPSE" -or $build -eq "2019") -and $ssaJobs.Count -lt 9)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage += "The detected version of SharePoint is missing 1 or more 'SSA' related timer jobs. It's recommended to run the commands in the Description"
    }
    elseif($build -eq "2016" -and $ssaJobs.Count -lt 8)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage += "The detected version of SharePoint is missing 1 or more 'SSA' related timer jobs. It's recommended to run the commands in the Description"
    }
    else
    {
        if($build -eq "2013" -and $ssaJobs.Count -lt 7)
        {
           $finding.Severity = [SPDiagnostics.Severity]::Warning
           $finding.WarningMessage += "The detected version of SharePoint is missing 1 or more 'SSA' related timer jobs. It's recommended to run the commands in the Description"
        }
    }
    if($finding.WarningMessage)
    {
    $finding.Description+=("SSAs should have several timer jobs associated with them. <br><br>")
    $finding.Description+=("-- SP 2013 should have 7 timer jobs<br> -- SP 2016 should have 8 timer jobs <br> -- SP 2019 & SPSE should have 9 jobs <br><br>")
    $finding.Description+=("If there are any less than these ( respective of the SP Version), then the easiest course of action to get those timer jobs back in place would be to run: ")
    $finding.Description+=("<ul style='color:#ffd700'><div class=`"code`">`$ssa = Get-SPEnterpriseSearchServiceApplication '$ssaDispName'<br>`$ssa.Status = 'Disabled'<br>`$ssa.Update()<br>`$ssa.Provision()</div></ul>")
    }
    else
    {
        $finding.Description+=("The Search Service Application '$($searchApplication.Displayname)' has the correct number of timer jobs.<br><br>")
    }
    return $finding
}

function Get-SPDiagnosticsSSATLegacyAdmin
{
  [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )

    $LAC = $searchApplication.AdminComponent
    $AdminComps = new-object PSObject
    $AdminComps | Add-Member -MemberType NoteProperty -name "Name" -Value $LAC.Name
    $AdminComps | Add-Member -MemberType NoteProperty -name "IndexLocation" -Value $LAC.IndexLocation
    $AdminComps | Add-Member -MemberType NoteProperty -name "Initialized" -Value $LAC.Initialized
    $AdminComps | Add-Member -MemberType NoteProperty -name "ServerName" -Value $($LAC.Servername)
    $AdminComps | Add-Member -MemberType NoteProperty -name "ServerId" -Value $LAC.ServerID
    $AdminComps | Add-Member -MemberType NoteProperty -name "Server" -Value $LAC.Server

    $finding = New-DiagnosticFinding -Name "Admin Component Info" -InputObject $null -format list
    if($null -eq $searchApplication.SystemManagerLocations)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+=" - We detect the 'System Manager Location' is empty. The SSA will be broken when this is the case."
    }
    else
    {
        $sysManagerLocation = $searchApplication.SystemManagerLocations.AbsoluteUri
        $server = $sysManagerLocation.ToString().split('/')[2].split(':')[0]
        $sysManagerLocation1=  $sysManagerLocation.ToString()
        $finding.Description+=" - The 'SystemManagerLocations' is associated with the 'non-legacy' piece of the AdminComponent. </br> - This value should never be empty and the serverName *should* match the 'Legacy Admin Component' below.</br> <ul>`$ssa.SystemManagerLocations = " + "<span style='color:#ffd700'>" + $sysManagerLocation1 + "</span></ul>"
    }
    if($null -eq $LAC.ServerName)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+="<li>We detected the 'Legacy Admin Component' is empty.</li>"
        $finding.WarningMessage+="<li>The SSA will be broken when this is the case. Accessing 'Content Sources', 'Crawl Rules', 'ServerNameMappings' should be inaccessible.</li>"
        $finding.WarningMessage+="<li>Try to repair this by running the following command:</li>" 
        $finding.WarningMessage+="<ul style='color:#ffd700'><div class=`"code`">`Set-SPEnterpriseSearchAdministrationComponent -SearchApplication 'ssa Name' -SearchServiceInstance AdminServerName -Force</div></ul>"

    }
    else
    {
        $finding.InputObject=$AdminComps
    }
    return $finding
}
function Get-SPDiagnosticsSSACDProp
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $finding = New-DiagnosticFinding -Name "Content Distributor Property" -InputObject $null -format list
    $conn = New-Object System.Data.SqlClient.SqlConnection
    $cmd = New-Object System.Data.SqlClient.SqlCommand
    
    $adminDb = $script:spDatabases | Where-Object{$_.Name -eq $searchapplication.SearchAdminDatabase.Name}
    $connectionString = $adminDb.DatabaseConnectionString
    $conn.ConnectionString = $connectionString
    $conn.Open()
    $cmd.connection = $conn

    $cmd.CommandText = "select top 1 Value from MSSConfiguration where name like '%FastConnector:ContentDistributor'"
    $rows = $cmd.ExecuteReader()
    if($rows.HasRows -eq $true)
    {
        while($rows.Read())
        {
            $row = $rows[0]
            if($row -match "net.tcp:///")
            {
                $finding.Severity = [SPDiagnostics.Severity]::Critical
                $finding.WarningMessage+='<li style="color:red">The ContentDistributor Property on this SSA is corrupt. The crawl will not continue until this is resolved</li>'
                $finding.WarningMessage+='<li>In the ULS on the crawl servers, The following HResult may be observed: 0x80131537.</li>'
                $finding.WarningMessage+='<li>The current property is set to: </li>'
                $finding.WarningMessage+='<ul style="color:darkblue">' + "  {0}" -f $row.Replace(',','<BR>') + '</ul>'
                $finding.WarningMessage+='<li>It should appear like:  </li>'
                $finding.WarningMessage+='<ul style="color:darkblue">' + "  {0}" -f $row.Replace(',','<BR>').replace("net.tcp:///", "net.tcp://servername/") + '</ul>'
                $finding.WarningMessage+='<li>To correct this, remove the incorrectly registered Content Processing Component(s) from the search topology and add them back by a PowerShell script.  </li>'
            }
            else
            {
                $finding.Description+=(" - This SSA's ContentDistributor Property is: ")
                #Split the list first, then handle each server
                $CDistribs = $row.split(',')
                foreach ($cdistrib in $CDistribs)
                {
                    $server = $cdistrib.ToString().split('/')[2].split(':')[0]
                    $row1=  $cdistrib.ToString()
                    $finding.Description+=('<ul style="color:#ffd700">' + "  {0}" -f $row1 + '</ul>')
                }
            }
        }
    }
    $rows.Close()
    $conn.Close()

    return $finding
}

function Get-SPDiagnosticsSSATopology
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $activeTopo = $searchApplication | Get-SPEnterpriseSearchTopology -Active
    $sComponents = Get-SPEnterpriseSearchComponent -SearchTopology $activeTopo | Select-Object ServerName, Name, ServerId, ComponentId, RootDirectory, IndexPartitionOrdinal | Sort-Object Name

    $ActiveComps = @()
    foreach ($comp in $sComponents)
    {
        $ActiveComp= New-Object psobject
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "ServerName"   -value $($comp.serverName)
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "Name"  -value $comp.Name
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "ServerID"  -value $comp.ServerID
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "ComponentId"  -value $comp.ComponentId
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "RootDirectory"  -value $comp.RootDirectory
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "IndexPartitionOrdinal"  -value $comp.IndexPartitionOrdinal
        $ActiveComps += $ActiveComp
    }

    $activeTopoName = "Active Topology ID:  " + $activeTopo.TopologyId
    $finding = New-DiagnosticFinding -Name $activeTopoName -InputObject $ActiveComps -format table
    return $finding
}

function Get-SPDiagnosticsSSADatabases
{ 
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )

    $searchDbFinding = New-DiagnosticFinding -Name "Search Databases" -InputObject $null -format Table
    
    $ssaAdminDb = $searchApplication.SearchAdminDatabase.Name
    $crawlStores = [array]$searchApplication.CrawlStores
    $linkStores = [array]$searchApplication.LinksStores
    $apcStores = [array]$searchApplication.AnalyticsReportingStores
    
    $dbCollection = @()
    $dbCollection += [pscustomobject]@{DatabaseServer = $($searchApplication.SearchAdminDatabase.Server.Name); DatabaseType = "Administration Database"; DatabaseName = $($ssaAdminDb)}
    
    if($apcStores.Count -eq 1)
    {
       $dbCollection += [pscustomobject]@{DatabaseServer = $($apcStores[0].Database.Server.Name); DatabaseType = "Analytics Database"; DatabaseName = $($apcStores[0].Database.Name) }
    }
    else
    {
      foreach($apcStore in $apcStores | Sort-Object -Property Name)
      {
        $dbCollection += [pscustomobject]@{DatabaseServer = $($apcStore.Database.Server.Name); DatabaseType = "Analytics Database"; DatabaseName = $($apcStore.Database.Name)}
      }
    }
    if($crawlStores.Count -eq 1)
    {
        $dbCollection += [pscustomobject]@{DatabaseServer = $($crawlStores[0].Database.Server.Name); DatabaseType = "Crawl Database"; DatabaseName = $($crawlStores[0].Database.Name)}
    }
    else
    {
      foreach($crawlStore in $crawlStores | Sort-Object -Property Name)
      {
        $dbCollection += [pscustomobject]@{DatabaseServer = $($crawlStore.Database.Server.Name); DatabaseType = "Crawl Database"; DatabaseName = $($crawlStore.Database.Name)}
      }
        
    }
    if($linkStores.Count -eq 1)
    {
       $dbCollection += [pscustomobject]@{DatabaseServer = $($linkStores[0].Database.Server.Name); DatabaseType = "Link Database"; DatabaseName = $($linkStores[0].Database.Name) }
       $limitConcern = Get-SPDiagnosticsSearchLinksStoreLimit $linkstores[0]
       if($limitConcern -ne $null)
       {
           $searchDBFinding.ChildFindings.Add(($limitConcern))
       }
    }
    else
    {
      foreach($linksStore in $linkStores | Sort-Object -Property Name)
      {
        $dbCollection += [pscustomobject]@{DatabaseServer = $($linksStore.Database.Server.Name); DatabaseType = "Link Database"; DatabaseName = $($linksStore.Database.Name) }
        $limitConcern = Get-SPDiagnosticsSearchLinksStoreLimit $linkstore
        if($limitConcern -ne $null)
        {
            $searchDBFinding.ChildFindings.Add(($limitConcern))
        }
      }
    }
    $searchDbFinding.InputObject = $dbCollection
    return $searchDbFinding
}

function Get-MSSCrawlStatHistory
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Object]
        $searchApplication
    )

    $crawlHistoryFinding = New-DiagnosticFinding -Name "Crawl History Stats (top 500)" -InputObject $null -format table

    $crawlStatqueryText = @"
DECLARE @Count int = 500;
DECLARE @ContentSourceID int = -1;

SELECT 
    CrawlStats.CrawlID                                                       AS CrawlID,
    CASE CrawlStats.CrawlID
        WHEN 1 THEN 8
        ELSE History.CrawlType
    END                                                                       AS CrawlType,
    CrawlStats.ContentSourceID                                                AS ContentSourceID,
    CASE CrawlStats.CrawlID
        WHEN 1 THEN 4
        ELSE History.Status
    END                                                                       AS Status,
    CrawlStats.CrawlStartTime                                                 AS CrawlStartTime,
    CASE CrawlStats.CrawlID
        WHEN 1 THEN BatchEndTime
        ELSE History.EndTime
    END                                                                       AS CrawlEndTime,

    -- Duration formatted as HH:MM:SS
    RIGHT('0' + CAST(DATEDIFF(SECOND, CrawlStats.CrawlStartTime,
        CASE CrawlStats.CrawlID
            WHEN 1 THEN BatchEndTime
            ELSE History.EndTime
        END) / 3600 AS VARCHAR(2)), 2) + ':' +
    RIGHT('0' + CAST((DATEDIFF(SECOND, CrawlStats.CrawlStartTime,
        CASE CrawlStats.CrawlID
            WHEN 1 THEN BatchEndTime
            ELSE History.EndTime
        END) % 3600) / 60 AS VARCHAR(2)), 2) + ':' +
    RIGHT('0' + CAST(DATEDIFF(SECOND, CrawlStats.CrawlStartTime,
        CASE CrawlStats.CrawlID
            WHEN 1 THEN BatchEndTime
            ELSE History.EndTime
        END) % 60 AS VARCHAR(2)), 2) AS CrawlDuration,

    CrawlStats.Successes                                                      AS Successes,
    CrawlStats.Warnings                                                       AS Warnings,
    CrawlStats.Errors                                                         AS Errors,
    CrawlStats.TopLevelErrors                                                 AS TopLevelErrors,
    CrawlStats.Deletes                                                        AS Deletes,
    CrawlStats.NotModified                                                    AS NotModified,
    CrawlStats.SecurityUpdates                                                AS SecurityUpdates,
    CrawlStats.SecurityErrors                                                 AS SecurityErrors,
    CrawlStats.RefreshOnly                                                    AS RefreshOnly,
    CrawlStats.RefreshModified                                                AS RefreshModified,
    CrawlStats.RetryCount                                                     AS RetryCount
FROM
(
    SELECT TOP (@Count) *
    FROM TVF_MSSCrawlStatistics_Crawl()
    WHERE ContentSourceID = @ContentSourceID
        OR @ContentSourceID = -1
    ORDER BY CrawlStartTime DESC
) CrawlStats
LEFT OUTER JOIN MSSCrawlHistory History
    ON History.CrawlID = CrawlStats.CrawlID
    AND CrawlStats.CrawlID IS NOT NULL;
"@

    #region Database connection
    $adminConn = New-Object System.Data.SqlClient.SqlConnection
    $adminCmd  = New-Object System.Data.SqlClient.SqlCommand

    try {
        $adminDb = $script:spDatabases | Where-Object { $_.Name -eq $searchApplication.SearchAdminDatabase.Name }

        $adminConn.ConnectionString = $adminDb.DatabaseConnectionString
        $adminConn.Open()

        $adminCmd.Connection  = $adminConn
        $adminCmd.CommandText = $crawlStatqueryText

        $reader = $adminCmd.ExecuteReader()
    }
    catch {
        Write-Host $_
    }
    #endregion

    #region Convert SQL rows Ã¢â€ â€™ PSObjects
    $fulldata = @()

    if ($reader.HasRows) {

        # Get column names once
        $columns = for ($i = 0; $i -lt $reader.FieldCount; $i++) {
            $reader.GetName($i)
        }

        # Build objects row-by-row
        while ($reader.Read()) {

            $obj = [PSCustomObject]@{}

            foreach ($col in $columns) {
                $obj | Add-Member -NotePropertyName $col -NotePropertyValue $reader[$col]
            }

            $fulldata += $obj
        }
    }

    # Cleanup
    $reader.Close()
    $adminConn.Close()
    #endregion

    # Output into your diagnostic wrapper
    $crawlHistoryFinding.InputObject = $fulldata
    return $crawlHistoryFinding
}

function Get-SPDiagnosticsSSASchemaMappings
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Object]
        $searchApplication
    )

    $finding = New-DiagnosticFinding -Name "Schema Mappings" -InputObject $null -Format Table
    $finding.Description += "- These are the current crawled : managed property mappings. They are directly pulled from SQL tables. </br>- We do this so we can see Schema Id's. SSA Level is '0', anything other than that means schema mappings exist at the Site level"

    $queryText = @'
Select sm.PID, mp.FriendlyName, sm.MappingOrder, sm.CrawledPropertyId, cp.PropertyName, cp.Propset, sm.SchemaId from MSSSchemaPropertyMappings sm, MSSManagedProperties mp, MSSCrawledProperties cp WHERE sm.PID = mp.PID AND sm.CrawledPropertyId = cp.CrawledPropertyId Order By PID, MappingOrder
'@

    #region Database connection
    $conn = New-Object System.Data.SqlClient.SqlConnection
    $cmd  = New-Object System.Data.SqlClient.SqlCommand

    try
    {
        $adminDb = $script:spDatabases | Where-Object { $_.Name -eq $searchApplication.SearchAdminDatabase.Name }
        $conn.ConnectionString = $adminDb.DatabaseConnectionString
        $conn.Open()

        $cmd.Connection  = $conn
        $cmd.CommandText = $queryText

        $reader = $cmd.ExecuteReader()
    }
    catch
    {
        Write-Host $_
    }
    #endregion

    #region Convert SQL rows -> PSObjects
    $fulldata = @()

    if ($reader.HasRows)
    {
        # Get column names once
        $columns = for ($i = 0; $i -lt $reader.FieldCount; $i++)
        {
            $reader.GetName($i)
        }

        # Build objects row-by-row
        while ($reader.Read())
        {
            $obj = [PSCustomObject]@{}

            foreach ($col in $columns)
            {
                $obj | Add-Member -NotePropertyName $col -NotePropertyValue $reader[$col]
            }

            $fulldata += $obj
        }
    }

    # Cleanup
    $reader.Close()
    $conn.Close()
    #endregion

    # Consolidate to one row per PID (PID + FriendlyName shown once, since both are 1:1 with the
    # managed property). Each crawled-property mapping's columns are stacked in parallel using the
    # ~~~BR~~~ sentinel (<br/> in HTML, " | " in text), matching "Service Instances on Server(s)".
    if ($fulldata.Count -gt 0)
    {
        $groupedMappings = @()
        foreach ($pidGroup in ($fulldata | Group-Object PID))
        {
            $groupedMappings += [PSCustomObject]@{
                PID               = $pidGroup.Name
                FriendlyName      = $pidGroup.Group[0].FriendlyName
                MappingOrder      = (($pidGroup.Group | ForEach-Object {$_.MappingOrder})      -join '~~~BR~~~')
                CrawledPropertyId = (($pidGroup.Group | ForEach-Object {$_.CrawledPropertyId}) -join '~~~BR~~~')
                PropertyName      = (($pidGroup.Group | ForEach-Object {$_.PropertyName})      -join '~~~BR~~~')
                Propset           = (($pidGroup.Group | ForEach-Object {$_.Propset})           -join '~~~BR~~~')
                SchemaId          = (($pidGroup.Group | ForEach-Object {$_.SchemaId})          -join '~~~BR~~~')
            }
        }
        $finding.InputObject = $groupedMappings
    }
    else
    {
        $finding.InputObject = $fulldata
    }
    return $finding
}

function Get-SPDiagnosticsSSAContentSources
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $csFindingName = "Content Sources"
    $findingCollection = New-DiagnosticFinding -name $csFindingName -InputObject $null -Format table
    $contentSources = Get-SPEnterpriseSearchCrawlContentSource -SearchApplication $searchapplication -ErrorAction SilentlyContinue
    Add-DiagnosticCommandSnapshot -Finding $findingCollection -CommandName 'Get-SPEnterpriseSearchCrawlContentSource' -Records $contentSources -Scope ([ordered]@{ farmId = $script:SPFarm.Id; serviceApplicationId = $searchApplication.Id }) -Source 'Get-SPEnterpriseSearchCrawlContentSource -SearchApplication' -Coverage 'Content sources in the selected search application; existing query errors remain in Error Collection. Numeric counters are captured before display formatting.' -PropertyNames @(
        'Id', 'Name', 'Type', 'StartAddresses', 'SharePointCrawlBehavior',
        'CrawlState', 'CrawlStatus', 'ContinuousCrawlStatus', 'CrawlPriority',
        'SuccessCount', 'WarningCount', 'ErrorCount', 'DeleteCount', 'CrawlStarted',
        'CrawlCompleted', 'EnableContinuousCrawls', 'FullCrawlSchedule', 'IncrementalCrawlSchedule'
    )
    foreach ($contentSrc in $contentSources)
    {
        
        $csName =  'Content Source: ' + $($($contentSrc.Name)) + ' || ' + '( ' + 'ID: ' + $contentSrc.ID + ' | ' + ' Type: ' + $contentSrc.Type + ' | ' + ' Behavior: ' + $contentSrc.SharePointCrawlBehavior + ')'
        $csObj = $contentSrc | Select-Object CrawlState, CrawlStatus, ContinuousCrawlStatus, CrawlPriority, SuccessCount, WarningCount, ErrorCount, DeleteCount, CrawlStarted, CrawlCompleted, EnableContinuousCrawls, LevelImportantTotalCount, LevelHighErrorCount, LevelHighRecurringErrorCount, LevelHighTotalCount, LevelImportantRecurringErrorCount, RefreshCrawls 
        # Add thousands separators
        $csObj.SuccessCount = $csObj.SuccessCount.ToString('N0')
        $csObj.WarningCount = $csObj.WarningCount.ToString('N0')
        $csObj.ErrorCount = $csObj.ErrorCount.ToString('N0')
        $csObj.DeleteCount = $csObj.DeleteCount.ToString('N0')
        $csObj.LevelImportantTotalCount = $csObj.LevelImportantTotalCount.ToString('N0')
        $csObj.LevelHighErrorCount = $csObj.LevelHighErrorCount.ToString('N0')
        $csObj.LevelHighRecurringErrorCount = $csObj.LevelHighRecurringErrorCount.ToString('N0')
        $csObj.LevelHighTotalCount = $csObj.LevelHighTotalCount.ToString('N0')
        $csObj.LevelImportantRecurringErrorCount = $csObj.LevelImportantRecurringErrorCount.ToString('N0')

        $csFinding = New-DiagnosticFinding -name $csName -InputObject $csObj -Format List

        $retObj = @()

        foreach ($startUri in $contentSrc.StartAddresses) 
        {
            $sAddressColl = [PSCustomObject]@{}
            if ($contentSrc.Type.toString() -ieq "SharePoint")
            {
            if ($startUri.Scheme.toString().toLower().startsWith("http")) 
            {
              $isRemoteFarm = $true ## Assume Remote Farm Until Proven Otherwise ##
              foreach ($altUrl in Get-SPAlternateUrl)
              {
                if ($startUri.AbsoluteUri.toString() -ieq $altUrl.Uri.toString()) 
                {
                  $isRemoteFarm = $false                
                  if ($altUrl.UrlZone -ieq "Default") 
                  {
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $($startUri.AbsoluteUri.ToString())
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "AAMZone" -Value $altUrl.UrlZone
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "RemoteFarm" -Value $false
                    
                    $inUserPolicy = $false;    #assume crawlAccount not inUserPolicy until verified
                    $webApp = Get-SPWebApplication $startUri.AbsoluteUri;
                    $IIS = $webApp.IisSettings[[Microsoft.SharePoint.Administration.SPUrlZone]::($altUrl.UrlZone)]
                    $isClaimsBased = $true
                    if ($webApp.UseClaimsAuthentication) 
                    { 
                        $sAddressColl | Add-Member -MemberType NoteProperty -Name "AuthenticationType" -Value "Claims"
                        
                        if (($IIS.ClaimsAuthenticationProviders).count -eq 1) 
                        {
                           $sAddressColl | Add-Member -MemberType NoteProperty -Name "AuthenticationProvider" -Value ($IIS.ClaimsAuthenticationProviders[0]).DisplayName
                        } 
                        else 
                        {
                          $providers = $null
                          foreach ($provider in ($IIS.ClaimsAuthenticationProviders)) 
                          {
                            $providers+=$provider.DisplayName + " | "
                          }
                          $providers=$providers.Trim(" | ")
                          $sAddressColl | Add-Member -MemberType NoteProperty -Name "AuthenticationProvider" -Value $providers
                        }
                    }
                    else {
                      $isClaimsBased = $false
                      $sAddressColl.AuthenticationType += "Classic"
                      
                      if ($IIS.DisableKerberos)
                      {
                        $sAddressColl | Add-Member -MemberType NoteProperty -Name "AuthenticationType" -Value "Windows:NTLM" 
                      }
                      else 
                      { 
                        $sAddressColl | Add-Member -MemberType NoteProperty -Name "AuthenticationType" -Value "Windows:Negotiate"
                      }
                    }
                    foreach ($userPolicy in $webApp.Policies) 
                    {
                      if($isClaimsBased)
                      {
                       $claimsPrefix = "i:0#.w|" 
                      }
                      if ($userPolicy.UserName.toLower().Equals(($claimsPrefix + $crawlAccount).toLower())) 
                      {
                        $inUserPolicy = $true;
                        $sAddressColl | Add-Member -MemberType NoteProperty -Name "WebAppUserPolicy" -Value $userPolicy.PolicyRoleBindings.toString()
                      }
                    }
                    if (!$inUserPolicy) 
                    {
                        $csFinding.Severity = [SPDiagnostics.Severity]::Warning   
                        $csFinding.WarningMessage+= $crawlAccount + " is NOT defined in the Web App's User Policy "
                    }
                  }
                  else
                  { 
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $($startUri.AbsoluteUri.ToString())
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "AAMZone" -Value $altUrl.UrlZone
                    $csFinding.WarningMessage +="[" + $altUrl.UrlZone + "] " + $startUri
                    $csFinding.WarningMessage +="--- Non-Default zone may impact Contextual Scopes (e.g. This Site) and other search functionality"
                    $csFinding.Description += "The only URL that should be crawled should be the 'Default Zone Public URL' and it should be Windows Authentication. If crawling both the Default Zone and another Zone URL, the non Default Zone Url should be removed from the start addresses"
                    $csFinding.ReferenceLink +="https://sparsenal.com/problems-crawling-the-non-default-zone-for-a-sharepoint-web-application/" 
                    $csFinding.Severity = [SPDiagnostics.Severity]::Warning
                    
                  }
                }
              }
          
              if($isRemoteFarm)
              {
                $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $($startUri.AbsoluteUri.ToString())
                $sAddressColl | Add-Member -MemberType NoteProperty -Name "RemoteFarm" -Value $true
              }
            
            } 
            else 
            {
              if($startUri.Scheme.toString().toLower().startsWith("sps")) 
              {
                 $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $($startUri.AbsoluteUri.ToString())
                 $sAddressColl | Add-Member -MemberType NoteProperty -Name "Type" -Value "Profile Crawl"
              }
              else 
              {
                if($startUri.Scheme.toString().toLower().startsWith("bdc"))
                {
                    $sAddressColl.StartAddress += $startUri.AbsoluteUri.ToString()
                    $retObj.Type += "BDC Crawl"
                }
                else 
                {
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $($startUri.AbsoluteUri.ToString())
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "Type" -Value "URI"
                }
              }
            }
          }
          else 
          {
            $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $($startUri.AbsoluteUri.ToString())
            $sAddressColl | Add-Member -MemberType NoteProperty -Name "Type" -Value "Unknown"
             #$retObj | Add-Member -MemberType NoteProperty -Name "Address" -Value $startUri.AbsoluteUri.toString()
           
           }
           $retObj += $sAddressColl
           #$retObj | Add-Member -MemberType NoteProperty -Name "Type" -Value $contentSrc.Type
           #$sAddress = '<span style="color:gray; font-size:14px">StartAddress ' + $count + "</span>"
           #$startAddressFinding = New-DiagnosticFinding -name $sAddress -InputObject $retObj -Format Table -Expand
           #$csFinding.ChildFindings.Add($startAddressFinding)
          }

        $sAddressFindingName = 'Start Addresses (' + $retObj.Count + ')'
        $startAddressFinding = New-DiagnosticFinding -name $sAddressFindingName -InputObject $retObj -Format Table -Expand
        $csFinding.ChildFindings.Add($startAddressFinding)
        $findingCollection.ChildFindings.Add($csFinding)

        $csCrawlScheduleColl = [PSCustomObject]@{}
        $csCrawlScheduleColl  | Add-Member -MemberType NoteProperty -Name "Full Crawl Schedule" -Value $contentSrc.FullCrawlSchedule.Description
        $csCrawlScheduleColl  | Add-Member -MemberType NoteProperty -Name "Incremental Crawl Schedule" -Value $contentSrc.IncrementalCrawlSchedule.Description
        $csSchedFinding = New-DiagnosticFinding -name "Crawl Schedule | $($SearchApplication.Name) | $($($contentSrc.Name))" -InputObject $csCrawlScheduleColl -Format List

        if(!$contentSrc.EnableContinuousCrawls -and [string]::IsNullOrEmpty($contentSrc.FullCrawlSchedule.Description) -and [string]::IsNullOrEmpty($contentSrc.IncrementalCrawlSchedule.Description))
        {
            # No scheduled or continuous crawl configured. Instead of promoting one Informational
            # finding per content source, accumulate the SSA + content source into a single farm-wide
            # consolidated finding built in Get-SPDiagnosticSearchFindings after the SSA loop.
            if($null -eq $script:NoScheduledCrawlContentSources)
            {
                $script:NoScheduledCrawlContentSources = @()
            }
            $script:NoScheduledCrawlContentSources += [PSCustomObject]@{
                "Search Service Application" = $($SearchApplication.Name)
                "Content Source"             = $($contentSrc.Name)
                "Type"                       = $($contentSrc.Type)
                "Full Crawl Schedule"        = $($contentSrc.FullCrawlSchedule.Description)
                "Incremental Crawl Schedule" = $($contentSrc.IncrementalCrawlSchedule.Description)
            }
        }

        if( ($contentSrc.IncrementalCrawlSchedule.RepeatInterval -gt 0) -and ($contentSrc.IncrementalCrawlSchedule.RepeatInterval -le 5) )
        {
            $csSchedFinding.Severity =  [SPDiagnostics.Severity]::Warning
            $csSchedFinding.WarningMessage += "Incremental crawls are scheduled to frequently for this contentsource: Every $($contentSrc.IncrementalCrawlSchedule.RepeatInterval) minutes. This can cause to high resource utilization on the system."
            $csSchedFinding.ReferenceLink += [uri]"https://learn.microsoft.com/en-us/sharepoint/search/add-edit-or-delete-a-content-source"
        }

        if( ( $contentSrc.FullCrawlSchedule.RepeatInterval -gt 0) -and ($contentSrc.FullCrawlSchedule.RepeatInterval -le 60))
        {
            $csSchedFinding.Severity =  [SPDiagnostics.Severity]::Warning
            $csSchedFinding.WarningMessage += "Full crawls are scheduled to frequently for this contentsource: Every $($contentSrc.FullCrawlSchedule.RepeatInterval) minutes. This can cause to high resource utilization on the system."
            $csSchedFinding.ReferenceLink += [uri]"https://learn.microsoft.com/en-us/sharepoint/search/add-edit-or-delete-a-content-source"
        }

        if( $contentSrc.EnableContinuousCrawls -eq $false -and $null -eq $contentSrc.IncrementalCrawlSchedule -and $contentSrc.FullCrawlSchedule.RepeatInterval -eq 0)
        {
            $csSchedFinding.Severity =  [SPDiagnostics.Severity]::Warning
            $csSchedFinding.WarningMessage += "Infrequent scheduled full crawls for this content source, can cause an outdated index"
            $csSchedFinding.ReferenceLink += [uri]"https://learn.microsoft.com/en-us/sharepoint/search/add-edit-or-delete-a-content-source"
        }

        if( $contentSrc.EnableContinuousCrawls -eq $false -and $null -eq $contentSrc.FullCrawlSchedule -and ($contentSrc.IncrementalCrawlSchedule.RepeatInterval -gt 240 -or $contentSrc.IncrementalCrawlSchedule.RepeatInterval -eq 0) )
        {
            $csSchedFinding.Severity = [SPDiagnostics.Severity]::Warning
            $csSchedFinding.WarningMessage += "Infrequent incremental  crawls for this content source, impact index freshness"
            $csSchedFinding.ReferenceLink += [uri]"https://learn.microsoft.com/en-us/sharepoint/search/add-edit-or-delete-a-content-source"
        }

        $csFinding.ChildFindings.Add($csSchedFinding)
      }
      return $findingCollection
}
#check for any server name mappings for this SSA
function Get-SPDiagnosticsSSAServerNameMappings
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $SNM = $searchApplication | Get-SPEnterpriseSearchCrawlMapping -ErrorAction SilentlyContinue
    if($null -ne $snm)
    {
        $SNMs = @()
        foreach ($snmp in $SNM)
        {
            $SNMa = [PSCustomObject] @{
                Source = $($snmp.Source.AbsoluteURI)
                Target = $($snmp.Target.AbsoluteURI)
            }
            $SNMs += $SNMa   
        }
        $finding = New-DiagnosticFinding -Name "Server Name Mappings" -InputObject $SNMs -format table
    }
    else
    {
        return $null
        #$finding = New-DiagnosticFinding -Name "Server Name Mappings" -InputObject $null -Description "This SSA has no Server Name Mappings" -format list
    }
    return $finding
}

function Get-SPDiagnosticsSSACrawlRules
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
        $tempcrawlrules = $searchApplication | Get-SPEnterpriseSearchCrawlRule -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty Parent
        if($null -ne $tempcrawlrules)
        {
            $crawlRules = @()
            foreach ($cr in $tempcrawlrules)
            {
                $crawlrule = [PSCustomObject] @{
                    Path = $($cr.Path)
                    Priority = $cr.Priority
                    PlugableSecurtiyTrimmer = $cr.PlugableSecurtiyTrimmer
                    Type =$cr.type
                    AuthenticationType  = $cr.AuthenticationType
                    AccountName = $($cr.AccountName)
                    Method =$cr.Method
                    AuthenticationPath =$cr.AuthenticationPath
                    ErrorPages =$cr.ErrorPages
                    SuppressIndexing =$cr.SuppressIndexing
                    FollowComplexUrls  =$cr.FollowComplexUrls
                    CrawlAsHTTP =$cr.CrawlAsHTTP
                    IsAdvancedRegularExpression = $cr.IsAdvancedRegularExpression
                    ContentClass =$cr.ContentClass
                }
                $crawlRules += $crawlrule
            }
            $finding = New-DiagnosticFinding -Name "Crawl Rules" -InputObject $crawlRules -format table
        }
        else
        {
            return $null
            #$finding = New-DiagnosticFinding -Name "Crawl Rules" -Description "This SSA has no Crawl Rules defined" -format list -InputObject $null
        }
    return $finding
}

function Get-SPDiagnostictsSSAQueryAuthority ($searchApplication)
{
    #Authoritative and demoted sites
    $AuthDemotedSites = @()

    $AuthDemotedFinding = New-DiagnosticFinding -Name "Autoritative and Demoted Sites" -InputObject $null -format table


    $Levels=@("Ssa", "SPSiteSubscription" , "SPSite", "SPWeb")

    foreach ($level in $levels)
    {
        $so = $null
        
           $so = Get-SPEnterpriseSearchOwner -Level $level -ErrorAction SilentlyContinue

        if ($so)
        {
            $AuthSites= Get-SPEnterpriseSearchQueryAuthority -SearchApplication $searchApplication -Owner $so
            $DemotedSites = Get-SPEnterpriseSearchQueryDemoted -SearchApplication $searchApplication -Owner $so

            foreach ($AuthSite in $AuthSites)
            {
                $as = New-Object psObject
                $as | Add-Member -MemberType NoteProperty -name "Type" -Value "Promoted"
                $as | Add-Member -MemberType NoteProperty -name "Url" -Value $($AuthSite.Url)
                $as | Add-Member -MemberType NoteProperty -name "Level" -Value $AuthSite.Level 
                $as | Add-Member -MemberType NoteProperty -name "Scope" -Value $so.Level 
                $as | Add-Member -MemberType NoteProperty -name "CrawledDocumentCount"-Value $Null
                $AuthDemotedSites += $as
            }
            foreach ($DemSite in $DemotedSites)
            {
                $as = New-Object psObject
                $as | Add-Member -MemberType NoteProperty -name "Type" -Value "Demoted"
                $as | Add-Member -MemberType NoteProperty -name "Url" -Value $($DemSite.Url)
                $as | Add-Member -MemberType NoteProperty -name "Level" -Value $null 
                $as | Add-Member -MemberType NoteProperty -name "Scope" -Value $so.Scope
                $as | Add-Member -MemberType NoteProperty -name "CrawledDocumentCount"-Value $DemSite.CrawledDocumentCount
                $AuthDemotedSites += $as
            }
        }
    }
    if ($AuthDemotedSites.Count -gt 0)
    {
        $AuthDemotedFinding.Description +=" - Promoted pages get a higher Ranking in Search results, the lower the level the higher the ranking.</br> - The less clicks it takes to get from a promoted site to a url in search results the higher the ranking.</br> - Demoted Urls receive a lower ranking"
        $AuthDemotedFinding.InputObject = $AuthDemotedSites
        return $AuthDemotedFinding
    }

}
function Get-SPDiagnosticsSSACrawlPolicies
{
    [CmdletBinding()]
    param (
     [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $crawlPolicyFinding = New-DiagnosticFinding -Name "SSA Crawl Policies" -InputObject $null -Format List
                 
    try
    {
        $CrawlPolicyColl = [PSCustomObject]@{
            "RecrawlErrorCount" = $($searchApplication.GetProperty("RecrawlErrorCount"))
            "RecrawlErrorInterval" = $searchApplication.GetProperty("RecrawlErrorInterval")
            "ErrorCountAllowed" = $searchApplication.GetProperty("ErrorCountAllowed")
            "ErrorIntervalAllowed" = $searchApplication.GetProperty("ErrorIntervalAllowed")
            "ErrorDeleteCountAllowed" = $searchApplication.GetProperty("ErrorDeleteCountAllowed")
            "ErrorDeleteIntervalAllowed" = $searchApplication.GetProperty("ErrorDeleteIntervalAllowed")
            "DeleteUnvisitedMethod" = $searchApplication.GetProperty("DeleteUnvisitedMethod")
            "LogDiscoveredLinks" = $searchApplication.GetProperty("LogDiscoveredLinks")
            "DisableAutoRecovery" = $searchApplication.GetProperty("DisableAutoRecovery")
            "MaxGrowFactor" = $searchApplication.GetProperty("MaxGrowFactor")
            "MaxDownloadSize" = $searchApplication.GetProperty("MaxDownloadSize")
            "MaxDownloadSizeExcel" = $searchApplication.GetProperty("MaxDownloadSizeExcel")
            "MaxPropertyDownloadSize" = $searchApplication.GetProperty("MaxPropertyDownloadSize")
            "MaxListItemChangeSizeInKB" = $searchApplication.GetProperty("MaxListItemChangeSizeInKB")

            "ContinuousCrawlInterval" = $searchApplication.GetProperty("ContinuousCrawlInterval")
            "RefreshBucketCount" = $searchApplication.GetProperty("RefreshBucketCount")
            "RefreshEnumDepthAdjustment" = $searchApplication.GetProperty("RefreshEnumDepthAdjustment")
            "RefreshMinInterval" = $searchApplication.GetProperty("RefreshMinInterval")
            "RefreshMaxInterval" = $searchApplication.GetProperty("RefreshMaxInterval")
            "RefreshMaxPromotion" = $searchApplication.GetProperty("RefreshMaxPromotion")
            "RefreshMaxDemotion" = $searchApplication.GetProperty("RefreshMaxDemotion")
            "RefreshPromoteLimitStart" = $searchApplication.GetProperty("RefreshPromoteLimitStart")
            "RefreshPromoteLimitEnd" = $searchApplication.GetProperty("RefreshPromoteLimitEnd")
            "RefreshDemoteLimitStart" = $searchApplication.GetProperty("RefreshDemoteLimitStart")
            "RefreshDemoteLimitEnd" = $searchApplication.GetProperty("RefreshDemoteLimitEnd")
        }

        $counterDefault = new-Object PsObject @{
            #crawl policy
            "RecrawlErrorCount"=5
            "RecrawlErrorInterval"=120
            "ErrorCountAllowed"=15
            "ErrorIntervalAllowed"=360
            "ErrorDeleteCountAllowed"=10
            "ErrorDeleteIntervalAllowed"=240
            "DeleteUnvisitedMethod"=1
            "LogDiscoveredLinks"=1
            "DisableAutoRecovery"=$False

            "MaxGrowFactor"=4
            "MaxDownloadSize"=64
            "MaxDownloadSizeExcel"=4
            "MaxPropertyDownloadSize"=1
            "MaxListItemChangeSizeInKB"=1024

            #refresh settings
            "ContinuousCrawlInterval"=15
            "RefreshBucketCount"=6
            "RefreshEnumDepthAdjustment"=2
            "RefreshMinInterval"=15
            "RefreshMaxInterval"=43200
            "RefreshMaxPromotion"=3
            "RefreshMaxDemotion"=2
            "RefreshPromoteLimitStart"=2
            "RefreshPromoteLimitEnd"=2
            "RefreshDemoteLimitStart"=-4
            "RefreshDemoteLimitEnd"=-4
        }
        if ($Script:Build -eq"2013")
        {
            $counterDefault.MaxDownloadSizeExcel=3
        }

        $PropDiff = $false
        foreach ($prop in $counterDefault.Keys)
        {
            if ( ( ($counterDefault.GetEnumerator() | where-Object {$_.Name -eq $prop}).value) -ne ( $CrawlPolicyColl.PSObject.Members[$prop].Value )  )
            {
                $PropDiff = $true
                $crawlPolicyFinding.WarningMessage += "CrawlPolicy value not default for $prop :  Default '$($counterDefault[$prop])'  <==>  Current setting: '$($CrawlPolicyColl.PSObject.Members[$prop].Value)'"
            }
        }

        if ($PropDiff)
        {
            $crawlPolicyFinding.InputObject = $CrawlPolicyColl
            $crawlPolicyFinding.Severity = [SPDiagnostics.Severity]::Warning
        }
        if ($CrawlPolicyColl.ContinuousCrawlInterval -lt 10)
        {
            $crawlPolicyFinding.WarningMessage += "Continuous Crawling Interval is set low: $($CrawlPolicyColl.ContinuousCrawlInterval) minutes. This can cause high resource utilization on the farm."
            $crawlPolicyFinding.Severity = [SPDiagnostics.Severity]::Warning       
        }
        else
        {
            return
            #$crawlPolicyFinding.Description +="All Crawl Policies are to default values"
        }


    } 
    catch 
    {
        $crawlPolicyFinding.WarningMessage += "We could be having trouble communicating with the admin component or accessing registry values due to inefficient permissions in SQL, so we are unable to access 'Crawl Policies' "
        $crawlPolicyFinding.Severity = [SPDiagnostics.Severity]::Warning

    }
    return $crawlPolicyFinding
}


function Get-SPDiagnosticsSSASearchService                                             
{
    [cmdletbinding()]
    Param()
    $searchInstance = Get-SPEnterpriseSearchService

    $siObj = [PSCustomObject]@{
   DisplayName = $searchInstance.DisplayName
   Id = $searchInstance.Id
   ServiceName = $searchInstance.ServiceName
   ProcessIdentity = $($searchInstance.ProcessIdentity)
   PerformanceLevel = $searchInstance.PerformanceLevel
   ConnectionTimeout = $searchInstance.ConnectionTimeout
   AcknowledgementTimeout = $searchInstance.AcknowledgementTimeout
   IgnoreSSLWarnings = $searchInstance.IgnoreSSLWarnings
   UseCrawlProxyForFederation = $searchInstance.UseCrawlProxyForFederation
   InternetIdentity = $searchInstance.InternetIdentity
   Status = $searchInstance.Status
}
    $finding = New-DiagnosticFinding -Name "'Farm Search' Service Instance" -InputObject $siObj -format List
    
    if ($siObj.ConnectionTimeout -gt 120)
    {
        $finding.WarningMessage += "Connection timeout is set high. This can lead to slow crawls when network connections no longer exist."
        $finding.Severity = [SPDiagnostics.Severity]::Informational
    }
    elseif ($siObj.ConnectionTimeout -le 15)
    {
        $finding.WarningMessage += "Connection timeout is set low. This can prevent the indexing of items with high latency network connection."
        $finding.Severity = [SPDiagnostics.Severity]::Informational
    }
    if ($siObj.AcknowledgementTimeout -gt 120)
    {
        $finding.WarningMessage += "AcknowledgementTimeout timeout is set high. This can lead to slow crawls when items no longer exist."
        $finding.Severity = [SPDiagnostics.Severity]::Informational
    } elseif ($siObj.AcknowledgementTimeout -le 15)
    {
        $finding.WarningMessage += "AcknowledgementTimeout timeout is set low. This can prevent the indexing of items with high latency network connection."
        $finding.Severity = [SPDiagnostics.Severity]::Informational
    }

    if ($siObj.IgnoreSSLWarnings -ne $true)
    {
        $finding.WarningMessage += "IgnoreSSLWarnings should be set to 'Yes' when external HTTPS content is crawled. When this value is set to 'No', all SSL certificates for the external content must be installed or trusted."
        $finding.Severity = [SPDiagnostics.Severity]::Informational
    }

    $SearchPerfLevel = $searchInstance.PerformanceLevel.value__
    #Check if SearchServers are dedicated SearchRole, SingleServer
    $RoleDedicatedSearch=$false
    $RoleSingleServer=$false
    foreach ($s in $script:servers)
    {
        if ($s.role -eq "Search")
        {
            $RoleDedicatedSearch = $true
        } elseif ($s.role -match "SingleServer")
        {
            $RoleSingleServer = $true
        }
    }
    # Dedicated Search Servers and PerfLevel not on  Maximum
    if ($RoleDedicatedSearch -and $SearchPerfLevel -ne 2)
    {
        $finding.WarningMessage += "When running dedicated Search Servers in the farm, the PerformanceLevel of the Search Service Instance should be set to Maximum."
        $finding.Severity = [SPDiagnostics.Severity]::Informational
    }
    # Single Server or SingleServer Farm with Search Perf Level Maximum
    if ($RoleSingleServer -and $SearchPerfLevel -eq 2)
    {
        $finding.WarningMessage += "Running Search Performance Level Maximum on a single Server or Single Server Farm can create high CPU utilization during crawls and render the farm inaccessible."
        $finding.Severity = [SPDiagnostics.Severity]::Warning
    }
    
    $ssaWebProxy = $searchInstance.WebProxy
    if($null -ne $ssaWebProxy.Address)
    {
       $proxyAddress = $ssaWebProxy.Address
       $bypassProxy = $ssaWebProxy.BypassProxyOnLocal
       $bypassList = $ssaWebProxy.BypassList
       $proxyCreds = $ssaWebProxy.Credentials
       $proxyUseDefCreds = $ssaWebProxy.UseDefaultCredentials
       $proxyArrayList = $ssaWebProxy.BypassArrayList

       $webProxyText = @"
<table style="border-color: white;" border="0">
<tr><td>Address</td><td><span style='color: #ffd700;'>$($proxyAddress)</span></td></tr>
<tr><td>BypassProxyOnLocal</td><td><span style='color: #ffd700;'>$bypassProxy</span></td></tr>
<tr><td>BypassList</td><td>{<span style='color: #ffd700;'>$($bypassList)</span>}</td></tr>
<tr><td>Credentials</td><td>{<span style='color: #ffd700;'>$($proxyCreds)</span>}</td></tr>
<tr><td>UseDefaultCredentials</td><td><span style='color: #ffd700;'>$proxyUseDefCreds</span></td></tr>
<tr><td>BypassArrayList</td><td>{<span style='color: #ffd700;'>$($proxyArrayList)</span>}</td></tr>
</table>
"@
        $finding.Description+="- The Search Service has a Web Proxy defined.</br>- This will impact ALL SSA's and route crawl traffic to the Proxy regardless if the 'IE settings' or 'netsh winhttp show proxy' are defined"
        $finding.Description+='<ul>' + $webProxyText + '</ul>'
    }
    $finding.ChildFindings.Add((Get-SPDiagnosticsCrawlerImpactRules))
    return $finding
}

function Get-SPDiagnosticsCrawlerImpactRules
{
    
    $CIRules = Get-SPEnterpriseSearchSiteHitRule 
    if ($CIRules.count -gt 0)
    {
        $CIfinding = New-DiagnosticFinding -Name "Crawler Impact Rules" -InputObject $null -format table
        $CIfinding.Description +="By default SharePoint requests 8 items in parallel when crawling. This can be influenced with Crawler Impact Rules.<BR>"
        $CIfinding.Description +="The HitRate for Simultaneous Requests changes the number of items requested in parallel.<BR>"
        $CIfinding.Description +="When DelayBetweenRequests is specified, a single item is requested, then a delay of seconds specified with HitRate is made before the next item is requested.<BR>"
    
        $CiRules2 = @()
        foreach ($ciRule in $CiRules)
        {
            $r = new-object PsObject
            $r | add-member -MemberType NoteProperty -Name "Site" -value $($ciRule.Site)
            $r | add-member -MemberType NoteProperty -Name "HitRate" -value $ciRule.HitRate
            $r | add-member -MemberType NoteProperty -Name "Behavior" -value $ciRule.Behavior
            $CiRules2 += $r
        }

        foreach ($ciRule in $CiRules2)
        {
            if ($ciRule.Behavior.value__ -eq 1)
            {
                $CIfinding.WarningMessage +="The crawl for $($ciRule.Site) will be slow because you only crawl 1 item every $($ciRule.HitRate) seconds."
            }
       }
       $CIFinding.InputObject = $CIRules2
       return $CIfinding
    }
}
function Get-SPDiagnosticsSSASearchInstances
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApps
    )

    $problemSearchInstanceColl = @()
    foreach($ssa in $searchApps)
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $ssa -Active
        $topoCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at
        $components = $topoCompList | Select-Object ServerName -Unique
        foreach($searchServer in $components)
        {    
            $serverInstances = Get-SPServiceInstance -Server $searchServer.ServerName | Where-Object{$_.TypeName -eq "SharePoint Server Search" -or $_.TypeName -match "Search Host Controller Service"} | Select-Object @{l="Server";e={$_.Server.Address}}, TypeName, Status, Id
            $problemSearchInstances = $serverInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
            foreach($problemInstance in $problemSearchInstances)
            {
                $problemSearchInstanceColl+=[PSCustomObject]@{
                    SSA = $ssa.DisplayName
                    Server = $problemInstance.Server.ToString()
                    TypeName = $problemInstance.TypeName
                    Status = $problemInstance.Status
                    Id = $problemInstance.Id
                }
            }
        }
    }
    $ssiFinding = New-DiagnosticFinding -Name "'Search\HostController Service' Instances" -InputObject $problemSearchInstanceColl -Format Table

    if($problemSearchInstanceColl.Count -gt 0)
    {
        $ssiFinding.Severity = [SPDiagnostics.Severity]::Critical
        $ssiFinding.WarningMessage = " - One or more 'SearchServiceInstance's or 'HostController Instances' are not online "
        $ssiFinding.Description += " - These Service Instances are critical for search to function properly.<br/> - If these are Disabled or stuck in a state other than 'Online', then we need to try to start them again to bring to a proper state.<br/> - To correct this, consider the following PowerShell command:<br/> <span style='color:#ffd700;'>Start-SPEnterpriseSearchServiceInstance 'serverName'</span>"
    }
    else
    {
        return $null
    }
    return $ssiFinding
}

function Get-SPDiagnosticsSSPJobInstances
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApps
    )

    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $problemSspJobInstanceColl = @()

    foreach($ssa in $searchApps)
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $ssa -Active
        $topoCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at
        $components = $topoCompList | Select-Object ServerName -Unique
        foreach($searchServer in $components)
        {
            #$sspJobServiceInstances = $farm.Servers[$searchServer.ServerName].ServiceInstances | Where-Object {$_.TypeName -like "SSP Job Control*"}
            $sspJobServiceInstances = $farm.Servers[$searchServer.ServerName].ServiceInstances | Where-Object {$_.Service -like "OfficeServerService"}  
            $problemSspJobServers = $sspJobServiceInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
            foreach($problemSspInstance in $problemSspJobServers)
            {
                $problemSspJobInstanceColl+=[PSCustomObject]@{
                    Server = $problemSspInstance.Server.DisplayName.ToLower()
                    TypeName = $problemSspInstance.TypeName
                    Status = $problemSspInstance.Status
                    Id = $problemSspInstance.Id
                }
            }
        }
    }
    $sspJobFinding = New-DiagnosticFinding -Name "'SSP Job Control' Service Instances" -InputObject $problemSspJobInstanceColl -Format Table
    if($problemSspJobInstanceColl.Count -gt 0)
    {

        $sspJobFinding.Severity = [SPDiagnostics.Severity]::Critical
        $sspJobFinding.WarningMessage = " - One or more 'SSP Job Control' Service Instances are not online "
        $sspJobFinding.Description+=(" - These Service Instances are critical for search to function properly. They are responsible for allowing the timer jobs, job-application-server-*, to run.</br> - Those timer jobs 'sync' search related data, so they need to be Online and those jobs need to be running every 1 min.</br> - To get these back 'Online', run the following PowerShell commands: </br> <ul style='color:#ffd700'><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guidOfDisabledInstance')<br>`$obj.Status = 'Online'<br>`$obj.Update()</div></ul>")
        
    }
    else
    {
        return $null
    }
    return $sspJobFinding
}

function Get-SPDiagnosticsCheckForRoot
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApps
    )

    foreach($ssa in $searchApps)
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $ssa -Active
        $topoCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at
        $components = $topoCompList | Select-Object ServerName -Unique
        $cRootCollection = @()
        $cRootFinding = New-DiagnosticFinding -Name "Missing 'root' Folder" -InputObject $null -format Table
        $MissingRoot = $false
        foreach($searchServer in $components)
        {
            $rootDirectory = "\\" + $searchServer.ServerName + "\c$\root" 
            if(Test-Path $rootDirectory)
            {
                # Has the root folder. Add to cRootCollection w/FALSE
                $cRootCollection +=[PSCustomObject]@{
                    Server = $($searchServer.ServerName)
                    "Missing 'C:\Root' " = 'False'
                    SSA = $ssa.DisplayName
                }
            }
            else
            {
                # Flag that we have some missing c:\root folders on search servers
                $MissingRoot = $true
                # Add the missing root server to the collection with TRUE
                $cRootCollection+=[PSCustomObject]@{
                    Server = $($searchServer.ServerName)
                    "Missing 'C:\Root' " = 'True'
                    SSA = $ssa.DisplayName
                }
            }
            }
        # Add the cRootCollection to the cRootFinding
        $cRootFinding.InputObject = $cRootCollection
        if($MissingRoot)
        {
            # We're missing some root findings so set the severity to Critical and set the warning message and description
            $cRootFinding.Severity = [SPDiagnostics.Severity]::Critical
            $cRootFinding.WarningMessage = " - One or more Servers are missing the 'C:\root' folder"
            $cRootFinding.Description += " - Each server in the Search Topology should have the 'c:\root' folder, unless you only have the 'CrawlComponent' on this search server.<br/> - If the 'C:\root' is missing, your SSA will not provision.<br/> - If you are missing this folder, you will need to delete the SSA you tried to create\provision, manually create the 'c:\root' on the server and re-create the SSA.<br/>"
        }
        else
        {
            return $null
        }
    }
    return $cRootFinding
}

function Get-DirectorySizeRecursive ($LiteralPath)
{
    # used by Get-SPDiagnosticsIndexDiskSpace   
    $fullName =  Convert-Path -ErrorAction Stop -LiteralPath $LiteralPath 
    $size = [Linq.Enumerable]::Sum([long[]] (Get-ChildItem -Force -Recurse -File -LiteralPath $fullName).ForEach('Length'))
    $Script:TotalSize += $size
    Get-ChildItem -Force -Directory -LiteralPath $fullName | ForEach-Object { Get-DirectorySizeRecursive -LiteralPath $_.FullName }
}

function Get-SPDiagnosticsIndexDiskSpace ($SearchApplication)
{
    $SSAIndexDiskSpaceFinding = New-DiagnosticFinding -Name "Index Disk space" -InputObject $null -format Table

    $activeTopo = Get-SPEnterpriseSearchTopology -SearchApplication $ssa -active
    $IndexComps = Get-SPEnterpriseSearchComponent -SearchTopology $activeTopo | Where-Object { $_.Name -match "IndexComponent" }
    foreach ($IndexComp in $IndexComps)
    {
        $IndexDiskSpaceInfos = @()
        if ($IndexComp.RootDirectory)
        {
            $IndexLocation = "\\" + $IndexComp.Servername + "\" + $IndexComp.RootDirectory.Replace(":","$")
            $IndexDrive = $IndexComp.RootDirectory.Substring(0,2)
        } else {
           $IndexLocation = "\\"  + $IndexComp.Servername + "\" + $searchApplication.AdminComponent.IndexLocation.Replace(":","$")
        $IndexDrive = $searchApplication.AdminComponent.IndexLocation.Substring(0,2)
        }

        [long]$script:TotalSize = 0
        Get-DirectorySizeRecursive -LiteralPath $IndexLocation       
        $IndexSize= $Script:TotalSize

        $WmiQuery ="select * from win32_LogicalDisk where DriveType=3 and DeviceID ='"+ $Indexdrive +"'"
        $ServerDiskInfo = get-wmiObject -query $WmiQuery  -ComputerName  $IndexComp.Servername
        $sdi = new-object PSObject
        $sdi | Add-Member -MemberType NoteProperty -Name "Computer" -value $($IndexComp.Servername)
        $sdi | Add-Member -MemberType NoteProperty -Name "Drive" -Value $serverDiskInfo.DeviceID
        $sdi | Add-Member -MemberType NoteProperty -Name "VolumeName" -Value $serverDiskInfo.VolumeName
        $sdi | Add-Member -MemberType NoteProperty -Name "Index Location" -Value  $IndexLocation
        $sdi | Add-Member -MemberType NoteProperty -Name "Index Size" -Value $IndexSize.ToString('N0')
        $sdi | Add-Member -MemberType NoteProperty -Name "Size" -Value $serverDiskInfo.Size.ToString('N0')
        $sdi | Add-Member -MemberType NoteProperty -Name "Free Space" -Value $serverDiskInfo.FreeSpace.ToString('N0')
        $sdi | Add-Member -MemberType NoteProperty -Name "Used Space" -Value ($serverDiskInfo.Size - $ServerDiskInfo.FreeSpace).ToString('N0')
        $IndexSizeRatio = [Math]::Round($ServerDiskInfo.FreeSpace / $IndexSize ,1)
        $sdi | Add-Member -MemberType NoteProperty -Name "Free Space / Index Size" -Value $IndexSizeRatio
        $IndexDiskSpaceInfos+=$sdi 

        If ($IndexSizeRatio -lt 1.5)
        {
            $SSAIndexDiskSpaceFinding.WarningMessage +="The disk " + $serverDiskInfo.DeviceID +  "on the server " + $sdi.Computer + " does not have 1.5 x the size of the index as free disk space. This is required for successful master merge of the index."
            $SSAIndexDiskSpaceFinding.Severity= [SPDiagnostics.Severity]::Critical
        } elseif ($IndexSizeRatio -lt 2.5)
        {
            $SSAIndexDiskSpaceFinding.WarningMessage +="The disk " + $serverDiskInfo.DeviceID +  "on the server " + $sdi.Computer + " does not have 2.5 x the size of the index as free disk space. This is required for changing the number of the partitions of the index."
            $SSAIndexDiskSpaceFinding.Severity= [SPDiagnostics.Severity]::Informational
        }    
    }
    $SSAIndexDiskSpaceFinding.InputObject = $IndexDiskSpaceInfos 
    return $SSAIndexDiskSpaceFinding 
}

function Get-SPDiagnosticsSSAEndpoints
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $finding = New-DiagnosticFinding -Name "SSA Endpoints" -InputObject $null -format list
    
    try
    {
        foreach($sqssPt in $searchApplication.Endpoints)
        {
            foreach($sqssEndPoint in $sqssPt.ListenUris)
            {
                $sqssUri = $sqssEndPoint.AbsoluteUri
                
                #$request = $null
                #$request = [System.Net.WebRequest]::Create($sqssUri)
                #$request.UseDefaultCredentials = $true
                $response = $(Invoke-WebRequest -Uri $sqssUri -Method Get -UseBasicParsing).StatusDescription
                #$finding.Description+=("<li>" + $sqssUri.ToString() + " -- " + $response.ToString() + "</li>")

                $server = $sqssUri.ToString().split('/')[2].split(':')[0]
                $findingString=  $sqssUri.ToString()
                $finding.Description+=("<li>" + $findingString + " -- " + $response.ToString() + "</li>")                

            }
        }
        $finding.Description+=("<ul>" + "  Search Service Endpoints Ok" + "</ul>")
    }
    catch
    {
       $finding.Severity = [SPDiagnostics.Severity]::Warning
       $finding.WarningMessage+=("There was a problem reaching:  {0}" -f $($sqssuri) + "</br> " + $_.Exception.Message )
    }

    $searchAdminWs = Get-SPServiceApplication | Where-Object{$_.Name -eq $searchapplication.Id}
    try
    {
        foreach($searchAdminpt in $searchAdminWs.Endpoints)
        {        
            foreach($saEndPoint in $searchAdminpt.ListenUris)
            {
                $searchAdminUri = $saEndPoint.AbsoluteUri
            
                #$request = $null
                #$request = [System.Net.WebRequest]::Create($searchAdminUri)
                #$request.UseDefaultCredentials = $true
                #$response = $request.GetResponse()
                $response = $(Invoke-WebRequest -Uri $searchAdminUri -Method Get -UseBasicParsing).StatusDescription
                #$finding.Description+=("<li>" + $searchAdminUri.ToString() + " -- " + $response.ToString() + "</li>")
               $server = $searchAdminUri.ToString().split('/')[2].split(':')[0]
               $findingString=  $searchAdminUri.ToString()
               $finding.Description+=("<li>" + $findingString + " -- " + $response.ToString() + "</li>")
               
            }
        }
        $finding.Description+=("<ul>" + "  Search Admin Endpoints Ok" + "</ul>")
    }
    catch
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage+=("There was a problem reaching:  {0}" -f $searchAdminURI + "</br> " + $_.Exception.Message )
    }
    

    return $finding

}

    # ------------------------------------------------------------------------------------------------------------------
    # VerifyHostControllerRepository: Verify that Host Controller HA (for dictionary repository) is OK
    # ------------------------------------------------------------------------------------------------------------------
    # Verify that Host Controller HA (for dictionary repository) is OK:
    #$VerifyHostControllerRepositoryFindings = VerifyHostControllerRepository
    #if($VerifyHostControllerRepositoryFindings)
    #{
    #    $searchFindings.ChildFindings.Add($VerifyHostControllerRepositoryFindings)
    #}
Function VerifyHostControllerRepository
{
        $VerifyHostControllerRepositoryFinding =  New-DiagnosticFinding -Name "Host Controller Repository" -Severity Default -InputObject $null -format Table

        $highestRepVer = 0
        $hostControllers = 0
        $primaryRepVer = -1
        $hcStat = @()
        $hcs = Get-SPEnterpriseSearchHostController
        foreach ($hc in $hcs)
        {
            $hostControllers += 1
            $repVer = $hc.RepositoryVersion
            $serverName = $($hc.Server.Name)
            if ($repVer -gt $highestRepVer)
            {
                $highestRepVer = $repVer
            }
            if ($hc.PrimaryHostController)
            {
                $primaryHC = $($hc.Server.Name)
                $primaryRepVer = $repVer
            }
            if ($repVer -ne -1)
            {
                $hcStat += "        $serverName : $repVer"
            }
        }

        if ($hostControllers -ge 1)
        {
            $SHCS = @()
            foreach ($hcss in $hcs)
            {
                $shc = new-object psobject
                $shc | Add-Member -MemberType NoteProperty -Name "Server" -Value  $($Hcss.Server.Name)
                $shc | Add-Member -MemberType NoteProperty -Name "PrimaryHostController" -Value $hcss.PrimaryHostController
                $shc | Add-Member -MemberType NoteProperty -Name "Status" -Value $hcss.Status
                $shc | Add-Member -MemberType NoteProperty -Name "ID" -Value $hcss.ID
                $shc | Add-Member -MemberType NoteProperty -Name "RepositoryVersion" -Value $hcss.RepositoryVersion
                $SHCS += $shc
            }

            $VerifyHostControllerRepositoryFinding.Description += "Primary search host controller (for dictionary repository): <strong>$primaryHC</strong>"
            $VerifyHostControllerRepositoryFinding.Description += " - The Host Controller Repository is the search configuration and linguistic resources repository maintained by the SharePoint Search Host Controller service. </br>- Its role is to distribute and synchronize the files and metadata required for search components (especially language-processing resources) across all search servers in the farm, ensuring consistent search behavior and search component management."
            $VerifyHostControllerRepositoryFinding.InputObject = ($SHCS | select-object Server, PrimaryHostController, Status, Id, RepositoryVersion | Sort-Object PrimaryHostController -Descending)
            
            if ($primaryRepVer -eq -1)
            {
                $script:serviceDegraded = $true
                $VerifyHostControllerRepositoryFinding.Severity = [SPDiagnostics.Severity]::Warning
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Warning: Primary host controller is not available"
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Recommended action: Restart server or set new primary host controller using Set-SPEnterpriseSearchPrimaryHostController"

                $hcstatfindings =  New-DiagnosticFinding -Name "Repository version for existing host controllers" -Severity Default -InputObject $hcstatfindings -format table
                $VerifyHostControllerRepositoryFinding.ChildFindings.Add($hcstatfindings)

            }
            elseif ($primaryRepVer -lt $highestRepVer)
            {
                $script:serviceDegraded = $true
                $VerifyHostControllerRepositoryFinding = [SPDiagnostics.Severity]::Warning
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Warning: Primary host controller does not have the latest repository version"
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Primary host controller repository version: $primaryRepVer "
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Latest repository version: $highestRepVer "
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Recommended action: Set new primary host controller using Set-SPEnterpriseSearchPrimaryHostController"

                $hcstatfindings =  New-DiagnosticFinding -Name "Repository version for existing host controllers" -Severity Default -InputObject $hcstatfindings -format table
                $VerifyHostControllerRepositoryFinding.ChildFindings.Add($hcstatfindings)
            }
            return $VerifyHostControllerRepositoryFinding            
        }

        return $null
    }

#endregion

#region HealthCheck

# ----------------------------------------------------------------------------------------------------------------------
# Search System / Master Merge Diagnostics
# ----------------------------------------------------------------------------------------------------------------------
# The three functions below reproduce - natively, with no dependency on the SRx module - the two tables that the
# SRx "Get-SRxIndexReports -ssa $xssa -DiskReport" command prints:
#     "Indexing System Diagnostics"  and  "Master Merge Diagnostics"
# All per-replica values come from Get-SPEnterpriseSearchStatus -HealthReport (the same plugin-health entries SRx
# parses) plus the on-disk index-size / free-space pattern already used by Get-SPDiagnosticsIndexDiskSpace.
# ----------------------------------------------------------------------------------------------------------------------

function Format-SPSearchIndexSize
{
    # Formats a byte count using the supplied size decorator (GB/MB/KB) as "{N0} {unit}".
    # Any non-numeric value (e.g. the literal string 'Unknown' or $null) is passed through as "Unknown",
    # mirroring how SRx renders index/disk values that could not be collected.
    param(
        $Bytes,
        [ValidateSet("GB","MB","KB")][string]$Decorator = "MB"
    )

    if ($null -eq $Bytes -or $Bytes -is [string]) { return "Unknown" }

    switch ($Decorator)
    {
        "GB"    { $unit = 1GB }
        "KB"    { $unit = 1KB }
        default { $unit = 1MB }
    }
    return ("{0:N0} {1}" -f ($Bytes / $unit), $Decorator)
}

function New-SPSearchIndexDiagFinding
{
    # Pure renderer: projects the per-replica objects produced by Get-SPSearchIndexReplicaReport into a parent
    # finding that holds two Table child findings mirroring the SRx report. Kept free of any SharePoint calls so
    # it can be unit-tested / previewed with mock data.
    param(
        [Parameter(Mandatory=$true)]
        $Replicas,

        [ValidateSet("GB","MB","KB")]
        [string]$SizeDecorator = "MB"
    )

    $replicaArray = @($Replicas)
    if ($replicaArray.Count -eq 0) { return $null }

    # ---- Indexing System Diagnostics (docs / generation / merge state - no disk access required) ----
    $systemRows = @()
    foreach ($r in $replicaArray)
    {
        $systemRows += [pscustomobject][ordered]@{
            "ServerName"  = $r.ServerName
            "Name"        = $r.Name
            "Cell"        = $r.Cell
            "Part"        = $r.Part
            "State"       = $r.State
            "Primary"     = $r.Primary
            "Generation"  = ("{0:N0}" -f [long]$r.Generation)
            "Docs(+dups)" = ("{0:N0}" -f [long]$r.TotalDocs)
            "Searchable"  = ("{0:N0}" -f [long]$r.ActiveDocs)
            "AvgDoc"      = $(if ($r.AvgDocSize -is [string]) { "Unknown" } else { ("{0:N0} KB" -f ($r.AvgDocSize / 1KB)) })
            "Merging"     = $r.Merging
            "Checkpoint"  = (Format-SPSearchIndexSize -Bytes $r.CheckpointSize -Decorator $SizeDecorator)
        }
    }
    $systemFinding = New-DiagnosticFinding -Name "Indexing System Diagnostics" -Severity Default -InputObject $systemRows -Format Table

    # ---- Master Merge Diagnostics (checkpoint + disk-based master-merge size estimates) ----
    $mergeRows = @()
    foreach ($r in $replicaArray)
    {
        $mergeRows += [pscustomobject][ordered]@{
            "ServerName"   = $r.ServerName
            "Name"         = $r.Name
            "Cell"         = $r.Cell
            "Part"         = $r.Part
            "Checkpoint"   = (Format-SPSearchIndexSize -Bytes $r.CheckpointSize -Decorator $SizeDecorator)
            "Index Files"  = (Format-SPSearchIndexSize -Bytes $r.FileSize       -Decorator $SizeDecorator)
            "MM (Est.)"    = (Format-SPSearchIndexSize -Bytes $r.EstMMTotal      -Decorator $SizeDecorator)
            "MM (Pending)" = (Format-SPSearchIndexSize -Bytes $r.EstMMPending    -Decorator $SizeDecorator)
            "Free Space"   = (Format-SPSearchIndexSize -Bytes $r.FreeSpace       -Decorator $SizeDecorator)
            "%(MM/Free)"   = $(if ($r.PctMMFree -is [string]) { "Unknown" } else { ("{0:N2} %" -f [decimal]$r.PctMMFree) })
        }
    }
    $mergeFinding = New-DiagnosticFinding -Name "Master Merge Diagnostics" -Severity Default -InputObject $mergeRows -Format Table

    # A master merge can fail and bloat the index if the index volume does not have at least 1.5x the
    # checkpoint size in free space. Flag any reachable replica that falls below that threshold.
    foreach ($r in $replicaArray)
    {
        if (($r.CheckpointSize -isnot [string]) -and ([long]$r.CheckpointSize -gt 0) -and ($r.FreeSpace -isnot [string]))
        {
            $requiredFree = [long](1.5 * [long]$r.CheckpointSize)
            if ([long]$r.FreeSpace -lt $requiredFree)
            {
                $ratio = [math]::Round(([long]$r.FreeSpace / [long]$r.CheckpointSize), 2)
                # Below 1x the checkpoint a master merge cannot complete (Critical); 1x-1.5x is at risk (Warning).
                if ([long]$r.FreeSpace -lt [long]$r.CheckpointSize) { $mergeFinding.Severity = [SPDiagnostics.Severity]::Critical }
                else { $mergeFinding.Severity = [SPDiagnostics.Severity]::Warning }
                $mergeFinding.WarningMessage += ("{0} ({1}): index volume free space is {2}, but a master merge needs at least 1.5x the checkpoint ({3}). Only {4}x the checkpoint is free - a master merge may fail and bloat the index." -f `
                    $r.ServerName, $r.Name, `
                    (Format-SPSearchIndexSize -Bytes $r.FreeSpace -Decorator $SizeDecorator), `
                    (Format-SPSearchIndexSize -Bytes $requiredFree -Decorator $SizeDecorator), `
                    $ratio)
            }
        }
    }

    $parent = New-DiagnosticFinding -Name "Indexing System and Master Merge Diagnostics" -Severity Default -InputObject $null -Format List -ReferenceLink "https://learn.microsoft.com/en-us/sharepoint/search/manage-the-search-index"
    $parent.Description += "Per index-replica system diagnostics and master-merge disk estimates, ported from the SRx Get-SRxIndexReports report (Indexing System Diagnostics and Master Merge Diagnostics sections)."
    $parent.ChildFindings.Add($systemFinding)
    $parent.ChildFindings.Add($mergeFinding)
    return $parent
}

function Get-SPSearchIndexReplicaReport
{
    # Collects per index-replica diagnostics for the given SSA (the raw data behind the two tables above).
    # Docs/generation/checkpoint/merge state come from Get-SPEnterpriseSearchStatus -HealthReport; on-disk index
    # size and volume free space use the same UNC + win32_LogicalDisk approach as Get-SPDiagnosticsIndexDiskSpace.
    # Any disk value that cannot be collected (server/path unreachable) degrades to the string 'Unknown'.
    param(
        [Parameter(Mandatory=$true)]
        $SearchApplication,

        [Parameter(Mandatory=$true)]
        $ComponentStateList,

        [Parameter(Mandatory=$false)]
        $TopologyComponentList
    )

    # SP2013 stores the checkpoint health value in bytes and needs a 2.5x master-merge overhead factor;
    # SP2016+ stores it in MB and needs only ~1.5x.
    $isSP2016OrLater = $true
    try { $isSP2016OrLater = ([Microsoft.SharePoint.Administration.SPFarm]::Local.BuildVersion.Major -ge 16) } catch { $isSP2016OrLater = $true }

    # ServerName, IndexPartitionOrdinal and RootDirectory live on the topology COMPONENT objects
    # (Get-SPEnterpriseSearchComponent) - NOT on the status objects (Get-SPEnterpriseSearchStatus), which
    # only carry Name/State/Details. Build a Name -> component lookup so we can join them.
    if ($null -eq $TopologyComponentList)
    {
        try
        {
            $activeTopo = Get-SPEnterpriseSearchTopology -SearchApplication $SearchApplication -Active -ErrorAction SilentlyContinue
            $TopologyComponentList = Get-SPEnterpriseSearchComponent -SearchTopology $activeTopo -ErrorAction SilentlyContinue
        }
        catch { $TopologyComponentList = @() }
    }
    $componentByName = @{}
    foreach ($tc in $TopologyComponentList) { if ($tc.Name) { $componentByName[$tc.Name] = $tc } }

    $replicas = @()

    foreach ($comp in $ComponentStateList)
    {
        if ($comp.Name -notmatch "Index") { continue }
        if ($comp.Name -match "Cell")     { continue }
        if ($comp.State -match "Unknown" -or $comp.State -match "Registering") { continue }

        $componentName = $comp.Name
        $topoComp      = $componentByName[$componentName]

        # ServerName / partition / RootDirectory come from the matching topology component object
        $serverName = $null
        $partition  = $null
        $rootDir    = $null
        if ($topoComp)
        {
            $serverName = $topoComp.ServerName
            $partition  = $topoComp.IndexPartitionOrdinal
            $rootDir    = $topoComp.RootDirectory
        }
        # Fall back to the status object's Details dictionary if the component wasn't matched
        if ([string]::IsNullOrEmpty($serverName) -and $comp.Details) { try { if ($comp.Details["Host"]) { $serverName = $comp.Details["Host"] } } catch {} }
        if (($null -eq $partition) -and $comp.Details) { try { if ($comp.Details["Partition"]) { $partition = $comp.Details["Partition"] } } catch {} }

        # ----- Plugin health report for this index replica -----
        $health = $null
        try { $health = Get-SPEnterpriseSearchStatus -SearchApplication $SearchApplication -HealthReport -Component $componentName -ErrorAction SilentlyContinue } catch { $health = $null }

        $generation = 0
        $checkpoint = 0
        $totalDocs  = 0
        $activeDocs = 0
        $merging    = $false
        $cellNumber = "?"

        if ($health)
        {
            $genEntry = $health | Where-Object { $_.Name -and $_.Name.StartsWith("plugin: newest generation id") } | Select-Object -First 1
            if ($genEntry) { $generation = [long]$genEntry.Message }

            $cpEntry = $health | Where-Object { $_.Name -and $_.Name.StartsWith("plugin: size of newest checkpoint") } | Select-Object -First 1
            if ($cpEntry)
            {
                if ($isSP2016OrLater) { $checkpoint = [long]$cpEntry.Message * 1MB } else { $checkpoint = [long]$cpEntry.Message }
            }

            $totalDocs = ($health | Where-Object { $_.Name -and $_.Name.StartsWith("part: number of documents including duplicate") } | ForEach-Object { [long]$_.Message } | Measure-Object -Sum).Sum
            if ($null -eq $totalDocs) { $totalDocs = 0 }

            $adEntry = $health | Where-Object { $_.Name -and $_.Name.StartsWith("plugin: number of documents") } | Select-Object -First 1
            if ($adEntry) { $activeDocs = [long]$adEntry.Message }

            $mmEntry = $health | Where-Object { $_.Name -and $_.Name.StartsWith("plugin: master merge running") } | Select-Object -First 1
            if ($mmEntry) { $merging = ($mmEntry.Message.ToString().ToLower() -eq 'true') }

            $initEntry = $health | Where-Object { $_.Name -and $_.Name.StartsWith("plugin: initialized[SP") } | Select-Object -First 1
            if ($initEntry)
            {
                $parts = $initEntry.Name -split '\.'
                if ($parts.Count -ge 3) { $cellNumber = $parts[2] }
            }
        }

        if ([string]::IsNullOrEmpty($cellNumber)) { $cellNumber = "?" }
        $cellName = "[I.{0}.{1}]" -f $cellNumber, $partition

        $avgDocSize = if ([long]$totalDocs -gt 0) { [long][math]::Ceiling($checkpoint / [long]$totalDocs) } else { 0 }

        # ----- Primary replica flag: read from the status object's Details dictionary (SRx's _JunoDetails.Primary),
        #       falling back to the -Primary -Component query if Details is unavailable -----
        $primary = $false
        $primaryResolved = $false
        if ($comp.Details)
        {
            try
            {
                foreach ($kv in $comp.Details.GetEnumerator())
                {
                    if ($kv.Key -ieq 'Primary')
                    {
                        $primary = ($kv.Value.ToString().ToLower() -eq 'true')
                        $primaryResolved = $true
                        break
                    }
                }
            }
            catch { $primaryResolved = $false }
        }
        if (-not $primaryResolved)
        {
            try { if (Get-SPEnterpriseSearchStatus -SearchApplication $SearchApplication -Primary -Component $componentName -ErrorAction SilentlyContinue) { $primary = $true } } catch { $primary = $false }
        }

        # ----- Best-effort on-disk index size + volume free space (same approach as Get-SPDiagnosticsIndexDiskSpace) -----
        $fileSize  = 'Unknown'
        $freeSpace = 'Unknown'
        try
        {
            if ([string]::IsNullOrEmpty($rootDir)) { $rootDir = $SearchApplication.AdminComponent.IndexLocation }
            if (-not [string]::IsNullOrEmpty($rootDir))
            {
                $indexUnc   = "\\" + $serverName + "\" + $rootDir.Replace(":","$")
                $indexDrive = $rootDir.Substring(0,2)

                if (Test-Path $indexUnc)
                {
                    [long]$script:TotalSize = 0
                    Get-DirectorySizeRecursive -LiteralPath $indexUnc
                    $fileSize = [long]$script:TotalSize
                }

                $wmiQuery = "select * from win32_LogicalDisk where DriveType=3 and DeviceID ='" + $indexDrive + "'"
                $disk = Get-WmiObject -Query $wmiQuery -ComputerName $serverName -ErrorAction SilentlyContinue
                if ($disk -and $disk.FreeSpace) { $freeSpace = [long]$disk.FreeSpace }
            }
        }
        catch
        {
            $fileSize  = 'Unknown'
            $freeSpace = 'Unknown'
        }

        # ----- Master-merge size estimates (SRx formula) -----
        $estMMTotal   = 'Unknown'
        $estMMPending = 'Unknown'
        $pctMMFree    = 'Unknown'
        if ($checkpoint -gt 0)
        {
            $overhead = if ($isSP2016OrLater) { $checkpoint * 0.5 } else { $checkpoint * 1.5 }
            # SP2013 worst-case: if not merging and the on-disk index already exceeds the overhead, use the file size
            if ((-not $isSP2016OrLater) -and ($fileSize -isnot [string]) -and (-not $merging) -and ($fileSize -gt $overhead)) { $overhead = $fileSize }
            $estMMTotal = [long]($checkpoint + $overhead)

            if ($fileSize -isnot [string])
            {
                $pending = $estMMTotal - $fileSize
                if ($pending -le 0) { $estMMPending = 'Unknown' } else { $estMMPending = [long]$pending }
            }

            if (($freeSpace -isnot [string]) -and ($estMMPending -isnot [string]) -and ([long]$freeSpace -gt 0))
            {
                $pctMMFree = [decimal]::Round(($estMMPending / $freeSpace), 4) * 100
            }
        }

        $replicas += [pscustomobject]@{
            ServerName     = $serverName
            Name           = $componentName
            Cell           = $cellName
            Part           = $partition
            State          = $comp.State
            Primary        = $primary
            Generation     = $generation
            TotalDocs      = $totalDocs
            ActiveDocs     = $activeDocs
            AvgDocSize     = $avgDocSize
            Merging        = $merging
            CheckpointSize = $checkpoint
            FileSize       = $fileSize
            FreeSpace      = $freeSpace
            EstMMTotal     = $estMMTotal
            EstMMPending   = $estMMPending
            PctMMFree      = $pctMMFree
        }
    }

    return $replicas
}

function Get-SPDiagnosticsSearchHealthCheck()
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )

    $script:ssa = $searchApplication

    # ------------------------------------------------------------------------------------------------------------------
    # GetCrawlStatus: Get crawl status
    # ------------------------------------------------------------------------------------------------------------------
    Function GetCrawlStatus
    {
        try 
        {
            if ($script:ssa.Ispaused())
            {
                switch ($script:ssa.Ispaused()) 
                { 
                    1       { $pauseReason = "ongoing search topology operation" } 
                    2       { $pauseReason = "backup/restore" } 
                    4       { $pauseReason = "backup/restore" } 
                    32      { $pauseReason = "crawl DB re-factoring" } 
                    64      { $pauseReason = "link DB re-factoring" } 
                    128     { $pauseReason = "external reason (user initiated)" } 
                    256     { $pauseReason = "index reset" } 
                    512     { $pauseReason = "index re-partitioning (query is also paused)" } 
                    default { $pauseReason = "multiple reasons ($($script:ssa.Ispaused()))" } 
                }
                $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name $script:ssa.Name -Value "Paused for $pauseReason"
            }
            else
            {
                $crawling = $false
                $contentSources = Get-SPEnterpriseSearchCrawlContentSource -SearchApplication $script:ssa -ErrorAction SilentlyContinue
                if ($contentSources) 
                {
                    foreach ($source in $contentSources)
                    {
                        if ($source.CrawlState -ne "Idle")
                        {
                            $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawling $($source.Name)" -Value $source.CrawlState
                            $crawling = $true
                        }
                    }
                    if (!$crawling)
                    {
                        $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawler" -Value "Crawler is Idle"
                    }
                }
                else
                {
                    $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawler" -Value "No content sources found"
                }
            }
        } 
        catch
        {
            $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawler" -Value "Crawler is down" 
        }
    }

    # ------------------------------------------------------------------------------------------------------------------
    # GetTopologyInfo: Get basic topology info and component health status
    # ------------------------------------------------------------------------------------------------------------------
    Function GetTopologyInfo
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $script:ssa -Active
        $script:topologyCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at | Sort-Object Name

        # Check if topology is prepared for HA
        $adminFound = $false
        foreach ($searchComp in ($script:topologyCompList))
        {
            if ($searchComp.Name -match "Admin")
            { 
                if ($adminFound) 
                { 
                    $script:haTopology = $true 
                } 
                else
                {
                    $adminFound = $true
                }
            }
        }    

        #
        # Get topology component state:
        #
        $script:componentStateList = Get-SPEnterpriseSearchStatus -SearchApplication $script:ssa -ErrorAction SilentlyContinue | Sort-Object Name

        # Find the primary admin component:
        foreach ($component in ($script:componentStateList))
        {
            if (($component.Name -match "Admin") -and ($component.State -ne "Unknown"))
            {
                if (Get-SPEnterpriseSearchStatus -SearchApplication $script:ssa -Primary -Component $($component.Name) -ErrorAction Continue)
                {
                    $script:primaryAdmin = $component.Name
                }
            }
        }    
        if (!$script:primaryAdmin)
        {
            Write-Host "Search component health state check failed. Recommended action: Ensure that at least one admin component is operational."
        }
    }

    # ------------------------------------------------------------------------------------------------------------------
    # PopulateHostHaList: For each component, determine properties and update $script:hostArray / $script:haArray
    # ------------------------------------------------------------------------------------------------------------------
    Function PopulateHostHaList($searchComp)
    {
        if ($searchComp.ServerName)
        {
            $hostName = $searchComp.ServerName
        }
        else
        {
            $hostName = "Unknown server"
        }
        $partition = $searchComp.IndexPartitionOrdinal
        $newHostFound = $true
        $newHaFound = $true
        $entity = $null

        foreach ($searchHost in ($script:hostArray))
        {
            if ($searchHost.hostName -eq $hostName)
            {
                $newHostFound = $false
            }
        }
        if ($newHostFound)
        {
            # Add the host to $script:hostArray
            $hostTemp = $script:hostTemplate | Select-Object *
            $hostTemp.hostName = $hostName
            $script:hostArray += $hostTemp
            $script:searchHosts += 1
        }

        # Fill in component specific data in $script:hostArray
        foreach ($searchHost in ($script:hostArray))
        {
            if ($searchHost.hostName -eq $hostName)
            {
                $partition = -1
                if ($searchComp.Name -match "Query") 
                { 
                    $entity = "QueryProcessingComponent" 
                    $searchHost.qpc = "QueryProcessing "
                    $searchHost.components += 1
                }
                elseif ($searchComp.Name -match "Content") 
                { 
                    $entity = "ContentProcessingComponent" 
                    $searchHost.cpc = "ContentProcessing "
                    $searchHost.components += 1
                }
                elseif ($searchComp.Name -match "Analytics") 
                { 
                    $entity = "AnalyticsProcessingComponent" 
                    $searchHost.apc = "AnalyticsProcessing "
                    $searchHost.components += 1
                }
                elseif ($searchComp.Name -match "Admin") 
                { 
                    $entity = "AdminComponent" 
                    if ($searchComp.Name -eq $script:primaryAdmin)
                    {
                        $searchHost.pAdmin = "Admin(Primary) "
                    }
                    else
                    {
                        $searchHost.sAdmin = "Admin "
                    }
                    $searchHost.components += 1
                }
                elseif ($searchComp.Name -match "Crawl") 
                { 
                    $entity = "CrawlComponent" 
                    $searchHost.crawler = "Crawler "
                    $searchHost.components += 1
                }
                elseif ($searchComp.Name -match "Index") 
                { 
                    $entity = "IndexComponent"
                    $partition = $searchComp.IndexPartitionOrdinal
                    $searchHost.index = "IndexPartition($partition) "
                    $searchHost.components += 1
                }
            }
        }

        # Fill in component specific data in $script:haArray
        foreach ($haEntity in ($script:haArray))
        {
            if ($haEntity.entity -eq $entity)
            {
                if ($entity -eq "IndexComponent")
                {
                    if ($haEntity.partition -eq $partition)
                    {
                        $newHaFound = $false
                    }
                }
                else 
                { 
                    $newHaFound = $false
                }
            }
        }
        if ($newHaFound)
        {
            # Add the HA entities to $script:haArray
            $haTemp = $script:haTemplate | Select-Object *
            $haTemp.entity = $entity
            $haTemp.components = 1
            if ($partition -ne -1) 
            { 
                $haTemp.partition = $partition 
            }
            $script:haArray += $haTemp
        }
        else
        {
            foreach ($haEntity in ($script:haArray))
            {
                if ($haEntity.entity -eq $entity) 
                {
                    if (($entity -eq "IndexComponent") )
                    {
                        if ($haEntity.partition -eq $partition)
                        {
                            $haEntity.components += 1
                        }
                    }
                    else
                    {
                        $haEntity.components += 1
                        if (($haEntity.entity -eq "AdminComponent") -and ($searchComp.Name -eq $script:primaryAdmin))
                        {
                            $haEntity.primary = $script:primaryAdmin
                        }
                    }
                }
            }
        }
    }

    # ------------------------------------------------------------------------------------------------------------------
    # AnalyticsStatus: Output status of analytics jobs
    # ------------------------------------------------------------------------------------------------------------------
    Function AnalyticsStatus
    {
        $AnalyticsStatusFindings = New-DiagnosticFinding -Name "Analytics Processing Job Status" -Severity Default -InputObject $null
        $analyticsStatus = Get-SPEnterpriseSearchStatus -SearchApplication $script:ssa -JobStatus -ErrorAction SilentlyContinue | Where-Object{$_.Name -ne "Not Available"}

        foreach ($analyticsEntry in $analyticsStatus)
        {
            $AnalyticsEntryFindings = New-DiagnosticFinding -Name $analyticsEntry.Name -Severity Default -InputObject $null -Format List

            $retObj = [PSCustomObject]@{
                Name = $analyticsEntry.Name
            }

            if ($analyticsEntry.Name -ne "Not available" -or $script:debug -eq $true)     
            {
                foreach ($details in ($analyticsEntry.Details))
                {
                    if ($details.Key -eq "Status")
                    {
                        $status = $details.Value
                    }
                }
                $retObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $status	
            }
            
            # Output additional diagnostics from the dictionary
            foreach ($details in ($analyticsEntry.Details))
            {
                # Skip entries that are listed as Not Available
                if ( ($details.Value -ne "Not available") -and ($details.Key -ne "Activity") -and ($details.Key -ne "Status") )
                {
                    $retObj | Add-Member -MemberType NoteProperty -Name $details.Key -Value $details.Value	

                    if ($details.Key -match "Last successful start time")
                    {
                        # Just passing in a current DateTime for TryParse method requirement
                        $dateLast = Get-Date

                        # Use ParseDateTime. This is required to support ShortDate formats that some customers use
                        # We have to do this because the details value is ALWAYS in the format of MM/DD/YYYY HH:MM:SS
                        if([System.DateTime]::TryParse($details.Value, [System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::None, [ref]$dateLast))
                        {
                            $dateNow = Get-Date

                            # While this seems redundant, when using alternate date formast from MM/DD/YYYY  on OS, this is required to ensure both dateLast and dateNow follow the same format
                            if([System.DateTime]::TryParse($dateNow.Value, [System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::None, [ref]$dateNow))
                            {
                                # Use DateTime subtraction to get a timespan. Previous method used DayOfYear which isn't a valid comparison between dates that span different years
                                $daysSinceLastSuccess = $dateNow - $dateLast

                                if ($daysSinceLastSuccess.Days -gt 3)
                                {
                                    $AnalyticsEntryFindings.Severity = [SPDiagnostics.Severity]::Warning
                                    $AnalyticsEntryFindings.WarningMessage += "Warning: More than three days since last successful run"
                                    $script:serviceDegraded = $true                        
                                }
                            }
                        }
                    }
                }
            }
            $AnalyticsEntryFindings.InputObject = $retObj

            $AnalyticsStatusFindings.ChildFindings.Add($AnalyticsEntryFindings)
        }
        return $AnalyticsStatusFindings
    }

    # ------------------------------------------------------------------------------------------------------------------
    # SearchComponentStatus: Analyze the component status for one component
    # ------------------------------------------------------------------------------------------------------------------
    Function SearchComponentStatus($component)
    {
        #$SearchComponentStatusDiagnosticsFinding = New-DiagnosticFinding -Name "Search Component Status" -Severity Default -InputObject $null -format List
        # Find host name
        $compTemp = $script:compTemplate | Select-Object *
        foreach($searchComp in ($script:topologyCompList))
        {
            if ($searchComp.Name -eq $component.Name)
            {
                $compTemp.ComponentId = $searchComp.ComponentId
                $compTemp.ServerId = $searchComp.ServerId
                if($searchComp.Name -match "IndexComp")
                {
                    if(!$searchComp.RootDirectory)
                    {
                        $cellName = "Cell:" + $searchComp.Name + "-"
                        $cellPath = $($script:componentStateList | where-object{$_.Name -match $cellName}).Name
                        $indexPath = "<" + "DataDirectoryPath" + ">" + "\" + $cellPath.Split("-")[1]
                        $compTemp.RootDirectory = $indexPath
                    }
                    else
                    {
                        $cellName = "Cell:" + $searchComp.Name + "-"
                        $cellPath = $($script:componentStateList | where-object{$_.Name -match $cellName}).Name
                        $indexPath = $searchComp.RootDirectory + "\" + $cellPath.Split("-")[1]
                        $compTemp.RootDirectory = $indexPath
                    }
                    
                }
                if ($searchComp.ServerName)
                {
                    $hostName = $searchComp.ServerName
                }
                else
                {
                    $hostName = "No server associated with this component. The server may have been removed from the farm."
                }
            }
        }
        if ($component.State -ne "Active" -or $script:debug -eq $true)
        {
            # String with all components that is not active:
            if ($component.State -eq "Unknown")
            {
                $script:unknownComponents += "$hostName - " +  "$($component.Name): $($component.State)"
            }
            elseif ($component.State -eq "Degraded")
            {
                $script:degradedComponents += "$hostName - " +  "$($component.Name):$($component.State)"
            }
            else
            {
                $script:failedComponents += "$hostName - " +  "$($component.Name):$($component.State)"
            }
            $script:serviceDegraded = $true
        }
        
        # Skip unnecessary info about cells and partitions if everything is fine
        $outputEntry = $true
        $retObj = [PSCustomObject]@{
        }
        # Indent the cell info, logically belongs to the component. 
        if ($component.Name -match "Cell")
        {
            if ($component.State -eq "Active" -and $script:debug -eq $false)
            {
                $outputEntry = $false
            }
            else
            {
                $retObj | Add-Member -MemberType NoteProperty -Name "Cell" -Value $component.Name	
            }
        }
        elseif ($component.Name -match "Partition")
        {
            if ($component.State -eq "Active" -and $script:debug -eq $false)
            {
                $outputEntry = $false
            }
            else
            {
                $retObj | Add-Member -MemberType NoteProperty -Name "Index" -Value $component.Name	
            }
        }
        else
        {
            # State for search components
            $primaryString = ""
            if ($component.Name -match "Query") { $entity = "QueryProcessingComponent" }
            elseif ($component.Name -match "Content") { $entity = "ContentProcessingComponent" }
            elseif ($component.Name -match "Analytics") { $entity = "AnalyticsProcessingComponent" }
            elseif ($component.Name -match "Crawl") { $entity = "CrawlComponent" }
            elseif ($component.Name -match "Admin") 
            { 
                $entity = "AdminComponent" 
                if ($script:haTopology)
                {
                    if ($component.Name -eq $script:primaryAdmin)
                    {
                        $primaryString = " (Primary)"
                    }
                }
            }
            elseif ($component.Name -match "Index") 
            { 
                $entity = "IndexComponent"
                foreach ($searchComp in ($script:topologyCompList))
                {
                    if ($searchComp.Name -eq $component.Name) 
                    {
                        $partition = $searchComp.IndexPartitionOrdinal
                    }
                }
                # find info about primary role
                foreach ($de in ($component.Details))
                {
                    if ($de.Key -eq "Primary")
                    {
                        if ($de.Value -eq "True")
                        {
                            $primaryString = " (Primary)"
                            foreach ($haEntity in ($script:haArray))
                            {
                                if (($haEntity.entity -eq $entity) -and ($haEntity.partition -eq $partition))
                                {
                                    $haEntity.primary = $component.Name

                                }
                            }                        
                        }
                    }
                }
            }
            foreach ($haEntity in ($script:haArray))
            {
                if ( ($haEntity.entity -eq $entity) -and ($component.State -eq "Active") )
                {
                    if ($entity -eq "IndexComponent")
                    {
                        if ($haEntity.partition -eq $partition)
                        {
                            $haEntity.componentsOk += 1
                        }
                    }
                    else 
                    { 
                        $haEntity.componentsOk += 1
                    }
                }
            }
            # Add the component entities to $script:compArray for output formatting
            
            $compTemp.Component = "$($component.Name)$primaryString"
            $compTemp.Server = $hostName
            $compTemp.State = $component.State

            if ($partition -ne -1 -and $compTemp.Component -match "Index") 
            { 
                $compTemp.Partition = $partition
            }

            $script:compArray += $compTemp

            if ($component.State -eq "Active")
            {
                $outputEntry = $false
            }
            else
            {
                $retObj | Add-Member -MemberType NoteProperty -Name "Component" -Value $component.Name	
            }
            
        }
        if ($outputEntry)
        {
            #$SearchComponentStatusDiagnosticsFinding.Severity = [SPDiagnostics.Severity]::Warning

            if ($component.State)
            {
                $retObj | Add-Member -MemberType NoteProperty -Name "State" -Value $component.State	
            }
            if ($hostName)
            {
                $retObj | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname	
            }
            if ($component.Message)
            {
                $retObj | Add-Member -MemberType NoteProperty -Name "Message" -Value $component.Message	
            }
        
            # Output additional diagnostics from the dictionary
            foreach ($de in ($component.Details))
            {
                if ($de.Key -ne "Host")
                {
                    $retObj | Add-Member -MemberType NoteProperty -Name $de.Key -Value $de.Value
                }
            }
            if ($script:haTopology)
            {
                if ($component.Name -eq $script:primaryAdmin)
                {
                    $retObj | Add-Member -MemberType NoteProperty -Name "Primary" -Value $true
                }
                elseif ($component.Name -match "Admin")
                {
                    $retObj | Add-Member -MemberType NoteProperty -Name "Primary" -Value $false
                }
            }

            return $retObj
            #$SearchComponentStatusDiagnosticsFinding.InputObject = $retObj
            #return $SearchComponentStatusDiagnosticsFinding
        }

        return $null
        
    }

    # ------------------------------------------------------------------------------------------------------------------
    # DetailedIndexerDiag: Output selected info from detailed component diag
    # ------------------------------------------------------------------------------------------------------------------
    Function DetailedIndexerDiag
    {
        $indexerInfo = @()
        $generationInfo = @()
        $generation = 0
        $DetailedIndexerDiagFinding = New-DiagnosticFinding -Name "Detailed Component Diag" -Severity Default -InputObject $null -format List

        foreach ($searchComp in ($script:componentStateList))
        {
            $component = $searchComp.Name

            if ( (($component -match "Index") -or ($component -match "Content") -or ($component -match "Admin")) -and ($component -notmatch "Cell") -and ($searchComp.State -notmatch "Unknown") -and ($searchComp.State -notmatch "Registering"))
            {

                $pl=Get-SPEnterpriseSearchStatus -SearchApplication $script:ssa -HealthReport -Component $component
                foreach ($entry in ($pl))
                {
                    if ($entry.Name -match "plugin: number of documents") 
                    { 
                        foreach ($haEntity in ($script:haArray))
                        {
                            if (($haEntity.entity -eq "IndexComponent") -and ($haEntity.primary -eq $component))
                            {
                                # Count indexed documents from all index partitions:
                                $script:indexedDocs += $entry.Message
                                $haEntity.docs = $entry.Message
                            }
                        }
                    }
                    if ($entry.Name -match "repartition")
                        { $indexerInfo += "Index re-partitioning state: $($entry.Message)" }
                    elseif (($entry.Name -match "splitting") -and ($entry.Name -match "fusion")) 
                        { $indexerInfo += "$component : Splitting index partition (appr. $($entry.Message) % finished)" }
                    elseif (($entry.Name -match "master merge running") -and ($entry.Message -match "true")) 
                    { 
                        $indexerInfo += "$component : Index Master Merge (de-fragment index files) in progress" 
                        $script:masterMerge = $true
                    }
                    elseif ($script:degradedComponents -and ($entry.Name -match "plugin: newest generation id"))
                    {
                        # If at least one index component is left behind, we want to output the generation number.  
                        $generationInfo += "$component : Index generation: $($entry.Message)" 
                        $gen = [int] $entry.Message
                        if ($generation -and ($generation -ne $gen))
                        {
                            # Verify if there are different generation IDs for the indexers
                            $script:generationDifference = $true
                        }
                        $generation = $gen
                    }
                    elseif (($entry.Level -eq "Error") -or ($entry.Level -eq "Warning"))
                    {
                        $script:serviceDegraded = $true
                        if ($entry.Name -match "fastserver")
                            { $indexerInfo += "$component ($($entry.Level)) : Indexer plugin error ($($entry.Name):$($entry.Message))" }
                        elseif ($entry.Message -match "fragments")
                            { $indexerInfo += "$component ($($entry.Level)) : Missing index partition" }
                        elseif (($entry.Name -match "active") -and ($entry.Message -match "not active"))
                            { $indexerInfo += "$component ($($entry.Level)) : Indexer generation controller is not running. Potential reason: All index partitions are not available" }
                        elseif ( ($entry.Name -match "in_sync") -or ($entry.Name -match "left_behind") )
                        { 
                            # Indicates replicas are out of sync, catching up. Redundant info in this script
                            $script:indexLeftBehind = $true
                        }                
                        elseif ($entry.Name -match "full_queue")
                            { $indexerInfo += "$component : Items queuing up in feeding ($($entry.Message))" }                                
                        elseif ($entry.Message -notmatch "No primary")
                        {
                            $indexerInfo += "$component ($($entry.Level)) : $($entry.Name):$($entry.Message)"
                        }
                    }
                }
            }
        } 

        if ($indexerInfo)
        {
            $retObj = [PSCustomObject]@{
                Name = "Indexer related additional status information"
            }
            $indexerInfoCount = 0
            foreach ($indexerInfoEntry in ($indexerInfo))
            {        
                $indexerInfoCount++
                $idxEntryInfoCount = 'IndexerInfoEntry ' + $indexerInfoCount
                $retObj | Add-Member -MemberType NoteProperty -Name $idxEntryInfoCount -Value $IndexerInfoEntry	
            }

            if ($script:indexLeftBehind -and $script:generationDifference)
            {
                # Output generation number for indexers in case any of them have been reported as left behind, and reported generation IDs are different.
                $generationInfoCount = 0
                foreach ($generationInfoEntry in ($generationInfo))
                {        
                     $generationInfoCount++
                     $genInfoCount = "Generation Information " + $generationInfoCount
                     $retObj | Add-Member -MemberType NoteProperty -Name $genInfoCount -Value $generationInfoEntry	
                }
            }
            $DetailedIndexerDiagFinding.InputObject = $retObj
            return $DetailedIndexerDiagFinding
        }
        #return $DetailedIndexerDiagFinding
    }

    # ------------------------------------------------------------------------------------------------------------------
    # VerifyHaLimits: Verify HA status for topology and index size limits
    # ------------------------------------------------------------------------------------------------------------------
    Function VerifyHaLimits
    {
        
        $VerifyHaLimitsDiagnosticFinding = New-DiagnosticFinding -Name "Verified HA Limits" -Description "Verifying HA status for topology and index size limits" -Severity Default -InputObject $null -format List
        $VerifyHaLimitsDiagnosticFinding.Description += "<br/><b>" + $script:ssa.DisplayName + "</b><br/>"
		
        $hacl = [PSCustomObject]@{
        }
        $haNotOk = $false
        $ixcwl = [PSCustomObject]@{
        }
        $ixcel = [PSCustomObject]@{
        }
        $docsExceeded = $false
        $docsHigh = $false
        $build = Get-SPVersion
        if($build -eq "2013")  
        {
            $is2016 = $false
            $is2013 = $true
        }
        else
        {
            $is2016 = $true
        }
        $hacCount = 0
        foreach ($hac in $script:haArray)
        {
            $hacCount++
            if ([int] $hac.componentsOk -lt 2)
            {
                if ([int] $hac.componentsOk -eq 0)
                {
                    # Service is down
                    $script:serviceFailed = $true
                    $haNotOk = $true   
                }
                elseif ($script:haTopology)
                {
                    # Only relevant to output if we have a HA topology in the first place
                    $haNotOk = $true   
                }

                if ($hac.partition -ne -1)
                {
                    $haclValue = "$($hac.componentsOk)($($hac.components)) -- Index partition $($hac.partition)"
                    $hacl |Add-Member -MemberType NoteProperty -Name $hacCount -Value $haclValue
                    
                }
                else
                {
                    $haclValue = "$($hac.componentsOk)($($hac.components)) -- $($hac.entity)"
                    $hacl |Add-Member -MemberType NoteProperty -Name $hacCount -Value $haclValue
                    #$hacl += "$($hac.componentsOk)($($hac.components)) : $($hac.entity)"
                }
            }
            if($is2016 -and $hac.entity -match "IndexComponent")
            {
                if ([int] $hac.docs -gt 20000000)
                {
                    $docsExceeded = $true
                    $hacCombo = "$($hac.entity) (partition $($hac.partition)): "
                    $ixcel | Add-Member -MemberType NoteProperty -Name $hacCombo -Value $hac.docs
                    #$ixcel += "$($hac.entity) (partition $($hac.partition)): $($hac.docs)"
                }
                elseif ([int] $hac.docs -gt 19000000)
                {
                    $docsHigh = $true
                    $hacCombo = "$($hac.entity) (partition $($hac.partition)): "  
                    $ixcwl | Add-Member -MemberType NoteProperty -Name $hacCombo -Value $hac.docs
                    #$ixcwl += "$($hac.entity) (partition $($hac.partition)): $($hac.docs)"
                }
            }
            elseif($is2013 -and $hac.entity -match "IndexComponent")
            {
                if ([int] $hac.docs -gt 10000000)
                {
                    $docsExceeded = $true
                    $hacCombo = "$($hac.entity) (partition $($hac.partition)): "
                    $ixcel | Add-Member -MemberType NoteProperty -Name $hacCombo -Value $hac.docs
                    #$ixcel += "$($hac.entity) (partition $($hac.partition)): $($hac.docs)"
                }
                elseif ([int] $hac.docs -gt 9000000)
                {
                    $docsHigh = $true   
                    $hacCombo = "$($hac.entity) (partition $($hac.partition)): "  
                    $ixcwl | Add-Member -MemberType NoteProperty -Name $hacCombo -Value $hac.docs
                    #$ixcwl += "$($hac.entity) (partition $($hac.partition)): $($hac.docs)"
                }
            }
        }
        if ($haNotOk)
        {
            $hacl = $hacl | Sort-Object
            if ($script:serviceFailed)
            {
                $VerifyHaLimitsDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                $VerifyHaLimitsDiagnosticFinding.WarningMessage += "Critical: Service 'possibly' down due to components not active"
            }
            else
            {
                $VerifyHaLimitsDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                $VerifyHaLimitsDiagnosticFinding.WarningMessage += "Warning: No High Availability for one or more components"

            }
            
            $VerifyHaLimitsDiagnosticFinding.Description += "- It has been detected that there are search components, in the topology, that has more than 1 component.<br/>- If you have more than 1 component for some components, but only 1 of others, we will flag this check. <br/>- We will also flag if you have multiple components and 1 or more of (x) components are down.<br/>"
            $VerifyHaLimitsDiagnosticFinding.Description += "- In a 'High Availability' setup, search should be able to function with minimal impact if you have a redundancy of components.<br/>"
            $VerifyHaLimitsDiagnosticFinding.ReferenceLink += "https://learn.microsoft.com/en-us/SharePoint/administration/plan-for-high-availability"
            $VerifyHaLimitsDiagnosticFinding.InputObject = $hacl
        }
        if ($docsExceeded)
        {
            $script:serviceDegraded = $true
            $docsExceededFindings = New-DiagnosticFinding -Name "Docs 'per Index Partition' Exceeded" -Severity Warning -InputObject $null -format List -WarningMessage "One or more index component exceeds the supported document limit"
            #$docsExceededFindings.WarningMessage += "Warning: One or more index component exceeds document limit"
            $docsExceededFindings.InputObject = $ixcel
            $VerifyHaLimitsDiagnosticFinding.ChildFindings.Add($docsExceededFindings)
        }
        if ($docsHigh)
        {
            $docsHighFindings = New-DiagnosticFinding -Name "Docs 'per Index Partition' Close To Limit" -Severity Warning -InputObject $null -format List -WarningMessage "Warning: One or more index component is close to the supported document limit"
            #$docsHighFindings.WarningMessage += "Warning: One or more index component is close to document limit"
            $docsHighFindings.InputObject = $ixcwl
            $VerifyHaLimitsDiagnosticFinding.ChildFindings.Add($docsHighFindings)
        }

        if($haNotOk -or $docsExceededFindings -or $docsHigh)
        {
            return $VerifyHaLimitsDiagnosticFinding
        }
        return $null
    }

    #---added by bspender--------------------------------------------------------------------------------------------------
    # VerifyApplicationServerSyncJobsEnabled: Verify that Application Server Admin Service Timer Jobs are running
    # ---------------------------------------------------------------------------------------------------------------------
    function VerifyRunningProcesses
    {
        $components = $script:ssa.ActiveTopology.GetComponents() | SORT-OBJECT ServerName | select-object ServerName, Name
        $VerifyRunningProcessesDiagnosticsFindings = New-DiagnosticFinding -Name "VerifyRunningProcesses" -Severity Default -format List

        foreach ($hostname in $script:hostArray.Hostname) 
        {
            $RunningProcessDiagnosticFinding = New-DiagnosticFinding -Name $hostname -Severity Default -Format List

            $retObj = [PSCustomObject]@{
                HostName = $hostname
            }

            $RunningProcessDiagnosticFinding.Description += "Components deployed to this server..."

            $crawler = $components | where-object {($_.Servername -ieq $hostname) -and ($_.Name -match "Crawl") } 
            if ($null -ne $crawler) {
                $retObj | Add-Member -MemberType NoteProperty -Name "Crawl" -Value $crawler.Name	
                
                $mssearch = (Get-Process mssearch -ComputerName $hostname -ErrorAction SilentlyContinue)
                if($mssearch)
                {
                    $retObj | Add-Member -MemberType NoteProperty -Name "MSSearch Process" -Value ("[PID: " + $mssearch.Id + "]")
                }
                else {
                    $RunningProcessDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                    $RunningProcessDiagnosticFinding.WarningMessage+= "No MSSearch Process Found"
                }
                
                
                $mssdmn = (Get-Process mssdmn -ComputerName $hostname -ErrorAction SilentlyContinue)
                if($mssdmn)
                {
                    $count = 0
                    $mssdmn | ForEach-Object {
                        $count++
                        $name = $_.ProcessName + "_" + $count + " PID"
                        $retObj | Add-Member -MemberType NoteProperty -Name $name -Value $_.Id
                    }
                }
                else {
                    $RunningProcessDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                    $RunningProcessDiagnosticFinding.WarningMessage+= "No MSSDMN Process Found"
                }
            }

            $junoComponents = $components | where-object {($_.Servername -ieq $hostname) -and ($_.Name -notMatch "Crawl") }     
            $noderunnerProcesses = (Get-Process noderunner -ComputerName $hostname -ErrorAction SilentlyContinue)

            foreach ($node in $noderunnerProcesses) {
                $node | Add-Member -Force -MemberType NoteProperty -Name _ProcessCommandLine -Value $(
                    (Get-WmiObject Win32_Process -ComputerName $hostname -Filter $("processId=" + $node.id)).CommandLine
                )

                $junoComponents | where-object {$_.Servername -ieq $hostname} | ForEach-Object {
                    $component = $($_).Name
                    if ($node._ProcessCommandLine -like $("*" + $component + "*")) {
                        $retObj | Add-Member -MemberType NoteProperty -Name $component -Value ($node.ProcessName + "[PID: " + $node.Id + "]")
                    }
                }
            }

            #if this is a custom object, wrap it in an array object so we can get a count in the step below
            if ($junoComponents -is [PSCustomObject]) { $junoComponents = @($junoComponents) } 

            if ($junoComponents.Count  -gt $noderunnerProcesses.Count) {
                $RunningProcessDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                $RunningProcessDiagnosticFinding.WarningMessage += "One or more noderunner processes is not running for components"
            }

            $services = Get-Service -ComputerName $hostname -Name SPTimerV4, SPAdminV4, OSearch15, SPSearchHostController 
            $running = $services | where-object {$_.Status -eq "Running"}
            if ($running) {
                $serviceinstances = New-DiagnosticFinding -Name "Running Service Instances" -Severity Default -format List -InputObject $running
                $RunningProcessDiagnosticFinding.ChildFindings.Add($serviceinstances)
            }
            $stopped = $services | where-object {$_.Status -eq "Stopped"}
            if ($stopped) {
                $serviceinstances = New-DiagnosticFinding -Name "Stopped Service Instances" -Severity Default -format List -InputObject $stopped
                $RunningProcessDiagnosticFinding.ChildFindings.Add($serviceinstances)
            }
            $other   = $services | where-object {($_.Status -ne "Running") -and ($_.Status -ne "Stopped")}
            if ($other) {
                $serviceinstances = New-DiagnosticFinding -Name "Service in an abnormal or transient state...s" -Severity Warning -format List -InputObject $other
                $RunningProcessDiagnosticFinding.ChildFindings.Add($serviceinstances)
            }
            $RunningProcessDiagnosticFinding.InputObject = $retObj
            $VerifyRunningProcessesDiagnosticsFindings.ChildFindings.Add($RunningProcessDiagnosticFinding)
        }
        return $VerifyRunningProcessesDiagnosticsFindings
    }

    $healthCheckName = "Search Healthcheck " + "( " + $ssa.DisplayName + " )"
    $SearchTopologyHealthCheck = New-DiagnosticFinding -Name $healthCheckName -Severity Default -InputObject $null -Format List

    # ------------------------------------------------------------------------------------------------------------------
    # Global variables:
    # ------------------------------------------------------------------------------------------------------------------
    $script:debug = $false #TODO: turn this to false for release
    $script:serviceDegraded = $false
    $script:serviceFailed = $false
    $script:unknownComponents = @()
    $script:degradedComponents = @()
    $script:failedComponents = @()
    $script:generationDifference = $false
    $script:indexLeftBehind = $false
    $script:searchHosts = 0
    #$script:ssa = GetSSA
    $script:componentStateList = $null
    $script:topologyCompList = $null
    $script:haTopology = $false
    $script:primaryAdmin = $null
    $script:indexedDocs = 0
    $script:masterMerge = $false

    #---added by bspender------------------------
    $script:SSPJobInstancesOffline = $(New-Object System.Collections.ArrayList)
    $script:ApplicationServerSyncTimerJobsOffline = $(New-Object System.Collections.ArrayList)
    $script:ApplicationServerSyncNotRunning = $(New-Object System.Collections.ArrayList)
    #--------------------------------------------
    $script:UnreachableSearchServiceSvc = $(New-Object System.Collections.ArrayList)
    $script:UnreachableSearchAdminSvc = $(New-Object System.Collections.ArrayList)
    #--------------------------------------------

    # Template object for the host array:
    $script:hostTemplate = New-Object psobject
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name hostName -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name components -Value 0
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name cpc -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name qpc -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name pAdmin -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name sAdmin -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name apc -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name crawler -Value $null
    $script:hostTemplate | Add-Member -MemberType NoteProperty -Name index -Value $null

    # Create the empty host array:
    $script:hostArray = @()

    # Template object for the HA group array:
    $script:haTemplate = New-Object psobject
    $script:haTemplate | Add-Member -MemberType NoteProperty -Name entity -Value $null
    $script:haTemplate | Add-Member -MemberType NoteProperty -Name partition -Value -1
    $script:haTemplate | Add-Member -MemberType NoteProperty -Name primary -Value $null
    $script:haTemplate | Add-Member -MemberType NoteProperty -Name docs -Value 0
    $script:haTemplate | Add-Member -MemberType NoteProperty -Name components -Value 0
    $script:haTemplate | Add-Member -MemberType NoteProperty -Name componentsOk -Value 0

    # Create the empty HA group array:
    $script:haArray = @()

    # Template object for the component/server table:
    $script:compTemplate = New-Object psobject
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name Component -Value $null
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name Server -Value $null
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name Partition -Value $null
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name State -Value $null
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name RootDirectory -Value $null
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name ComponentId -Value $null
    $script:compTemplate | Add-Member -MemberType NoteProperty -Name ServerId -Value $null
    

    $script:SearchTopologyValues = New-Object psobject

    # Create the empty component/server table:
    $script:compArray = @()

    # Get basic topology info and component health status
    GetTopologyInfo

    #---added by bspender------------------------
    #VerifyRunningProcesses
    #VerifyApplicationServerSyncJobsEnabled


    # Traverse list of components, determine properties and update $script:hostArray / $script:haArray
    foreach ($searchComp in ($script:topologyCompList))
    {
        PopulateHostHaList($searchComp)
    }

    # Analyze the component status:
    $compStatusColl = @()
    foreach ($component in ($script:componentStateList))
    {
        $findings = SearchComponentStatus($component)  
        # The SearchComponentStatus only returns data if there is worhtwhile data to return
        # So check for null, and only add to the findings if value

        if($findings)
        {
            $compStatusColl += $findings
            #$SearchTopologyHealthCheck.ChildFindings.Add($findings)                 
        }
    }
    if($compStatusColl)
    {
        #$SearchComponentStatusDiagnosticsFinding = New-DiagnosticFinding -Name "Broken Search Components" -Severity Default -InputObject $compStatusColl -format Table
        #$SearchComponentStatusDiagnosticsFinding.Severity = [SPDiagnostics.Severity]::Warning
        #$SearchTopologyHealthCheck.ChildFindings.Add($SearchComponentStatusDiagnosticsFinding)
    }

    # Look for selected info from detailed indexer diagnostics:
    $findings = DetailedIndexerDiag
    if($findings){
        $SearchTopologyHealthCheck.ChildFindings.Add($findings)                 
    } 

    # Output list of components with state OK:
    if ($script:compArray)
    {
        $script:compArray = $script:compArray | Sort-Object -Property Component

        # ------------------------------------------------------------------------------------------
        # Build the "Search Application Topology" grid: one row per server, one column per component
        # type (plus one column per index partition). A check mark indicates the server hosts that
        # component; "(p)" flags the primary Admin component and the primary Index component.
        # ------------------------------------------------------------------------------------------

        # Distinct servers (rows) and index partition ordinals (extra columns)
        $stpServers = @($script:compArray | ForEach-Object { $_.Server } | Where-Object { $_ } | Sort-Object -Unique)

        $stpPartitions = @()
        foreach ($sc in $script:compArray)
        {
            if ($sc.Component -match "Index" -and $null -ne $sc.Partition -and $sc.Partition -ne -1)
            {
                $stpPartitions += [int]$sc.Partition
            }
        }
        $stpPartitions = @($stpPartitions | Sort-Object -Unique)

        # Map each component into a grid cell: $stpGrid[server][columnKey] = @{ Present; Primary; StateRank; StateLabel }
        # StateRank: 0 = Active/healthy, 1 = Degraded, 2 = Unknown/Failed (worst state wins per cell)
        $stpGrid = @{}
        $stpHasIssue = $false
        foreach ($sc in $script:compArray)
        {
            $rawName = [string]$sc.Component
            $isPrimary = ($rawName -match "\(Primary\)")
            $colKey = $null
            if     ($rawName -match "Admin")     { $colKey = "Admin" }
            elseif ($rawName -match "Crawl")     { $colKey = "Crawler" }
            elseif ($rawName -match "Content")   { $colKey = "Content" }
            elseif ($rawName -match "Analytics") { $colKey = "Analytics" }
            elseif ($rawName -match "Query")     { $colKey = "Query" }
            elseif ($rawName -match "Index")
            {
                $part = if ($null -ne $sc.Partition) { [int]$sc.Partition } else { 0 }
                $colKey = "Index$part"
            }

            if ($colKey)
            {
                $state = [string]$sc.State
                $rank = 0
                if ([string]::IsNullOrEmpty($state) -or $state -eq "Active") { $rank = 0 }
                elseif ($state -match "Degrad") { $rank = 1 }
                else { $rank = 2 }   # Unknown, Failed, Registering, etc.
                if ($rank -gt 0) { $stpHasIssue = $true }
                $stateLabel = if ([string]::IsNullOrEmpty($state)) { "Active" } else { $state }

                if (-not $stpGrid.ContainsKey($sc.Server)) { $stpGrid[$sc.Server] = @{} }
                if (-not $stpGrid[$sc.Server].ContainsKey($colKey))
                {
                    $stpGrid[$sc.Server][$colKey] = @{ Present = $true; Primary = $false; StateRank = $rank; StateLabel = $stateLabel }
                }
                elseif ($rank -gt $stpGrid[$sc.Server][$colKey].StateRank)
                {
                    $stpGrid[$sc.Server][$colKey].StateRank = $rank
                    $stpGrid[$sc.Server][$colKey].StateLabel = $stateLabel
                }
                if ($isPrimary) { $stpGrid[$sc.Server][$colKey].Primary = $true }
            }
        }

        # Column definitions: fixed component columns followed by one column per index partition
        $stpColumns = @(
            [PSCustomObject]@{ Key = "Admin";     Label = "Admin";                Part = $null }
            [PSCustomObject]@{ Key = "Crawler";   Label = "Crawler";              Part = $null }
            [PSCustomObject]@{ Key = "Content";   Label = "Content Processing";   Part = $null }
            [PSCustomObject]@{ Key = "Analytics"; Label = "Analytics Processing"; Part = $null }
            [PSCustomObject]@{ Key = "Query";     Label = "Query Processing";     Part = $null }
        )
        foreach ($p in $stpPartitions)
        {
            $stpColumns += [PSCustomObject]@{ Key = "Index$p"; Label = "Index Partition"; Part = $p }
        }

        # Render the grid as a self-contained HTML table. Scale the cell density down as the
        # number of index partitions grows (an SSA supports up to 25) so the grid stays readable
        # and a horizontal-scroll wrapper guards against extreme widths.
        $densityClass = ''
        if ($stpPartitions.Count -ge 15) { $densityClass = ' density-tiny' }
        else { $densityClass = ' density-compact' }

        $partCount = $stpPartitions.Count
        $rowSpan = if ($partCount -gt 0) { ' rowspan="2"' } else { '' }

        $stpHtml = ('<div class="searchtopo-wrap"><table class="searchtopo{0}"><thead>' -f $densityClass)
        $stpHtml += '<tr>'
        $stpHtml += ('<th class="stp-srv"{0}>Server Name</th>' -f $rowSpan)
        $stpHtml += ('<th{0}>Admin</th>' -f $rowSpan)
        $stpHtml += ('<th{0}>Crawler</th>' -f $rowSpan)
        $stpHtml += ('<th{0}>Content Processing</th>' -f $rowSpan)
        $stpHtml += ('<th{0}>Analytics Processing</th>' -f $rowSpan)
        $stpHtml += ('<th{0}>Query Processing</th>' -f $rowSpan)
        if ($partCount -gt 0) { $stpHtml += ('<th class="stp-partgroup" colspan="{0}">Index Partition</th>' -f $partCount) }
        $stpHtml += '</tr>'
        if ($partCount -gt 0)
        {
            $stpHtml += '<tr>'
            foreach ($p in $stpPartitions) { $stpHtml += ('<th class="stp-partnum">{0}</th>' -f $p) }
            $stpHtml += '</tr>'
        }
        $stpHtml += '</thead><tbody>'

        foreach ($srv in $stpServers)
        {
            $srvEnc = [System.Security.SecurityElement]::Escape([string]$srv)
            $stpHtml += ('<tr><td class="stp-srv">{0}</td>' -f $srvEnc)
            foreach ($col in $stpColumns)
            {
                $cell = $null
                if ($stpGrid.ContainsKey($srv) -and $stpGrid[$srv].ContainsKey($col.Key)) { $cell = $stpGrid[$srv][$col.Key] }
                if ($cell)
                {
                    $stateEnc = [System.Security.SecurityElement]::Escape([string]$cell.StateLabel)
                    if ($cell.StateRank -ge 2)
                    {
                        $icon = ('<span class="stp-ico-wrap" title="{0}"><svg class="stp-ico stp-ico-err" viewBox="0 0 16 16" width="14" height="14"><circle cx="8" cy="8" r="7.5" fill="#d9534f"/><path d="M5.2 5.2 L10.8 10.8 M10.8 5.2 L5.2 10.8" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/></svg></span>' -f $stateEnc)
                    }
                    elseif ($cell.StateRank -eq 1)
                    {
                        $icon = ('<span class="stp-ico-wrap" title="{0}"><svg class="stp-ico stp-ico-warn" viewBox="0 0 18 16" width="16" height="14"><path d="M9 1 L17 15 L1 15 Z" fill="#f0ad4e" stroke="#d18b25" stroke-width="0.6" stroke-linejoin="round"/><rect x="8.2" y="6" width="1.6" height="5" rx="0.7" fill="#5a3d00"/><circle cx="9" cy="12.6" r="0.95" fill="#5a3d00"/></svg></span>' -f $stateEnc)
                    }
                    else
                    {
                        $icon = '<span class="stp-chk">&#10003;</span>'
                    }
                    if ($cell.Primary) { $icon += ' <span class="stp-pri">(p)</span>' }
                    $stpHtml += ('<td>{0}</td>' -f $icon)
                }
                else
                {
                    $stpHtml += '<td></td>'
                }
            }
            $stpHtml += '</tr>'
        }
        $stpHtml += '</tbody></table></div>'

        # Legend icons (re-used inline in the caption)
        $legendChk  = '<span class="stp-chk">&#10003;</span>'
        $legendWarn = '<svg class="stp-ico stp-ico-warn" viewBox="0 0 18 16" width="14" height="12"><path d="M9 1 L17 15 L1 15 Z" fill="#f0ad4e" stroke="#d18b25" stroke-width="0.6" stroke-linejoin="round"/><rect x="8.2" y="6" width="1.6" height="5" rx="0.7" fill="#5a3d00"/><circle cx="9" cy="12.6" r="0.95" fill="#5a3d00"/></svg>'
        $legendErr  = '<svg class="stp-ico stp-ico-err" viewBox="0 0 16 16" width="12" height="12"><circle cx="8" cy="8" r="7.5" fill="#d9534f"/><path d="M5.2 5.2 L10.8 10.8 M10.8 5.2 L5.2 10.8" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/></svg>'
        $stpCaption  = 'Search Application Topology &ndash; component layout across farm servers. '
        $stpCaption += '<b>(p)</b> marks the primary Admin component and the primary Index component for each partition.'
        $stpCaption += ('<div class="stp-legend">Legend: {0} Active &nbsp;&nbsp; {1} Degraded &nbsp;&nbsp; {2} Unknown / Failed</div>' -f $legendChk, $legendWarn, $legendErr)

        # Parent finding: the visual topology grid
        $TopologyGridFinding = New-DiagnosticFinding -Name "Search Application Topology" -Severity Default -InputObject $null -Format Table
        $TopologyGridFinding.Description += ($stpCaption + $stpHtml)
        if ($stpHasIssue) { $TopologyGridFinding.Severity = [SPDiagnostics.Severity]::Warning }

        # Child finding: original detailed "Search Topology Status" table (all components + RootDirectory)
        $ActiveSearchTopo = @()
        foreach ($sc in $script:compArray)
        {
            $sci = New-Object PSObject
            $sci | Add-Member -MemberType NoteProperty -Name "Component" -Value $sc.Component
            $sci | Add-Member -MemberType NoteProperty -Name "Server" -Value $($sc.Server)
            $sci | Add-Member -MemberType NoteProperty -Name "Partition" -Value $sc.Partition
            $sci | Add-Member -MemberType NoteProperty -Name "State" -Value $sc.State
            $sci | Add-Member -MemberType NoteProperty -Name "RootDirectory" -Value $sc.RootDirectory
            $sci | Add-Member -MemberType NoteProperty -Name "ComponentId" -Value $sc.ComponentId
            $sci | Add-Member -MemberType NoteProperty -Name "ServerId" -Value $sc.ServerId
            $ActiveSearchTopo += $sci
        }
        $searchTopologyName = "Search Topology Status (ID: " + $script:ssa.ActiveTopology.TopologyId + " )"
        $ComponentFindings = New-DiagnosticFinding -Name $searchTopologyName -Severity Default -InputObject $ActiveSearchTopo -Format Table
        $ComponentFindings.Description += "Detailed status of every search component, including the physical index RootDirectory. '&lt;DataDirectoryPath&gt;' denotes the default search index location configured on the server."
        $TopologyGridFinding.ChildFindings.Add($ComponentFindings)

        $SearchTopologyHealthCheck.ChildFindings.Add($TopologyGridFinding)
    }

    # Indexing System Diagnostics + Master Merge Diagnostics (ported from SRx Get-SRxIndexReports -DiskReport).
    # Placed directly under "Search Application Topology" and before "Analytics Processing Job Status".
    $indexReplicaReport = Get-SPSearchIndexReplicaReport -SearchApplication $script:ssa -ComponentStateList $script:componentStateList -TopologyComponentList $script:topologyCompList
    if ($indexReplicaReport)
    {
        $indexDiagFinding = New-SPSearchIndexDiagFinding -Replicas $indexReplicaReport
        if ($indexDiagFinding) { $SearchTopologyHealthCheck.ChildFindings.Add($indexDiagFinding) }
    }

    #Only do these things if the primaryAdmin is set
    if($null -ne $script:primaryAdmin)
    {
        # Verify HA status for topology and index size limits:
        $VerifyHaLimitsFindings = VerifyHaLimits
        if($VerifyHaLimitsFindings)
        {
            $SearchTopologyHealthCheck.ChildFindings.Add($VerifyHaLimitsFindings)
        }      

        # Output components by server (for servers with multiple search components):
        if ($script:haTopology -and ($script:searchHosts -gt 2))
        {
            $componentsByServer = $false
            foreach ($hostInfo in $script:hostArray)
            {
                if ([int] $hostInfo.components -gt 1)
                {
                    $componentsByServer = $true
                }
            }
            if ($componentsByServer)
            {
                $MultiComponentServers = New-DiagnosticFinding -Name "Servers with multiple search components" -Severity Default -InputObject $null
                foreach ($hostInfo in $script:hostArray)
                {
                    if ([int] $hostInfo.components -gt 1)
                    {
                        foreach ($hi in $hostInfo)
                        {
                            $hi.hostName = $($hi.hostName) 
                        }

                        $hostinfofindings = New-DiagnosticFinding -Name $hostinfo.hostName -Severity Default -InputObject $hostInfo -Format Table 
                        $MultiComponentServers.ChildFindings.Add($hostinfofindings)
                    }
                                    
                }
                $SearchTopologyHealthCheck.ChildFindings.Add($MultiComponentServers)
            }
        }        
    }

    # Analytics Processing Job Status:
    $AnalyticsStatus = AnalyticsStatus
    $SearchTopologyHealthCheck.ChildFindings.Add($AnalyticsStatus)

    if ($script:masterMerge)
    {
        $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Master Merge" -Value "Index Master Merge (de-fragment index files) in progress on one or more index components."
    }

    if ($script:serviceFailed -eq $false)
    {
        if ($script:indexedDocs)
        {
            $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Searchable Items" -Value $script:indexedDocs.ToString('N0')
        } else {
            $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Searchable Items" -Value 0
        }
    }

    GetCrawlStatus
        
    if ($script:unknownComponents)
    {
        $UnknownComponents = New-DiagnosticFinding -Name "The following components are not reachable" -InputObject $null 
        $UnknownComponents.Severity = [SPDiagnostics.Severity]::Warning
        $UnknownComponents.WarningMessage = "Recommended action: Restart Host Controller process or restart the associated server(s) and review ULS logs during that period"

        $description = $null
        foreach ($uc in ($script:unknownComponents))
        {
            $description += $uc.ToString() + "<br/>"
            
        }
        $UnknownComponents.Description += $description
        $SearchTopologyHealthCheck.ChildFindings.Add($UnknownComponents)
        
    }

    if ($script:degradedComponents)
    {
        $DegradedComponents = New-DiagnosticFinding -Name "The following components are degraded" -Severity Warning -InputObject $null
        $DegradedComponents.Severity = [SPDiagnostics.Severity]::Warning
        $DegradedComponents.WarningMessage = "Recommended action for degraded components:</br>"
        $DegradedComponents.WarningMessage+= "    Component registering or resolving:</br>"
        $DegradedComponents.WarningMessage+= "    This can be a transient state during component restart or re-configuration. Re-run the script.</br>"
        
        $description = $null
        foreach ($dc in ($script:degradedComponents))
        {
            $description += $dc.ToString() + "<br/>"
        }

        $DegradedComponents.Description += $description

        if ($script:indexLeftBehind)
        {
            $DegradedComponents.WarningMessage+= "    Index component left behind:</br>"
            if ($script:generationDifference)
            {
                $DegradedComponents.WarningMessage+= "        This is normal after adding an index component or index component/server recovery.</br>"
                $DegradedComponents.WarningMessage+= "        Indicates that the replica is being updated from the primary replica.</br>"
            }
            else
            {
                $DegradedComponents.WarningMessage+= "        Index replicas listed as degraded but index generation is OK.</br>"
                $DegradedComponents.WarningMessage+= "        Will get out of degraded state as soon as new/changed items are being indexed.</br>"
            }
        }
        $SearchTopologyHealthCheck.ChildFindings.Add($DegradedComponents)
    }

    if ($script:failedComponents)
    {
        $FailedComponentsDiagnosticFindings = New-DiagnosticFinding -Name "The following components are reported in error" -Severity Warning -InputObject $null -format List -WarningMessage "Recommended action: Restart the associated server(s)"
        $description = $null

        foreach($fc in $failedComponents)
        {
            $description += $fc.ToString() + "<br/>"
        }

        $FailedComponentsDiagnosticFindings.Description += $description
        $SearchTopologyHealthCheck.ChildFindings.Add($FailedComponentsDiagnosticFindings)
        
    }

    if ($script:serviceFailed)
    {
        $SearchTopologyHealthCheck.Severity = [SPDiagnostics.Severity]::Critical
        $SearchTopologyHealthCheck.WarningMessage += " Search Service Overall State: Failed "
    }
    elseif ($script:serviceDegraded)
    {
        $SearchTopologyHealthCheck.Severity = [SPDiagnostics.Severity]::Warning
        $SearchTopologyHealthCheck.WarningMessage += " Search Service Overall State: Degraded "
    }
    else
    {
        $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Search service overall state" -Value "OK"
    }
    
    $SearchTopologyHealthCheck.InputObject = $script:SearchTopologyValues

    return $SearchTopologyHealthCheck

}

function Select-SPDiagnosticSSA
{
    $ssas = @(Get-SPEnterpriseSearchServiceApplication | Sort-Object Name)

    if($ssas.Count -eq 1)
    {
        $script:ssa = $ssas[0]
    }
    elseif($ssas.Count -gt 1)
    {
        $menu = @{}
        for($i=1;$i -le $ssas.count; $i++)
        {
            Write-Host "$i. $($ssas[$i-1].name)"
            $menu.Add($i,($ssas[$i-1].name))
        }
        ""
        [int]$ans = Read-Host 'Select Primary SSA for Usage Analysis and Reporting'
        $selection = $menu.Item($ans)
        $script:ssa = Get-SPEnterpriseSearchServiceApplication $selection
    }
}

function Get-SPDiagnosticUsageAndReportingInformation($siteUrl)
{
    $Script:UsageLogDir = ""
    $script:ImportProgressFile = "importprogress.ini"
    
    # Some things can only be done on certain version of Powershell and/or SharePoint. 
    $Script:CheckServiceACLs = $false

    $Script:TimerServiceAccount = $null
    $script:W3WPAppPoolAccount = $null
    $Script:ReportingFeatureId = "7094bd89-2cfe-490a-8c7e-fbace37b4a34"
    $script:UsageAndHealthDataCollectionProxyName = "Usage and Health Data Collection Proxy"
    $script:UsageDefinitionsWithReceivers = @("Analytics Usage","File IO","Page Requests","Simple Log Event Usage Data_SPUnifiedAuditEntry")

    if($PSversionTable.PSversion.Major -ge 5)
    {
        $Script:CheckServiceACLs = $true
    }
        
    function Get-SPAnalyticsTopologyDiagnosticFinding($ssa)
    {
        $AnalyticsTopology = $null 

        # On 2013 Servers there is no AnalytisTopology accessor. Try getting it the old fashioned way if it's null
        $spVersion = Get-SPVersion

        if(($spVersion) -eq "2013" -or $spVersion -eq "2016")
        {
            $AnalyticsTopology = $ssa | Get-SPEnterpriseSearchTopology -Active
        }
        else
        {
            $AnalyticsTopology = $ssa.AnalyticsTopology
        }

        if($null -ne $AnalyticsTopology)
        {

            $retObj = [PSCustomObject]@{
                TopologyId = $AnalyticsTopology.TopologyId
                CreationDate = $AnalyticsTopology.CreationDate
                SystemManagerLocation = $AnalyticsTopology.SystemManagerLocation
                ConstellationName = $AnalyticsTopology.ConstellationName
                ConstellationType = $AnalyticsTopology.ConsteallationType
                QueryGraph = $AnalyticsTopology.QueryGraph
                State = $AnalyticsTopology.State
                ComponentCount = $AnalyticsTopology.ComponentCount
            }
    
            $server = $AnalyticsTopology.SystemManagerLocation.ToString().split('/')[2].split(':')[0]
            $retObj.SystemManagerLocation =  $AnalyticsTopology.SystemManagerLocation.ToString()
    
            $finding = New-DiagnosticFinding -Name "Analytics Topology" -Severity Default -Format List -InputObject $retObj

            $components = $AnalyticsTopology.GetComponents()
            foreach($component in $components)
            {

                # Get all properties of the object
                $properties = $component | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name

                # Create a custom object dynamically with all properties
                $customObject = [PSCustomObject]@{}
                foreach ($property in $properties) {
                    if ($property -like "ServerName")
                    {
                        $customObject | Add-Member -MemberType NoteProperty -Name $property -Value $($component.$property)
                    }
                    else {
                        $customObject | Add-Member -MemberType NoteProperty -Name $property -Value $component.$property
                    }
                    
                }

                $componentFinding = New-DiagnosticFinding -Name $component.Name -Severity Default -Format List -InputObject $customObject

                $finding.ChildFindings.Add($componentFinding)
            }
        }
        else {
            $finding = New-DiagnosticFinding -Name "Analytics Topology" -Severity Default -Format List -InputObject $null
            $finding.WarningMessage += "No Analytics Topology Found"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
        }
    
    
        return $finding
    }
        
    function Get-SPDiagnosticSitePropertiesOfInterest($site)
    {
        $SPReportingFeatureEnabled = Get-SPReportingFeatureEnabled $site
    
        $tempSite = $site | select-object Url, CompatibilityLevel
        $tempSite | Add-Member -MemberType NoteProperty -Name "SPReportingFeatureEnabled" -Value $SPReportingFeatureEnabled
        
        $retObj = [PSCustomObject]@{
            Url = $($tempSite.Url)
            CompatibilityLevel = $tempSite.CompatibilityLevel
            SPReportingFeatureEnabled = $tempSite.SPReportingFeatureEnabled
        }

        $finding = New-DiagnosticFinding -Name "Site and WebRoot Properties" -Severity Default -InputObject $retObj -Format Table
        
        if(!$SPReportingFeatureEnabled)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            $finding.WarningMessage = "Reporting Feature is not enabled on this site, reporting will not be available or will be stale"
        }
        
        $finding.ChildFindings.Add((Get-SPDiagnosticWebPropertiesOfInterest $site.RootWeb))
        $finding.ChildFindings.Add((Get-SPDiagnosticWebApplicationPropertiesOfInterest $site.WebApplication))
        
        $webs = $site.AllWebs
        $webFinding =  New-DiagnosticFinding -Name "All Webs" -Severity Default -InputObject $null -Format Table -Expand
    
        foreach($web in $webs)
        {
            $webFinding.ChildFindings.Add((Get-SPDiagnosticWebPropertiesOfInterest $web))
        }
    
        $finding.ChildFindings.Add($webFinding)
    
        return $finding
    }
    
    function Get-SPReportingFeatureEnabled($site)
    {
        $SPReportingFeatureEnabled = ($null -ne (Get-SPFeature -Identity $Script:ReportingFeatureId -ErrorAction SilentlyContinue -Site $site))
    
        return $SPReportingFeatureEnabled
        
    }
    
    function Get-SPDiagnosticWebPropertiesOfInterest($web)
    {
        $retObj = [PSCustomObject]@{
            Url = $($web.Url)
            CompatibilityLevel = $web.NoCrawl
            WelcomePage = $web.RootFolder.WelcomePage
        }

        $finding = New-DiagnosticFinding -Name "Web Properties" -Severity Default -InputObject $retObj -Format Table
        if($web.NoCrawl -eq $true)
        {
            $finding.WarningMessage = 'NoCrawl is $true on this web. This may prevent accurate reporting, site views, etc,.'
            $finding.Severity = [SPDiagnostics.Severity]::Warning
        }

        # There's an issue if inheritance is disabled on the library where the homepage points to. Identify the library and check permissions
        if(![string]::IsNullOrEmpty($web.RootFolder.WelcomePage))
        {
            $RelativeWelcomePageUrl = $web.ServerRelativePath.ToString()
            
            # Handle instances where ServerRelativePath doesn't end in /
            if(!$RelativeWelcomePageUrl.EndsWith("/"))
            {
                $RelativeWelcomePageUrl = $RelativeWelcomePageUrl + "/"
            }
            
            # Concat the welcomePage Url
            $RelativeWelcomePageUrl = $RelativeWelcomePageUrl+ $web.RootFolder.WelcomePage.ToString()

            # Find the List that owns the Welcome PAge
            $SPListItem = $web.GetListItem($RelativeWelcomePageUrl)

            if($null -ne $SPListItem)
            {
                $SPList = $SPListItem.ParentList

                # Ensure List doesn't have unique role assignments
                if($SPList.HasUniqueRoleAssignments)
                {
                    $finding.WarningMessage += "The WelcomePage for Web '$web' uses a List '$SPList' which has unique role assignments. This has been known to cause problems with Site Usage Metrics."
                    $finding.WarningMessage += "If you find the Site Usage Metrics are reporting 0 visits to this site, this may need to be corrected."
                    $finding.Severity = [SPDiagnostics.Severity]::Warning
                }
            }
        }
    
        return $finding
    }
    function Get-SPDiagnosticWebApplicationPropertiesOfInterest($webApp)
    {
        $tempWebApp = $webApp | select-object AllowAnalyticsCookieForAnonymousUsers
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Pool Name" -Value $webApp.ApplicationPool.Name
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Pool UserName" -Value $($webApp.ApplicationPool.Username)
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Managed Account" -Value $($webApp.ApplicationPool.ManagedAccount)
    
        $script:W3WPAppPoolAccount = $($webApp.ApplicationPool.Username)
        $finding = New-DiagnosticFinding -Name "WebApp Properties" -Severity Default -InputObject $tempWebApp -Format List
        
        return $finding
    }
    
    function Set-OWSTimerServiceAccountForScript()
    {
        $OWSTimerService = Get-WmiObject -Class Win32_Service | where-object{$_.Name -like "SPTimerV4"}
        
        #Removing Finding as it is not necessary. 
        #$finding = New-DiagnosticFinding -Name "OWSTimer/SPTimerV4" -Severity Default -Format List
    
        if($null -ne $OWSTimerService)
        {
            #$finding.InputObject = $OWSTimerService
            
            $Script:TimerServiceAccount  = $OWSTimerService.StartName
        }
    
        #return $finding
    }
    
    function Get-SPDiagnosticFindingSPUsageManager()
    {
        $SPUsageManager = [Microsoft.SharePoint.Administration.SPUsageManager]::Local
        $finding = New-DiagnosticFinding -Name "SPUsageManager Details" -Severity Default -Format List
    
        if($null -eq $SPUsageManager)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage = "The SPUSageManager is missing for this farm. Usage Analytics will not function"
        }
        else {
            $finding.InputObject = $SPUsageManager
    
            if($SPUsageManager.LoggingEnabled -eq $false)
            {
                $finding.Severity = [SPDiagnostics.Severity]::Warning
                $finding.WarningMessage = "LoggingEnabled is false on the SPUsageManager. Usage Analytics will not function."
            }
            <# Action when all if and elseif conditions are false #>
        }
    
        return $finding
    }
    
    

    function Get-SPUsageServiceDiagnosticFinding()
    {
        $finding = New-DiagnosticFinding -Name "SPUsageService Details" -Severity Default -Format List
    
        $SPUsageService = Get-SPUsageService
        Add-DiagnosticCommandSnapshot -Finding $finding -CommandName 'Get-SPUsageService' -Records $SPUsageService -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPUsageService' -Coverage 'Usage service settings collected only when UsageAndReporting runs.' -PropertyNames @(
            'Id', 'Name', 'TypeName', 'Status', 'UsageLogDir', 'UsageLogMaxSpaceGB',
            'UsageLogCutTime', 'LoggingEnabled', 'UsageLogMaxFileSize'
        )
        if($null -eq $SPUsageService)
        {
            $finding.WarningMessage = "There is no SPUsageService. This will prevent .usage logs from being created"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            return $finding
        }
        else
        {
            $binding = [System.Reflection.BindingFlags]::Static, [System.Reflection.BindingFlags]::NonPublic
            $type = $SPUsageService.GetType()
            $IsUsageReportingEnabled = $type.GetMethod("IsUsageReportingEnabled", $binding)
            $IsUsageReportingEnabled = $IsUsageReportingEnabled.Invoke($SPUsageService, $null)
        
        }
    
        #$SPUsageService | Add-Member -MemberType NoteProperty -Name "IsUsageReportingEnabled" -value $IsUsageReportingEnabled

        if(!$IsUsageReportingEnabled)
        {
            $finding.WarningMessage += "IsUsageReportingEnabled is returning False. This indicates SPUsageManager logging is disabled, there is no SPUsageManager or the job-usage-log-file-processing is disabled"
        }

        $finding.InputObject = $SPUsageService
    
        $instances = $SPUsageService.Instances | Select-Object Server, Status, NeedsUpgrade, CanUpgrade, IsBackwardsCompatible, ID, Parent, Version | sort-object Server
    
        if($SPUsageService.LoggingEnabled -eq $false)
        {
            $finding.WarningMessage += "SPUsageService Logging is disabled. This will prevent .usage logs from being created"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
        }
    
        if($SPUsageService.Status.ToString().ToLower() -ne "online")
        {
            $finding.WarningMessage += "SPUsageService Status is not online. This will prevent job-usage-log-file-import from processing .usage files and updating importprogress.ini"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
        }
    
    
        if($null -ne $instances)
        {
            $retObj = [PSCustomObject]@{
                Server = $($instances.Server)
                Status = $instances.status
                NeedsUpgrade = $instances.NeedsUpgrade
                CanUpgrade = $instances.CanUpgrade
                IsBackwardsCompatible = $instances.IsBackwardsCompatible
                Id = $instances.ID
                Parent = $($instances.Parent)
                Version = $instances.Version
            }
            
            $instancesFinding = New-DiagnosticFinding -Name "SPUsageService Instances" -Severity Default -Format Table -InputObject $retObj
    
            foreach($instance in $instances)
            {
                $status = $instance.Status
    
                if($status -ne "Online")
                {
                    $instanceFinding = New-DiagnosticFinding -Name "SPUsageService Instance" -Severity Default -Format List -InputObject $instance
                    $server = $instance.Server
                    $instanceFinding.WarningMessage = "The SPUsageService Instance for $server is $status rather than Online. This will prevent job-usage-log-file-import from processing .usage files on this server if it's a WFE"
                    $instancesFinding.ChildFindings.Add($instanceFinding)
                }

            }

            $finding.ChildFindings.Add($instancesFinding)
        }
        else {
            $finding.WarningMessage += "There are no SPUSageService Instances, this will prevent .Usage logs from being processed"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
        }
    
        $applications = $SPUsageService.Applications
        if($null -eq $applications)
        {
            $finding.WarningMessage += "There are no SPUSageService Applications, this will prevent .Usage logs from being processed. See New-SPUSageApplication"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
        }
        else {
            $applicationFinding = New-DiagnosticFinding -Name "SPUSageApplication Instances" -Severity Default -Format List -InputObject $applications
            $finding.ChildFindings.Add($applicationFinding)
        }
    
    
        $Script:UsageLogDir = $SPUsageService.UsageLogDir
    
        if(!$Script:UsageLogDir.EndsWith("\"))
        {
            $Script:UsageLogDir += "\"
        }
    
        $jobDefinitionsFinding = New-DiagnosticFinding -Name "Job Definitions on SPUsageService" -Severity Default -Format Table
    
        $jobDefinitionsCount = [PSCustomObject]@{
            "Job Definition Count" = $SPUsageService.JobDefinitions.Count
        }
    
        $jobDefinitionsFinding.InputObject = $jobDefinitionsCount
    
        foreach($job in $SPUsageService.JobDefinitions)
        {
           
            $jobname = $Job.Name
            $jobDefinitionFinding = New-DiagnosticFinding -Name "Job Definitions: $jobname" -Severity Default -Format List -InputObject $job
            Add-DiagnosticTimerJobSnapshot -Finding $jobDefinitionFinding -Jobs $job -Scope ([ordered]@{ farmId = $script:SPFarm.Id; serviceId = $SPUsageService.Id }) -Source 'SPUsageService.JobDefinitions (existing command-equivalent service enumeration)' -Coverage 'Usage service job definitions inspected by the existing collector; not all farm timer jobs.'
            $JobHistoryFindingEntries = New-DiagnosticFinding -Name "Most Recent 20 Job History Entries" -Severity Default -Format Table 

            $JobHistoryEntries = $job.HistoryEntries | Sort-Object -Descending StartTime | Select-Object Servername, Status, StartTime, EndTime, ErrorMessage -First 20

            $JobHistoryFindingEntries.InputObject = $($JobHistoryEntries)

            $jobDefinitionFinding.ChildFindings.Add($JobHistoryFindingEntries)
            if($job.LastRunTime -eq [System.DateTime]::MinValue)
            {
                $jobDefinitionFinding.Severity = [SPDiagnostics.Severity]::Warning
                $jobDefinitionFinding.WarningMessage += "$jobname has not run"
            }
            elseif($job.LastRunTime -le [System.DateTime]::Now.AddDays(-1))
            {
                $jobDefinitionFinding.Severity = [SPDiagnostics.Severity]::Warning
                $jobDefinitionFinding.WarningMessage += "$jobname Has Not run in over a day"
            }
            
            if($job.IsDisabled  -eq $true)
            {
                $jobDefinitionFinding.Severity = [SPDiagnostics.Severity]::Warning
                $jobDefinitionFinding.WarningMessage += "$jobname is disabled"
            }elseif($RunNow)
            {
                Write-Host " Running Job: $job now"
                $job.RunNow()
            }
    
            $jobDefinitionsFinding.ChildFindings.Add($jobDefinitionFinding)
        }
    
        $finding.ChildFindings.Add($jobDefinitionsFinding)
    
        $JobHistoryFindingEntries = New-DiagnosticFinding -Name "Most Recent 20 Job History Entries On SPUsageService" -Severity Default -Format Table 
        
        $JobHistoryEntries = $SPUsageService.JobHistoryEntries | Sort-Object -Descending StartTime | Select-Object Servername, Status, StartTime, EndTime, ErrorMessage -First 20
    
        $JobHistoryFindingEntries.InputObject = $($JobHistoryEntries)
    
        $finding.ChildFindings.Add($JobHistoryFindingEntries)
    
        return $finding
    }
  
    function Get-SPUsageDefinitionDiagnosticFinding()
    {
        $finding = New-DiagnosticFinding -Name "SPUsageDefinitions" -Severity Default -Format Table
        $definitions = Get-SPUsageDefinition
        $finding.InputObject = $definitions | Select-Object Name, Status, Enabled, EnableReceivers, Retention, DaysToKeepData, DaysToKeepUsageFiles, UsageDatabaseEnabled, TableName, MaxTotalSizeInBytes, Hidden, Description
        Add-DiagnosticCommandSnapshot -Finding $finding -CommandName 'Get-SPUsageDefinition' -Records $definitions -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPUsageDefinition' -Coverage 'Usage definitions collected only when UsageAndReporting runs; selected identity, retention, and enablement settings.' -PropertyNames @(
            'Id', 'Name', 'Status', 'Enabled', 'EnableReceivers', 'Retention',
            'DaysToKeepData', 'DaysToKeepUsageFiles', 'UsageDatabaseEnabled',
            'TableName', 'MaxTotalSizeInBytes', 'Hidden', 'Description'
        )
    
        foreach($definition in $definitions)
        {
          
            # Does this definition usually use receivers? 
            if($script:UsageDefinitionsWithReceivers.Contains($definition.Name))
            {
                $tempName = $definition.Name
                $definitionFinding = New-DiagnosticFinding -Name $tempName -Severity Default -Format List -InputObject $definition

                if(!$definition.EnableReceivers)
                {
                    $definitionFinding.Severity = [SPDiagnostics.Severity]::Warning
                    $definitionFinding.WarningMessage += "$tempName SPUsageReceiverDefinition 'EnableReceivers' is false. This will prevent usage collection for this type."
                }
                
                if($definition.Receivers.Count -eq 0)
                {
                    $definitionFinding.Severity = [SPDiagnostics.Severity]::Warning
                    $definitionFinding.WarningMessage += "$tempName SPUsageReceiverDefinition is missing its EventReceiver. This may be the case if EnableReceivers is false."
                }
    
                foreach($receiver in $definition.Receivers)
                {
                    $receiverFinding = New-DiagnosticFinding -Name $receiver -Severity Default -Format Table -InputObject $definition
                    $assembly = $receiver.ReceiverAssembly
                    
                    if($null -ne $assembly)
                    {
                        $assemblyProperty = [PSCustomObject]@{
                            ReceiverAssembly = $assembly
                        }
    
                        $receiverFinding.InputObject = $assemblyProperty
                        
                        if($assembly.Contains("15.0.0.0") -and $Script:SPFarmBuild.Major -eq "16")
                        {
                            $receiverFinding.Severity = [SPDiagnostics.Severity]::Warning
                            $receiverFinding.WarningMessage = "Assembly version is 15.0.0.0, and SP Version is 2016+. Ensure assembly is loading"
                        }
                    }
    
                    $definitionFinding.ChildFindings.Add($receiverFinding)
                }

                # Check to see that UsageDatabaseEnabled is TRUE. Call out as Informational
                $table = $definition.TableName

                if(!$definition.UsageDatabaseEnabled -and $table -ne "AnalyticsUsage")
                {
                    $definitionFinding.Severity = [SPDiagnostics.Severity]::Informational
                    $definitionFinding.WarningMessage += "$tempName has UsageDatabaseEnabled set to False. This defaults to FALSE on most definitions but note, data will not be recorded to the $table partitions in the Usage Database "
                }
                
                $finding.ChildFindings.Add($definitionFinding)
    
            }
   

        }
    
        return $finding
    }
    
    function Get-UsageAndHealthDataCollectionProxyDiagnosticFinding()
    {
        $finding = New-DiagnosticFinding -Name $script:UsageAndHealthDataCollectionProxyName -Severity Default -Format List -ReferenceLink "https://learn.microsoft.com/en-us/sharepoint/administration/configure-usage-and-health-data-collection"
    
        $UHDCP = Get-SPServiceApplicationProxy | where-object {$_.TypeName -eq $script:UsageAndHealthDataCollectionProxyName}
        if($null -ne $UHDCP)
        {
            $finding.InputObject = $UHDCP
            if($UHDCP.Status -ne "Online")
            {
                $finding.Severity = [SPDiagnostics.Severity]::Warning
                $finding.WarningMessage  = ($script:UsageAndHealthDataCollectionProxyName + " status is " + $UHDCP.Status)
                if($UHDCP.Status -eq "Disabled")
                {
                    $finding.WarningMessage += "Status is Disabled. The Usage and Health Data Collection Proxy may need to be provisioned."
                    $finding.WarningMessage += '     $UsageAppProxy = Get-SPServiceApplicationProxy | Where {$_.TypeName -eq "Usage and Health Data Collection Proxy"}'
                    $finding.WarningMessage += '     $UsageAppProxy.Provision()'
                }
            }
        }
        else {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage = ("There is no " + $script:UsageAndHealthDataCollectionProxyName + " Proxy.")
        }
    
        return $finding
    
    }
    
    function Get-EventTypeDefinitionsDiagnosticFinding()
    {
        $finding = New-DiagnosticFinding -Name "EventType Definitions" -Severity Default -Format Table
    
        if($null -eq $script:ssa)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage = "There is no SSA, no EventTypes will be reported on"
            return $finding
        }
    
        $SSP = Get-SPEnterpriseSearchServiceApplicationProxy
        $tenantConfig = $SSP.GetAnalyticsTenantConfiguration([Guid]::Empty)
        $events = $tenantConfig.EventTypeDefinitions
        $finding.InputObject = $events | select-object EventName, EventTypeId, TailTrimming, LifeTimeManagedPropertyName, RecentManagedPropertyName, RecommendationWeight, RelevanceWeight, RecentPopularityTimeframe, AggregationType, Rollups, Options,IsReadOnly, ApplicationName

        foreach($event in $events)
        {
            if($event.Enabled -eq $false)
            {
                $name = $event.EventName
                $eventFinding = New-DiagnosticFinding -Name $name -Severity Default -Format List -InputObject $event
                $eventFinding.Severity = [SPDiagnostics.Severity]::Informational
                $eventFinding.WarningMessage = "$name is not enabled, this will impact reports relying on $name data. This can be safely ignored for some event types"
                $finding.ChildFindings.Add($eventFinding)
            }

        }
        return $finding
    }
    
    Function Get-EventStoreFolderInfoDiagnosticFinding($ssa)
    {
        $finding = New-DiagnosticFinding -Name "Event Store Folder" -Severity Default
    
        if($null -eq $ssa)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage+= "There is no SSA, No Eventstore Files to be found"
            return $finding
        }
    
        $apcServers = Get-AnalyticsProcessingComponentServers $ssa
        $IsAPCServer = $false
        foreach($apcServer in $apcServers)
        {
            if($apcServer.ServerName -ilike $env:COMPUTERNAME)
            {
                $IsAPCServer = $true
            }
        }
    
        if(!$IsAPCServer)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Informational
            $finding.WarningMessage += "This is not an Analytics Processing Component Server. Skipping EventFolder check. Recommend running script on an APC as well."
            return $finding
        }
    
        $name = "Event Store Folder Info"
        $path = GetEventStorePath
    
        $finding.ChildFindings.Add((Get-FolderInfoDiagnosticFinding $name $path))
      
        return $finding
    }
    
    function GetEventStorePath {
    
        $buildVersion = [string]$Script:SPFarmBuild.Major + "." + [string]$Script:SPFarmBuild.Minor
        $regpath = "HKLM:\Software\Microsoft\Office Server\" + $buildVersion + "\Search\Setup"
        $datapath = (Get-Item $regpath).GetValue("DataDirectory")
    
        $eventshare = Join-Path $datapath "Analytics_$($script:ssa.ApplicationName)"
        $eventstore = Join-Path $eventshare "EventStore"
        return $eventstore
        
    }
    
    Function Get-FolderInfoDiagnosticFinding($findingName, $path)
    {
        $finding = New-DiagnosticFinding -Name $findingName -Severity Default -Format List 
    
        $properties = [PSCustomObject]@{
            Path = $path
        }
        
        $finding.InputObject = $properties
    
        if(![System.IO.Directory]::Exists($path))
        {
            $finding.Format = [SPDiagnostics.Format]::Table
            $finding.WarningMessage += "$path does not exist"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
    
        $folderacls = Get-PermissionsForObject $path
    
        if($null -ne $folderacls)
        {
            $permissionFinding = New-DiagnosticFinding -Name "Permissions for $path" -Severity Default -Format Table 
           
            if($Script:CheckServiceACLs)
            {
                if(![String]::IsNullOrEmpty($Script:TimerServiceAccount))
                {
                    $permissionFinding.ChildFindings.Add((CheckAccountMembership $folderacls $Script:TimerServiceAccount "Timer Service"))
                }
                if(![String]::IsNullOrEmpty($Script:W3WPAppPoolAccount))
                {
                    $permissionFinding.ChildFindings.Add((CheckAccountMembership $folderacls $script:W3WPAppPoolAccount "W3WP App Pool"))
                }
            }
            
            #$permissionFinding.InputObject = $ACLS 
            $permissionFinding.InputObject = $folderacls.access | Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited, InheritanceFlags, PropagationFlags
    
            $finding.ChildFindings.Add($permissionFinding)
            
        }
    
        $items = get-childitem -Path $path -ErrorAction SilentlyContinue -Recurse | Select-Object Name, Length, CreationTime, LastAccessTime,LastWriteTime,Attributes | Sort-Object LastWriteTime -Descending
    
        if($null -ne $items)
        {
            $EventStoreContentFinding =  New-DiagnosticFinding -Name "$findingName Contents" -Severity Default -Format Table -InputObject $items 
            $finding.ChildFindings.Add($EventStoreContentFinding)
        }
        else {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage = "There are no Items in: $path"
        }
         
        return $finding
    }
    
    function Get-PermissionsForObject ($folder) 
    {
        if($NoPermCheck -eq $true) {return}
    
        $folderacls = get-acl $folder -ErrorAction SilentlyContinue
        return $folderacls      
    }
    function CheckAccountMembership($acls, $account, $context)
    {
        $collection = @()
    
        foreach($acl in $acls.Access)
        {
            $identityReference = $acl.IdentityReference
    
            # Does this group begin with the COMPUTERNAME
            $identityReference = $identityReference.ToString().ToLower()
            if($identityReference.StartsWith($env:COMPUTERNAME.ToLower()))
            {
                # Remove Computername from group name for call to Get-LocalGroupMember
                $identityReference = $identityReference.Substring($env:COMPUTERNAME.Length+1)
    
                $localGroupMembers = Get-LocalGroupMember $identityReference
    
                $retObj = $null
                # Identify whether the member is a member of each local group
                foreach($member in $localGroupMembers)
                {
                    # Once you've found the member, you can break from the foreach loop to save time
                    if($member.Name.ToLower() -like $Script:TimerServiceAccount.ToLower())
                    {
                        $retObj = [PSCustomObject]@{
                            Sevice = $context
                            Account =  $Script:TimerServiceAccount
                            "Member Of" = $identityReference
                        }
                        break
                    }
                }
    
                if($null -ne $retObj)
                {
                    $collection += $retObj
                }
            } 
        }
    
        if($collection.Length -gt 0)
        {
            $finding = New-DiagnosticFinding -Name "Account Membership" -Severity Default -Format Table -InputObject $collection
            return $finding
        }
    
    }
    
    Function Get-RequestUsageFolderInfoDiagnosticFinding()
    {
        $name = "RequestsUsage Folder Info"
        $path = $Script:UsageLogDir + "RequestUsage\" 
        $finding = Get-FolderInfoDiagnosticFinding $name $path
    
        $FullFilePath = $path + $script:ImportProgressFile
    
        $importProgressItem = Get-Item -Path $FullFilePath -ErrorAction SilentlyContinue
        
        if($null -ne $finding)
        {
            if($null -ne $importProgressItem)    {
                    $ImportProgressContent = Get-Content $importProgressItem
                    $temp = $finding.InputObject
                    $temp | Add-Member -MemberType NoteProperty -Name $script:ImportProgressFile -Value "$ImportProgressContent"
                    $finding.InputObject = $temp
            }
            else {
                $finding.Severity = [SPDiagnostics.Severity]::Warning
                $finding.WarningMessage += $script:ImportProgressFile + " Not Found, ensure that job-usage-log-file-import is running"
            }
        }
    
    
        return $finding
    }
    
    function Get-UsageAnalyticsInfoDiagnosticFinding
    {
        $finding = New-DiagnosticFinding -Name "Usage Analytics Timerjob Information" -Severity Default -Format List 
    
        if($null -eq $script:ssa)
        {
            $finding.WarningMessage = "No SSA Present, There will be no Usage Analytics Timer Job"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
        
        $usageAnalyticsJobName = "Usage Analytics Timer Job for Search Application " + $script:ssa.Id
        $usageJob = Get-SPTimerJob | Where-Object{$_.Name -eq $usageAnalyticsJobName}
        Add-DiagnosticTimerJobSnapshot -Finding $finding -Jobs $usageJob -Scope ([ordered]@{ farmId = $script:SPFarm.Id; serviceApplicationId = $script:ssa.Id }) -Source 'Get-SPTimerJob filtered by usage analytics job name' -Coverage 'The selected search application usage analytics job; not all farm timer jobs.'
    
        if($usageJob)
        {
            $finding.InputObject = $usageJob
            $analysisInfo = $usageJob.GetAnalysisInfo()
            $AnalysisInfoFinding = New-DiagnosticFinding -Name "Analysis Information from TimerJob" -Severity Default -Format List -InputObject $analysisInfo
           
            if($analysisInfo.LastRunFailedErrorMsg.Contains("is not of the expected format"))
            {
                $AnalysisInfoFinding.Severity = [SPDiagnostics.Severity]::Critical
                $AnalysisInfoFinding.WarningMessage += "Analysis Info LastRunFailedErrorMsg:" + $analysisInfo.LastRunFailedErrorMsg
                $AnalysisInfoFinding.WarningMessage += "Ensure that the Timer Service account's regional date format in the OS Settings is using a date format that uses '/' as a date separator."
                $AnalysisInfoFinding.WarningMessage += "This will prevent Analytics Data from being processed, and reports will be inaccurate."
            }

            $finding.ChildFindings.Add($AnalysisInfoFinding)
        }
        else
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage += ("The Usage Analytics Timer Jobs is missing for this SSA: " + $script:ssa.Name)
        }
    
        return $finding
    }
    
    function Get-SearchAnalysisEngineInformationDiagnosticFinding
    {
        $finding = New-DiagnosticFinding -Name "AnalyticsJobDefinition Jobs" -Severity Default -Format List 
    
        if($null -eq $script:ssa)
        {
            $finding.WarningMessage = "No SSA Present, There will be no Usage Analytics Timer Job"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
    
    
        $jobs = get-sptimerjob | Where-Object{$_.TypeName -like "Microsoft.Office.Server.Search.Analytics.AnalyticsJobDefinition"}
        Add-DiagnosticTimerJobSnapshot -Finding $finding -Jobs $jobs -Scope ([ordered]@{ farmId = $script:SPFarm.Id; collectorServiceApplicationId = $script:ssa.Id }) -Source 'Get-SPTimerJob filtered by AnalyticsJobDefinition type' -Coverage 'Analytics job definitions inspected in the selected search application collector context; scope does not establish job ownership.'
    
        if($null -eq $jobs) 
        {
            $finding.WarningMessage = "Microsoft.Office.Server.Search.Analytics.AnalyticsJobDefinition TimerJob not found"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
    
        foreach($job in $jobs)
        {
            $jobFinding =  New-DiagnosticFinding -Name $job.Name -Severity Default -Format List -InputObject $job
    
            $analysisjobs = $job.Analyses 
    
            foreach($analysisjob in $analysisjobs)
            {
                $analysisJobFinding = New-DiagnosticFinding -Name $analysisjob.Name -Severity Default -Format List -InputObject $analysisjob
    
                $analysisInfo = $analysisjob.GetAnalysisInfo()
                if($analysisInfo)
                {
                      $AnalysisInfoFinding = New-DiagnosticFinding -Name "Analysis Info" -Severity Default -Format List -InputObject $analysisInfo
                    if($analysisInfo.LastRunFailedErrorMsg.Contains("is not of the expected format"))
                    {
                        $AnalysisInfoFinding.Severity = [SPDiagnostics.Severity]::Critical
                        $AnalysisInfoFinding.WarningMessage += "Analysis Info LastRunFailedErrorMsg:" + $analysisInfo.LastRunFailedErrorMsg
                        $AnalysisInfoFinding.WarningMessage += "Ensure that the Timer Service account's regional date format in the OS Settings is using a date format that uses '/' as a date separator."
                        $AnalysisInfoFinding.WarningMessage += "This will prevent Analytics Data from being processed, and reports will be inaccurate."
                    }
                    $analysisJobFinding.ChildFindings.Add($AnalysisInfoFinding)
                }
                else {
                    $analysisJobFinding.Severity = [SPDiagnostics.Severity]::Informational
                    $analysisJobFinding.WarningMessage += "No Analysis Info found"
                }

                $analysisConfiguration = $analysisjob.GetAnalysisConfiguration()
                if($analysisConfiguration)
                {
                    $AnalysisConfigurationFinding =  New-DiagnosticFinding -Name "Analysis Configuration" -Severity Default -Format Table -InputObject $analysisConfiguration
                    $analysisJobFinding.ChildFindings.Add($AnalysisConfigurationFinding)
    
                }else {
                    $analysisJobFinding.Severity = [SPDiagnostics.Severity]::Informational
                    $analysisJobFinding.WarningMessage += "No Analysis Configuration found"
                }
    
                # checking and calling out LastRunCompletedTime
    
                $LastRunCompletedTime = $info.LastRunCompletedTime
                if($null -ne $LastRunCompletedTime)
                {
                    $timespan = (Get-Date) - $LastRunCompletedTime
                    if($timespan.Days -gt 3)
                    {
                        $analysisJobFinding.Severity = [SPDiagnostics.Severity]::Warning
                        $analysisJobFinding.WarningMessage += " It's been more than 3 days since the AnalyticsJobDefinition LastRunCompletedTime was successful"
                    }
                }
                $jobFinding.ChildFindings.Add($analysisJobFinding)
            }
    
            $finding.ChildFindings.Add($jobFinding)
        }
        
        return $finding
    }
    
    function Get-AnalyticsProcessingComponentServers($ssa)
    {
        $ActiveTopology = $ssa.ActiveTopology
        $components = $ActiveTopology.GetComponents() 
        $AnalyticsProcessComponents = @()
        foreach($component in $components)
        {
            if($component.GetType().Name -ilike 'AnalyticsProcessingComponent')
            {
                $AnalyticsProcessComponents += $component
            }
        }
        return $AnalyticsProcessComponents
    }

    $UsageAndReportFinding = New-DiagnosticFinding -Name "Usage Analysis and Reporting Findings" -InputObject $null -Format Table
    Set-OWSTimerServiceAccountForScript

    #$UsageAndReportFinding.ChildFindings.Add((Get-SPDiagnosticFarmFindings))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPAnalyticsTopologyDiagnosticFinding $script:ssa))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPDiagnosticSitePropertiesOfInterest $site))
    
    $UsageAndReportFinding.ChildFindings.Add((Get-SPDiagnosticFindingSPUsageManager))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPUsageServiceDiagnosticFinding))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPUsageDefinitionDiagnosticFinding))
    $UsageAndReportFinding.ChildFindings.Add((Get-UsageAndHealthDataCollectionProxyDiagnosticFinding))
    $UsageAndReportFinding.ChildFindings.Add((Get-EventTypeDefinitionsDiagnosticFinding))
    $UsageAndReportFinding.ChildFindings.Add((Get-EventStoreFolderInfoDiagnosticFinding $script:ssa))
    $UsageAndReportFinding.ChildFindings.Add((Get-RequestUsageFolderInfoDiagnosticFinding))
    $UsageAndReportFinding.ChildFindings.Add((Get-UsageAnalyticsInfoDiagnosticFinding))
    $UsageAndReportFinding.ChildFindings.Add((Get-SearchAnalysisEngineInformationDiagnosticFinding))

    return $UsageAndReportFinding
}


#endregion


#region TLS
<#
    Required actions per version:
        2019
            - N/A 1.2 is used by default

        2016
            - ODBC driver 11 must be installed
                https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016#ODBC1.1
            - SQL 2012 Native Clinet for 1.2 support
                https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016#sql2012

        2013
            - Enable TLS 1.1/1.2 in Schannel
            - Enable TLS 1.1/1.2 in WinHTTP
            - Enable TLS 1.1/1.2 in Internet Explorer
            - Install SQL Server 2008 R2 Native CLient w/TLS 1.2 support

        2010
            - Enable TLS 1.1/1.2 in Schannel
            - Enable TLS 1.1/1.2 in WinHTTP
            - Enable TLS 1.1/1.2 in Internet Explorer
            - Install SQL Server 2008 R2 Native CLient w/TLS 1.2 support
            - Install ADO.NET 2.0 SP2 upate
            - Install .Net framework update

        Optional (applies to all versions):
            - Enable strong cryptography in .Net 3.5
            - Disable earlier versions of TLS in Schannel
#>


function Get-RegistryValue
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string]
        $ServerName,

        [Parameter()]
        [Microsoft.Win32.RegistryHive]
        $RegistryHive = [Microsoft.Win32.RegistryHive]::LocalMachine,

        [Parameter()]
        [String]
        $Key,

        [Parameter()]
        [string]
        $Property
    )

    if([string]::Equals($ServerName, [Microsoft.SharePoint.Administration.SPServer]::Local.Name, [system.StringComparison]::InvariantCultureIgnoreCase))
    {
        switch ($RegistryHive)
        {
            ClassesRoot {$root = "HKCR"}
            CurrentConfig {$root = "HKCC"}
            CurrentUser {$root = "HKCU"}
            LocalMachine {$root = "HKLM"}
            PerformanceData {$root = "HKPD"}
            Users   {$root = "HKU"}
            default {$root = "HKLM"}
        }

        $regPath = "{0}:\{1}" -f $root, $Key

        $itemProp = Get-ItemProperty -Path $regPath -Name $Property -ErrorAction SilentlyContinue
        return $itemProp.$Property
        


    }
    else
    {
        $keyPath = $Key.Replace("\", "\\")
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $ServerName)
        $regKey = $reg.OpenSubKey($keyPath)
        if($null -eq $regKey)
        {
            return $null
        }

        $value = $regKey.GetValue($Property)
        return $value
    }
}

function checkFriendlyName ([string]$checkName)
{
    switch ($checkName)
    {
        oldTlsVersionsDisabled          {return "Disable earlier versions of TLS in Windows Schannel"}
        tlsEnabledInSchannel            {return "Enable TLS 1.1 and 1.2 support in Windows Schannel"}
        tlsEnabledInWinHTTP             {return "Enable TLS 1.1 and 1.2 support in WinHTTP"}
        sql2008R2NativeClientUpdated    {return "Install SQL Server 2008R2 Native Client update for TLS 1.2 support"}
        sql2012NativeClientUpdated      {return "Install SQL Server 2012 Native Client update for TLS 1.2 support"}
        adoNetUpdated                   {return "Install ADO.NET 2.0 SP2 update for TLS 1.1 and TLS 1.2 support"}
        strongCyptographyEnabled4       {return "Enable strong cryptography in .NET Framework 4.6 or higher"}
        strongCyptographyEnabled2       {return "Enable strong cryptography in .NET Framework 3.5"}
        netDefaultTlsVersion            {return "Install .Net Framework 3.5 update for TLS 1.1 and TLS 1.2 support"}
        odbc11Updated                   {return "Install OBDC Driver 11 for SQL Server update for TLS 1.2 support"}
        net46orHigherInstalled          {return "Install .Net Framework 4.6 or higher"}
    }
    
}

function oldTlsVersionsDisabled ($ServerName)
{
    if
    (
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Property "DisabledByDefault") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Property "DisabledByDefault") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Property "DisabledByDefault") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Property "DisabledByDefault") -eq 1
    )
    {
        return $true
    }
    
    return $false
}


function tlsEnabledInSchannel ($ServerName)
{
    if
    (
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client\TLS 1.2" -Property "DisabledByDefault") -eq 0 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Client\TLS 1.2" -Property "Enabled") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2" -Property "DisabledByDefault") -eq 0 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2" -Property "Enabled") -eq 1
    )
    {
        #it's explicitly enabled, return true
        return $true
    }
    elseif 
    (
        $null -eq (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2" -EA 0) -or
        (
            $null -eq (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2\Client" -EA 0) -and
            $null -eq (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Server\TLS 1.2\Server" -EA 0)
        )
    ) 
    {
        return $true
    }

    return $false
}


function tlsEnabledInWinHTTP ($ServerName)
{
    $64value = Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Property "DefaultSecureProtocols"
    $32value = Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Property "DefaultSecureProtocols"

    if
    (
        $64value -band 2048 -gt 0 -and
        $32value -band 2048 -gt 0
    )
    {
        return $true
    }

    return $false
}


function sql2008R2NativeClientUpdated ($ServerName)
{
    $products = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($product in $products)
    {
        try 
        {
            if($product.GetValue("DisplayName").Contains("Microsoft SQL Server 2008 R2 Native Client"))
            {
                $locatedVersion = New-Object "System.Version" -ArgumentList @($product.GetValue("DisplayVersion"))
                break
            }
        }
        catch {}
    }
    
    if($locatedVersion.Build -ge 6560)
    {
        return $true
    }

    return $false
}


function adoNetUpdated
{
    #later... maybe...
}


function strongCyptographyEnabled4 ($ServerName)
{
    if
    (
        (Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Property "SchUseStrongCrypto") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Property "SchUseStrongCrypto") -eq 1
    )
    {
        return $true
    }
    
    return $false
}

function strongCyptographyEnabled2 ($ServerName)
{
    if
    (
        (Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Property "SchUseStrongCrypto") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Property "SchUseStrongCrypto") -eq 1
    )
    {
        return $true
    }
    
    return $false
}


function netDefaultTlsVersion ($ServerName)
{
    if
    (
        (Get-RegistryValue -ServerName $ServerName -Key "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Property "SystemDefaultTlsVersions") -eq 1 -and
        (Get-RegistryValue -ServerName $ServerName -Key "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Property "SystemDefaultTlsVersions") -eq 1
    )
    {
        return $true
    }

    return $false
}


function odbc11Updated ($ServerName)
{
    $products = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($product in $products)
    {
        try 
        {
            if($product.GetValue("DisplayName").Contains("Microsoft ODBC Driver 11 for SQL Server"))
            {
                $locatedVersion = New-Object "System.Version" -ArgumentList @($product.GetValue("DisplayVersion"))
                break
            }
        }
        catch {}
    }
    
    if($locatedVersion.Build -ge 5543)
    {
        return $true
    }

    return $false
}


function sql2012NativeClientUpdated
{
    $products = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    foreach ($product in $products)
    {
        try 
        {
            if($product.GetValue("DisplayName").Contains("Microsoft SQL Server 2012 Native Client"))
            {
                $locatedVersion = New-Object "System.Version" -ArgumentList @($product.GetValue("DisplayVersion"))
                break
            }
        }
        catch {}
    }
    
    if($locatedVersion.Build -ge 7001)
    {
        return $true
    }

    return $false
}


function net46orHigherInstalled ($ServerName)
{
    if
    (
        (Get-RegistryValue -ServerName $ServerName -Key "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Property "Release") -ge 393295
    )
    {
        return $true
    }

    return $false
}


function getWindowsVersion ($ServerName)
{
    $v = [version](Get-WmiObject Win32_OperatingSystem -ComputerName $ServerName -ErrorAction Stop).Version
    switch ($v.Major) {
        6
        {
            if($v.Minor -eq 1)
            {
                return "2008R2"
            }
            elseif($v.Minor -eq 2)
            {
                return "2012"
            }
            elseif($v.Minor -eq 3)
            {
                return "2012R2"
            }
        }
        10
        {
            return "2016+"
        }
        Default {}
    }
}

#AzureFrontDoorCiphersEnabled joeric-2019-wfe
function AzureFrontDoorCiphersEnabled ($ServerName)
{
    $afdCiphers = @(
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    )
    $supportedCiphers = New-Object System.Collections.ArrayList
    $priorityThreshold = 10
    $priorityWarning = $false

    $regLocations = @(
        "SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL"
        "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL"
    )

    $registryHive  = [Microsoft.Win32.RegistryHive]::LocalMachine
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($registryHive, $ServerName)
    foreach ($regLocation in $regLocations)
    {
        $keyPath = $regLocation.Replace("\", "\\")
        $key = $reg.OpenSubKey($keyPath)
        foreach ($subKeyName in $key.GetSubKeyNames())
        {
            if($subKeyName.EndsWith("00010002"))
            {
                $subKey = $key.OpenSubKey($subKeyName)
                $cipherString = $subKey.GetValue("Functions")
                if(![String]::IsNullOrEmpty($cipherString))
                {
                    $ciphers = $cipherString.Split(",")
                    foreach($afdCipher in $afdCiphers)
                    {
                        if($ciphers.Contains($afdCipher) -and !$supportedCiphers.Contains($afdCipher))
                        {
                            $supportedCiphers+=[PSCustomObject]@{
                                SupportedCipher = $afdCipher.ToString()
                            }
                            $idx = $ciphers.IndexOf($afdCipher)
                            if($idx -gt $priorityThreshold-1)
                            {
                                $priorityWarning = $true
                            }
                        }
                    }
                }
            }
        }
    }
    
    $afdFinding = New-DiagnosticFinding `
        -Name ("Azure Front Door Compatible Ciphers: {0}" -f $ServerName) `
        -Description "Azure Front Door (AFD) serves as a gateway for much of M365, as such most hybrid scenarios require the ability to establish a secure connection to AFD." `
        -ReferenceLink "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq#what-are-the-current-cipher-suites-supported-by-azure-front-door-"

    if($supportedCiphers.Count -le 0)
    {
        $afdFinding.Severity = [SPDiagnostics.Severity]::Warning
        $afdFinding.WarningMessage += "No supported ciphers found to communicate with AFD. If hybrid functionality is intending to be used, or currently being used, this should be addressed."
    }
    else
    {
        $afdFinding.InputObject = $supportedCiphers
        $afdFinding.Format = [SPDiagnostics.Format]::Table

        if($priorityWarning)
        {
            #Write-Warning "Priority of Azure Front Door compatible ciphers may be too low"
            $afdFinding.WarningMessage+="Priority of Azure Front Door compatible ciphers may be too low. If hybrid functionality is encountering any issues, this should be investigated."
            $afdFinding.Severity = [SPDiagnostics.Severity]::Warning
            $afdFinding.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/troubleshoot/administration/authentication-errors-tls12-support"
        }
    }

    if((Get-WmiObject Win32_OperatingSystem -ErrorAction Stop).Version.StartsWith("6."))
    {
        $afdFinding.WarningMessage+="Pre windows 2016 detected, even with proper ciphers enabled there may still be intermittent issues, please refer to reference articles for more information."
        $afdFinding.Severity = [SPDiagnostics.Severity]::Warning
        $afdFinding.WarningMessage += "https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/apps-forcibly-closed-tls-connection-errors"
    }

    return $afdFinding
}

function Get-SPDiagnosticsTlsFinding
{
    $finding = New-DiagnosticFinding `
        -Name "TLS Configuration" `
        -InputObject $null `
        -Description "These findings are specific to enabling and providing support for TLS 1.2 connections, this is necessary in environments where TLS 1.0/1.1 has been disabled or when enabling hybrid or other functionality that requires connectivity to TLS 1.2 secured resources. Please refer to the reference material for more information."

    $spVersion = Get-SPVersion
    switch ($spVersion) {
        2013
        {
            $finding.ReferenceLink += New-Object -TypeName Uri -ArgumentList "https://docs.microsoft.com/en-us/SharePoint/security-for-sharepoint-server/enable-tls-and-ssl-support-in-sharepoint-2013"
        }
        2016
        {
            $finding.ReferenceLink += New-Object -TypeName Uri -ArgumentList "https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2016"
        }
        2019
        {
            $finding.Description += "SharePoint Server 2019 natively support TLS1.2, there are no configurations necessary."
            $finding.ReferenceLink += New-Object -TypeName Uri -ArgumentList "https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2019"
        }
        SPSE
        {
            $finding.Description += "SharePoint Server Subscription Edition natively support TLS1.2, there are no configurations necessary."
            $finding.ReferenceLink += New-Object -TypeName Uri -ArgumentList "https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-server/enable-tls-1-1-and-tls-1-2-support-in-sharepoint-server-2019"
        }
        Default {}
    }

    $servers = $script:servers | Where-Object {$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    foreach($server in $servers)
    {
        try 
        {
            
            $serverFinding = New-DiagnosticFinding `
                -Name ("TLS Configurations: {0}" -f $server.Name) `
                -InputObject $null
            
            $winVersion = getWindowsVersion -ServerName $server.Name
            $checks = @()
            switch ($spVersion) {
                2010
                {
                    #Not investing in writing analyzers for 2010.
                    return $null
                }
                2013
                {
                    switch ($winVersion)
                    {
                        2008R2
                        {
                            $checks+="tlsEnabledInSchannel,True"
                            $checks+="tlsEnabledInWinHTTP,True"
                        }
                        2012
                        {
                            $checks+="tlsEnabledInWinHTTP,True"
                        }
                        2012R2
                        {
                            #
                        }
                        Default {}
                    }
                    $checks+="sql2008R2NativeClientUpdated,True"
                    $checks+="net46orHigherInstalled,True"
                    $checks+="strongCyptographyEnabled4,True"
                    $checks+="strongCyptographyEnabled2,False"
                    $checks+="oldTlsVersionsDisabled,False"
                }
                2016
                {
                    $checks+="odbc11Updated,True"
                    $checks+="sql2012NativeClientUpdated,True"
                    $checks+="strongCyptographyEnabled4,False"
                    $checks+="strongCyptographyEnabled2,False"
                    $checks+="oldTlsVersionsDisabled,False"
                }
                2019
                {
                    $checks+="oldTlsVersionsDisabled,False"
                }
                SPSE
                {
                    $checks+="oldTlsVersionsDisabled,False"
                }
                Default {}
            }


            $results = @()
            foreach($check in $checks)
            {
                $results+=[PSCustomObject]@{
                    Name = checkFriendlyName $check.Split(",")[0]
                    Required = $check.Split(",")[1]
                    Configured = (Invoke-Expression ("{0} -ServerName `"{1}`"" -f $check.Split(",")[0], $server.Name))
                }
            }

            #AzureFrontDoorCiphersEnabled
            $afdFinding = AzureFrontDoorCiphersEnabled -ServerName $server.Name
            
            if(!!($results | Where-Object{![bool]::Parse($_.Configured) -and [bool]::Parse($_.Required)}))
            {
                $serverFinding.WarningMessage += "Required configurations for TLS 1.2 support have not been made, this is necessary in environments where TLS 1.0/1.1 has been disabled or when enabling hybrid or other functionality that requires connectivity to TLS 1.2 secured resources."
            }

            $serverFinding.InputObject = $results
            $serverFinding.Format = "Table"
            $serverFinding.ChildFindings.Add($afdFinding)      
        }
        catch
        {
            $serverFinding.WarningMessage += "Could not generate finding for this server"
        }
        finally
        {
            $finding.ChildFindings.Add($serverFinding)
        }
        
    }
    return $finding
}
#endregion

#region DistributedCache
Function Get-SPDiagnosticsDCacheFinding
{
    $DCacheFindings = New-DiagnosticFinding -Name "Distributed Cache" -InputObject $null -Format List

    #DCache data collection works only on servers that host the Distributed Cache
    if ( ($Null -eq (get-spserviceInstance | Where-Object{$_.typename -match "Cache" -and $_.Status -ne "disabled" -and $_.Server.Name -eq $env:ComputerName}))  -or (!(IsElevated)))
    {
        $DcacheFindings.Description += 'Data collection for Distributed Cache works only on Servers that host a Distributed Cache Instance and this script is running in a PowerShell session that was started with "Run as Administrator"'
    }
    else
    {
        #Get DCache Servers in SPSE
        $DCacheServers = (get-spserviceInstance | Where-Object{$_.typename -match "Cache" -and $_.Status -ne "disabled"} | Select-Object server).server.name

        $SPSE = ($Script:Build -eq "SPSE")

        if ($SPSE)
        {
            #Get DCache Server Config
            $DCacheHostConfig = $DCacheServers | ForEach-Object { Get-SPCacheHostConfig -HostName $_ }

            #Get DCache Server Status
            $DCacheHostStatus = $DCacheHostConfig  | ForEach-Object { Get-SPCacheHost -HostName $_.HostName -CachePort $_.CachePort}

            #Cache Names and Host
            $Caches = Get-SPCache

        }
        else
        {
            Use-CacheCluster

            #Get DCache Server Config
            $DCacheHostConfig = $DCacheServers | ForEach-Object { Get-CacheHostConfig -HostName $_ -Port 22233 }

            #Get DCache Server Status
            $DCacheHostStatus = Get-CacheHost

            #Cache Names and Host
            $Caches = Get-Cache

        }

        #CacheHost Status
        $CacheHostStatus = @()
        foreach ($ch in $DCacheHostStatus)
        {
            $chd = New-Object psobject
            $chd | add-Member -MemberType NoteProperty -Name "Hostname" -Value $($ch.HostName)
            $chd | add-Member -MemberType NoteProperty -Name "PortNo" -Value $ch.PortNo
            $chd | add-Member -MemberType NoteProperty -Name "ServiceName" -Value $ch.ServiceName
            $chd | add-Member -MemberType NoteProperty -Name "Status" -Value $ch.Status
            $chd | add-Member -MemberType NoteProperty -Name "VersionInfo" -Value $ch.VersionInfo
            $CacheHostStatus += $chd
        }

        $DCacheHStatus = New-DiagnosticFinding -Name "  Distributed Cache Host Status" -InputObject $CacheHostStatus -Format Table
        $DCacheFindings.ChildFindings.Add(($DCacheHStatus))
        if($Performance)
        {
        $script:TotalDCacheReserved=0
        #CacheHost Configuration
        $CacheHostConfig= @()
        foreach($dchs in $DCacheHostConfig)
        {
            $chs = new-Object PSObject
            $chs | Add-Member -MemberType NoteProperty -Name "HostName" -Value $($dchs.HostName)
            $chs | Add-Member -MemberType NoteProperty -Name "ClusterPort" -Value $dchs.ClusterPort
            $chs | Add-Member -MemberType NoteProperty -Name "CachePort" -Value $dchs.CachePort
            $chs | Add-Member -MemberType NoteProperty -Name "ArbitrationPort" -Value $dchs.ArbitrationPort
            $chs | Add-Member -MemberType NoteProperty -Name "ReplicationPort" -Value $dchs.ReplicationPort
            $chs | Add-Member -MemberType NoteProperty -Name "Size" -Value $dchs.Size.ToString('N0')
            $chs | Add-Member -MemberType NoteProperty -Name "ServiceName" -Value $dchs.ServiceName
            $chs | Add-Member -MemberType NoteProperty -Name "HighWatermark" -Value $dchs.HighWatermark.ToString('N0')
            $chs | Add-Member -MemberType NoteProperty -Name "LowWatermark" -Value $dchs.LowWatermark.ToString('N0')
            $chs | Add-Member -MemberType NoteProperty -Name "IsLeadHost" -Value $dchs.IsLeadHost
            $CacheHostConfig += $chs
            $script:TotalDCacheReserved +=$dchs.Size
        }
        $DCacheHConfig = New-DiagnosticFinding -Name "  Distributed Cache Host Configuration" -InputObject $CacheHostConfig -Format Table
        if(IsElevated)
        {
            $InstalledMem = 0
            (((get-WmiObject Win32_PhysicalMemory) | ForEach-Object { $InstalledMem += $_.Capacity}))
            $InstalledMem = $InstalledMem / 1MB
            
            if ($dchs.size -gt (($InstalledMem - 2048) / 2))
            {
                $DCacheHConfig.WarningMessage = "Distributed Cache size is too large on server" 
                $DCacheHConfig.Severity = [SPDiagnostics.Severity]::Warning
            }
            if ($dchs.size -lt (($InstalledMem -2048) / 10))
            {
                $DCacheHConfig.description += "Distributed Cache  size could be too small on server" 
                $DCacheHConfig.Severity = [SPDiagnostics.Severity]::Informational
            }
            if ($DCacheHConfig.WarningMessage.Count -gt 0)                          
            {
                $DCacheHConfig.ReferenceLink = [uri]"https://learn.microsoft.com/en-us/sharepoint/administration/manage-the-distributed-cache-service?tabs=SCS1%2CSCS2%2CSCS3%2CSCS%2CSCS4#change-the-memory-allocation-of-the-distributed-cache-service"
                $DCacheHConfig.ReferenceLink = [uri]"https://learn.microsoft.com/en-us/sharepoint/administration/plan-for-feeds-and-the-distributed-cache-service"
                #$DCacheHConfig.Severity = [SPDiagnostics.Severity]::Warning
            }
        }    
        $DCacheHConfig.Description += "Total memory reserved on all Distributed Cache Hosts: $(($script:TotalDCacheReserved *1MB).ToString('N0')) Bytes"
        $DCacheFindings.ChildFindings.Add(($DCacheHConfig))


        #Individual Cache Statistics
        $DCacheStatitistics = @()
        $DCacheStatisticsFindings = New-DiagnosticFinding -Name "  Distributed Cache Statistics" -InputObject $Null -Format Table
        if (!(IsElevated))
        {
            $DCacheStatisticsFindings.Description += "Distributed Cache Statistics can only be executed when the script is running executed with 'Run as Administrator'."

        } else {

            #foreach ($CacheContainerType in [enum]::GetNames("Microsoft.SharePoint.DistributedCaching.Utilities.SPDistributedCacheContainerType"))
            $script:TotalDCacheBytes=0
            $failedCacheStatistics=0
            foreach ($Cache in $Caches)
            {
                $css = $null
                try
                {
                    if ($SPSE)
                    {
                        $css = Get-SPCacheStatistics -CacheName $cache.CacheName -ErrorAction Stop
                    } else {
                        $css = Get-CacheStatistics -CacheName $cache.CacheName -ErrorAction Stop
                    }
                    if ($null -eq $css)
                    {
                        throw "No statistics were returned."
                    }
                    $missingCounters = @(
                        'Size', 'ItemCount', 'RegionCount', 'RequestCount',
                        'ReadRequestCount', 'WriteRequestCount', 'MissCount',
                        'IncomingBandwidth', 'OutgoingBandwidth'
                    ) | Where-Object { $null -eq $css.$_ }
                    if ($missingCounters)
                    {
                        throw "Statistics did not include required values: $($missingCounters -join ', ')."
                    }
                }
                catch
                {
                    $message = "Could not collect Distributed Cache statistics for '$($cache.CacheName)': $($_.Exception.Message)"
                    Write-Warning $message
                    $DCacheStatisticsFindings.WarningMessage += $message
                    $DCacheStatisticsFindings.Severity = [SPDiagnostics.Severity]::Warning
                    $failedCacheStatistics++
                    continue
                }
                $cs = New-Object PSObject 
                $cs | Add-Member -MemberType NoteProperty -Name "Name" -value $cache.CacheName
                $cs | Add-Member -MemberType NoteProperty -Name "Host" -value $($($cache.HostRegionMap.Keys[0]))
                $cs | Add-Member -MemberType NoteProperty -Name "Size" -value $css.Size.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "ItemCount" -value $css.ItemCount.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "RegionCount" -value $css.RegionCount
                $cs | Add-Member -MemberType NoteProperty -Name "RequestCount" -value $css.RequestCount.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "ReadRequestCount" -value $css.ReadRequestCount.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "WriteRequestCount" -value $css.WriteRequestCount.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "MissCount" -value $css.MissCount.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "IncomingBandwidth" -value $css.IncomingBandwidth.ToString('N0')
                $cs | Add-Member -MemberType NoteProperty -Name "OutgoingBandwidth" -value  $css.OutgoingBandwidth.ToString('N0')
                $DCacheStatitistics += $cs
                $script:TotalDCacheBytes += $css.Size
            }
            $DCacheStatisticsFindings.InputObject = $DCacheStatitistics 
            if ($failedCacheStatistics -eq 0)
            {
                $DCacheStatisticsFindings.Description +="Total Memory used for all cached data: $($script:TotalDCacheBytes.ToString('N0')) Bytes."
            }
            elseif ($DCacheStatitistics.Count -gt 0)
            {
                $DCacheStatisticsFindings.Description += "Partial results: memory used by $($DCacheStatitistics.Count) caches with available statistics: $($script:TotalDCacheBytes.ToString('N0')) Bytes. Statistics for $failedCacheStatistics caches could not be collected; total memory used for all cached data is unavailable."
            }
            else
            {
                $DCacheStatisticsFindings.Description += "Statistics for all $failedCacheStatistics queried caches could not be collected; total memory used for all cached data is unavailable."
            }
        }
        $DCacheFindings.ChildFindings.Add(($DCacheStatisticsFindings))

        #Distributed Cache Client Settings
        $RequestTimeoutToLow =@()
        $ChannelOpenTimeoutToLow=@()
        $MaxConnectionsToServerToHigh=@()

        $DCacheClientSettingsFindings = New-DiagnosticFinding -Name "  Distributed Cache Client Settings" -InputObject $DCacheClientSettings -Format Table
        $DCacheClientSettings=@()
        foreach ($Cache in $Caches)
        {
            $CacheType = $Cache.CacheName.Split("_")[0]
            $CacheTypes = [enum]::GetNames("Microsoft.SharePoint.DistributedCaching.Utilities.SPDistributedCacheContainerType")
            if ($CacheTypes -contains $CacheType)
            {
                if ($SPSE)
                {
                    $CacheClientSettings = Get-SPDistributedCacheClientSetting -ContainerType $CacheType
                } else {
                    $CacheClientSettings = Get-SPDistributedCacheClientSetting -ContainerType $CacheType
                }

                foreach ($ccs in $CacheClientSettings)
                {
                    $cc = New-Object PSObject
                    $cc | Add-Member -MemberType NoteProperty -Name "Name" -Value $CacheType
                    $cc | Add-Member -MemberType NoteProperty -Name "Host" -value $($($cache.HostRegionMap.Keys[0]))
                    $cc | Add-Member -MemberType NoteProperty -Name "ChannelInitializationTimeout" -Value $ccs.ChannelInitializationTimeout
                    $cc | Add-Member -MemberType NoteProperty -Name "ConnectionBufferSize" -Value $ccs.ConnectionBufferSize
                    $cc | Add-Member -MemberType NoteProperty -Name "MaxBufferPoolSize" -Value $ccs.MaxBufferPoolSize
                    $cc | Add-Member -MemberType NoteProperty -Name "MaxBufferSize" -Value $ccs.MaxBufferSize
                    $cc | Add-Member -MemberType NoteProperty -Name "MaxOutputDelay" -Value $ccs.MaxOutputDelay
                    $cc | Add-Member -MemberType NoteProperty -Name "ReceiveTimeout" -Value $ccs.ReceiveTimeout
                    $cc | Add-Member -MemberType NoteProperty -Name "ChannelOpenTimeOut" -Value $ccs.ChannelOpenTimeOut
                    $cc | Add-Member -MemberType NoteProperty -Name "RequestTimeout" -Value $ccs.RequestTimeout
                    $cc | Add-Member -MemberType NoteProperty -Name "MaxConnectionsToServer" -Value $ccs.MaxConnectionsToServer

                    if ($ccs.RequestTimeout -lt 3000)
                    {
                        #$DCacheClientSettingsFindings.WarningMessage +="$($CacheType): The RequestTimeout could be set too low" 
                        $RequestTimeoutToLow += $CacheType
                    }

                    if ($ccs.ChannelOpenTimeOut -lt 3000)
                    {
                        #$DCacheClientSettingsFindings.WarningMessage +="$($CacheType): The ChannelOpenTimeout could be set too low" 
                        $ChannelOpenTimeoutToLow += $CacheType
                    }

                    if ($ccs.MaxConnectionsToServer -gt 1)
                    {
                        #$DCacheClientSettingsFindings.WarningMessage +="$($CacheType): Too many parallel client connections allowed to server" 
                        $MaxConnectionsToServerToHigh += $CacheType
                    }
                    $DCacheClientSettings += $cc
                }
            } # else { write-host "unknown Cache Type $CacheType" }
        }

        if ( $RequestTimeoutToLow.Count -gt 0)
        {
            $DCacheClientSettingsFindings.WarningMessage +="The RequestTimeout could be set too low for the following Cache Types: " + $($RequestTimeoutToLow -join (', '))
            $DCacheClientSettingsFindings.Severity =[SPDiagnostics.Severity]::Informational 
            $DCacheClientSettingsFindings.WarningMessage += "<BR>"
        }

        if ( $ChannelOpenTimeoutToLow.Count -gt 0)
        {
            $DCacheClientSettingsFindings.WarningMessage +="The ChannelOpenTimeout could be set too low for the following Cache Types: " + $($ChannelOpenTimeoutToLow -join (', '))
            $DCacheClientSettingsFindings.Severity =[SPDiagnostics.Severity]::Informational 
            $DCacheClientSettingsFindings.WarningMessage += "<BR>"
        }

        if ( $MaxConnectionsToServerToHigh.Count -gt 0)
        {
            $DCacheClientSettingsFindings.WarningMessage +="Too many parallel client connections allowed to server for the following Cache Types: " + $($MaxConnectionsToServerToHigh -join (', '))
            $DCacheClientSettingsFindings.Severity =[SPDiagnostics.Severity]::Informational 
            $DCacheClientSettingsFindings.WarningMessage += "<BR>"
        }

        if ($DCacheClientSettingsFindings.WarningMessage.Count -gt 0)                          
        {
            $DCacheClientSettingsFindings.ReferenceLink = [uri]"https://learn.microsoft.com/en-us/sharepoint/administration/manage-the-distributed-cache-service?tabs=SCS1%2CSCS2%2CSCS3%2CSCS%2CSCS4#fine-tune-the-distributed-cache-service-by-using-a-powershell-script"
            $DCacheClientSettingsFindings.Severity = [SPDiagnostics.Severity]::Informational
        }

        $DCacheClientSettingsFindings.InputObject=$DCacheClientSettings 
        foreach($settingsRecord in $DCacheClientSettings)
        {
            Add-DiagnosticCommandSnapshot -Finding $DCacheClientSettingsFindings -CommandName 'Get-SPDistributedCacheClientSetting' -Records $settingsRecord -Scope ([ordered]@{ farmId = $script:SPFarm.Id; containerType = $settingsRecord.Name }) -Source 'Get-SPDistributedCacheClientSetting -ContainerType (existing collector)' -Coverage 'Farm/container-type client settings inspected by the optional DistributedCache/Performance collector. Host is an optional display observation, may be null, and does not identify a per-host configuration query.' -IdentityProperties @('Name')
        }
        $DCacheFindings.ChildFindings.Add(($DCacheClientSettingsFindings))

        #Ping Test for all DCache Ports
        $DCacheNetworkPortTestFindings = New-DiagnosticFinding -Name "Distributed Cache Network Port Test" -InputObject $null -Format Table
        
        $DCacheClusterPortTests=@()
        foreach ($DCacheHost in $DCacheHostConfig)
        {
            $ptCluster = Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.ClusterPort
            $ptCache = Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.CachePort
            if ($DCacheServers.Count -gt 1) {$ptArbitration =Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.ArbitrationPort}
            $ptRepl = Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.ReplicationPort

            $DCacheClusterPortTest = new-Object PSObject
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Client" -Value $($env:COMPUTERNAME)
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Distributed Cache Server" -Value $($DCacheHost.HostName)
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "SourceIP" -Value $($ptCluster.SourceAddress.IPAddress)
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "RemoteIP" -Value $($ptCluster.RemoteAddress.IPAddressToString)
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Cache Port 22233" -Value $ptCache.TcpTestSucceeded
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Cluster Port 22234" -Value $ptCluster.TcpTestSucceeded
            if ($DCacheServers.Count -eq 1) { $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Arbitration Port 22235" -Value "not tested - Single Server Cluster"}
            else { $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Arbitration Port 22235" -Value $ptArbitration.TCPTestSucceeded }
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Replication Port 22236" -Value $ptRepl.TcpTestSucceeded
            $DCacheClusterPortTests +=$DCacheClusterPortTest
        }
        $DCacheNetworkPortTestFindings.InputObject =$DCacheClusterPortTests 
        $DCacheFindings.ChildFindings.Add(($DCacheNetworkPortTestFindings))
    }
    }
    return $DCacheFindings
}
#endregion #DistributedCache

#region WOPI / Office Online Server
Function Get-OfficeOnlineServerFindings
{
    param([SPDiagnostics.Finding]$SnapshotFinding)

    $OfficeOnlineServerFindings = New-DiagnosticFinding -Name "Office Online Server " -InputObject $null -Format Table
    $wopiSnapshotFinding = if($null -ne $SnapshotFinding) { $SnapshotFinding } else { $OfficeOnlineServerFindings }
    $WopiBindingsFinding = New-DiagnosticFinding -Name "WOPI Bindings" -InputObject $null -Format Table
    

    $DisplayWopiBindings = @()
    $wopiBindings = Get-SPWopiBinding
    Add-DiagnosticCommandSnapshot -Finding $wopiSnapshotFinding -CommandName 'Get-SPWopiBinding' -Records $wopiBindings -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPWopiBinding' -Coverage 'Existing WOPI binding inventory; composite identity retains distinct actions, extensions, and servers.' -IdentityProperties @('Application', 'Extension', 'ProgId', 'Action', 'ServerName', 'WopiZone') -PropertyNames @(
        'Application', 'Extension', 'ProgId', 'Action', 'IsDefaultAction', 'ServerName', 'WopiZone'
    )
    if ($WopiBindings)
    {
        foreach ($wopiBinding in $wopibindings)
        {
            $wb = new-object psobject
            $wb | Add-member -memberType NoteProperty -name "Application" -value $wopiBinding.Application
            $wb | Add-member -memberType NoteProperty -name "Extension" -value  $WopiBinding.Extension
            $wb | Add-member -memberType NoteProperty -name "ProgId" -value $Wopibinding.ProgId
            $wb | Add-member -memberType NoteProperty -name "Action" -value $WopiBinding.Action
            $wb | Add-member -memberType NoteProperty -name "IsDefaultAction" -value $WopiBinding.IsDefaultAction
            $wb | Add-member -memberType NoteProperty -name "ServerName" -value  $($wopiBinding.ServerName)
            $wb | Add-member -memberType NoteProperty -name "WopiZone" -value  $WopiBinding.WopiZone           
            $DisplayWopiBindings += $wb
        }
        $WopiBindingsFinding.InputObject = $DisplayWopiBindings

        $WopiZone = Get-SPWopiZone
        Add-DiagnosticCommandSnapshot -Finding $wopiSnapshotFinding -CommandName 'Get-SPWopiZone' -Records ([pscustomobject]@{ Zone = $WopiZone }) -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPWopiZone' -Coverage 'Zone queried by the existing collector only when WOPI bindings exist.' -IdentityProperties @()
        $OfficeOnlineServerFindings.Description += "Farm WOPI zone: $WopiZone"
        
        $WopiSuppressionsFinding = $null
        $WopiSuppressions = Get-SPWOPISuppressionSetting
        $suppressionCommandRecords = @($WopiSuppressions | ForEach-Object { [pscustomobject]@{ Setting = [string]$_ } })
        Add-DiagnosticCommandSnapshot -Finding $wopiSnapshotFinding -CommandName 'Get-SPWOPISuppressionSetting' -Records $suppressionCommandRecords -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPWOPISuppressionSetting' -Coverage 'Suppression strings preserved without lossy splitting; queried only when WOPI bindings exist.' -IdentityProperties @('Setting')
        if ($WopiSuppressions)
        {
            $WopiSuppressionsReport= @()
            foreach ($WopiSuppression in $WopiSuppressions)
            {
                $wsr = new-object PSObject
                $wsr | Add-member -memberType NoteProperty -name "File Name Extension" -value $WopiSuppression.split(' ')[0]
                $wsr | Add-member -memberType NoteProperty -name "Action" -value $WopiSuppression.split(' ')[1]

                $WopiSuppressionsReport+= $wsr
            }

            $WopiSuppressionsFinding = New-DiagnosticFinding -Name "WOPI Suppressions" -InputObject $WopiSuppressionsReport -Format table
            $WopiSuppressionsFinding.Description += "Office Web Apps are disabled for the action, file name extension, or programmatic identifier specified."
            $WopiSuppressionsFinding.ReferenceLink += "https://learn.microsoft.com/en-us/powershell/module/sharepoint-server/new-spwopisuppressionsetting?view=sharepoint-server-ps"
        }

        #Task 501: Removing connection tests due to perf
        <#
        if ((Get-SPWopiZone).Split("-")[1] -eq "http")
        {
            $wt = Test-NetConnection $wopiBindings[0].ServerName -port 80
        } else {
            $wt = Test-NetConnection $wopiBindings[0].ServerName -port 443
        }
        if ($wt.PingSucceeded -or $wt.TcpTestSucceeded)
        {
            $ConObject = new-object psobject
            $ConObject |add-Member -memberType NoteProperty -Name "ComputerName" -Value $wt.ComputerName
            $ConObject |add-Member -memberType NoteProperty -Name "RemoteAddress" -Value $wt.RemoteAddress
            $ConObject |add-Member -memberType NoteProperty -Name "PingSucceeded"  -Value $wt.PingSucceeded
            $ConObject |add-Member -memberType NoteProperty -Name "TcpTestSucceeded" -Value $wt.TcpTestSucceeded
            $ConObject |add-Member -memberType NoteProperty -Name "RemotePort" -Value $wt.RemotePort
            $ConObject |add-Member -memberType NoteProperty -Name "PingReplyTime" -Value $wt.PingReplyDetails.RoundtripTime
        }
        $WopiConnectionTestFinding = New-DiagnosticFinding -Name "WOPI Connection Test" -InputObject $ConObject -Format List
        #>

        $OfficeOnlineServerFindings.ChildFindings.add(($WopiBindingsFinding))
        if ($WopiSuppressionsFinding)
        {
            $OfficeOnlineServerFindings.ChildFindings.add(($WopiSuppressionsFinding)) 
        }
        #Task 501: Removing connection tests due to perf
        #$OfficeOnlineServerFindings.ChildFindings.add(($WopiConnectionTestFinding)) 

    } 
    else 
    {
        #$OfficeOnlineServerFindings.Description += "No WOPI Bindings configured in farm"
        return
    }
    return $OfficeOnlineServerFindings
}
#endregion WOPI

#region ContentDeployment
function Get-ContentDeploymentFindings
{
    $ContentDeploymentFinding = New-DiagnosticFinding -Name "Content Deployment" -InputObject $null -Format Table

    $ContentDeploymentPaths = Get-SPContentDeploymentPath
    $ContentDeploymentJobs = Get-SPContentDeploymentJob

    if ($null -eq $ContentDeploymentPaths -and $null -eq $ContentDeploymentJobs)
    {
        return
        #$ContentDeploymentFinding.Description ="No content deployment configured in farm."
    } else {
        #Not well tested code
        $ContentDeploymentPathsReport = @()
        foreach ($ContentDeploymentPath in $ContentDeploymentPaths)
        {
            $cdp = new-Object PSObject
            $cdp | Add-Member -MemberType NoteProperty -Name "DestinationCentralAdministrationURL" -Value $($ContentDeploymentPath.DestinationCentralAdministrationURL)
            $cdp | Add-Member -MemberType NoteProperty -Name "DestinationSPSite" -Value $($ContentDeploymentPath.DestinationSPSite)
            $cdp | Add-Member -MemberType NoteProperty -Name "DestinationSPWebApplication" -Value $($ContentDeploymentPath.DestinationSPWebApplication)
            $cdp | Add-Member -MemberType NoteProperty -Name "Name" -Value $($ContentDeploymentPath.Name)
            $cdp | Add-Member -MemberType NoteProperty -Name "PathAccount" -Value $($ContentDeploymentPath.PathAccount.Username)
            $cdp | Add-Member -MemberType NoteProperty -Name "SourceSPSite" -Value $($ContentDeploymentPath.SourceSPSite)
            $cdp | Add-Member -MemberType NoteProperty -Name "SourceSPWebApplication" -Value $($ContentDeploymentPath.SourceSPWebApplication)
            $ContentDeploymentPathsReport +=$cdp 

        }
        $ContentDeploymentPathsFinding = New-DiagnosticFinding -Name "Content Deployment Paths" -InputObject $ContentDeploymentPathsReport  -Format Table
        $ContentDeploymentFinding.ChildFindings.Add($ContentDeploymentPathsFinding)

        $ContentDeploymentJobsReport =@()
        foreach ($ContentDeploymentJob in $ContentDeploymentJobs)
        {
            $cdj = new-Object PSObject
            $cdj | Add-Member -MemberType NoteProperty -Name "Identity" -Value $ContentDeploymentJob.Identity 
            $cdj | Add-Member -MemberType NoteProperty -Name "Description " -Value $($ContentDeploymentJob.Description)
            $cdj | Add-Member -MemberType NoteProperty -Name "EmailAddresses " -Value $(($ContentDeploymentJob.EmailAddresses -join(',')))
            $cdj | Add-Member -MemberType NoteProperty -Name "EmailNotifications " -Value $($ContentDeploymentJob.EmailNotifications)
            $cdj | Add-Member -MemberType NoteProperty -Name "HostingSupportEnabled" -Value $ContentDeploymentJob.HostingSupportEnabled
            $cdj | Add-Member -MemberType NoteProperty -Name "IncrementalEnabled" -Value $ContentDeploymentJob.HostingSupportEnabled
            $cdj | Add-Member -MemberType NoteProperty -Name "Name" -Value $($ContentDeploymentJob.Name)
            $cdj | Add-Member -MemberType NoteProperty -Name "Schedule" -Value $ContentDeploymentJob.Schedule
            $cdj | Add-Member -MemberType NoteProperty -Name "ScheduleEnabled" -Value $ContentDeploymentJob.ScheduleEnabled
            $cdj | Add-Member -MemberType NoteProperty -Name "Scope " -Value $($ContentDeploymentJob.Scope)
            $cdj | Add-Member -MemberType NoteProperty -Name "SqlSnapshotSetting "$ContentDeploymentJob.SqlSnapshotSetting
            $ContentDeploymentJobsReport += $cdj
        }

        #fixing 
        $ContentDeploymentJobsFinding = New-DiagnosticFinding -Name "Content Deployment Jobs" -InputObject $ContentDeploymentJobsReport -Format Table
        $ContentDeploymentFinding.ChildFindings.Add($ContentDeploymentJobsFinding)

    }
    return $ContentDeploymentFinding
}
#endregion #ContentDeplyoment

#region Network Latency
Function Get-SPDiagnosticFarmNetworkLatency()
{
    $servers = $script:servers
    $NetworkLatencies = @()
    $NetworkLatencyFinding = New-DiagnosticFinding -Name "Intra Farm Network Latency" -InputObject $null -Format Table

    if ($servers.count -eq 1)
    {
        $NetworkLatencyFinding.Description += "No tests in a single server farm"
    }

    #get SQL aliases
    if (test-path "HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo" )
    {
        $AliasGroup = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo" 
        $AliasNames = $AliasGroup.GetValueNames()
    }
    else
    {
        $AliasNames = $null
    }

    #make servers unique and weed out E-Mail servers
    $servers = $servers | sort-Object -Unique | Where-Object {
        # Keep the servers that do not have the Invalid role
        $_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid -or
        # Or the servers that have the Invalid role but do not have the E-Mail service instance
        # Or the servers that have the Invalid role and more than 2 ServiceInstance counts
        ($_.Role -eq [Microsoft.SharePoint.Administration.SPServerRole]::Invalid -and
        ($_.ServiceInstances.Count -gt 1 -or
        $_.ServiceInstances.TypeName -inotlike "*E-Mail*"))
    }
    
    foreach ($server in $servers)
    {
        $sName = $server.Name
        
        # Task 514: validate if server name is a sql alias
        if($AliasNames -icontains $sName)
        {
            $sName = $AliasGroup.GetValue($sName).Split(",")[1]
        }
        
        #Task 445: Account for named instances in sql server names
        if($sName.IndexOf("\") -ge 0)
        {
            $sName = $server.Name.Split("\")[0]
        }
        
        if ($sName -ne $env:COMPUTERNAME)
        {
            $serverLatency = New-Object psobject
            $pingRespose = Test-NetConnection -ComputerName $sName -ea 0 #-InformationLevel Quiet
            $serverLatency | Add-Member -MemberType NoteProperty -Name "Source" -Value $($env:COMPUTERNAME)
            $serverLatency | Add-Member -MemberType NoteProperty -Name "Destination" -Value $($pingRespose.Computername)
            $serverLatency | Add-Member -MemberType NoteProperty -Name "DestinationIP" -Value $($pingRespose.RemoteAddress)
            $serverLatency | Add-Member -MemberType NoteProperty -Name "PingSucceeded" -Value $pingRespose.PingSucceeded
            $serverLatency | Add-Member -MemberType NoteProperty -Name "RoundTripTime" -Value $pingRespose.PingReplyDetails.RoundtripTime
            $NetworkLatencies += $serverLatency
        }
    }
    $NetworkLatencyFinding.InputObject = $NetworkLatencies

    foreach ($NetworkLatency in $NetworkLatencies)
    {
        if ([String]::IsNullOrEmpty($NetworkLatency.DestinationIP))
        {
            $networklatencyFinding.WarningMessage +="Could not resolve address'$($NetworkLatency.Destination)'. Validate if name resolution is working correctly."            
        }
        elseif ($NetworkLatency.PingSucceeded -eq $false)
        {
            $networklatencyFinding.WarningMessage +="Ping was not successful between servers '$($NetworkLatency.source)' and '$($NetworkLatency.Destination)'. Validate if there is no firewall blocking ping between the servers."            
        }

        if ($NetworkLatency.RoundTripTime -gt 5)
        {
            $networklatencyFinding.WarningMessage +="The ping response time between the servers '$($NetworkLatency.source)' and '$($NetworkLatency.Destination)' is way too high"            
            $networklatencyFinding.Severity =  [SPDiagnostics.Severity]::Critical
        } elseif ($NetworkLatency.RoundTripTime -gt 2)
        {
            $networklatencyFinding.WarningMessage +="The ping response time between the servers '$($NetworkLatency.source)' and '$($NetworkLatency.Destination)' is too high"            
        }
    }
    return $NetworkLatencyFinding
}
#endregion 

#region Certificates in SPSE
function Get-SPDiagnosticCertificateFindings
{
    param([SPDiagnostics.Finding]$SnapshotFinding)

    if ($Script:Build -ne "SPSE")
    {
        return $null
    } else {
        $CertificateFinding = New-DiagnosticFinding -Name "Managed Certificates" -InputObject $null -Format List
        $certificateSnapshotFinding = if($null -ne $SnapshotFinding) { $SnapshotFinding } else { $CertificateFinding }
        if (IsElevated)
        {

            #Get all Certifcates in SPSE Cert Store with some properties
            $Certs = Get-SPCertificate | select-Object FriendlyName, CommonName,  NotBefore, NotAfter, Exportable, IsSelfSigned, Status, ID, storeType, Subject  #,AlternativeNames  #SAN is an array
            Add-DiagnosticCommandSnapshot -Finding $certificateSnapshotFinding -CommandName 'Get-SPCertificate' -Records $Certs -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPCertificate curated public metadata selection' -Coverage 'SharePoint SE certificate inventory when elevated; public identity, validity, and status only.'
            if ($Certs.Count -eq 0)
            {
                return
                #$CertificateFinding.Description += "No Certificates found in the SharePoint Certificate store"
            }



            #Get the Default settings for Certificates in the Farm
            $certSettings = Get-SPCertificateSettings
            Add-DiagnosticCommandSnapshot -Finding $certificateSnapshotFinding -CommandName 'Get-SPCertificateSettings' -Records $certSettings -Scope ([ordered]@{ farmId = $script:SPFarm.Id }) -Source 'Get-SPCertificateSettings' -Coverage 'Public expiration alert thresholds; existing query runs only on elevated SPSE with certificates present. Contact details excluded.' -IdentityProperties @() -PropertyNames @(
                'CertificateExpirationAttentionThresholdDays', 'CertificateExpirationWarningThresholdDays',
                'CertificateExpirationErrorThresholdDays'
            )

            #Get the dates for Attention, Warning, Error
            $ad = $certSettings.CertificateExpirationAttentionThresholdDays
            $wd = $certSettings.CertificateExpirationWarningThresholdDays
            $ed = $certSettings.CertificateExpirationErrorThresholdDays

            if ($certs.Count -gt 0) 
            {
                if ( ($ad -eq 0) -or ($wd -eq 0) -or ($ed -eq 0) )
                {
                    $CertificateFinding.WarningMessage += "Found certificates in the SharePoint Certificate store, but no threshold days for alerts."
                } else {
                    if ($ad -lt 60)
                    {
                        $CertificateFinding.WarningMessage += "Warning for Certificates that will expire in the near future is set to $ad days. This could be too short when it takes long to get certificates renewed."
                        $CertificateFinding.Severity=[SPDiagnostics.Severity]::Informational 
                    }
                    if ($wd -lt 15)
                    {
                        $CertificateFinding.WarningMessage += "Warning for Certificates that will expire is set to $wd days. This could be too short."
                        $CertificateFinding.Severity=[SPDiagnostics.Severity]::Warning 
                    }
                }

                if ($null -eq $certSettings.CertificateNotificationContacts)
                {
                    $CertificateFinding.WarningMessage += "Found certificates in the SharePoint Certificate store, but no contact for alerts"               
                }
            }
            # defaults
            if ($ad -eq 0) {$ad = 60}
            if ($wd -eq 0) {$wd = 15}
            if ($ed -eq 0) {$ed = 15}
        
            #Group the certificates
            $VeryOldCerts = $Certs | Where-Object {$_.NotAfter -lt (Get-Date).AddDays(-$ed) } | Sort-Object -Property NotAfter
            $errorCerts = $Certs | Where-Object {(($_.NotAfter -gt (get-date)) -and ($_.NotAfter -lt (Get-Date).AddDays(-$ed)) -and $_.NotBefore -lt (Get-Date))} | Sort-Object -Property NotAfter
            $warnCerts =  $Certs | Where-Object {(($_.NotAfter -gt (get-date)) -and ($_.NotAfter -lt (Get-Date).AddDays($wd)) -and $_.NotBefore -lt (Get-Date))} | Sort-Object -Property NotAfter
            $AttentionCerts =  $Certs | Where-Object { ( ($_.NotAfter -lt (get-date).AddDays($ad)) -and ($_.NotAfter -gt (Get-Date).AddDays($wd)) -and $_.NotBefore -lt (Get-Date))} | Sort-Object -Property NotAfter
            $goodCerts  = $Certs | Where-Object {(($_.NotAfter -gt (Get-Date).AddDays($ad)) -and ($_.NotBefore -lt (Get-Date)) )} | Sort-Object -Property NotAfter
            $NotValidYetCerts = $Certs | Where-Object {$_.NotBefore -gt (Get-Date)}

            if ($errorCerts)
            {
                $ExpiredCertsFinding = New-DiagnosticFinding -Name "  Recently expired Certificates" -InputObject $errorCerts -Format Table
                $ExpiredCertsFinding.Description ="Found Certificates managed by SharePoint expired less than $ed days ago."
                $ExpiredCertsFinding.Severity=[SPDiagnostics.Severity]::Critical
                $CertificateFinding.ChildFindings.Add(($ExpiredCertsFinding))
            }


            if ($warnCerts)
            {
                $WarningCertsFinding = New-DiagnosticFinding -Name "  Certificates expiring in less than $wd days" -InputObject $warnCerts -Format Table
                $WarningCertsFinding.Description ="Found Certificates managed by SharePoint expiring in less than $wd days."
                $WarningCertsFinding.Severity=[SPDiagnostics.Severity]::Critical
                $CertificateFinding.ChildFindings.Add(($WarningCertsFinding))
            }

            if ($AttentionCerts)
            {
                $AttentionCertsFinding = New-DiagnosticFinding -Name "  Certificates expiring in $wd - $ad days" -InputObject $AttentionCerts -Format Table
                $AttentionCertsFinding.Description ="Found valid Certificates managed by SharePoint expiring in $wd - $ad days."
                $AttentionCertsFinding.Severity=[SPDiagnostics.Severity]::Warning
                $CertificateFinding.ChildFindings.Add(($AttentionCertsFinding))
            }

            if ($VeryOldCerts)
            {
                $VeryOldCertsFinding = New-DiagnosticFinding -Name "  Long expired Certificates" -InputObject $VeryOldCerts -Format Table
                $VeryOldCertsFinding.Description ="Found Certificates managed by SharePoint expired more than $ed days ago."
                $VeryOldCertsFinding.Severity=[SPDiagnostics.Severity]::Informational
                $CertificateFinding.ChildFindings.Add(($VeryOldCertsFinding))
            }

            if ($goodCerts)
            {
                $GoodCertsFinding = New-DiagnosticFinding -Name "  Good Certificates" -InputObject $goodCerts -Format Table
                $GoodCertsFinding.Description ="Found valid certificates managed by SharePoint valid for more than $ad days."
                #$GoodCertsFinding.Severity=[SPDiagnostics.Severity]::Information
                $CertificateFinding.ChildFindings.Add(($GoodCertsFinding))
            }

            if ($NotValidYetCerts)
            {
                $NotYetValiddCertsFinding = New-DiagnosticFinding -Name "  Not yet valid certificates" -InputObject $NotValidYetCerts -Format Table
                $NotYetValiddCertsFinding.Description ="Found Certificates managed by SharePoint that are not yet valid."
                $NotYetValiddCertsFinding.Severity=[SPDiagnostics.Severity]::Information
                $CertificateFinding.ChildFindings.Add(($NotYetValiddCertsFinding))
            }
        } else {
            $CertificateFinding.Description='Certificates can only be validated when the script is executed in a PowerShell Session that is "Run as Administrator".'
        }
    }
    return $CertificateFinding
}
#endregion

#region DBMirorring
function Get-MirroredDBsFinding
{
    $MirroredDBFinding = New-DiagnosticFinding -Name "Mirrored Databases" -InputObject $null -Format Table

    $MirrorDB= $script:spDatabases | Where-Object {$_.FailoverServer -or $_.FailoverInstance} | Select-Object @{N='Name';E={$($_.Name)}}, @{N='server';E={$($_.server)}} , @{N='FailoverServer';E={$($_.FailoverServer.Name)}}
    if ($MirrorDB.count -eq 0)
    {
        $MirroredDBFinding.Description += "No mirrored databases in the farm."
    } else {
        $MirroredDBFinding.InputObject=$MirrorDB
    }
    return $MirroredDBFinding
}
#endregion
#region SQL and AlwaysOn

#Region DB Infos
function Get-DBInfosFinding ($DBServer)
{
    $DBInfosFinding = New-DiagnosticFinding -Name "Database Information" -InputObject $null -Format Table
        
    $ServerDBS = $script:spDatabases | Where-Object {($_.server.name -eq $dbServer) -or ($_.server -eq  $dbServer)}
    $dbs = $ServerDBS.name -join ","
    $dbs = $dbs.replace(",", "','")
    $dbs = "'" + $dbs +"'"
    $sqlquery = "select database_id, name, Compatibility_Level, collation_name, user_access_desc, state_desc, is_read_only, is_auto_shrink_on, snapshot_isolation_state_desc, recovery_model_desc, is_auto_create_stats_on, is_auto_update_stats_on, create_date, is_encrypted, delayed_durability_desc from sys.databases where name in ($dbs)"
    
    $DBInfosSQL = Invoke-SPSqlCommand -spDatabase $ServerDBS[0] -query $sqlquery -ErrorAction SilentlyContinue

    $DBInfos =@()
    foreach ($DBInfoSQL in $DBInfosSQL)
    {
        $DBInfo = new-object PSObject
        $DBInfo | add-member -memberType NoteProperty -name "DB_ID" -Value $DBInfoSQL.Database_ID
        $DBInfo | add-member -memberType NoteProperty -name "Database Name" -Value $($DBInfoSQL.Name)
        $DBInfo | add-member -memberType NoteProperty -name "Compatibility Level" -Value $DBInfoSQL.Compatibility_Level
        $DBInfo | add-member -memberType NoteProperty -name "Collation" -Value $DBInfoSQL.Collation_name
        $DBInfo | add-member -memberType NoteProperty -name "Access" -Value $DBInfoSQL.user_access_desc
        $DBInfo | add-member -memberType NoteProperty -name "State" -Value $DBInfoSQL.state_desc
        $DBInfo | add-member -memberType NoteProperty -name "Snapshot Isolation" -Value $DBInfoSQL.snapshot_isolation_state_desc
        $DBInfo | add-member -memberType NoteProperty -name "Recovery Model" -Value $DBInfoSQL.recovery_model_desc 
        $DBInfo | add-member -memberType NoteProperty -name "Auto Create Stats" -Value $DBInfoSQL.is_auto_create_stats_on
        $DBInfo | add-member -memberType NoteProperty -name "Auto Update Stats" -Value $DBInfoSQL.is_auto_update_stats_on
        $DBInfo | add-member -memberType NoteProperty -name "Create Date" -Value $DBInfoSQL.create_date
        $DBInfo | add-member -memberType NoteProperty -name "Read Only" -Value $DBInfoSQL.is_read_only
        $DBInfo | add-member -memberType NoteProperty -name "Encrypted" -Value $DBInfoSQL.is_encrypted
        $DBInfo | add-member -memberType NoteProperty -name "Delayed Durability" -Value $DBInfoSQL.delayed_durability_desc
        #$DBInfo | add-member -memberType NoteProperty -name "" -Value

        $DBInfos += $DBInfo
    }
    $DBInfosFinding.InputObject = $dbInfos

    $TargetCompatLevel =110
    switch ($script:Build)
    {
        "2013"  {$TargetCompatLevel = 110}
        "2016"  {$TargetCompatLevel = 110}
        "2019"  {$TargetCompatLevel = 130}
        "SPSE"    {$TargetCompatLevel = 150}
        default {$TargetCompatLevel = 150}
    }

    $IncorrectCompatLevelDBs =@()
    $IncorrectCollationDBs=@()
    $IncorrectAccessDBs=@()
    $IncorrectStateDBs=@()
    $IncorrectReadOnlyDBs=@()
    $IncorrectEncryptedDBs=@()
    $IncorrectDelayedDurabilityDBs=@()
    $IncorrectAutoCreateStatsDBs=@()
    $IncorrectAutoUpdateStatsDBs=@()
    $IncorrectRecoveryModelDBs=@()



    foreach ($dbinfo in $DBInfos)
    {

        if ($DBInfo.'Compatibility Level' -ne $TargetCompatLevel) 
        {
            $IncorrectCompatLevelDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.Collation -ne "Latin1_General_CI_AS_KS_WS") 
        {
            $IncorrectCollationDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.Access -ne "MULTI_USER") 
        {
            $IncorrectAccessDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.'Recovery Model' -ne "FULL") 
        {
            $IncorrectRecoveryModelDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.State -ne "ONLINE") 
        {
            $IncorrectStateDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.'Read Only' -ne $False) 
        {
            $IncorrectReadOnlyDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.'Snapshot Isolation' -ne "OFF") 
        {
            $IncorrectSnapShotIsolationDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.Encrypted -ne $false) 
        {
            $IncorrectEncryptedDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.'Delayed Durability' -ne "DISABLED") 
        {
            $IncorrectDelayDurabilityDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.'Auto Create Stats' -ne $false) 
        {
            $IncorrectAutoCreateStatsDBs += $DBInfo.'Database Name'
        }

        if ($DBInfo.'Auto Update Stats' -ne $true) 
        {
            $IncorrectAutoUpdateStatsDBs += $DBInfo.'Database Name'
        }
        
    }

    # Add findings for the DBs as separate Warnings

    # Read Only
    if ($IncorrectReadOnlyDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases set to ReadOnly: " + $($IncorrectReadOnlyDBs -join (', '))
    }

    # State
    if ($IncorrectStateDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect Incorrect State: " + $($IncorrectStateDBs -join (', '))
    }
    
    # Compat Level
    if ($IncorrectCompatLevelDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect Database_Compatibility Level: " + $($IncorrectCompatLevelDBs -join (', '))
    }

    # Collation
    if ($IncorrectCollationDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect Collation: " + $($IncorrectCollationDBs -join (', '))
    }

    # Encrypted
    if ($IncorrectEncryptedDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Encrypted Databases: " + $($IncorrectEncryptedDBs  -join (', '))
    }

    # Delayed Durability
    if ($IncorrectDelayedDurabilityDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect 'Delayed Durability' configuration: " + $($IncorrectDelayedDurabilityDBs -join (', '))
    }

    # Access
    if ($IncorrectAccessDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect Access Settings: " + $($IncorrectAccessDBs -join (', '))
    }

    # Snapshot Isolation
    if ($IncorrectSnapShotIsolationDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect 'Snapshot Isolation' Settings: " + $($IncorrectSnapShotIsolationDBs -join (', '))
    }

<# False Positives for some default DBs, therefore create no warning.
    # Auto Create Stats
    if ($IncorrectAutoCreateStatsDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect 'Auto Create Statistics' settings: " + $($IncorrectAutoCreateStatsDBs -join ('; '))
        $DBInfosFinding.WarningMessage += "<BR>"
    }

    # Auto Update Stats
    if ($IncorrectAutoUpdateStatsDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases with incorrect 'Auto Update Statistics' settings: " + $($IncorrectAutoUpdateStatsDBs -join ('; '))
        $DBInfosFinding.WarningMessage += "<BR>"
    }

    # Recovery Model
    if ($IncorrectRecoveryModelDBs.Count -gt 0)
    {
        $DBInfosFinding.Severity =[SPDiagnostics.Severity]::Warning 
        $DBInfosFinding.WarningMessage += "Databases not set to Recovery Model 'FULL': " + $($IncorrectRecoveryModelDBs -join ('; '))
        $DBInfosFinding.WarningMessage += "<BR>"
    }
#>
    return $DBInfosFinding
}
#endregion

#region SPServiceAccountsSQLPerms
Function Get-SPServiceAccountSQLPerms
{
    $SPAccounts = "'" +( ((Get-SPManagedAccount).Username) -join "','") +"'"
    $query = "select loginname, denylogin, hasaccess, sysadmin, securityadmin, serveradmin,setupadmin,processadmin,diskadmin,dbcreator,bulkadmin,status from syslogins with (NOLOCK) where loginname in ("
    $query += $SPAccounts 
    $query +=") "
 
    $SQLDBPermissions = (Invoke-SPSqlCommand -spDatabase $spdb -query $query -ErrorAction SilentlyContinue)
    $SPSrvAccountsSQLPerms=@()
    $SPSrvAccountsSQLPermsFinding = New-DiagnosticFinding -Name "SP Managed Accounts SQL Permissions" -InputObject $SPSrvAccountsSQLPerms -Format Table


    foreach ($row in $SQLDBPermissions)
    {
        $SPSrvAccountSQLPerms = new-object PSObject
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "LoginName" -Value $($row[0])
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "DenyLogin" -value $row[1]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "HasAccess" -value $row[2]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "SysAdmin"  -value $row[3]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "SecurityAdmin" -value $row[4]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "ServerAdmin" -value $row[5]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "Setupadmin" -value $row[6]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "ProcessAdmin" -value $row[7]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "DiskAdmin" -value $row[8]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "DBCreator" -value $row[9]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "BulkAdmin" -value $row[10]
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "Status" -value $row[11]
        $SPSrvAccountsSQLPerms += $SPSrvAccountSQLPerms

        if ($SPSrvAccountSQLPerms.DenyLogin -eq 1)
        {
            $SPSrvAccountsSQLPermsFinding.WarningMessage += "$($row[0]) has Deny Login permissions on SQL server."
            $SPSrvAccountsSQLPermsFinding.Severity=[SPDiagnostics.Severity]::Warning   
        }
        if ($SPSrvAccountSQLPerms.HasAccess -eq 0)
        {
            $SPSrvAccountsSQLPermsFinding.WarningMessage += "$($row[0]) has no Access on SQL server."
            $SPSrvAccountsSQLPermsFinding.Severity=[SPDiagnostics.Severity]::Warning   
        }
    }
     
    $SPSrvAccountsSQLPermsFinding.InputObject = $SPSrvAccountsSQLPerms
    
    return $SPSrvAccountsSQLPermsFinding
}
#endregion SPServiceAccountsSQLPerms

Function Get-SPDiagnosticSQLFindings()
{
    $SQLServersFinding = New-DiagnosticFinding -Name "SQL Servers" -InputObject $null -Format List

    $dbServers = ($script:spDatabases  | ForEach-Object {$_.parent.server.Address})  | Sort-Object | Get-Unique
    foreach ($dbServer in $DBServers)
    {
        $SPDBs = ($script:spDatabases | Where-Object {$_.parent.server.name -eq $dbserver})
        if ($SPDBs)
        {
            $SQLServerData = New-Object PSObject
            
            # SQL Server versions
            $SPDB = $SPDBs[0]           
            $SQLServerData  | add-member -memberType NoteProperty -name "SQL Server Version" -value $((Invoke-SPSqlCommand -spDatabase $spdb -query "SELECT @@version")[0] ) -ErrorAction SilentlyContinue
            
            #sql Protocol and Authentication
            $sql_transport_auth = Invoke-SPSqlCommand -spDatabase $spdb -query "SELECT net_transport, auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID" -ErrorAction SilentlyContinue
            
            $SQLServerData  | add-member -memberType NoteProperty -name "Net_Transport" -value $sql_transport_auth.net_transport
            $SQLServerData  | add-member -memberType NoteProperty -name "Auth_Scheme" -value  $sql_transport_auth.auth_scheme

            # SQL Server Cluster
            $ClusterNodes = (Invoke-SPSqlCommand -spDatabase $spdb -query "Select * from sys.dm_os_cluster_nodes with (NOLOCK)" -ErrorAction SilentlyContinue)
            if ($Null -eq $ClusterNodes)
            {
                $SQLServerData  | add-member -memberType NoteProperty -name "Cluster" -value "SQL Server is not running as part of a Cluster"
            } else {
                $CNodes = $ClusterNodes -Join (',')
                $SQLServerData  | add-member -memberType NoteProperty -name "Cluster Nodes" -value $Cnodes
            }

            $SQLServerFinding = New-DiagnosticFinding -Name "SQL Server ($($dbServer))" -InputObject $SQLServerData -Format List
            
            # Task 531: Hide findings uneless there is something to report.
            #$SQLServerFinding.ChildFindings.Add((Get-SPServiceAccountSQLPerms))
            $sqlAccountPermsFinding = Get-SPServiceAccountSQLPerms
            if($sqlAccountPermsFinding.Severity -ge [SPDiagnostics.Severity]::Informational)
            {
                $SQLServerFinding.ChildFindings.Add($sqlAccountPermsFinding)
            }

            $SQLServersFinding.ChildFindings.add(($SQLServerFinding))
            $SQLServerFinding.ChildFindings.Add((Get-DBInfosFinding $dbServer))
            
            # Task 531: Hide findings uneless there is something to report.
            #$SQLServerFinding.ChildFindings.Add((Get-MirroredDBsFinding))
            $mirroredDbsFinding = Get-MirroredDBsFinding
            if($mirroredDbsFinding.Severity -ge [SPDiagnostics.Severity]::Informational)
            {
                $SQLServerFinding.ChildFindings.Add($mirroredDbsFinding)
            }

#region AAG
            #SQL Server AAG Info
            $SQL_AAG_Finding = New-DiagnosticFinding -Name "SQL Server Always On" -InputObject $Null -Format List

#region AAG Cluster
            $AAGClusterFinding = New-DiagnosticFinding -Name "SQL Server Availablity Group Cluster" -InputObject $null -Format Table
            $AAG_ClusterInfo = (Invoke-SPSqlCommand -spDatabase $spdb -query "Select * from sys.dm_hadr_cluster" -ErrorAction SilentlyContinue)
            if ($null -ne $AAG_ClusterInfo)
            {
            if ($AAG_ClusterInfo[0])
            {
                #Cluster Info
                $ClusterInfo = new-object PSObject
                $ClusterName = $($AAG_ClusterInfo[0])
                $ClusterInfo | add-member -memberType NoteProperty -name "Cluster name" -value $ClusterName
                $ClusterInfo | add-member -memberType NoteProperty -name "Quorum Type" -value $AAG_ClusterInfo[2]
                $ClusterInfo | add-member -memberType NoteProperty -name "Quorum State" -value $AAG_ClusterInfo[4]
                $AAGClusterFinding.InputObject = $ClusterInfo

                #Cluster Members
                $AAG_ClusterMembersDB = (Invoke-SPSqlCommand -spDatabase $spdb -query "select * from sys.dm_hadr_cluster_members with (NOLOCK)" -ErrorAction SilentlyContinue)
                $ClusterMembers=@()
                foreach ($row in $AAG_ClusterMembersDB)
                {
                    $ClusterMember = new-object PSObject
                    $ClusterMember | add-member -memberType NoteProperty -name "Member name" -value $($Row[0])
                    $ClusterMember | add-member -memberType NoteProperty -name "Member type description" -value $Row[2]
                    $ClusterMember | add-member -memberType NoteProperty -name "Member State" -value $Row[4]
                    $ClusterMember | add-member -memberType NoteProperty -name "Member Number of Quorum votes" -value $Row[5]
                    $ClusterMembers += $ClusterMember
                }

                $AAGClusterMemberFinding = New-DiagnosticFinding -Name "SQL Server Cluster Members" -InputObject $ClusterMembers -Format Table
                $AAGClusterFinding.ChildFindings.Add($AAGClusterMemberFinding)

                #Cluster Network
                $AAG_ClusterNetworkDB = (Invoke-SPSqlCommand -spDatabase $spdb -query "select * from sys.dm_hadr_cluster_networks with (NOLOCK)" -ErrorAction SilentlyContinue)
                $ClusterNetworkInfos=@()
                foreach ($row in $AAG_ClusterNetworkDB)
                {
                    $ClusterNetworkInfo = new-object PSObject
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "Member name" -value $($Row[0])
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "Network subnet" -value $($Row[1])
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "Network Subnet IP4 Mask" -value $Row[2]
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "Network Public" -value $Row[4]
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "IP 4" -value $Row[4]
                    $ClusterNetworkInfos += $ClusterNetworkInfo
                }

                $AAGClusterNetworkFinding = New-DiagnosticFinding -Name "SQL Server Cluster Network" -InputObject $ClusterNetworkInfos -Format Table
                $AAGClusterFinding.ChildFindings.Add($AAGClusterNetworkFinding)


                #Availablity Group Resources
                $ResourcesDB = (Invoke-SPSqlCommand -spDatabase $spdb -query "select * from sys.dm_hadr_instance_node_map" -ErrorAction SilentlyContinue)
                $ClusterResources=@()
                foreach ($row in $ResourcesDB)
                {
                    $ClusterResource = new-object PSObject
                    $ClusterResource | add-member -memberType NoteProperty -name "Resource ID" -value $Row[0]
                    $ClusterResource | add-member -memberType NoteProperty -name "Instance Name" -value $($Row[1])
                    $ClusterResource | add-member -memberType NoteProperty -name "Node Name" -value $($Row[2])
                    $ClusterResources += $ClusterResource
                }

                $AAGClusterResourcesFinding = New-DiagnosticFinding -Name "SQL Instance Roadmap" -InputObject $ClusterResources -Format Table
                $AAGClusterFinding.ChildFindings.Add($AAGClusterResourcesFinding)
                

                #Availablity Group Name ID Map
                $NameIDMapDB = (Invoke-SPSqlCommand -spDatabase $spdb -query "select * from sys.dm_hadr_name_id_map" -ErrorAction SilentlyContinue) 
                $ClusterNameIDMaps=@()
                foreach ($row in $NameIDMapDB)
                {
                    $ClusterNameIDMap = new-object PSObject
                    $ClusterNameIDMap | add-member -memberType NoteProperty -name "AG Name" -value $($Row[0])
                    $ClusterNameIDMap | add-member -memberType NoteProperty -name "AG ID" -value $Row[1]
                    $ClusterNameIDMap | add-member -memberType NoteProperty -name "AG Resource ID" -value $Row[2]
                    $ClusterNameIDMap | add-member -memberType NoteProperty -name "AG Group ID" -value $Row[3]
                    $ClusterNameIDMaps += $ClusterNameIDMap
                }

                $AAGClusterNameIDMapFinding = New-DiagnosticFinding -Name "SQL Availability Groups Name ID Map" -InputObject $ClusterNameIDMaps -Format Table
                $AAGClusterFinding.ChildFindings.Add($AAGClusterNameIDMapFinding)

                } else {
                    $AAGClusterFinding.Description = "No SQL Server High Availability Cluster found"
                }
            } else {
                $AAGClusterFinding.Description = "No SQL Server High Availability Cluster found"
            }
            $SQL_AAG_Finding.ChildFindings.Add($AAGClusterFinding)
#endregion # AAG Cluster

#region AAG Groups

            $AAG_GroupsFinding = New-DiagnosticFinding -Name "SQL Server Availablity Groups" -InputObject $null -Format Table
            $AAG_Groups = (Invoke-SPSqlCommand -spDatabase $spdb -query "Select * from sys.availability_groups with (NOLOCK)" -ErrorAction SilentlyContinue)
            if ($AAG_Groups)
            {
                $AAGGroups= @()
                #AAG Group Info
                foreach ($row in $AAG_Groups)
                {
                    $AAGGroupInfo = new-object PSObject
                    $GroupName = $($row[1])
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "name" -value $GroupName
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "Group ID" -value $row[0]
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "Resource ID" -value $row[2]
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "Resource Group ID" -value $row[3]
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "Failure Condition Level" -value $row[4]
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "Health Check Timeout" -value $row[5]
                    $AAGGroupInfo | add-member -memberType NoteProperty -name "Automated Backup preference Description" -value $row[7]
                    $AAGGroups += $AAGGroupInfo
                }
                $AAG_GroupsFinding.InputObject =$AAGGroups

                $AAG_GroupsStateFinding = New-DiagnosticFinding -Name "SQL Server Availablity Group States" -InputObject $null -Format Table
                $AAG_GroupStates = (Invoke-SPSqlCommand -spDatabase $spdb -query "select * from sys.dm_hadr_availability_group_states with (NOLOCK)" -ErrorAction SilentlyContinue)
                if ($AAG_GroupStates)
                {
                    $AAGGroupsState= @()
                    #AAG Group Info
                    foreach ($row in $AAG_GroupStates)
                    {
                        $AAGGroupStateInfo = new-object PSObject
                        $PrimaryReplica = $($row[1])
                        $AAGGroupStateInfo | add-member -memberType NoteProperty -name "Group ID" -value $row[0]
                        $AAGGroupStateInfo | add-member -memberType NoteProperty -name "Primary Replica" -value $PrimaryReplica
                        $AAGGroupStateInfo | add-member -memberType NoteProperty -name "Primary Recovery Health" -value $row[3]
                        $AAGGroupStateInfo | add-member -memberType NoteProperty -name "Secondary Recovery Health" -value $row[5]
                        $AAGGroupStateInfo | add-member -memberType NoteProperty -name "Failure Condition Level" -value $row[4]
                        $AAGGroupStateInfo | add-member -memberType NoteProperty -name "Synchronization Health" -value $row[7]
                        $AAGGroupsState += $AAGGroupStateInfo
                    }
                    $AAG_GroupsStateFinding.InputObject =$AAGGroupsState
                    $AAG_GroupsFinding.ChildFindings.Add($AAG_GroupsStateFinding)
                }

            }  
            else  
            {
                $AAG_GroupsFinding.Description = "No SQL Server Availability Groups found"
            }
            $SQL_AAG_Finding.ChildFindings.Add($AAG_GroupsFinding)
#endregion AAG Groups

#region AAG Replicas
            $AAG_ReplicasFinding = New-DiagnosticFinding -Name "SQL Server Availablity Replicas" -InputObject $null -Format Table
            $AAG_Replicas = (Invoke-SPSqlCommand -spDatabase $spdb -query "Select replica_id, group_id, replica_server_name,  endpoint_url, availability_mode_desc, failover_mode_desc, session_timeout, primary_role_allow_connections_desc,  secondary_role_allow_connections_desc  from sys.availability_replicas with (NOLOCK)" -ErrorAction SilentlyContinue)
            if ($AAG_Replicas)
            {
                $AAGReplicas= @()
                #AAG Group Info
                foreach ($row in $AAG_Replicas)
                {
                    $AAGReplicaInfo = new-object PSObject
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Replica ID" -value $row[0]
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Group ID" -value $row[1]
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "ReplicaServername" -value $($row[2])
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "EndPoint URL" -value $($row[3])
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Availablity Mode" -value $row[4]
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Failover mode" -value $row[5]
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Session Timeout" -value $row[6]
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Primary Node Allow connections" -value $row[7]
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "Secondary Node Allow connections" -value $row[8]
                    $AAGReplicas += $AAGReplicaInfo
                }
                $AAG_ReplicasFinding.InputObject =$AAGReplicas


            }  else  
            {
                $AAG_ReplicasFinding.Description = "No SQL Server Availability Replicas found"
            }
            $SQL_AAG_Finding.ChildFindings.Add($AAG_ReplicasFinding)
#endregion AAG Replicas

#region AAG Databases
            $AAG_DBFinding = New-DiagnosticFinding -Name "SQL Server Availablity Databases" -InputObject $null -Format Table
            $dbSQLQuery ="select sdb.name,sdb.group_database_id, sdb.replica_id, dbrs.Is_Primary_Replica,  synchronization_state_desc, synchronization_health_desc, "
            $dbSQLQuery+="database_state_desc, is_suspended, suspend_reason_desc, last_hardened_time, last_commit_time, is_failover_ready, "
            $dbSQLQuery+="is_pending_secondary_suspend, is_database_joined "
            $dbSQLQuery+="from sys.availability_databases_cluster adc with (NOLOCK)  "
            $dbSQLQuery+="inner join sys.databases sdb with (NOLOCK) on adc.group_database_id =  sdb.group_database_id "
            $dbSQLQuery+="inner join sys.dm_hadr_database_replica_states dbrs with (NOLOCK)  on sdb.group_database_id = dbrs.group_database_id "
            $dbSQLQuery+="inner join sys.dm_hadr_database_replica_cluster_states dbrcs with (NOLOCK)  on sdb.group_database_id = dbrcs.group_database_id"

            $AAG_DBs = (Invoke-SPSqlCommand -spDatabase $spdb -query $dbSQLQuery -ErrorAction SilentlyContinue)
            if ($AAG_DBs)
            {
                $AAGDBs= @()
                #AAG Group Info
                foreach ($row in $AAG_DBs)
                {
                    # All DBs in the AG will be listed even when they are not part of the SP Farm
                    if (Get-SPDatabase -name $($row["name"]))
                    {
                        $AAGDB = new-object PSObject
                        $AAGDB | add-member -memberType NoteProperty -name "Database Name" -value $($row[0])
                        $AAGDB | add-member -memberType NoteProperty -name "Group Database ID" -value $row[1]
                        $AAGDB | add-member -memberType NoteProperty -name "Replica ID" -value $row[2]
                        $AAGDB | add-member -memberType NoteProperty -name "Is Primary" -value $row[3]
                        $AAGDB | add-member -memberType NoteProperty -name "Synchronization Status" -value $row[4]
                        $AAGDB | add-member -memberType NoteProperty -name "Synchronization Health" -value $row[5]
                        $AAGDB | add-member -memberType NoteProperty -name "Database State" -value $row[6]
                        $AAGDB | add-member -memberType NoteProperty -name "Is Suspended" -value $row[7]
                        $AAGDB | add-member -memberType NoteProperty -name "Suspended reason" -value $row[8]
                        $AAGDB | add-member -memberType NoteProperty -name "Last Hardened" -value $row[9]
                        $AAGDB | add-member -memberType NoteProperty -name "Last Committed" -value $row[10]
                        $AAGDB | add-member -memberType NoteProperty -name "Failover ready" -value $row[11]
                        $AAGDB | add-member -memberType NoteProperty -name "Pending Secondary Suspend" -value $row[12]
                        $AAGDB | add-member -memberType NoteProperty -name "Is Database Joined" -value $row[13]
                        $AAGDBs += $AAGDB
                    }
                }
                $AAG_DBFinding.InputObject =$AAGDBs


            }  else  
            {
                $AAG_DBFinding.Description = "No SQL Server Availability Databases found"
            }
            $SQL_AAG_Finding.ChildFindings.Add($AAG_DBFinding)
#endregion AAG Databases

#region AAG Listener
            $AAG_ListenerFinding = New-DiagnosticFinding -Name "SQL Server Availablity Group Listeners" -InputObject $null -Format Table
            $ListenerSQLQuery = "select l1.listener_id, l1.ip_address, l1.is_dhcp, l1.ip_subnet_mask, l1.network_subnet_ipv4_mask, l1.state_desc, " 
            $ListenerSQLQuery +="l2.dns_name, l2.port, l2.is_conformant " #, l2.is_distributed_network_name
            $ListenerSQLQuery +="from sys.availability_group_listener_ip_addresses l1 with (NOLOCK)  "
            $ListenerSQLQuery +="inner join sys.availability_group_listeners l2 with (NOLOCK)  on l1.listener_id = l2.listener_id"

            $AAG_Listeners = (Invoke-SPSqlCommand -spDatabase $spdb -query $ListenerSQLQuery -ErrorAction SilentlyContinue)
            if ($AAG_Listeners)
            {
                $AAGListeners= @()
                #AAG Group Info
                foreach ($row in $AAG_Listeners)
                {
                    $AAGListener = new-object PSObject
                    $AAGListener | add-member -memberType NoteProperty -name "Listener ID" -value $row[0]
                    $AAGListener | add-member -memberType NoteProperty -name "IP Address" -value $($row[1])
                    $AAGListener | add-member -memberType NoteProperty -name "Is DHCP" -value $row[2]
                    $AAGListener | add-member -memberType NoteProperty -name "IP Subnet Mask" -value $row[3]
                    $AAGListener | add-member -memberType NoteProperty -name "Network Subnet Mask" -value $row[4]
                    $AAGListener | add-member -memberType NoteProperty -name "State" -value $row[5]
                    $AAGListener | add-member -memberType NoteProperty -name "DNS Name" -value $($row[6])
                    $AAGListener | add-member -memberType NoteProperty -name "Port" -value $($row[7])
                    $AAGListener | add-member -memberType NoteProperty -name "Is Conformant" -value $row[8]
                    #$AAGListener | add-member -memberType NoteProperty -name "Is distributed network name" -value $row[9]

                    $AAGListeners +=$AAGListener
                }
                $AAG_ListenerFinding.InputObject =$AAGListeners
            }  else  
            {
                $AAG_ListenerFinding.Description = "No Listener found"
            }
            $SQL_AAG_Finding.ChildFindings.Add($AAG_ListenerFinding)
#endregion AAG Listener

            # Task 531: Hide findings uneless there is something to report.
            #$SQLServerFinding.ChildFindings.add(($SQL_AAG_Finding))
            if($null -ne $AAGClusterFinding.InputObject)
            {
                $SQLServerFinding.ChildFindings.add(($SQL_AAG_Finding))
            }
#endregion AAG
        }

    }

    return $SQLServersFinding
}
#endregion SQL and AlwaysOn

function Get-SPFarmInfoHelp
{
    Write-Host "
        SPFarmInfo
        SPFarmInfo is used to collect high level information and report on known configuration issues for SharePoint Server 2013 and up. While we strive to ensure compatibility across all versions of SharePoint OnPrem versions, our primary focus is on versions that continue to be supported by Microsoft.
        
        Usage
        Like previous versions of SPFarmInfo, the script can simply be run out of the box to collect information about a single SharePoint Farm. This information includes
        
        Farm Information
        Servers in the farm
        Services on each Server
        Service Applications
        Service Application Proxy Information
        Proxy Group associations
        Timer Job Information
        Web Application and AAMs
        Side By Side Patching
        Farm Solutions
        Distributed Cache
        Office Online Server
        Authentication configuration
        Search Information
        Kerberos Account configuration

        In addition to the above information collected automatically, the script has other useful switches, some of which gather additional information or perform basic diagnosis.
        
        -PatchInfo
        This requires a nuget provider and module (MSI) to be installed. It checks MSI and WSUS installs and reports back the last few SharePoint patches installed on each server.
        
        -UsageAndReporting
        This will provide additional information specifically designed to troubleshoot Usage and Reporting issues in SharePoint Server and will call out many issues. The information it collects includes
        
            Analytics Topology
            Site and WebRoot Properties specific to Usage and Reporting requirements
            SPUsageManager and SPUsageService definitions
            EventStore Folder Details (and permissions)
            RequestUsage Folder Info and files
            Usage Analytics TimerJob details

        -SiteUrl
        Currently only required if using the UsageAndReporting switch. Can be purposed for other uses, and if not provided it will query for a site Url
        
        -SkipSearchCheck
        This allows skipping the entirety of the Search check that the SPFarmInfo Script utilizes.

        -SkipSearchHealthCheck
        This allows skipping the exhaustive health check that the SPFarmInfo scripts. Useful if you're not interested in all the search health details but still want to collect some search data.
        
        -SkipErrorCollection
        This skips the collection of errors generating during script execution from being saved in the report. 

        -Text
        This provides ability to export the script as a TXT file instead of HTML"
}

function GetMD5Hash($string, $hash)
{
    # Convert string to byte array
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($string)

    # Get the SHA-256 HASH
    $hasher = $null
    switch($hash)
    {
        "SHA256" {$hasher = [System.Security.Cryptography.SHA256Managed]::Create("SHA-256")}
        default {$hasher = [System.Security.Cryptography.MD5]::Create("MD5")}
    }

    # Compute the HASH bytes
    $hashbytes = $hasher.ComputeHash($bytes)

    # Convert the HashBytes to String and remove -
    $bytestring = [System.BitConverter]::ToString($hashbytes).Replace("-","")
    

    return $bytestring
}



function Write-ScriptDisclaimer
{
    # If not skipping the disclaimer, display it
    if(!$SkipDisclaimer)
    {
        Clear-Host
        $title = "Disclaimer"
        $message = "SPFarmInfo is a data collection tool only. It does not make any changes to the SharePoint Environment."
        $message += "`r`nThis script collects servername, domain names, IP addresses, and account names used by SharePoint Server, similar"
        $message += "`r`nto typical data that would be found in ULS logs." 

        $yes = [System.Management.Automation.Host.ChoiceDescription]::new("&Yes")
        $no = [System.Management.Automation.Host.ChoiceDescription]::new("&No")
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $message += " Continue?"


        $result = $host.UI.PromptForChoice($title, $message, $options,0)

        # Don't continue
        if ($result -eq 1)
        {
            exit
        }
    
        
    }
}

function Show-ScriptParameterMenu {
    param (
        [Hashtable]$MenuItems
    )

    # If ISE is used we will want to display the numbered menu
    [bool]$hostIsISE = $SkipParameterMenu -or $host.Name -like "Windows PowerShell ISE Host"

    $selectedIndex = 0

    # Parameters listed in the menu should match the order specified
    $MenuTextItemsList = @()
    $MenuItems.Values | Select-Object Name, @{l="Position";e={$_.Attributes.Position}} | Sort-Object -Property Position | ForEach-Object{$MenuTextItemsList+=$_.Name}
    [string[]]$MenuTextItems = [string[]]$MenuTextItemsList

    if(!$hostIsISE)
    {
        while ($true) {
            
            # Clear the screen and print menu items
            Clear-Host

            $message = [string]::Empty
            $message += "This script contains a number of default collectors. Choose to include additional collectors by selecting"
            $message += "`r`nadditional items from the list below.`r`n"

            write-host $message

            for ($i = 0; $i -lt $MenuTextItems.Length; $i++) {


                    $prefix = "[ ]"

                    # Get the variable with this name and check value
                    if((get-variable $MenuTextItems[$i] -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -ValueOnly) -eq $true)
                    {
                        $prefix = "[X]"
                    }

                if ($i -eq $selectedIndex) {
                    Write-Host ">> $prefix $($MenuTextItems[$i])" -ForegroundColor Cyan
                } else {
                    Write-Host "   $prefix $($MenuTextItems[$i])"
                }
            }

            $message = "`r`n "
            $message +=  ($MenuItems[$MenuTextItems[$selectedIndex]].Attributes.HelpMessage)
            write-host $message -ForegroundColor Cyan

            Write-host "`r`n`r`n Arrow Keys to navigate, [Space] to Toggle an item, [Enter] to continue with script execution"

            # Capture user input
            $readKey = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

            switch ($readKey.VirtualKeyCode) {
                38 { # Up arrow
                    if ($selectedIndex -gt 0) { $selectedIndex-- }
                }
                40 { # Down arrow
                    if ($selectedIndex -lt $MenuTextItems.Length - 1) { $selectedIndex++ }
                }
                32 { # Space Bar - flip the bool
                    $value = (Get-Variable $MenuTextItems[$selectedIndex] -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -ValueOnly)
                    Set-Variable -Name $MenuTextItems[$selectedIndex] -Scope Script -Value (!$value)
                }
                13 { # Enter key
                    # Exit out of menu
                    write-host "`r`n Beginning SPFarmInfo Generation`r`n" -ForegroundColor Cyan
                    return
                }
            }
        }
    }
    else
    {
        #For ISE show the old numbered menu:
        $message = [string]::Empty
        $message += "This script contains a number of default collectors, you can choose to include additional collectors by selecting"
        $message += "`r`nadditional items from the list below."
    
        $paramCount = 0
        $iseMenuParams = $MenuItems.Values | Select-Object Name, @{l="Position";e={$_.Attributes.Position}}, Attributes | Sort-Object -Property Position
        foreach($param in $iseMenuParams)
        {
            $paramCount++
            $selected = " "
            if((Get-Variable $param.Name | Select-Object Value).Value)
            {
                $selected = "X"
            }
            $message += ("`r`n  [{0}] {1}: {2}: {3}" -f $selected, $paramCount, $param.Name, $param.Attributes.HelpMessage)
        }
    
        $message += "`r`n"
        Write-Host $message
    
        $promptMessage = "Please enter the number(s) corresponding to the collector(s) you would like to add or remove separated by a comma"
        $promptMessage += "`r`nor semicolon or press enter to continue"
    
        $promptResult = Read-Host $promptMessage
    
        if([string]::IsNullOrEmpty($promptResult))
        {
            return $null
        }
        else 
        {
            $promptResult = $promptResult.Split(",")
            $promptResult = $promptResult.Split(";")
            $promptResult = $promptResult.Split(":")
            foreach ($paramToToggle in $promptResult)
            {
                $param = $iseMenuParams[($paramToToggle-1)]
                Set-Variable -Name $param.Name -Scope Script -Value (!(Get-Variable $param.Name | Select-Object Value).Value)
            }
        }
        Show-ScriptParameterMenu $MenuItems
    }
}

function Write-ScriptParametersMenu($parameters)
{
    # Don't use if SkipParmeterMenu is used or this is not runing under PowerShell
    #if($SkipParameterMenu -or $host.Name -like "Windows PowerShell ISE Host"){return}

    # Create a new hashtable that will be used for just switch based parameters
    $switchParameters = @{}

    # Loop through each parameter and add only wanted Switch parameters
    foreach($key in $parameters.Keys)
    {
        $parameterMetaData = $parameters[$key]
        if($parameterMetaData.ParameterType -like "switch" -and $parameterMetaData.Name -notin $script:hiddenParams)
        {
            $switchParameters[$key] = $parameterMetaData
        }

    }

    # Show the menu
    Show-ScriptParameterMenu -MenuItems $switchParameters
}


# Main function that calls into building the report and contains the first level findings.
# Keep this clean and organized to make future additions easier
function main
{
    [cmdletbinding()]
    Param()

    Write-ScriptDisclaimer

    #Retrieve list of diags (switches) to run
    Write-ScriptParametersMenu $script:parameters

    #Temporarily disabling the progress bar. Note this does not work properly in this script without using the $Global prefix 
    $oldProgress = $global:ProgressPreference
    $global:ProgressPreference = "SilentlyContinue"
    
    # No need to clear out the errors collection if it's not being collected
    if(!$SkipErrorCollection)
    {
        $error.Clear()
    }
    
    # Attempt to add/detect the Micorosft SharePoint Powershell. SPSE loads this automatically in all Powershell instances
    if($null -eq (Get-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue) -and $null -eq (Get-Command Get-SPFarm -ErrorAction SilentlyContinue))
    {
        Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
    }

    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    if ($null -eq $farm)
    {
       write-host -f Red "Please run this script with an account that has SharePoint Farm Admin rights"
       return
    }
    
    $joined = $farm.GetType().GetProperty("Joined").GetValue($farm)
    
    if(!$joined)
    {
        throw (New-Object -TypeName System.Exception -ArgumentList "The server is not currently connected to a SharePoint farm")
    }
    
    $script:SPFarm = $farm
    $Script:SPFarmBuild = $script:SPFarm.BuildVersion
    $script:servers = Get-SPServer | Sort-Object Name
    $script:spDatabases = Get-SPDatabase | Sort-Object Name

    if($Help)
    {
        Get-SPFarmInfoHelp
        break
    }

    $Script:RunStartTime=Get-Date
    $Script:build = Get-SPVersion

    # Keeps track of finding times for execution
    $Script:FindingTimes = @()

    <# task:546 removing PatchInfo
    # Warn that PatchInfo requires a Nuget Proider and Microsoft MSI Module to be installed. 
    if($PatchInfo)
    {
        $title    = "PatchInfo Warning"
        $prompt = "PatchInfo requires a Nuget Provider and Microsoft's MSI Module to be installed. This may be prompt for each server in the farm. Continue with PatchInfo?"
        $choices  = "&Yes", "&No"

        $choice = $Host.UI.PromptForChoice($title, $prompt, $choices, 1)
        if ($choice -ne 0) {
            #No
            Write-Host "Disabling PatchInfo Gathering"
            $PatchInfo = $false
        }
    }
    #>

    $site = $null

    if([string]::IsNullOrEmpty($script:siteUrl) -and $UsageAndReporting)
    {
        $script:siteUrl = Read-Host "Please provide a site url [Default:http://sharepoint]"
        if([String]::IsNullOrEmpty($siteUrl))
        {
            $script:siteUrl = "http://sharepoint"
        }
       
    }

    if($UsageAndReporting)
    {
        $site = get-spsite $siteUrl
    }
    
    if($null -eq $site -and $UsageAndReporting)
    {
        Write-Host "Site $siteUrl Not Found" -ForegroundColor Red
        return;
    }

    if($UsageAndReporting -and $site)
    {
        Select-SPDiagnosticSSA
    }
    
    $rootFindingCollection = New-Object SPDiagnostics.FindingCollection[SPDiagnostics.Finding]
    if($UsageAndReporting -and $site)
    {
        $rootFindingCollection.Add((Get-SPDiagnosticUsageAndReportingInformation $site))
    }

    $supportDateFinding = Get-SPDiagnosticSupportDateFinding
    if ($null -ne $supportDateFinding -and (
            [int]$supportDateFinding.Severity -ge [int][SPDiagnostics.Severity]::Warning -or
            $supportDateFinding.ChildFindings.Count -gt 0))
    {
        $rootFindingCollection.Add($supportDateFinding)
    }
    $rootFindingCollection.Add((Get-SPDiagnosticFarmFindings))
    $rootFindingCollection.Add((Get-SPDiagnosticAuthFindings))
    $rootFindingCollection.Add((Get-SPDiagnosticSearchFindings))

    #if($Search)
    #{
    #    $rootFindingCollection.Add((Get-SPDiagnosticSearchFindings))
    #}   

    if($DistributedCache -or $Performance)
    {
        $rootFindingCollection.Add((Get-SPDiagnosticsDCacheFinding))
    }

    if($TLS)
    {
        $rootFindingCollection.Add((Get-SPDiagnosticsTlsFinding))
    }

    $scriptDiagnosticFinding = (Get-ScriptExecutionInfo) # Info about server the script is executed on


    # Collect Errors during script execution for script diagnostics. Can be avoided with -SkipErrorCollection switch
    if($error.Count -gt 0 -and !$SkipErrorCollection)
    {
        # Remove the well known "No Windows PowerShell snap-ins matching the pattern" Error from the collection
        if($error[$error.Count - 1].Exception.Message.StartsWith("No Windows PowerShell"))
        {
            $error.RemoveAt($error.count -1)
        }

        # If there's still a collection of errors, then report on it.
        if($error.Count -gt 0)
        {
            $errorFinding = New-DiagnosticFinding -Name "Error Collection" -InputObject $Null -Format List
            $errorFinding.Description = "These are errors generated ONLY during script execution. They do not represent an issue that needs to be resolved"
                $errorFinding.Description += "These are intended to assist with identifying SPFarmInfo script issues"
                $errorFinding.InputObject = $error
            $scriptDiagnosticFinding.ChildFindings.Add($errorFinding)
        }
    }

    $rootFindingCollection.Add($scriptDiagnosticFinding)

    write-host "Generating HTML file"

    $diagnosticContent = $null
    $fileName = "SPFarmInfo_"

    $fileName = "{0}\$fileName{1}_{2}" -f $ENV:UserProfile, $build, [datetime]::Now.ToString("yyyy_MM_dd_HH_mm")

    if($text)
    {
        $diagnosticContent = Write-DiagnosticReport -Findings $rootFindingCollection -OutputFormat TEXT
        $fileName = $fileName + ".txt"
    }
    else
    {
        $diagnosticContent = Write-DiagnosticReport -Findings $rootFindingCollection
        $fileName = $fileName + ".html"
    }
  
    if($UseEncodedServerId)
    {
        Write-Host "Generating Hashes for Servernames and Addresses"
        foreach($server in $script:servers)
        {
            $diagnosticContent = $diagnosticContent.Replace($server.Address,$server.EncodedServerId)
            $diagnosticContent = $diagnosticContent.Replace($server.Name,$server.EncodedServerId)
        }
    }

    if($text)
    {
        Set-Content -Value $diagnosticContent -LiteralPath $fileName
    }
    else
    {
        Set-Content -Value $diagnosticContent -LiteralPath $fileName -Encoding UTF8
    }
    
    

    # Do not attempt to load the HTML file on Server Core
    if (!((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\windows NT\CurrentVersion" -Name "InstallationType").InstallationType -match "Core"))
    {
        write-Host "Opening file"
        Invoke-Item $fileName
    }
    Write-Host ("`n`nScript complete, review the output file at `"{0}`"" -f $fileName) -ForegroundColor Green

    #reset ProgressPreference back to original value. Note: This does not work without using $global prefix
    $global:ProgressPreference = $oldProgress
}

main