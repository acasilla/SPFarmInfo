<#
.SYNOPSIS
    Collects high level farm information and reports known configuration issues for SharePoint 2013+
.DESCRIPTION
    Collects information including but not limited to:
        + Farm build and configuration database location and name
        + Web application urls and alternate access mappings
        + Service applications
        + Authentication methods and configurations
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    None at this time
.OUTPUTS
    An html report documenting findings.
.NOTES
    General notes
    Version .1
#>
param(
    [Parameter(Position=1,HelpMessage="Displays Help associated with the SPFarmInfo script")]
    [switch]$Help,
    [Parameter(Position=2,HelpMessage="Queries MSI and Update Session for Patch Information related to SharePoint")]
    [switch]$PatchInfo,
    [Parameter(Position=3,HelpMessage="Performs Data Collection to assist in troubleshooting Usage Analysis and Reporting Issues. Requires -SiteUrl parameter")]
    [switch]$UsageAndReporting,
    [Parameter(Position=4,HelpMessage="SiteUrl parameter, required for UsageAndReporting check")]
    [string]$SiteUrl,
    [Parameter(Position=5,HelpMessage="Skips the indepth Search Health Check")]
    [switch]$SkipSearchHealthCheck,
    [Parameter(Position=6,HelpMessage="Performs checks on whether configurations necessary for TLS1.2 and ciphers necessary for connecting to Azure Front Door (M365) are done")]
    [switch]$TLS
)

if([System.IntPtr]::Size -lt 8)
{
    Write-Error "Get-SPFarmInfo Is not supported on x86 Powershell/Powershell ISE instances"
    exit
}

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
Add-Type -TypeDefinition $cs -Language CSharp


#cmdlet used to create new SPDiagnostics.Finding objects for eas of consumption
#use this method to create diagnostic findings that will be included in the report
function New-SPDiagnosticFinding
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
    $finding = New-SPDiagnosticFinding -Name "Security Token Service Config" -Description "Details of Get-SPSecurityTokenServiceConfig" -Category Authentication -Severity Default -InputObject $sts -Format Table
    
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
        throw (New-Object System.ArgumentException -ArgumentList @("Warning message cannot be empty for an error or warning finding"))
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

    Write-Host ("Generating finding -- {0}" -f $Name)

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
function New-SPDiagnosticFindingCollection
{
    [cmdletbinding()]
    Param()

    return New-Object SPDiagnostics.FindingCollection[SPDiagnostics.Finding]
}



# Internal method that should not be directly consumed outside of the core framework to generate the report
function Write-DiagnosticFindingFragment
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [SPDiagnostics.Finding]
        $Finding,

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

        $preContent = "<details{0}><summary class=`"heading {1}`">{2}</summary><div class=`"finding`">" -f $expandStr, $class, $Finding.Name
        foreach($warningMessage in $finding.WarningMessage)
        {
            $preContent+="<div class=`"warning-message`"> {0} </div><br>" -f $warningMessage
        }
        
        foreach($desc in $finding.Description)
        {
            $preContent+="<div class=`"description`">{0}</div>" -f $desc
        }
        
        foreach($link in $Finding.ReferenceLink)
        {
            $preContent+="<div>Reference: <a href=`"{0}`" target=`"_blank`">{0}</a></div><br/>" -f $link.AbsoluteUri
        }

        $postContent = "</details>"
        
        if($null -ne $Finding.InputObject)
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
            
            if($properties.Count -eq 1)
            {
                $property =  $properties[0]
                $propertyName = $property.Name
                $htmlFragment = $Finding.InputObject | ConvertTo-Html -Property $propertyName -PreContent $preContent -As $Finding.Format -Fragment
            }
            else
            {
                $htmlFragment = $Finding.InputObject | ConvertTo-Html -PreContent $preContent -As $Finding.Format -Fragment
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
                $childContent = Write-DiagnosticFindingFragment -Finding $child
                $htmlFragment+=$childContent
            }
        }

        $htmlFragment+=$postContent

        return $htmlFragment
    }
    catch
    {
        Write-Error $_
        return $null
    }
}



#Core function to write html report
function Write-DiagnosticReport
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [SPDiagnostics.Finding[]]
        $Findings
    )

    #Defining CSS to be applied to the report
    $globalCss = @"
    <style>
        table {
            font-family: calibri;
            border: 1px solid;
            border-radius: 5px;
            border-style: solid;
            border-color: gray;
        }

        th {
            padding-top: 6px;
            padding-bottom: 6px;
            text-align: center;
            background-color: #0072c6;
            color: white;
            border-radius: 5px;
        }

        body {
            font-family: Segoe UI;
        }

        .error {
            color: Red;
        }

        .warning {
            color: darkorange;
        }

        .review-section {
            border: black;
            border: 1px;
            border-style: solid;
            border-radius: 10px;
            padding: 5px;
        }

        .warning-message {
            color: Red;
        }

        tbody tr:nth-child(even) {
            background: #f1f1f1;
        }

        .finding {
            padding-left: 30px;
            font-size: 15px;
            /*color: #575757;*/
        }

        .heading {
            font-size: large;
            font-weight: bold;
            padding-top: 10px;
            padding-bottom: 10px;
            border-radius: 5px;
        }

        .code {
            font-size: `$base-font-size * 0.875;
            font-family: 'consolas', 'monospace';
            color: blue;
            padding: 0 1em;
        }
    </style>
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
    

    $html = "<!DOCTYPE html><head><Title>SPFarmReport - {0}</Title></head><body>" -f $build
    $html+=$globalCss
    $html+="<div id=`"topInfo`""
    $html+="<h1>SPFarmReport - {0}</h1>" -f $build
    $html+="<p style=`"font-style: italic;`">Generated at {0} UTC</p>" -f [datetime]::UtcNow.ToString("MM/dd/yyyy hh:mm:ss tt")    
    $html+="<a href='#/' id='expAll' class='col'>Expand All</a>"
    $html+="<div id=`"ieWarning`" />
    <script type=`"text/javascript`">
        var isIe = navigator.userAgent.indexOf(`"Trident`") > -1;
        if(isIe){
            document.getElementById(`"expAll`").style.display = `"none`";
            document.getElementById(`"ieWarning`").innerHTML = `"This report is not optimized for IE for best results open this report in Microsoft Edge.`";
        }
    </script>"
    $html+="</div>"

    # Identify "Critical" and "Warning" findings so that they can be promoted
    $criticalFindings = Get-SPErrorFindings -Findings $Findings -Severity Critical
    $warningFindings = Get-SPErrorFindings -Findings $Findings -Severity Warning
    $informationalFindings = Get-SPErrorFindings -Findings $Findings -Severity Informational
    
    # If there are critical findings create a "review-section" for critical findings at the top of the report
    if($criticalFindings.Count -ge 1)
    {
        $html+="<div class=`"review-section`" style=`"border-color:red;`"><div class=`"error heading`">Critical Findings</div>"
        foreach($finding in $criticalFindings)
        {
            try
            {
                $expand = $finding.Expand
                $finding.Expand = $true
                $fragment = Write-DiagnosticFindingFragment -Finding $finding -ExcludeChildFindings
                $html+=$fragment
                $finding.Expand = $expand
            }
            catch
            {
                Write-Warning $_
            }
        }
        $html+="</div><br>"
    }

    # Similar to critical findings promote any warnings that may be present
    if($warningFindings.Count -ge 1)
    {
        $html+="<div class=`"review-section`" style=`"border-color:darkorange`"><div class=`"warning heading`">Review Items</div>"
        foreach($finding in $warningFindings)
        {
            try
            {
                $fragment = Write-DiagnosticFindingFragment -Finding $finding -ExcludeChildFindings
                $html+=$fragment
            }
            catch
            {
                Write-Warning $_
            }
        }
        $html+="</div><br>"
    }


    # Similar to critical findings promote any warnings that may be present
    if($informationalFindings.Count -ge 1)
    {
        $html+="<div class=`"review-section`" style=`"border-color:black`"><div class=`"heading`">Informational Items</div>"
        foreach($finding in $informationalFindings)
        {
            try
            {
                $fragment = Write-DiagnosticFindingFragment -Finding $finding -ExcludeChildFindings
                $html+=$fragment
            }
            catch
            {
                Write-Warning $_
            }
        }
        $html+="</div><br>"
    }
    
    foreach($finding in $Findings)
    {
        if($null -eq $finding)
        {
            continue
        }
        try
        {
            $fragment = Write-DiagnosticFindingFragment -Finding $finding
            $html+=$fragment
        }
        catch
        {
            Write-Warning $_
        }
    }

    $html+=("<script type=`"text/javascript`">{0}</script>" -f $expandAllJS)
    $html+="</body></html>"

    return $html
}

function Get-SPErrorFindings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [SPDiagnostics.Finding[]]
        $Findings,

        [Parameter(Mandatory=$true)]
        [SPDiagnostics.Severity]
        $Severity
    )
    
    $returnFindings = New-SPDiagnosticFindingCollection #New-Object SPDiagnostics.FindingCollection
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
                    $returnFindings+=(Get-SPErrorFindings -Findings $ChildFinding -Severity $Severity -ErrorAction SilentlyContinue)
                }
            }
        }
    }
    return $returnFindings
}

#endregion

#SPVersion Function
function GetSPVersion($buildPrefix)
{
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $script:SPFarm = $farm
    $Script:SPFarmBuild = $script:SPFarm.BuildVersion

    If($farm.BuildVersion.Major -eq 16 -or $farm.BuildVersion.Major -eq 15)
    {
        if($farm.BuildVersion.Major -eq 16)
        {
            if($farm.BuildVersion.Build -ge 14326)
            {
                $buildFoo = "SPSE"
            }
            elseif($farm.BuildVersion.Build -ge 10337 -and $farm.BuildVersion.Build -lt 14320)
            {
                $buildFoo = "2019"
            }
            else
            {
                $buildFoo = "2016"
            }
        }
        else
        {
            $buildFoo = "2013"
        }

    }
    elseIf($farm.BuildVersion.Major -eq 14)
    {
        Write-Warning "The support for SharePoint 2010 has ended, please update this farm to a newer version of SharePoint.. Aborting Script"
        exit
    }
    else
    {
        Write-Warning "Unsupported Version of SP... Aborting script"
        exit
    }
    return $buildFoo
}

function Get-SPDiagnosticsSupportDateFinding
{
    [cmdletbinding()]
    Param()
    $supportDateFinding = New-SPDiagnosticFinding -Name "Support Dates" -InputObject $null -Format Table -Expand
    
    $adminWebApp = [Microsoft.SharePoint.Administration.SPAdministrationWebApplication]::Local
    $adminSite = $adminWebApp.sites["/"]
    $build = GetSPVersion $buildPrefix

    $endOfSupportInfo = [PSCustomObject]@{
    }

    if($build -eq "SPSE")
    {
        $endOfSupportNotificationLink = "https://go.microsoft.com/fwlink/?LinkId=2198657" #"<a href=`"{0}`" target=`"_blank`">{0}</a>" -f "https://go.microsoft.com/fwlink/?LinkId=2198657"
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2199, 12, 1), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2199, 12, 1), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        
    }
    elseif($build -eq "2019")
    {
        $endOfSupportNotificationLink = "https://go.microsoft.com/fwlink/?LinkId=2198656" #"<a href=`"{0}`" target=`"_blank`">{0}</a>" -f "https://go.microsoft.com/fwlink/?LinkId=2198656"
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2024, 1, 9), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2026, 7,14), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
    }
    elseIf($build -eq "2016")
    {
        $endOfSupportNotificationLink = "https://go.microsoft.com/fwlink/?LinkId=2198655" #"<a href=`"{0}`" target=`"_blank`">{0}</a>" -f "https://go.microsoft.com/fwlink/?LinkId=2198655"
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2021, 7, 13), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2026, 7, 14), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
    }
    elseif($build -eq "2013")
    {
        $endOfSupportNotificationLink = "https://go.microsoft.com/fwlink/?LinkId=2198654" #"<a href=`"{0}`" target=`"_blank`">{0}</a>" -f "https://go.microsoft.com/fwlink/?LinkId=2198654"
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2018, 4, 10), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2023, 4, 11), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
    }
    else
    {
        " Your version of SharePoint is no longer Supported"
        return
    }
    
    $endOfSupportSeverityLevel = "   None   "

    $endOfSupportDateInfo = $endOfSupportDate.AddYears(-2)
    $endOfSupportDateWarning = $endOfSupportDate.AddMonths(-18)

    $mainstreamSupportDateInfo = $mainstreamSupportDate.AddMonths(-12)
    $mainstreamSupportDateWarning = $mainstreamSupportDate.AddMonths(-6)

    $endOfSupportDateString = [Microsoft.SharePoint.Utilities.SPUtility]::FormatDate($adminSite.RootWeb, $endOfSupportDate, [Microsoft.SharePoint.Utilities.SPDateFormat]::DateOnly)
    $mainstreamSupportDateString = [Microsoft.SharePoint.Utilities.SPUtility]::FormatDate($adminSite.RootWeb, $mainstreamSupportDate, [Microsoft.SharePoint.Utilities.SPDateFormat]::DateOnly)

    $currentDate = [System.DateTime]::UtcNow.AddDays(-1)

    $mainstreamDateWarning = ($currentDate -gt $mainstreamSupportDateWarning) -and ($currentDate -lt $mainstreamSupportDate) 

    if([System.DateTime]::Compare($currentDate, $endOfSupportDateInfo) -ge 0)
    {
        if([System.DateTime]::Compare($currentDate, $endOfSupportDateWarning) -lt 0)
        {
            $endOfSupportSeverityLevel = "Attention";
        }

        elseif([System.DateTime]::Compare($currentDate, $endOfSupportDate) -lt 0)
        {
            $endOfSupportSeverityLevel = "Warning";
            $supportDateFinding.Description += "This version of SharePoint Server is in 'Extended' Support.</br> Extended Support provides limited supportability. Microsoft does not accept requests for fixes, design changes, or new features during the Extended Support Phase.</br> Microsoft will only release 'Security' related updates in the patching cycle.</br>"
        }
        else
        {
            $endOfSupportSeverityLevel = "Alert";
            $supportDateFinding.WarningMessage += "Support for this version of SharePoint Server has ended!</br> This means that Microsoft Support cannot provide any technical support.</br> Please Upgrade to a supported version of SharePoint"
        }   
    }
    else
    {
        If([System.DateTime]::Compare($currentDate, $mainstreamSupportDateInfo) -ge 0)
        {
            if([System.DateTime]::Compare($currentDate, $mainstreamSupportDateWarning) -lt 0)
            {
                $endOfSupportSeverityLevel = "Attention";
            }

            elseif([System.DateTime]::Compare($currentDate, $mainstreamSupportDate) -lt 0)
            {
                $endOfSupportSeverityLevel = "Warning";
                $supportDateFinding.Description += "This version of SharePoint Server is in nearing the end of 'Mainstream' support.</br>In 'Extended Support', Microsoft provides limited supportability. Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' Phase.</br> Microsoft will only release 'Security' related updates in the patching cycle.</br>"
            }
            else
            {
                $endOfSupportSeverityLevel = "Alert";
                $supportDateFinding.Description += "This version of SharePoint Server is in 'Extended' Support.</br> Extended Support provides limited supportability. Microsoft does not accept requests for fixes, design changes, or new features during the Extended Support Phase.</br> Microsoft will only release 'Security' related updates in the patching cycle.</br>"
            }   
        }
    }
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Alert" -Value $endOfSupportSeverityLevel
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Mainstream End Date" -Value $mainstreamSupportDateString
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Extended End Date" -Value $endOfSupportDateString
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Information" -Value $endOfSupportNotificationLink
        
        #if($mainstreamDateWarning)
        #{
        #    $supportDateFinding.WarningMessage += "Your version of SharePoint is in nearing the end of 'Mainstream' support.</br> This means that once we are in 'Extended Support', Microsoft Support cannot file any requests for any 'bugs' or 'change requests.'</br> Microsoft will only release 'Security' related updates in the patching cycle."
        #}
        #
        #if($endOfSupportInfo.Alert -contains "Warning")
        #{
        #    $supportDateFinding.WarningMessage += "Your version of SharePoint is in no longer in 'Mainstream' support.</br> This means that Microsoft Support cannot file any requests for any 'bugs' or 'change requests' while in 'Extended' support.</br> Microsoft will only release 'Security' related updates in the patching cycle."
        #}
        #if($endOfSupportInfo.Alert -contains "Alert")
        #{
        #    $supportDateFinding.WarningMessage += "Your version of SharePoint is in no longer supported.</br> This means that Microsoft Support cannot any technical support.</br> Please Upgrade to a supported version of SharePoint"
        #}

        $supportDateFinding.InputObject =  $endOfSupportInfo
        return $supportDateFinding              
}

Function Get-SPDiagnosticFarmFindings
{
    [cmdletbinding()]
    Param()
    $farmFindings = New-SPDiagnosticFinding -Name "Farm configuration" -InputObject $null
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticFarmBuildInfo))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServersInFarm))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServicesOnServer))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServiceAppInfo))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticTimerAndAdminServiceFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticTimerJobHistoryFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsWebAppsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsSideBySidePathcingFinding))

    return $farmFindings
}

function Get-SPDiagnosticFarmBuildInfo
{
    [cmdletbinding()]
    Param()
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $configDb = Get-SPDatabase | Where-Object{$_.TypeName -match "Configuration Database"}
    $SPDiagnosticConfig = Get-SPDiagnosticConfig
    $LogLevel = Get-SPLogLevel
    $countOfVerboseEx = ($LogLevel | Where-Object{$_.TraceSeverity -eq "VerboseEx"} | measure-object | select-object Count).Count


    $retObj = [PSCustomObject]@{
        FarmBuildVersion = $farm.BuildVersion.ToString()
        "ULS Log Location" = $SPDiagnosticConfig.LogLocation
        DaysToKeepLogs = $SPDiagnosticConfig.DaysToKeepLogs
        LogMaxDiskSpaceUsageEnabled = $SPDiagnosticConfig.LogMaxDiskSpaceUsageEnabled
        LogDiskSpaceUsageGB = $SPDiagnosticConfig.LogDiskSpaceUsageGB
        "VerboseEx LogLevel Count" = $countOfVerboseEx
        ConfigDbName = $configDb.Name
        ConfigDbId = $configDb.Id
        ConfigDbSql = $configDb.ServiceInstance.Server.Address
        ConfigDbInstance = $configDb.ServiceInstance.Instance
    }
    $finding = New-SPDiagnosticFinding -Name "Farm Info" -Description "Farm build, ULS Location, and config db" -InputObject $retObj -Format List -Expand 

    if($countOfVerboseEx -gt 0 -or $countOfVerboseEx -gt 0 -or $countOfVerboseEvents)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "TraceSeverity is set to VerboseEx on $countOfVerboseEx LogLevel(s). This may cause performance issues"
    }
    return $finding

}

function Get-SPDiagnosticServersInFarm
{
    $serverColl = @()
    $servers = (Get-SPServer | Sort-Object Role, Name)
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
                $productStatusLevel = [SPDiagnostics.Severity]::Warning
                if($productStatus -ieq "UpgradeBlocked" -or $productStatus -ieq "InstallRequired" -or $productStatus -ieq "UpgradeInProgress" )
                {
                    $productStatusLevel = [SPDiagnostics.Severity]::Critical
                }
            }

        }

        $osInfo = Get-SPDiagnosticsOsInfo $svr

        $serverColl+=  [PSCustomObject]@{
            Name = $svr.DisplayName
            Role = $svr.Role
            Id = $svr.Id
            EncodedServerId = $svr.EncodedServerId
            Status = $svr.Status
            ProductStatus = $productStatus
            OperatingSystem = $osInfo.OSName
            ServicePack = $osInfo.ServicePack
            Model           = $osInfo.Model
            Processors      = $osInfo.ProcessorCount
            Cores           = $osInfo.ProcessorCoreCount
            TotalRAM          = $osInfo.TotalRAM
            TimeZone = $osInfo.TimeZone
        }
    }
    
    $finding = New-SPDiagnosticFinding -Name "Servers in Farm" -Severity Default -InputObject $serverColl -Format Table -Expand

    if($PatchInfo)
    {
        $patchInfoServerList = $servers | Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
        foreach($server in $patchInfoServerList)
        {
            $finding.ChildFindings.Add((Get-SPPatchInfo $server))
        }
    }

    if($productStatusBool)
    {
        $finding.Severity = $productStatusLevel
        $finding.WarningMessage = "Inconsistent patch or upgrade state identified, please complete relevant actions on the identified servers"
        $finding.Expand = $false
    }

    return $finding

}


function Get-SPDiagnosticsOsInfo
{
    [cmdletbinding()]
    Param([Microsoft.SharePoint.Administration.SPServer]$server)

    try
    {
        $timeZone = $(Get-WMIObject -Class Win32_TimeZone -Computer $svr.DisplayName -ErrorAction Stop).Description
        [wmi]$sysInfo = get-wmiobject Win32_ComputerSystem -Namespace "root\CIMV2" -ComputerName $svr.DisplayName -ErrorAction Stop
        [wmi]$os = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -Computername $svr.DisplayName -ErrorAction Stop
        [array]$procs = Get-WmiObject Win32_Processor -Namespace "root\CIMV2" -Computername $svr.DisplayName -ErrorAction Stop
        #[array]$mem = Get-WmiObject Win32_PhysicalMemory -Namespace "root\CIMV2" -ComputerName $svr.DisplayName -ErrorAction Stop
        
        if(![string]::IsNullOrEmpty($os.Name))
        {
            $osName = [string]$os.Name.Substring(0,$os.Name.IndexOf("|"))
            $osName = $osName.Replace("Microsoft Windows", "")
        }
        else
        {
            $osName = [string]::Empty
        }

        if(![string]::IsNullOrEmpty($os.ServicePackMajorVersion))
        {
            $servicePack = ("SP {0}" -f [string]$os.ServicePackMajorVersion)
        }
        else 
        {
            $servicePack = [string]::Empty
        }
        $model = [string]$sysInfo.Model
        $procCount = [string]@($procs).Count
        $coreCount = [string]$procs[0].NumberOfCores
        $totalRAM = "$([string]([System.Math]::Round($sysInfo.TotalPhysicalMemory/1gb,2))) GB"
    }
    catch
    {
        ##swallow exceptions
        return $null
    }

    $retObj = [PSCustomObject]@{
        TimeZone = $timeZone
        OsName = $osName
        ServicePack = $servicePack
        Model = $model
        ProcessorCount = $procCount
        ProcessorCoreCount = $coreCount
        TotalRAM = $totalRAM
    }

    return $retObj
}


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
        $patchFinding = New-SPDiagnosticFinding -Name $server.DisplayName -Severity Default -InputObject $refined -format Table -Description "Patching Information"
        return $patchFinding
    }

    return $null

}

function Get-SPDiagnosticServicesOnServer
{
    [cmdletbinding()]
    Param()
    $runningServices = @()
    $servers = Get-SPServer | Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    foreach($server in $servers)
    {
        $services = $server.ServiceInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Disabled}
        foreach ($service in $services)
        {
            $runningServices+=[PSCustomObject]@{
                Server = $server.Address
                Service = $service.TypeName
                Status = $service.Status
                Id = $service.Id
            }
        }
    }

    $finding = New-SPDiagnosticFinding -Name "Services on Server" -InputObject $runningServices -Format Table
    
    $troubleServices = $runningServices | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    if($null -ne $troubleServices)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "One or more services identified in a starting or stopping state"
    }
    
    return $finding
}


function Get-SPDiagnosticTimerAndAdminServiceFinding
{
    [cmdletbinding()]
    Param()
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $timerInstances = $farm.TimerService.Instances | Select-Object @{l="Server";e={$_.Server.Address}}, Status, AllowServiceJobs, AllowContentDatabaseJobs, Id
    $problemTimerInstances = $timerInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    
    $timerFinding = New-SPDiagnosticFinding -Name "Timer Service Instances" -InputObject $timerInstances -Format Table

    if($null -ne $problemTimerInstances)
    {
        $timerFinding.Severity = [SPDiagnostics.Severity]::Critical
        $timerFinding.WarningMessage += "One or more Timer Service Instances is not online"
        $timerFinding.Description+=("Example PowerShell to set the 'Timer Service Instance' object back online.<br/><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guid of disabled object')<br/>`$obj.Status = [Microsoft.SharePoint.Administration.SPObjectStatus]::Online<br/>`$obj.Update()</div>Once the above PowerShell is performed you Must restart the 'SharePoint Timer Service' service on that server (within services.msc console)<br/>")
        $timerFinding.ReferenceLink += "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"
    }

    
    $adminSvc = $farm.Services | Where-Object{$_.TypeName -eq "Microsoft SharePoint Foundation Administration"}
    $adminInstances = $adminSvc.Instances | Select-Object @{l="Server";e={$_.Server.Address}}, Status, Id
    $problemAdminInstances = $adminInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    
    $adminFinding = New-SPDiagnosticFinding -Name "Administration Service Instances" -InputObject $adminInstances -Format Table

    if($null -ne $problemAdminInstances)
    {
        $adminFinding.Severity = [SPDiagnostics.Severity]::Critical
        $adminFinding.WarningMessage = "One or more Admin Service Instances is not online"
        $adminFinding.Description+=("Example PowerShell to set the 'Admin Service Instance' object back online.<br/><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guid of disabled object')<br/>`$obj.Status = [Microsoft.SharePoint.Administration.SPObjectStatus]::Online<br/>`$obj.Update()</div>Once the above PowerShell is performed you Must restart the 'SharePoint Administration' service on that server (within services.msc console)<br/>")
        $adminFinding.ReferenceLink = "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"
    }


    $finding = New-SPDiagnosticFinding -Name "Timer and Admin Service Instances" -InputObject $null -Format Table
    $finding.Description += "The 'Timer' and 'Admin' Service Instances are critical for proper SP functionality. They are *not* to be confused with the 'Timer' and 'SP Admin' services within 'services.msc' console. <br/>Your 'services' in the console can be 'running' fine, but if these 'instances' are not Online, then the execution of one-time timer jobs will not function.<br/>This can prevent other service instances from 'provisioning' properly.<br/>"
    $finding.ChildFindings.Add($timerFinding)
    $finding.ChildFindings.Add($adminFinding)

    return $finding
}


function Get-SPDiagnosticServiceAppInfo
{
    [cmdletbinding()]
    Param()
    $serviceApps = Get-SPServiceApplication | Select-Object DisplayName, TypeName, Id, Status
    $serviceAppFinding = New-SPDiagnosticFinding -Name "Service Applications" -InputObject $serviceApps -Format Table

    ## Dump out proxies as well
    $proxies = Get-SPServiceApplicationProxy | Select-Object DisplayName, TypeName, Id, Status
    $proxyFinding = New-SPDiagnosticFinding -Name "Service Application Proxies" -InputObject $proxies -Format Table

    ## As a child finding dump out the service application associations
    $proxyGroups = Get-SPServiceApplicationProxyGroup
    $proxyGroupObjects = @()
    foreach($proxyGroup in $proxyGroups)
    {
        foreach($proxy in $proxyGroup.Proxies)
        {
            $proxyGroupObjects += [PSCustomObject]@{
                ProxyGroup = $proxyGroup.FriendlyName
                Proxy = $proxy.DisplayName
            }
        }
    }
    $proxyGroupFinding = New-SPDiagnosticFinding -Name "Proxy Group Associations" -InputObject $proxyGroupObjects -Format Table

    $serviceAppFinding.ChildFindings.Add($proxyFinding)
    $serviceAppFinding.ChildFindings.Add($proxyGroupFinding)

    return $serviceAppFinding
}

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


function Get-SPDiagnosticTimerJobHistoryFinding
{
    [cmdletbinding()]
    Param()
    $servers = Get-SPServer | Where-Object{$_.Role -ne "Invalid"}
    $warningRowCount = 1000000*$servers.Count
    $configDb = Get-SPDatabase  | Where-Object{$_.TypeName -match "Configuration Database"}
    $result = Invoke-SPSqlCommand -spDatabase $configDb -query "select count(1) from dbo.TimerJobHistory with(nolock)"
    $rowCount = $result.Column1[0]

    $result2 = Invoke-SPSqlCommand -spDatabase $configDb -query "Select MIN(EndTime) as Oldest, MAX(EndTime) as Newest from TimerJobHistory with(nolock)"

    $finding = New-SPDiagnosticFinding -Name "TimerJobHistory" -Description ("<ul><li>The timer job history table currently has {0} rows</li>" -f $rowCount.ToString('N0')) -InputObject $null -Format Table
    if($rowCount -ge $warningRowCount)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage += ("Timer job history table has more than {0} rows, make sure that timer job history is being properly cleaned up" -f $rowCount.ToString('N0'))
        $finding.ReferenceLink += "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"
    }

    $job = Get-SPTimerJob job-delete-job-history
    $finding.Description+=("<li>Job LastRunTime: {0}</li>" -f $job.LastRunTime)
    $finding.description+=("<li>Oldest record: {0}</li>" -f $result2.Oldest[0])
    $finding.description+=("<li>Newest record: {0}</li>" -f $result2.Newest[0])
    $finding.Description+=("<li>DaysToKeepHistory: {0}</li></ul>" -f $job.DaysToKeepHistory)
    $uri = New-Object System.Uri('https://blog.stefan-gossner.com/2017/12/13/changes-in-the-timerjobhistory-table-maintenance-introduced-in-november-2017-cu-for-sharepoint-2013/')
    $finding.ReferenceLink += $uri

    if($null -eq $job)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+=("`nThe timer job `"{0}}`" does not exist, take steps to reprovision the job" -f $job.DisplayName)
    }

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
   
    return $finding
}

function Get-SPDiagnosticsWebAppsFinding
{
    [cmdletbinding()]
    Param()
    $webAppsFinding = New-SPDiagnosticFinding -Name "Web Applications & AAMs"
    $webApps = Get-SPWebApplication -IncludeCentralAdministration
    foreach($webApp in $webApps)
    {
        $aams = $webApp.AlternateUrls | Select-Object -Property IncomingUrl, Zone, PublicUrl | Sort-Object -Property Zone
        $webAppName = "Web Application: '" + $webApp.DisplayName + "' (" + $webApp.Url + ") || (DB Count: " + $webApp.ContentDatabases.Count + " | " + "Site Count: " + $webApp.Sites.Count + ")"
        $webAppFinding = New-SPDiagnosticFinding -Name $webAppName -InputObject $aams -Format Table

        $dbInfo = $webApp.ContentDatabases | Select-Object Name, @{N='SiteCount'; E={$_.CurrentSiteCount}}, Id, Status, BuildVersion, @{N='DB Server'; E={$_.NormalizedDataSource}},@{N="DB Size(GB)"; E={$([string]([System.Math]::Round($_.DiskSizeRequired/1gb,2)))}}, IsReadOnly, IsAttachedToFarm, IsSqlAzure, PreferredTimerServerInstance
        $cdbfinding = New-SPDiagnosticFinding -Name "Content Database(s) Information" -Severity Default -InputObject $dbInfo -Format Table
        $webAppFinding.ChildFindings.Add($cdbfinding)

        # itterate through aams to get zones to check to be sure to not miss manually created aams
        # if there are manually created AAMs call them out
        foreach($aam in $aams)
        {
            if($aam.IncomingUrl -eq $aam.PublicUrl)
            {
                $iisSettings = $webApp.IisSettings[$aam.Zone]
                if($null -eq $iisSettings)
                {
                    $webAppFinding.Severity = "Warning"
                    $webAppFinding.WarningMessage += ("The [{0}] Zone Url is manually created, the manually created aam should be removed and the web application properly extended into the zone" -f $aam.Zone)
                }
                else
                {
                    $iisSettingName = "IIS Settings: " + " -- Zone: " + $aam.Zone + " | Url:  " + $aam.PublicUrl
                    $iisSettingsFinding = New-SPDiagnosticFinding -Name $iisSettingName -InputObject $null -Format List
                    $iisSettingsObj = $iisSettings | Select-Object ServerComment, Path, PreferredInstanceId, AuthenticationMode, MembershipProvider, RoleManager, AllowAnonymous, EnableClientIntegration, UseWindowsIntegratedAuthentication, UseBasicAuthentication, DisableKerberos, ClaimsAuthenticationRedirectionUrl, ClientObjectModelRequiresUseRemoteAPIsPermission
                    $iisSettingsFinding.InputObject = $iisSettingsObj

                    $iisBindingFinding = New-SPDiagnosticFinding -Name "IIS Bindings" -InputObject $null -Format List

                    $iisBindingFinding.InputObject += $iisSettings.ServerBindings
                    $iisBindingFinding.InputObject += $iisSettings.SecureBindings
                    $iisSettingsFinding.ChildFindings.Add($iisBindingFinding)
                    $webAppFinding.ChildFindings.Add($iisSettingsFinding)
                }
            }            
        }
        
        $webAppsFinding.ChildFindings.Add($webAppFinding)
    }
    return $webAppsFinding
}

function Get-SPDiagnosticsSideBySidePathcingFinding
{
    [cmdletbinding()]
    Param()

    ##SBS is only relevant in SP2016 or greater
    $farmBuild = [Microsoft.SharePoint.Administration.SPFarm]::Local.BuildVersion
    if($farmBuild.Major -lt 16)
    {
        return $null
    }

    $contentSvc = [Microsoft.SharePoint.Administration.SPWebService]::ContentService
    $sbsEnabled = $contentSvc.EnableSideBySide
    $sbsToken = $contentSvc.SideBySideToken
    $farmBuildToken = $farmBuild.ToString()
    $sbsTokenIsCurrent = $null
    if(![string]::IsNullOrEmpty($sbsToken))
    {
        $sbsTokenIsCurrent = $sbsToken -eq $farmBuildToken
    }

    $retObj = [PSCustomObject]@{
        EnabledSideBySide = $sbsEnabled
        SideBySideToken = $sbsToken
        FarmBuildToken = $farmBuildToken
        SideBySideTokenMatchesFarmBuild = $sbsTokenIsCurrent
    }

    $finding = New-SPDiagnosticFinding `
        -Name "Side by Side Patching"  `
        -ReferenceLink "https://blog.stefan-gossner.com/2017/01/10/sharepoint-server-2016-patching-using-side-by-side-functionality-explained/" `
        -InputObject $retObj `
        -Format List
    if($sbsTokenIsCurrent -eq $false)
    {
        $finding.WarningMessage = "SideBySideToken is not the current farm build, consider updating the side by side value to the current farm build or disabling side by side functionality."
    }

    return $finding
}

#region Auth

function Get-SPDiagnosticAuthFindings
{
    $authFindings = New-SPDiagnosticFinding -Name "Authentication" -Severity Default -InputObject $null
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsWebAppAuthSettingsFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPSecurityTokenServiceConfigFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPTrustedIdentityTokenIssuerFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPTrustedSecurityTokenIssuerFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPClaimProviderFinding))

    return $authFindings
}

function Get-SPDiagnosticsWebAppAuthSettingsFinding
{
    [cmdletbinding()]
    Param()

    $was = Get-SPWebApplication -IncludeCentralAdministration
    $webAppAuthSettings = @()
    $noWindowsInDefaultZone = $false
    foreach($wa in $was)
    {   
        foreach($zone in [enum]::GetNames("Microsoft.SharePoint.Administration.SPUrlZone"))
        {
            $iisSettings = $wa.IisSettings[$zone]
            if($null -ne $iisSettings)
            {
                $aam = $wa.AlternateUrls.GetResponseUrl($zone)

                [string]$providerStr = [string]::Empty
                foreach($provider in $iisSettings.ClaimsAuthenticationProviders)
                {
                    $providerStr+=($provider.DisplayName + ", ")
                }
                $providerStr = $providerStr.TrimEnd(", ")

                $waAuthEntry = [PSCustomObject]@{
                    WebApplication = $wa.DisplayName
                    Zone = $zone
                    Url = $aam.IncomingUrl
                    ClaimsAuthentication = $iisSettings.UseClaimsAuthentication
                    Kerberos = !$iisSettings.DisableKerberos
                    Anonymous =  $iisSettings.AllowAnonymous
                    LoginPage = $iisSettings.ClaimsAuthenticationRedirectionUrl
                    ClaimsAuthenticationProviders = $providerStr
                }

                if($zone -eq "Default" -and !$iisSettings.UseWindowsIntegratedAuthentication)
                {
                    $noWindowsInDefaultZone = $true
                }

                $webAppAuthSettings+=$waAuthEntry
            }
        }
    }
    
    
    $finding = New-SPDiagnosticFinding -Name "Web application authentication providers" -Severity Default -InputObject $webAppAuthSettings -Format Table
    if($noWindowsInDefaultZone)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "Windows Authentication is not enabled in the default zone of one or more web applications, this is required for search crawl to work correctly"
        $finding.ReferenceLink += "https://docs.microsoft.com/en-us/sharepoint/search/best-practices-for-crawling"
    }
    return $finding
}

function Get-SPDiagnosticsSPSecurityTokenServiceConfigFinding
{
    [cmdletbinding()]
    Param()
    
    $stsConfig = Get-SPSecurityTokenServiceConfig
    $finding = New-SPDiagnosticFinding -Name "Security token service config" -ReferenceLink "https://joshroark.com/sharepoint-users-forced-to-re-authenticate-unexpectedly/" -InputObject $stsConfig -Format List

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
    $Certinfo = $cert | select-object Subject, Thumbprint, NotBefore, NotAfter
    $certfinding = New-SPDiagnosticFinding -Name "$sname Certificate Information" -InputObject $Certinfo -Format Table
    $CertLifeTime =  $Certinfo.NotAfter  - (get-date)
    If($CertLifeTime.days -le 180 -and $CertLifeTime.days -gt 0)
    {
        $certfinding.severity = [SPDiagnostics.severity]::Warning
        $certfinding.WarningMessage+="Certificate is going to expire in $($CertLifeTime.days) days"
    }
    ElseIf($CertLifeTime.days -lt 1 -and $certtype -eq "TIP" )
    {
        $certfinding.severity = [SPDiagnostics.severity]::critical
        $certfinding.WarningMessage+="Certificate has expired.  Please replace this expired certificate. $tipURL"
        $certfinding.ReferenceLink+=$tipURL
    }
    ElseIf($CertLifeTime.days -lt 1 -and $certtype -eq "STS" )
    {
        $certfinding.severity = [SPDiagnostics.severity]::critical
        $certfinding.WarningMessage+="Certificate has expired.  Please replace this expired certificate. $stsURL"
        $certfinding.ReferenceLink+=$stsURL
    }
    return $certfinding
}

function Get-SPDiagnosticsSPTrustedIdentityTokenIssuerFinding
{
    [cmdletbinding()]
    Param()

    $TrustedIssuerFindings = New-SPDiagnosticFindingCollection
    $trustedIdentityTokenIssuers = Get-SPTrustedIdentityTokenIssuer
    foreach($tokenIssuer in $trustedIdentityTokenIssuers)
    {
        $finding = New-SPDiagnosticFinding -Name ("Trusted Identity Provider: {0}" -f $tokenIssuer.Name) -Severity Default -InputObject $tokenIssuer -Format List
        $claimTypes = $tokenIssuer.ClaimTypeInformation | Select-Object DisplayName, InputClaimType, MappedClaimType, IsIdentityClaim
        $claimMappings = New-SPDiagnosticFinding -Name "Claim mappings" -InputObject $claimTypes -Format Table
        $cert = $tokenIssuer.SigningCertificate
        $finding.ChildFindings.Add($claimMappings)
        $finding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ($tokenIssuer.name) "TIP"))
        $TrustedIssuerFindings.Add($finding)
        
    }

    return $TrustedIssuerFindings
}


function Get-SPDiagnosticsSPTrustedSecurityTokenIssuerFinding
{
    [cmdletbinding()]
    Param()

    $trustedSecurityTokenIssuers = Get-SPTrustedSecurityTokenIssuer
    if($trustedSecurityTokenIssuers.Count -ge 1)
    {
        $Findings = New-SPDiagnosticFinding -Name "Trusted Security Token Issuers" -InputObject $null -Format Table
        foreach($tokenIssuer in $trustedSecurityTokenIssuers)
        {
            $tokenIssuerFinding = New-SPDiagnosticFinding -Name $tokenIssuer.Name -InputObject $tokenIssuer -Format List
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
    $finding = New-SPDiagnosticFinding -Name "Claim providers" -InputObject $claimProviders -Format Table
    return $finding
}


#endregion 

#region search

function Get-SPDiagnosticSearchFindings
{

    $SSAs = Get-SPEnterpriseSearchServiceApplication  | Sort-Object Name 

    $searchFindings = New-SPDiagnosticFinding -Name "Search Information" -Severity Default -InputObject $null
    if($null -eq $SSAs -or $SSAs.Count -eq 0)
    {
        $searchFindings.Description+="There are no SSA's in this farm"
        return $searchFindings
    }

    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSASearchService))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSASearchInstances -searchApps $SSAs))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSPJobInstances -searchApps $SSAs))
    $ssaCount = 0
    foreach($ssa in $SSAs)
    {
        $ssaCount++
        $crawlAccount = (New-Object Microsoft.Office.Server.Search.Administration.Content $ssa).DefaultGatheringAccount
        #$ssaName = "SSA " + $ssaCount + ":  " + "<span style='color:#0072c6'>'" + $ssa.Name +"'</span>" + " || <span style='color:gray'>CrawlAccount: " + $crawlAccount + "</span>"
        $ssaName = "SSA " + $ssaCount + ":  " + $ssa.Name + " || CrawlAccount: " + $crawlAccount
        $ssaFindings = New-SPDiagnosticFinding -Name $ssaName -Severity Default -InputObject $null   # this could be moved into the Get-SPDiagnosticsSSAObject func
        #$ssaFindings.Description+=("CrawlAccount: " + $crawlAccount)
        if($ssa.NeedsUpgradeIncludeChildren -eq $true -or $ssa.NeedsUpgrade -eq $true)
        {
            $ssaName = $ssa.DisplayName
            $ssaFindings.Severity = [SPDiagnostics.Severity]::Warning
            $ssaFindings.WarningMessage+="<li style='color:red'>We have detected that your 'SSA' needs to be upgraded!</li>"
            $ssaFindings.WarningMessage+="<li>In order to perform this action, please run the following command: </li>" 
            $ssaFindings.WarningMessage+="<ul style='color:#0072c6'><div class=`"code`">`Upgrade-SPEnterpriseSearchServiceApplication '$ssaName'</div></ul>"
        }
        if($ssa.CloudIndex -eq $True)
        {
            $spoProxy = Get-SPServiceApplicationProxy | Where-Object{$_.TypeName -match "SharePoint Online Application Principal Management Service"}
            $spoTenantUri = $spoProxy.OnlineTenantUri.AbsoluteUri
            $ssaFindings.Description+="<li style='color:#063970'>We have detected this is a Cloud SSA.</li>"
            $ssaFindings.Description+="<li style='color:#063970'>Your SPO Tenant is: </li>"
            $ssaFindings.Description+="<ul style='color:#727272'>  $spoTenantUri</ul>"
        }

        if(!$SkipSearchHealthCheck)
        {
            $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSearchHealthCheck -searchApplication $ssa))
        } 
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAObject -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAProxyPartition -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSATimerJobs -searchapplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSATopology -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSADatabases -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSATLegacyAdmin -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSACDProp -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAContentSources -searchapplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAServerNameMappings -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSACrawlRules -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSACrawlPolicies -searchApplication $ssa))
        $ssaFindings.ChildFindings.Add((Get-SPDiagnosticsSSAEndpoints -searchApplication $ssa))
        
        $searchFindings.ChildFindings.Add($ssaFindings) 
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

    $findings = New-SPDiagnosticFinding -Name "SSA Object Info" -InputObject $searchApplication -format list

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

    $finding = New-SPDiagnosticFinding -Name "SSA Partition Info" -InputObject $null -format list
    
    $proxyAppGuid = $searchapplication.id -replace "-", "" 
    $ssaProxy = Get-SPEnterpriseSearchServiceApplicationProxy | Where-Object{$_.ServiceEndpointuri -like ("*$proxyAppGuid*")}
    $ssaProxyPropertiesProperty = $ssaProxy.Properties["Microsoft.Office.Server.Utilities.SPPartitionOptions"]
    $ssaPropertiesProperty = $searchapplication.Properties["Microsoft.Office.Server.Utilities.SPPartitionOptions"]
    $ssaDisplayName = $searchApplication.DisplayName
    if($null -eq $ssaProxy)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage+="There is no proxy associated with this SSA:  " + $ssaDisplayName
        $finding.Description+=("In order to create a proxy for this ssa, you should run the following: </br>")
        $finding.Description+=("<ul style='color:#0072c6'><div class=`"code`">`New-SPEnterpriseSearchServiceApplicationProxy -Name '$ssaDisplayName' -SearchApplication '$ssaDisplayName'<br></div></ul>")
        return $finding
    }
    if($ssaPropertiesProperty -ne "UnPartitioned")
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage +="This SSA, $ssaDisplayName, is not set to 'UnPartitioned'."
        $finding.Description += (" If the SSA is partitioned ( this would have been done at creation time ), URLMapping does not take place and will break contextual searches on Web Apps that have been extended to another zone. ( This can impact queries on extended zone URLs, among other search functions) ")
        $finding.Description += 'In order to correct this, you would need to either recreate the SSA or set the SSA to "IgnoreTenatization" with the following: '
        $finding.Description += "<ul><div style='color:#0072c6' class=`"code`">`$ssa = Get-SPEnterpriseSearchServiceApplication '$ssaDisplayName'<br>`$ssa.SetProperty('IgnoreTenantization', 1)<br>`$ssa.Update()</div><br/></ul>"
    }
    if($ssaProxyPropertiesProperty -ne "UnPartitioned")
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage +="The Search Proxy for this SSA is not set to 'UnPartitioned'. "
        $ssaProxyName = $ssaProxy.DisplayName
        $finding.Description +=(" If the proxy is partitioned ( this would have been done at creation time ), URLMapping does not take place and will break contextual searches on Web Apps that have been extended to another zone Property for 'searchProxy.Properties' is set to:  '$ssaProxyPropertiesProperty' ( This can impact queries on extended zone URLs, among other search functions) ")
        $finding.Description += 'In order to correct this, you would need to delete the SSA Proxy and recreate it with the following: '
        $finding.Description += "<ul><div style='color:#0072c6' class=`"code`">`Remove-SPEnterpriseSearchServiceApplicationProxy '$ssaProxyName' -Confirm:$false<br>`New-SPEnterpriseSearchServiceApplicationProxy -Name '$ssaDisplayName' -SearchApplication '$ssaDisplayName'<br></div></ul>"
    }
    
    else
    {
        $finding.Description+=("<li>SSA Properties:  <span style='color:#0072c6'>{0}</span></li>" -f $ssaPropertiesProperty)
        $finding.Description+=("<li>SSA Proxy Properties:  <span style='color:#0072c6'>{0}</span></li>" -f $ssaProxyPropertiesProperty)
    }

    
    return $finding

}

function Get-SPDiagnosticsSSATimerJobs
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $build = GetSPVersion $buildPrefix
    $ssaJobNames = "Application " + $searchApplication.Id
    $ssaDispName = $searchApplication.DisplayName
    $ssaJobs = Get-SPTimerJob | Where-Object{$_.Name -match $ssaJobNames} | Select-Object DisplayName, Id, Status, LastRunTime, Schedule
    $finding = New-SPDiagnosticFinding -Name "SSA Related Timer Jobs" -InputObject $ssaJobs -format Table
    if(($build -eq "SPSE" -or $build -eq "2019") -and $ssaJobs.Count -lt 9)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage += "We detected your version of SharePoint is missing 1 or more 'SSA' related timer jobs. It's recommended to run the commands in the Description"
    }
    elseif($build -eq "2016" -and $ssaJobs.Count -lt 8)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage += "We detected your version of SharePoint is missing 1 or more 'SSA' related timer jobs. It's recommended to run the commands in the Description"
    }
    else
    {
        if($build -eq "2013" -and $ssaJobs.Count -lt 7)
        {
           $finding.Severity = [SPDiagnostics.Severity]::Warning
           $finding.WarningMessage += "We detected your version of SharePoint is missing 1 or more 'SSA' related timer jobs. It's recommended to run the commands in the Description"
        }
    }
    $finding.Description+=("SSAs should have several timer jobs associated with them. <br><br>")
    $finding.Description+=("-- SP 2013 should have 7 timer jobs<br> -- SP 2016 should have 8 timer jobs <br> -- SP 2019 & SPSE should have 9 jobs <br><br>")
    $finding.Description+=("If there are any less than these ( respective of the SP Version), then the easiest course of action to get those timer jobs back in place would be to run: ")
    $finding.Description+=("<ul style='color:#0072c6'><div class=`"code`">`$ssa = Get-SPEnterpriseSearchServiceApplication '$ssaDispName'<br>`$ssa.Status = 'Disabled'<br>`$ssa.Update()<br>`$ssa.Provision()</div></ul>")
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
    $finding = New-SPDiagnosticFinding -Name "Admin Component Info" -InputObject $null -format list
    if($null -eq $searchApplication.SystemManagerLocations)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+="<li>We detect the 'System Manager Location' to be empty. Your SSA will be broken when this is the case. </li>"
    }
    else
    {
        $sysManagerLocation = $searchApplication.SystemManagerLocations.AbsoluteUri
        $finding.Description+="<li>The 'SystemManagerLocations' is associated with the 'non-legacy' piece of the AdminComponent</li>"
        $finding.Description+="<li>This value should never be empty and the serverName *should* match the 'Legacy Admin Component' below</li><br/>"
        $finding.Description+="<ul>`$ssa.SystemManagerLocations = " + "<span style='color:#0072c6'>" + $sysManagerLocation + "</span></ul><br/>"
    }
    if($null -eq $LAC.ServerName)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+="<li>We detected the 'Legacy Admin Component' is empty.</li>"
        $finding.WarningMessage+="<li>The SSA will be broken when this is the case. Accessing 'Content Sources', 'Crawl Rules', 'ServerNameMappings' should be inaccessible.</li>"
        $finding.WarningMessage+="<li>Try to repair this by running the following command:</li>" 
        $finding.WarningMessage+="<ul style='color:#0072c6'><div class=`"code`">`Set-SPEnterpriseSearchAdministrationComponent -SearchApplication 'ssa Name' -SearchServiceInstance AdminServerName -Force</div></ul>"

    }
    else
    {
        $finding.InputObject=$LAC
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
    $finding = New-SPDiagnosticFinding -Name "Content Distributor Property" -InputObject $null -format list
    $conn = New-Object System.Data.SqlClient.SqlConnection
    $cmd = New-Object System.Data.SqlClient.SqlCommand
    
    $adminDb = Get-SPDatabase | Where-Object{$_.Name -eq $searchapplication.SearchAdminDatabase.Name}
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
                $finding.WarningMessage+='<li>In the ULS, on the crawl servers, you should see this HResult being thrown: 0x80131537.</li>'
                $finding.WarningMessage+='<li>The current property is set to: </li>'
                $finding.WarningMessage+='<ul style="color:darkblue">' + "  {0}" -f $row + '</ul>'
                $finding.WarningMessage+='<li>It should appear like:  </li>'
                $finding.WarningMessage+='<ul style="color:darkblue">' + "  {0}" -f $row.replace("net.tcp:///", "net.tcp://servername/") + '</ul>'
            }
            else
            {
                $finding.Description+=("<li>" + " Checking the Content Distributor Property from SSA Admin DB. If the property contains anything that reflects 'net.tcp:///' instead of 'net.tcp://serverName/, then your crawls will hang. In the ULS, on the crawl servers, you should see this HResult being thrown:   0x80131537." + "</li>")               
                $finding.Description+=("<li>" + "  This SSA's ContentDistributor Property is:" + "</li>")
                $finding.Description+=('<ul style="color:#0072c6">' + "  {0}" -f $row + '</ul>')
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
    $activeTopoName = "Active Topology ID:  " + $activeTopo.TopologyId
    $finding = New-SPDiagnosticFinding -Name $activeTopoName -InputObject $sComponents -format table
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
    $searchDbFinding = New-SPDiagnosticFinding -Name "Search Databases" -InputObject $null -format List
    $ssaAdminDb = $searchApplication.SearchAdminDatabase.Name
    $crawlStores = [array]$searchApplication.CrawlStores
    $linkStores = [array]$searchApplication.LinksStores
    $apcStores = [array]$searchApplication.AnalyticsReportingDatabases
    $dbCollection = [PSCustomObject]@{
    }
    $dbCollection | Add-Member -MemberType NoteProperty -Name "AdminDatabase" -Value $ssaAdminDb
    if($crawlStores.Count -eq 1)
    {
        $dbCollection | Add-Member -MemberType NoteProperty -Name "CrawlDatabase" -Value $($crawlStores[0]).Name
    }
    else
    {
      $crawlDbs = $null
      foreach($crawlStore in $crawlStores | Sort-Object -Property Name)
      {
        $crawlDbs+="{"+$crawlStore.Name+"}" + " -- "
      }
      $crawlDbs = $crawlDbs.TrimEnd(" -- ")
      $dbCollection | Add-Member -MemberType NoteProperty -Name "CrawlDatabases" -Value $crawlDbs
        
    }
    if($linkStores.Count -eq 1)
    {
       $dbCollection | Add-Member -MemberType NoteProperty -Name "LinksDatabase" -Value $($linkStores[0]).Name
    }
    else
    {
      $linkDbs = $null
      foreach($linksStore in $linkStores | Sort-Object -Property Name)
      {
        $linkDbs+="{"+$linksStore.Name+"}" + " -- "
      }
      $linkDbs = $linkDbs.TrimEnd(" -- ")
      $dbCollection | Add-Member -MemberType NoteProperty -Name "LinksDatabases" -Value $linkDbs
    }
    if($apcStores.Count -eq 1)
    {
       $dbCollection | Add-Member -MemberType NoteProperty -Name "AnalyticsDatabase" -Value $($apcStores[0]).Name
    }
    else
    {
      $apcDbs = $null
      foreach($apcStore in $apcStores | Sort-Object -Property Name)
      {
        $apcDbs+="{"+$apcStore.Name+"}" + " -- "
      }
      $apcDbs = $apcDbs.TrimEnd(" -- ")
      $dbCollection | Add-Member -MemberType NoteProperty -Name "AnalyticsDatabases" -Value $apcDbs
    }
    $searchDbFinding.InputObject = $dbCollection
    return $searchDbFinding
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
    $findingCollection = New-SPDiagnosticFinding -name $csFindingName -InputObject $null -Format table
    $contentSources = Get-SPEnterpriseSearchCrawlContentSource -SearchApplication $searchapplication;
    foreach ($contentSrc in $contentSources)
    {
        
        $csName =  'Content Source: ' + $contentSrc.Name + ' || ' + '( ' + 'ID: ' + $contentSrc.ID + ' | ' + ' Type: ' + $contentSrc.Type + ' | ' + ' Behavior: ' + $contentSrc.SharePointCrawlBehavior + ')'
        $csObj = $contentSrc | Select-Object CrawlState, CrawlStatus, ContinuousCrawlStatus, CrawlPriority, SuccessCount, WarningCount, ErrorCount, DeleteCount, CrawlStarted, CrawlCompleted, EnableContinuousCrawls, LevelImportantTotalCount, LevelHighErrorCount, LevelHighRecurringErrorCount, LevelHighTotalCount, LevelImportantRecurringErrorCount, RefreshCrawls 
        $csFinding = New-SPDiagnosticFinding -name $csName -InputObject $csObj -Format List

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
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $startUri.AbsoluteUri.ToString()
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
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $startUri.AbsoluteUri.ToString()
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "AAMZone" -Value $altUrl.UrlZone
                    $csFinding.WarningMessage +="[" + $altUrl.UrlZone + "] " + $startUri
                    $csFinding.WarningMessage +="--- Non-Default zone may impact Contextual Scopes (e.g. This Site) and other search functionality"
                    $csFinding.Description += "The only URL that should be crawled should be the 'Default Zone Public URL' and it should be Windows Authentication. If you are crawling both the Default Zone and another Zone URL, you should remove the non Default Zone Url from your start addresses"
                    $csFinding.ReferenceLink +="https://www.ajcns.com/2021/02/problems-crawling-the-non-defaul-zone-for-a-sharepoint-web-application" 
                    $csFinding.Severity = [SPDiagnostics.Severity]::Warning
                    
                  }
                }
              }
          
              if($isRemoteFarm)
              {
                $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $startUri.AbsoluteUri.ToString()
                $sAddressColl | Add-Member -MemberType NoteProperty -Name "RemoteFarm" -Value $true
              }
            
            } 
            else 
            {
              if($startUri.Scheme.toString().toLower().startsWith("sps")) 
              {
                 $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $startUri.AbsoluteUri.ToString()
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
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $startUri.AbsoluteUri.ToString()
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "Type" -Value "URI"
                }
              }
            }
          }
          else 
          {
            $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $startUri.AbsoluteUri.ToString()
            $sAddressColl | Add-Member -MemberType NoteProperty -Name "Type" -Value "Unknown"
             #$retObj | Add-Member -MemberType NoteProperty -Name "Address" -Value $startUri.AbsoluteUri.toString()
           
           }
           $retObj += $sAddressColl
           #$retObj | Add-Member -MemberType NoteProperty -Name "Type" -Value $contentSrc.Type
           #$sAddress = '<span style="color:gray; font-size:14px">StartAddress ' + $count + "</span>"
           #$startAddressFinding = New-SPDiagnosticFinding -name $sAddress -InputObject $retObj -Format Table -Expand
           #$csFinding.ChildFindings.Add($startAddressFinding)
          }
        $startAddressFinding = New-SPDiagnosticFinding -name "Start Addresses" -InputObject $retObj -Format Table -Expand
        $csFinding.ChildFindings.Add($startAddressFinding)
        $findingCollection.ChildFindings.Add($csFinding)

        $csCrawlScheduleColl = [PSCustomObject]@{}
        $csCrawlScheduleColl  | Add-Member -MemberType NoteProperty -Name "Full Crawl Schedule" -Value $contentSrc.FullCrawlSchedule.Description
        $csCrawlScheduleColl  | Add-Member -MemberType NoteProperty -Name "Incremental Crawl Schedule" -Value $contentSrc.IncrementalCrawlSchedule.Description
        $csSchedFinding = New-SPDiagnosticFinding -name "Crawl Schedule" -InputObject $csCrawlScheduleColl -Format List
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
    $SNM = $searchApplication | Get-SPEnterpriseSearchCrawlMapping
    if($null -ne $snm)
    {
        $finding = New-SPDiagnosticFinding -Name "Server Name Mappings" -InputObject $SNM -format table
    }
    else
    {
        $finding = New-SPDiagnosticFinding -Name "Server Name Mappings" -InputObject $null -Description "This SSA has no Server Name Mappings" -format list
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
        $crawlrules = $searchApplication | Get-SPEnterpriseSearchCrawlRule | Select-Object * -ExcludeProperty Parent
        if($null -ne $crawlrules)
        {
            $finding = New-SPDiagnosticFinding -Name "Crawl Rules" -InputObject $crawlrules -format table
        }
        else
        {
            $finding = New-SPDiagnosticFinding -Name "Crawl Rules" -Description "This SSA has no Crawl Rules defined" -format list -InputObject $null
        }
    return $finding
}

function Get-SPDiagnosticsSSACrawlPolicies
{
    [CmdletBinding()]
    param (
     [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
                     
    $CrawlPolicyColl = [PSCustomObject]@{} 
    $CrawlPolicyColl | Add-Member  -MemberType NoteProperty -Name "RecrawlErrorCount" -Value  $($searchApplication.GetProperty("RecrawlErrorCount"))
    $CrawlPolicyColl | Add-Member RecrawlErrorInterval $searchApplication.GetProperty("RecrawlErrorInterval")
    $CrawlPolicyColl | Add-Member ErrorCountAllowed $searchApplication.GetProperty("ErrorCountAllowed")
    $CrawlPolicyColl | Add-Member ErrorIntervalAllowed $searchApplication.GetProperty("ErrorIntervalAllowed")
    $CrawlPolicyColl | Add-Member ErrorDeleteCountAllowed $searchApplication.GetProperty("ErrorDeleteCountAllowed")
    $CrawlPolicyColl | Add-Member ErrorDeleteIntervalAllowed $searchApplication.GetProperty("ErrorDeleteIntervalAllowed")
    $CrawlPolicyColl | Add-Member DeleteUnvisitedMethod $searchApplication.GetProperty("DeleteUnvisitedMethod")
    $CrawlPolicyColl | Add-Member LogDiscoveredLinks $searchApplication.GetProperty("LogDiscoveredLinks")
    $CrawlPolicyColl | Add-Member DisableAutoRecovery $searchApplication.GetProperty("DisableAutoRecovery")
    $CrawlPolicyColl | Add-Member MaxGrowFactor $searchApplication.GetProperty("MaxGrowFactor")
    $CrawlPolicyColl | Add-Member MaxDownloadSize $searchApplication.GetProperty("MaxDownloadSize")
    $CrawlPolicyColl | Add-Member ContinuousCrawlInterval $searchApplication.GetProperty("ContinuousCrawlInterval")
    $CrawlPolicyColl | Add-Member RefreshBucketCount $searchApplication.GetProperty("RefreshBucketCount")
    $CrawlPolicyColl | Add-Member RefreshEnumDepthAdjustment $searchApplication.GetProperty("RefreshEnumDepthAdjustment")
    $CrawlPolicyColl | Add-Member RefreshMinInterval $searchApplication.GetProperty("RefreshMinInterval")
    $CrawlPolicyColl | Add-Member RefreshMaxInterval $searchApplication.GetProperty("RefreshMaxInterval")
    $CrawlPolicyColl | Add-Member RefreshMaxPromotion $searchApplication.GetProperty("RefreshMaxPromotion")
    $CrawlPolicyColl | Add-Member RefreshMaxDemotion $searchApplication.GetProperty("RefreshMaxDemotion")
    $CrawlPolicyColl | Add-Member RefreshPromoteLimitStart $searchApplication.GetProperty("RefreshPromoteLimitStart")
    $CrawlPolicyColl | Add-Member RefreshPromoteLimitEnd $searchApplication.GetProperty("RefreshPromoteLimitEnd")
    $CrawlPolicyColl | Add-Member RefreshDemoteLimitStart $searchApplication.GetProperty("RefreshDemoteLimitStart")
    $CrawlPolicyColl | Add-Member RefreshDemoteLimitEnd $searchApplication.GetProperty("RefreshDemoteLimitEnd")
    
    $crawlPolicyFinding = New-SPDiagnosticFinding -Name "SSA Crawl Policies" -InputObject $CrawlPolicyColl -Format List
 
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
   ProcessIdentity = $searchInstance.ProcessIdentity
   PerformanceLevel = $searchInstance.PerformanceLevel
   ConnectionTimeout = $searchInstance.ConnectionTimeout
   AcknowledgementTimeout = $searchInstance.AcknowledgementTimeout
   IgnoreSSLWarnings = $searchInstance.IgnoreSSLWarnings
   UseCrawlProxyForFederation = $searchInstance.UseCrawlProxyForFederation
   InternetIdentity = $searchInstance.InternetIdentity
   Status = $searchInstance.Status
}
    $finding = New-SPDiagnosticFinding -Name "'Farm Search' Service Instance" -InputObject $siObj -format List
    
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
<tr><td>Address</td><td><span style='color: #0072c6;'>$proxyAddress</span></td></tr>
<tr><td>BypassProxyOnLocal</td><td><span style='color: #0072c6;'>$bypassProxy</span></td></tr>
<tr><td>BypassList</td><td>{<span style='color: #0072c6;'>$bypassList</span>}</td></tr>
<tr><td>Credentials</td><td>{<span style='color: #0072c6;'>$proxyCreds</span>}</td></tr>
<tr><td>UseDefaultCredentials</td><td><span style='color: #0072c6;'>$proxyUseDefCreds</span></td></tr>
<tr><td>BypassArrayList</td><td>{<span style='color: #0072c6;'>$proxyArrayList</span>}</td></tr>
</table>
"@
        $finding.Description+="<li>The Search Service has a Web Proxy defined.</li>"
        $finding.Description+="<li>This will impact ALL SSA's and route crawl traffic to the Proxy regardless if the 'IE settings' or 'netsh winhttp show proxy' are defined</li>"
        $finding.Description+='<ul>' + $webProxyText + '</ul>'
    }
    return $finding
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
    foreach($ssa in $SSAs)
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
    $ssiFinding = New-SPDiagnosticFinding -Name "'Search\HostController Service' Instances" -InputObject $problemSearchInstanceColl -Format Table

    if($problemSearchInstanceColl.Count -gt 0)
    {
        $ssiFinding.Severity = [SPDiagnostics.Severity]::Critical
        $ssiFinding.WarningMessage = "One or more SearchServiceInstances or HostController Instances are not online "
        $ssiFinding.Description+=("<li>These Service Instances are critical for search to function properly.</li>")
        $ssiFinding.Description+=("<li> If these are Disabled or stuck in a state other than 'Online', then we need to try to start them again to bring to a proper state.</li>")
        $ssiFinding.Description+=("<li> You will want to run the following PowerShell command:  </li>")
        $ssiFinding.Description+=('<ul style="color:#0072c6">' + " Start-SPEnterpriseSearchServiceInstance 'serverName'" + "</ul>")
    }
    else
    {
        $ssiFinding.Description+=('<ul style="color:green"> All of your Search related Service Instances are Online!</ul>')
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
    $farmSspJob = $farm.Services | Where-Object {$_.GetType().Name -like "OfficeServerService"}
    $problemSspJobInstanceColl = @()
    if($farmSspJob.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online)
    {
        $problemSspJobInstanceColl+=[PSCustomObject]@{
            Server = 'Farm Level  '
            TypeName = $farmSspJob.TypeName
            Status = $farmSspJob.Status
            Id = $farmSspJob.Id
        }
        
    }

    foreach($ssa in $SSAs)
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $ssa -Active
        $topoCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at
        $components = $topoCompList | Select-Object ServerName -Unique
        foreach($searchServer in $components)
        {
            #$sspJobServiceInstances = $farm.Servers[$searchServer.ServerName].ServiceInstances | Where-Object {$_.TypeName -like "SSP Job Control*"}
            $sspJobServiceInstances = $farm.Servers[$searchServer.ServerName].ServiceInstances | Where-Object {$_.GetType().Name -like "OfficeServerService"}   
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
    $sspJobFinding = New-SPDiagnosticFinding -Name "'SSP Job Control' Service Instances" -InputObject $problemSspJobInstanceColl -Format Table
    if($problemSspJobInstanceColl.Count -gt 0)
    {

        $sspJobFinding.Severity = [SPDiagnostics.Severity]::Critical
        $sspJobFinding.WarningMessage = "One or more 'SSP Job Control' Service Instances are not online "
        $sspJobFinding.Description+=("<li>These Service Instances are critical for search to function properly. They are responsible for allowing the timer jobs, job-application-server-*, to run.</li>")
        $sspJobFinding.Description+=("<li> Those timer jobs 'sync' search related data, so they need to be Online and those jobs need to be running every 1 min</li>")
        $sspJobFinding.Description+=("<li> To get these back 'Online', run the following PowerShell commands:  </li>")
        $sspJobFinding.Description+=("<ul style='color:#0072c6'><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guidOfDisabledInstance')<br>`$obj.Status = 'Online'<br>`$obj.Update()</div></ul>")
        
    }
    else
    {
        $sspJobFinding.Description+=('<ul style="color:green"> All of your SSP Job Control Service Instances are Online</ul>')
    }
    return $sspJobFinding
}

function Get-SPDiagnosticsSSAEndpoints
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )
    $finding = New-SPDiagnosticFinding -Name "SSA Endpoints" -InputObject $null -format list
    
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
                $response = $(Invoke-WebRequest -Uri $sqssUri -Method Get).StatusDescription
                $finding.Description+=("<li>" + $sqssUri.ToString() + " -- " + $response.ToString() + "</li>")
            }
        }
        $finding.Description+=("<ul>" + "  Search Service Endpoints Ok" + "</ul>")
    }
    catch
    {
        
       $finding.Severity = [SPDiagnostics.Severity]::Warning
       $finding.WarningMessage+=("There was a problem reaching:  {0}" -f $sqssuri + "</br> " + $_.Exception.Message )
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
                $response = $(Invoke-WebRequest -Uri $searchAdminUri -Method Get).StatusDescription
                $finding.Description+=("<li>" + $searchAdminUri.ToString() + " -- " + $response.ToString() + "</li>")
                
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

#endregion

#region HealthCheck

function Get-SPDiagnosticsSearchHealthCheck()
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $searchApplication
    )

    $global:ssa = $searchApplication

    # ------------------------------------------------------------------------------------------------------------------
    # GetCrawlStatus: Get crawl status
    # ------------------------------------------------------------------------------------------------------------------
    Function GetCrawlStatus
    {
        if ($global:ssa.Ispaused())
        {
            switch ($global:ssa.Ispaused()) 
            { 
                1       { $pauseReason = "ongoing search topology operation" } 
                2       { $pauseReason = "backup/restore" } 
                4       { $pauseReason = "backup/restore" } 
                32      { $pauseReason = "crawl DB re-factoring" } 
                64      { $pauseReason = "link DB re-factoring" } 
                128     { $pauseReason = "external reason (user initiated)" } 
                256     { $pauseReason = "index reset" } 
                512     { $pauseReason = "index re-partitioning (query is also paused)" } 
                default { $pauseReason = "multiple reasons ($($global:ssa.Ispaused()))" } 
            }
            $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name $global:ssa.Name -Value "Paused for $pauseReason"
            
        }
        else
        {
            $crawling = $false
            $contentSources = Get-SPEnterpriseSearchCrawlContentSource -SearchApplication $global:ssa
            if ($contentSources) 
            {
                foreach ($source in $contentSources)
                {
                    if ($source.CrawlState -ne "Idle")
                    {
                        $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawling $($source.Name)" -Value $source.CrawlState
                        $crawling = $true
                    }
                }
                if (!$crawling)
                {
                    $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawler" -Value "Crawler is Idle"
                }
            }
            else
            {
                $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Crawler" -Value "No content sources found"
            }
        }
    }

    # ------------------------------------------------------------------------------------------------------------------
    # GetTopologyInfo: Get basic topology info and component health status
    # ------------------------------------------------------------------------------------------------------------------
    Function GetTopologyInfo
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $global:ssa -Active
        $global:topologyCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at

        # Check if topology is prepared for HA
        $adminFound = $false
        foreach ($searchComp in ($global:topologyCompList))
        {
            if ($searchComp.Name -match "Admin")
            { 
                if ($adminFound) 
                { 
                    $global:haTopology = $true 
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
        $global:componentStateList = Get-SPEnterpriseSearchStatus -SearchApplication $global:ssa -ErrorAction Continue

        # Find the primary admin component:
        foreach ($component in ($global:componentStateList))
        {
            if (($component.Name -match "Admin") -and ($component.State -ne "Unknown"))
            {
                if (Get-SPEnterpriseSearchStatus -SearchApplication $global:ssa -Primary -Component $($component.Name) -ErrorAction Continue)
                {
                    $global:primaryAdmin = $component.Name
                }
            }
        }    
        if (!$global:primaryAdmin)
        {
            Write-Host "Search component health state check failed. Recommended action: Ensure that at least one admin component is operational."
        }
    }

    # ------------------------------------------------------------------------------------------------------------------
    # PopulateHostHaList: For each component, determine properties and update $global:hostArray / $global:haArray
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

        foreach ($searchHost in ($global:hostArray))
        {
            if ($searchHost.hostName -eq $hostName)
            {
                $newHostFound = $false
            }
        }
        if ($newHostFound)
        {
            # Add the host to $global:hostArray
            $hostTemp = $global:hostTemplate | Select-Object *
            $hostTemp.hostName = $hostName
            $global:hostArray += $hostTemp
            $global:searchHosts += 1
        }

        # Fill in component specific data in $global:hostArray
        foreach ($searchHost in ($global:hostArray))
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
                    if ($searchComp.Name -eq $global:primaryAdmin)
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

        # Fill in component specific data in $global:haArray
        foreach ($haEntity in ($global:haArray))
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
            # Add the HA entities to $global:haArray
            $haTemp = $global:haTemplate | Select-Object *
            $haTemp.entity = $entity
            $haTemp.components = 1
            if ($partition -ne -1) 
            { 
                $haTemp.partition = $partition 
            }
            $global:haArray += $haTemp
        }
        else
        {
            foreach ($haEntity in ($global:haArray))
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
                        if (($haEntity.entity -eq "AdminComponent") -and ($searchComp.Name -eq $global:primaryAdmin))
                        {
                            $haEntity.primary = $global:primaryAdmin
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
        $AnalyticsStatusFindings = New-SPDiagnosticFinding -Name "Analytics Processing Job Status" -Severity Default -InputObject $null
        $analyticsStatus = Get-SPEnterpriseSearchStatus -SearchApplication $global:ssa -JobStatus | Where-Object{$_.Name -ne "Not Available"}

        foreach ($analyticsEntry in $analyticsStatus)
        {
            $AnalyticsEntryFindings = New-SPDiagnosticFinding -Name $analyticsEntry.Name -Severity Default -InputObject $null -Format List

            $retObj = [PSCustomObject]@{
                Name = $analyticsEntry.Name
            }

            if ($analyticsEntry.Name -ne "Not available" -or $global:debug -eq $true)     
            {
                foreach ($de in ($analyticsEntry.Details))
                {
                    if ($de.Key -eq "Status")
                    {
                        $status = $de.Value
                    }
                }
                $retObj | Add-Member -MemberType NoteProperty -Name "Status" -Value $status	
            }
            
            # Output additional diagnostics from the dictionary
            foreach ($de in ($analyticsEntry.Details))
            {
                # Skip entries that is listed as Not Available
                if ( ($de.Value -ne "Not available") -and ($de.Key -ne "Activity") -and ($de.Key -ne "Status") )
                {
                    $retObj | Add-Member -MemberType NoteProperty -Name $de.Key -Value $de.Value	

                    if ($de.Key -match "Last successful start time")
                    {
                        $dLast = Get-Date $de.Value
                        $dNow = Get-Date
                        $daysSinceLastSuccess = $dNow.DayOfYear - $dLast.DayOfYear
                        if ($daysSinceLastSuccess -gt 3)
                        {
                            $AnalyticsEntry.Severity = [SPDiagnostics.Severity]::Warning
                            $analyticsEntry.WarningMessage += "Warning: More than three days since last successful run"
                            $global:serviceDegraded = $true                        
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
        #$SearchComponentStatusDiagnosticsFinding = New-SPDiagnosticFinding -Name "Search Component Status" -Severity Default -InputObject $null -format List

        # Find host name
        foreach($searchComp in ($global:topologyCompList))
        {
            if ($searchComp.Name -eq $component.Name)
            {
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
        if ($component.State -ne "Active" -or $global:debug -eq $true)
        {
            # String with all components that is not active:
            if ($component.State -eq "Unknown")
            {
                $global:unknownComponents += "$hostName - " +  "$($component.Name): $($component.State)"
            }
            elseif ($component.State -eq "Degraded")
            {
                $global:degradedComponents += "$hostName - " +  "$($component.Name):$($component.State)"
            }
            else
            {
                $global:failedComponents += "$hostName - " +  "$($component.Name):$($component.State)"
            }
            $global:serviceDegraded = $true
        }
        
        # Skip unnecessary info about cells and partitions if everything is fine
        $outputEntry = $true
        $retObj = [PSCustomObject]@{
        }
        # Indent the cell info, logically belongs to the component. 
        if ($component.Name -match "Cell")
        {
            if ($component.State -eq "Active" -and $global:debug -eq $false)
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
            if ($component.State -eq "Active" -and $global:debug -eq $false)
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
                if ($global:haTopology)
                {
                    if ($component.Name -eq $global:primaryAdmin)
                    {
                        $primaryString = " (Primary)"
                    }
                }
            }
            elseif ($component.Name -match "Index") 
            { 
                $entity = "IndexComponent"
                foreach ($searchComp in ($global:topologyCompList))
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
                            foreach ($haEntity in ($global:haArray))
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
            foreach ($haEntity in ($global:haArray))
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
            # Add the component entities to $global:compArray for output formatting
            $compTemp = $global:compTemplate | Select-Object *
            $compTemp.Component = "$($component.Name)$primaryString"
            $compTemp.Server = $hostName
            $compTemp.State = $component.State
            if ($partition -ne -1 -and $compTemp.Component -match "Index") 
            { 
                $compTemp.Partition = $partition 
            }
            $global:compArray += $compTemp

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
            if ($global:haTopology)
            {
                if ($component.Name -eq $global:primaryAdmin)
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
        $DetailedIndexerDiagFinding = New-SPDiagnosticFinding -Name "Detailed Component Diag" -Severity Default -InputObject $null -format List

        foreach ($searchComp in ($global:componentStateList))
        {
            $component = $searchComp.Name

            if ( (($component -match "Index") -or ($component -match "Content") -or ($component -match "Admin")) -and ($component -notmatch "Cell") -and ($searchComp.State -notmatch "Unknown") -and ($searchComp.State -notmatch "Registering"))
            {

                $pl=Get-SPEnterpriseSearchStatus -SearchApplication $global:ssa -HealthReport -Component $component
                foreach ($entry in ($pl))
                {
                    if ($entry.Name -match "plugin: number of documents") 
                    { 
                        foreach ($haEntity in ($global:haArray))
                        {
                            if (($haEntity.entity -eq "IndexComponent") -and ($haEntity.primary -eq $component))
                            {
                                # Count indexed documents from all index partitions:
                                $global:indexedDocs += $entry.Message
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
                        $global:masterMerge = $true
                    }
                    elseif ($global:degradedComponents -and ($entry.Name -match "plugin: newest generation id"))
                    {
                        # If at least one index component is left behind, we want to output the generation number.  
                        $generationInfo += "$component : Index generation: $($entry.Message)" 
                        $gen = [int] $entry.Message
                        if ($generation -and ($generation -ne $gen))
                        {
                            # Verify if there are different generation IDs for the indexers
                            $global:generationDifference = $true
                        }
                        $generation = $gen
                    }
                    elseif (($entry.Level -eq "Error") -or ($entry.Level -eq "Warning"))
                    {
                        $global:serviceDegraded = $true
                        if ($entry.Name -match "fastserver")
                            { $indexerInfo += "$component ($($entry.Level)) : Indexer plugin error ($($entry.Name):$($entry.Message))" }
                        elseif ($entry.Message -match "fragments")
                            { $indexerInfo += "$component ($($entry.Level)) : Missing index partition" }
                        elseif (($entry.Name -match "active") -and ($entry.Message -match "not active"))
                            { $indexerInfo += "$component ($($entry.Level)) : Indexer generation controller is not running. Potential reason: All index partitions are not available" }
                        elseif ( ($entry.Name -match "in_sync") -or ($entry.Name -match "left_behind") )
                        { 
                            # Indicates replicas are out of sync, catching up. Redundant info in this script
                            $global:indexLeftBehind = $true
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

            if ($global:indexLeftBehind -and $global:generationDifference)
            {
                # Output generation number for indexers in case any of them have been reported as left behind, and reported generation IDs are different.
                $generationEntryCount = 0
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
        $VerifyHaLimitsDiagnosticFinding = New-SPDiagnosticFinding -Name "Verified HA Limits" -Description "Verifying HA status for topology and index size limits" -Severity Default -InputObject $null -format List 
		
        $hacl = [PSCustomObject]@{
        }
        $haNotOk = $false
        $ixcwl = [PSCustomObject]@{
        }
        $ixcel = [PSCustomObject]@{
        }
        $docsExceeded = $false
        $docsHigh = $false
        $build = GetSPVersion $buildPrefix
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
        foreach ($hac in $global:haArray)
        {
            $hacCount++
            if ([int] $hac.componentsOk -lt 2)
            {
                if ([int] $hac.componentsOk -eq 0)
                {
                    # Service is down
                    $global:serviceFailed = $true
                    $haNotOk = $true   
                }
                elseif ($global:haTopology)
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
            if ($global:serviceFailed)
            {
                $VerifyHaLimitsDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                $VerifyHaLimitsDiagnosticFinding.WarningMessage += "Critical: Service 'possibly' down due to components not active"
            }
            else
            {
                $VerifyHaLimitsDiagnosticFinding.Severity = [SPDiagnostics.Severity]::Warning
                $VerifyHaLimitsDiagnosticFinding.WarningMessage += "Warning: No High Availability for one or more components"
            }
            $VerifyHaLimitsDiagnosticFinding.InputObject = $hacl
        }
        if ($docsExceeded)
        {
            $global:serviceDegraded = $true
            $docsExceededFindings = New-SPDiagnosticFinding -Name "Docs 'per Index Partition' Exceeded" -Severity Warning -InputObject $null -format List -WarningMessage "One or more index component exceeds the supported document limit"
            #$docsExceededFindings.WarningMessage += "Warning: One or more index component exceeds document limit"
            $docsExceededFindings.InputObject = $ixcel
            $VerifyHaLimitsDiagnosticFinding.ChildFindings.Add($docsExceededFindings)
        }
        if ($docsHigh)
        {
            $docsHighFindings = New-SPDiagnosticFinding -Name "Docs 'per Index Partition' Close To Limit" -Severity Warning -InputObject $null -format List -WarningMessage "Warning: One or more index component is close to the supported document limit"
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

    # ------------------------------------------------------------------------------------------------------------------
    # VerifyHostControllerRepository: Verify that Host Controller HA (for dictionary repository) is OK
    # ------------------------------------------------------------------------------------------------------------------
    Function VerifyHostControllerRepository
    {
        $VerifyHostControllerRepositoryFinding =  New-SPDiagnosticFinding -Name "Host Controller Repository" -Severity Default -InputObject $null -format Table

        $retObj = [PSCustomObject]@{
        }

        $highestRepVer = 0
        $hostControllers = 0
        $primaryRepVer = -1
        $hcStat = @()
        $hcs = Get-SPEnterpriseSearchHostController
        foreach ($hc in $hcs)
        {
            $hostControllers += 1
            $repVer = $hc.RepositoryVersion
            $serverName = $hc.Server.Name
            if ($repVer -gt $highestRepVer)
            {
                $highestRepVer = $repVer
            }
            if ($hc.PrimaryHostController)
            {
                $primaryHC = $serverName
                $primaryRepVer = $repVer
            }
            if ($repVer -ne -1)
            {
                $hcStat += "        $serverName : $repVer"
            }
        }

        if ($hostControllers -ge 1)
        {
            $VerifyHostControllerRepositoryFinding.Description += "<ul>Primary search host controller (for dictionary repository): $primaryHC</ul>"
            $VerifyHostControllerRepositoryFinding.InputObject = ($hcs | select-object Server, PrimaryHostController, Status, Id, RepositoryVersion | Sort-Object PrimaryHostController -Descending)
            
            if ($primaryRepVer -eq -1)
            {
                $global:serviceDegraded = $true
                $VerifyHostControllerRepositoryFinding.Severity = [SPDiagnostics.Severity]::Warning
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Warning: Primary host controller is not available"
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Recommended action: Restart server or set new primary host controller using Set-SPEnterpriseSearchPrimaryHostController"

                $hcstatfindings =  New-SPDiagnosticFinding -Name "Repository version for existing host controllers" -Severity Default -InputObject $hcstatfindings -format table
                $VerifyHostControllerRepositoryFinding.ChildFindings.Add($hcstatfindings)

            }
            elseif ($primaryRepVer -lt $highestRepVer)
            {
                $global:serviceDegraded = $true
                $VerifyHostControllerRepositoryFinding = [SPDiagnostics.Severity]::Warning
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Warning: Primary host controller does not have the latest repository version"
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Primary host controller repository version: $primaryRepVer "
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Latest repository version: $highestRepVer "
                $VerifyHostControllerRepositoryFinding.WarningMessage += "Recommended action: Set new primary host controller using Set-SPEnterpriseSearchPrimaryHostController"

                $hcstatfindings =  New-SPDiagnosticFinding -Name "Repository version for existing host controllers" -Severity Default -InputObject $hcstatfindings -format table
                $VerifyHostControllerRepositoryFinding.ChildFindings.Add($hcstatfindings)
            }
            return $VerifyHostControllerRepositoryFinding            
        }

        return $null
    }

    #---added by bspender--------------------------------------------------------------------------------------------------
    # VerifyApplicationServerSyncJobsEnabled: Verify that Application Server Admin Service Timer Jobs are running
    # ---------------------------------------------------------------------------------------------------------------------
    function VerifyRunningProcesses
    {
        $components = $global:ssa.ActiveTopology.GetComponents() | SORT-OBJECT ServerName | select-object ServerName, Name
        $VerifyRunningProcessesDiagnosticsFindings = New-SPDiagnosticFinding -Name "VerifyRunningProcesses" -Severity Default -format List

        foreach ($hostname in $global:hostArray.Hostname) 
        {
            $RunningProcessDiagnosticFinding = New-SPDiagnosticFinding -Name $hostname -Severity Default -Format List

            $retObj = [PSCustomObject]@{
                HostName = $hostname
            }

            $RunningProcessDiagnosticFinding.Description = "Components deployed to this server..."

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
                $serviceinstances = New-SPDiagnosticFinding -Name "Running Service Instances" -Severity Default -format List -InputObject $running
                $RunningProcessDiagnosticFinding.ChildFindings.Add($serviceinstances)
            }
            $stopped = $services | where-object {$_.Status -eq "Stopped"}
            if ($stopped) {
                $serviceinstances = New-SPDiagnosticFinding -Name "Stopped Service Instances" -Severity Default -format List -InputObject $stopped
                $RunningProcessDiagnosticFinding.ChildFindings.Add($serviceinstances)
            }
            $other   = $services | where-object {($_.Status -ne "Running") -and ($_.Status -ne "Stopped")}
            if ($other) {
                $serviceinstances = New-SPDiagnosticFinding -Name "Service in an abnormal or transient state...s" -Severity Warning -format List -InputObject $other
                $RunningProcessDiagnosticFinding.ChildFindings.Add($serviceinstances)
            }
            $RunningProcessDiagnosticFinding.InputObject = $retObj
            $VerifyRunningProcessesDiagnosticsFindings.ChildFindings.Add($RunningProcessDiagnosticFinding)
        }
        return $VerifyRunningProcessesDiagnosticsFindings
    }

    $healthCheckName = "Search Healthcheck " + "( " + $ssa.DisplayName + " )"
    $SearchTopologyHealthCheck = New-SPDiagnosticFinding -Name $healthCheckName -Severity Default -InputObject $null -Format List

    # ------------------------------------------------------------------------------------------------------------------
    # Global variables:
    # ------------------------------------------------------------------------------------------------------------------
    $global:debug = $false #TODO: turn this to false for release
    $global:serviceDegraded = $false
    $global:serviceFailed = $false
    $global:unknownComponents = @()
    $global:degradedComponents = @()
    $global:failedComponents = @()
    $global:generationDifference = $false
    $global:indexLeftBehind = $false
    $global:searchHosts = 0
    #$global:ssa = GetSSA
    $global:componentStateList = $null
    $global:topologyCompList = $null
    $global:haTopology = $false
    $global:primaryAdmin = $null
    $global:indexedDocs = 0
    $global:masterMerge = $false

    #---added by bspender------------------------
    $global:SSPJobInstancesOffline = $(New-Object System.Collections.ArrayList)
    $global:ApplicationServerSyncTimerJobsOffline = $(New-Object System.Collections.ArrayList)
    $global:ApplicationServerSyncNotRunning = $(New-Object System.Collections.ArrayList)
    #--------------------------------------------
    $global:UnreachableSearchServiceSvc = $(New-Object System.Collections.ArrayList)
    $global:UnreachableSearchAdminSvc = $(New-Object System.Collections.ArrayList)
    #--------------------------------------------

    # Template object for the host array:
    $global:hostTemplate = New-Object psobject
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name hostName -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name components -Value 0
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name cpc -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name qpc -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name pAdmin -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name sAdmin -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name apc -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name crawler -Value $null
    $global:hostTemplate | Add-Member -MemberType NoteProperty -Name index -Value $null

    # Create the empty host array:
    $global:hostArray = @()

    # Template object for the HA group array:
    $global:haTemplate = New-Object psobject
    $global:haTemplate | Add-Member -MemberType NoteProperty -Name entity -Value $null
    $global:haTemplate | Add-Member -MemberType NoteProperty -Name partition -Value -1
    $global:haTemplate | Add-Member -MemberType NoteProperty -Name primary -Value $null
    $global:haTemplate | Add-Member -MemberType NoteProperty -Name docs -Value 0
    $global:haTemplate | Add-Member -MemberType NoteProperty -Name components -Value 0
    $global:haTemplate | Add-Member -MemberType NoteProperty -Name componentsOk -Value 0

    # Create the empty HA group array:
    $global:haArray = @()

    # Template object for the component/server table:
    $global:compTemplate = New-Object psobject
    $global:compTemplate | Add-Member -MemberType NoteProperty -Name Component -Value $null
    $global:compTemplate | Add-Member -MemberType NoteProperty -Name Server -Value $null
    $global:compTemplate | Add-Member -MemberType NoteProperty -Name Partition -Value $null
    $global:compTemplate | Add-Member -MemberType NoteProperty -Name State -Value $null

    $global:SearchTopologyValues = New-Object psobject

    # Create the empty component/server table:
    $global:compArray = @()

    # Get basic topology info and component health status
    GetTopologyInfo

    #---added by bspender------------------------
    #VerifyRunningProcesses
    #VerifyApplicationServerSyncJobsEnabled


    # Traverse list of components, determine properties and update $global:hostArray / $global:haArray
    foreach ($searchComp in ($global:topologyCompList))
    {
        PopulateHostHaList($searchComp)
    }

    # Analyze the component status:
    $compStatusColl = @()
    foreach ($component in ($global:componentStateList))
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
        #$SearchComponentStatusDiagnosticsFinding = New-SPDiagnosticFinding -Name "Broken Search Components" -Severity Default -InputObject $compStatusColl -format Table
        #$SearchComponentStatusDiagnosticsFinding.Severity = [SPDiagnostics.Severity]::Warning
        #$SearchTopologyHealthCheck.ChildFindings.Add($SearchComponentStatusDiagnosticsFinding)
    }

    # Look for selected info from detailed indexer diagnostics:
    $findings = DetailedIndexerDiag
    if($findings){
        $SearchTopologyHealthCheck.ChildFindings.Add($findings)                 
    } 

    # Output list of components with state OK:
    if ($global:compArray)
    {
        $global:compArray = $global:compArray | Sort-Object -Property Component
        $ComponentFindings = New-SPDiagnosticFinding -Name "Search Topology" -Severity Default -InputObject $global:compArray  -Format Table
        $SearchTopologyHealthCheck.ChildFindings.Add($ComponentFindings)
    }

    # Verify HA status for topology and index size limits:
    $VerifyHaLimitsFindings = VerifyHaLimits
    if($VerifyHaLimitsFindings)
    {
        $SearchTopologyHealthCheck.ChildFindings.Add($VerifyHaLimitsFindings)
    }
    

    # Verify that Host Controller HA (for dictionary repository) is OK:
    $VerifyHostControllerRepositoryFindings = VerifyHostControllerRepository
    if($VerifyHostControllerRepositoryFindings)
    {
        $SearchTopologyHealthCheck.ChildFindings.Add($VerifyHostControllerRepositoryFindings)
    }

    # Output components by server (for servers with multiple search components):
    if ($global:haTopology -and ($global:searchHosts -gt 2))
    {
        $componentsByServer = $false
        foreach ($hostInfo in $global:hostArray)
        {
            if ([int] $hostInfo.components -gt 1)
            {
                $componentsByServer = $true
            }
        }
        if ($componentsByServer)
        {
            $MultiComponentServers = New-SPDiagnosticFinding -Name "Servers with multiple search components" -Severity Default -InputObject $null
            foreach ($hostInfo in $global:hostArray)
            {
                if ([int] $hostInfo.components -gt 1)
                {
                    $hostinfofindings = New-SPDiagnosticFinding -Name $hostinfo.hostName -Severity Default -InputObject $hostInfo -Format Table 
                    $MultiComponentServers.ChildFindings.Add($hostinfofindings)
                }
                                
            }
            $SearchTopologyHealthCheck.ChildFindings.Add($MultiComponentServers)
        }
    }

    # Analytics Processing Job Status:
    $AnalyticsStatus = AnalyticsStatus
    $SearchTopologyHealthCheck.ChildFindings.Add($AnalyticsStatus)


    if ($global:masterMerge)
    {
        $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Master Merge" -Value "Index Master Merge (de-fragment index files) in progress on one or more index components."
    }

    if ($global:serviceFailed -eq $false)
    {
        $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Searchable Items" -Value $global:indexedDocs
    }

    GetCrawlStatus
        
    if ($global:unknownComponents)
    {
        $UnknownComponents = New-SPDiagnosticFinding -Name "The following components are not reachable" -InputObject $null 
        $UnknownComponents.Severity = [SPDiagnostics.Severity]::Warning
        $UnknownComponents.WarningMessage = "Recommended action: Restart Host Controller process or restart the associated server(s) and review ULS logs during that period"

        $description = $null
        foreach ($uc in ($global:unknownComponents))
        {
            $description += $uc.ToString() + "<br/>"
            
        }
        $UnknownComponents.Description = $description
        $SearchTopologyHealthCheck.ChildFindings.Add($UnknownComponents)
        
    }

    if ($global:degradedComponents)
    {
        $DegradedComponents = New-SPDiagnosticFinding -Name "The following components are degraded" -Severity Warning -InputObject $null
        $DegradedComponents.Severity = [SPDiagnostics.Severity]::Warning
        $DegradedComponents.WarningMessage = "Recommended action for degraded components:</br>"
        $DegradedComponents.WarningMessage+= "    Component registering or resolving:</br>"
        $DegradedComponents.WarningMessage+= "    This is normally a transient state during component restart or re-configuration. Re-run the script.</br>"
        
        $description = $null
        foreach ($dc in ($global:degradedComponents))
        {
            $description += $dc.ToString() + "<br/>"
        }

        $DegradedComponents.Description = $description

        if ($global:indexLeftBehind)
        {
            $DegradedComponents.WarningMessage+= "    Index component left behind:</br>"
            if ($global:generationDifference)
            {
                $DegradedComponents.WarningMessage+= "        This is normal after adding an index component or index component/server recovery.</br>"
                $DegradedComponents.WarningMessage+= "        Indicates that the replica is being updated from the primary replica.</br>"
            }
            else
            {
                $DegradedComponents.WarningMessage+= "        Index replicas listed as degraded but index generation is OK.</br>"
                $DegradedComponents.WarningMessage+= "        Will get out of degraded state as soon as new/changed items are being idexed.</br>"
            }
        }
        $SearchTopologyHealthCheck.ChildFindings.Add($DegradedComponents)
    }

    if ($global:failedComponents)
    {
        $FailedComponentsDiagnosticFindings = New-SPDiagnosticFinding -Name "The following components are reported in error" -Severity Warning -InputObject $null -format List -WarningMessage "Recommended action: Restart the associated server(s)"
        $description = $null

        foreach($fc in $failedComponents)
        {
            $description += $fc.ToString() + "<br/>"
        }

        $FailedComponentsDiagnosticFindings.Description = $description
        $SearchTopologyHealthCheck.ChildFindings.Add($FailedComponentsDiagnosticFindings)
        
    }

    if ($global:serviceFailed)
    {
        $SearchTopologyHealthCheck.Severity = [SPDiagnostics.Severity]::Critical
        $SearchTopologyHealthCheck.WarningMessage += " Search Service Overall State: Failed "
    }
    elseif ($global:serviceDegraded)
    {
        $SearchTopologyHealthCheck.Severity = [SPDiagnostics.Severity]::Warning
        $SearchTopologyHealthCheck.WarningMessage += " Search Service Overall State: Degraded "
    }
    else
    {
        $global:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Search service overall state" -Value "OK"
    }
    
    $SearchTopologyHealthCheck.InputObject = $global:SearchTopologyValues

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
    $script:SPFarm = $null
    $script:UsageDefinitionsWithReceivers = @("Analytics Usage","File IO","Page Requests","Simple Log Event Usage Data_SPUnifiedAuditEntry")

    if($PSversionTable.PSversion.Major -ge 5)
    {
        $Script:CheckServiceACLs = $true
    }
    
    function GetSPVersion($buildPrefix)
    {
        $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
        If($farm.BuildVersion.Major -eq 16 -or $farm.BuildVersion.Major -eq 15)
        {
            if($farm.BuildVersion.Major -eq 16)
            {
                if($farm.BuildVersion.Build -ge 14326)
                {
                    $buildFoo = "SPSE"
                }
                elseif($farm.BuildVersion.Build -ge 10337 -and $farm.BuildVersion.Build -lt 14320)
                {
                    $buildFoo = "2019"
                }
                else
                {
                    $buildFoo = "2016"
                }
            }
            else
            {
                $buildFoo = "2013"
            }
    
        }
        elseIf($farm.BuildVersion.Major -eq 14)
        {
            Write-Warning "The support for SharePoint 2010 has ended, please update this farm to a newer version of SharePoint.. Aborting Script"
            exit
        }
        else
        {
            Write-Warning "Unsupported Version of SP... Aborting script"
            exit
        }
        return $buildFoo
    }
        
    function Get-SPAnalyticsTopologyDiagnosticFinding($ssa)
    {
        $AnalyticsTopology = $null 

        # On 2013 Servers there is no AnalytisTopology accessor. Try getting it the old fashioned way if it's null
        if((GetSPVersion) -eq "2013")
        {
            $AnalyticsTopology = $ssa | Get-SPEnterpriseSearchTopology -Active
        }
        else
        {
            $AnalyticsTopology = $ssa.AnalyticsTopology
        }
    
        $finding = New-SPDiagnosticFinding -Name "Analytics Topology" -Severity Default -Format List -InputObject $AnalyticsTopology
        
        if($null -ne $AnalyticsTopology)
        {
            $components = $AnalyticsTopology.GetComponents()
            foreach($component in $components)
            {
                $componentFinding = New-SPDiagnosticFinding -Name $component.Name -Severity Default -Format List -InputObject $component
                $finding.ChildFindings.Add($componentFinding)
            }
        }
        else {
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
        
        $finding = New-SPDiagnosticFinding -Name "Site and WebRoot Properties" -Severity Default -InputObject $tempSite -Format Table
        
        if(!$SPReportingFeatureEnabled)
        {
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            $finding.WarningMessage = "Reporting Feature is not enabled on this site, reporting will not be available or will be stale"
        }
        
        $finding.ChildFindings.Add((Get-SPDiagnosticWebPropertiesOfInterest $site.RootWeb))
        $finding.ChildFindings.Add((Get-SPDiagnosticWebApplicationPropertiesOfInterest $site.WebApplication))
        
        $webs = $site.AllWebs
        $webFinding =  New-SPDiagnosticFinding -Name "All Webs" -Severity Default -InputObject $null -Format Table -Expand
    
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
        $tempWeb = $web | Select-Object Url, NoCrawl
        $finding = New-SPDiagnosticFinding -Name "Web Properties" -Severity Default -InputObject $tempWeb -Format Table
        if($tempWeb.NoCrawl -eq $true)
        {
            $finding.WarningMessage = 'NoCrawl is $true on this web. This may prevent accurate reporting, site views, etc,.'
            $finding.Severity = [SPDiagnostics.Severity]::Warning
        }
    
        return $finding
    }
    function Get-SPDiagnosticWebApplicationPropertiesOfInterest($webApp)
    {
        $tempWebApp = $webApp | select-object AllowAnalyticsCookieForAnonymousUsers
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Pool Name" -Value $webApp.ApplicationPool.Name
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Pool UserName" -Value $webApp.ApplicationPool.Username
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Managed Account" -Value $webApp.ApplicationPool.ManagedAccount
    
        $script:W3WPAppPoolAccount = $webApp.ApplicationPool.Username
        $finding = New-SPDiagnosticFinding -Name "WebApp Properties" -Severity Default -InputObject $tempWebApp -Format List
        
        return $finding
    }
    
    function Get-SPDiagnosticOWSTimerService()
    {
        $OWSTimerService = Get-WmiObject -Class Win32_Service | where-object{$_.Name -like "SPTimerV4"}
    
        $finding = New-SPDiagnosticFinding -Name "OWSTimer/SPTimerV4" -Severity Default -Format List
    
        if($null -ne $OWSTimerService)
        {
            $finding.InputObject = $OWSTimerService
            $Script:TimerServiceAccount  = $OWSTimerService.StartName
        }
        else
        {
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            $finding.WarningMessage = "Cannot Identify the SPTimerV4 Service"
        }
    
        return $finding
    }
    
    function Get-SPDiagnosticFindingSPUsageManager()
    {
        $SPUsageManager = [Microsoft.SharePoint.Administration.SPUsageManager]::Local
        $finding = New-SPDiagnosticFinding -Name "SPUsageManager Details" -Severity Default -Format List
    
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
        $finding = New-SPDiagnosticFinding -Name "SPUsageService Details" -Severity Default -Format List
    
        $SPUsageService = Get-SPUsageService
        if($null -eq $SPUsageService)
        {
            $finding.WarningMessage = "There is no SPUsageService. This will prevent .usage logs from being created"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            return $finding
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
            $instancesFinding = New-SPDiagnosticFinding -Name "SPUsageService Instances" -Severity Default -Format Table -InputObject $instances
    
            foreach($instance in $instances)
            {
                $status = $instance.Status
    
                if($status -ne "Online")
                {
                    $instanceFinding = New-SPDiagnosticFinding -Name "SPUsageService Instance" -Severity Default -Format List -InputObject $instance
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
            $applicationFinding = New-SPDiagnosticFinding -Name "SPUSageApplication Instances" -Severity Default -Format List -InputObject $applications
            $finding.ChildFindings.Add($applicationFinding)
        }
    
    
        $Script:UsageLogDir = $SPUsageService.UsageLogDir
    
        if(!$Script:UsageLogDir.EndsWith("\"))
        {
            $Script:UsageLogDir += "\"
        }
    
        $jobDefinitionsFinding = New-SPDiagnosticFinding -Name "Job Definitions on SPUsageService" -Severity Default -Format Table
    
        $jobDefinitionsCount = [PSCustomObject]@{
            "Job Definition Count" = $SPUsageService.JobDefinitions.Count
        }
    
        $jobDefinitionsFinding.InputObject = $jobDefinitionsCount
    
        foreach($job in $SPUsageService.JobDefinitions)
        {
           
            $jobname = $Job.Name
            $jobDefinitionFinding = New-SPDiagnosticFinding -Name "Job Definitions: $jobname" -Severity Default -Format List -InputObject $job
            $JobHistoryFindingEntries = New-SPDiagnosticFinding -Name "Most Recent 20 Job History Entries" -Severity Default -Format Table 

            $JobHistoryEntries = $job.HistoryEntries | Sort-Object -Descending StartTime | Select-Object Servername, Status, StartTime, EndTime, ErrorMessage -First 20
            $JobHistoryFindingEntries.InputObject = $JobHistoryEntries

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
    
        $JobHistoryFindingEntries = New-SPDiagnosticFinding -Name "Most Recent 20 Job History Entries On SPUsageService" -Severity Default -Format Table 
        
        $JobHistoryEntries = $SPUsageService.JobHistoryEntries | Sort-Object -Descending StartTime | Select-Object Servername, Status, StartTime, EndTime, ErrorMessage -First 20
    
        $JobHistoryFindingEntries.InputObject = $JobHistoryEntries
    
        $finding.ChildFindings.Add($JobHistoryFindingEntries)
    
        return $finding
    }
    
    function Get-SPUsageDefinitionDiagnosticFinding()
    {
        $finding = New-SPDiagnosticFinding -Name "SPUsageDefinitions" -Severity Default -Format Table
        $definitions = Get-SPUsageDefinition
        $finding.InputObject = $definitions | Select-Object Name, Status, Enabled, EnableReceivers, Retention, DaysToKeepData, DaysToKeepUsageFiles, UsageDatabaseEnabled, TableName, MaxTotalSizeInBytes, Hidden, Description
    
        foreach($definition in $definitions)
        {
          
            # Does this definition usually use receivers? 
            if($script:UsageDefinitionsWithReceivers.Contains($definition.Name))
            {
                $tempName = $definition.Name
                $definitionFinding = New-SPDiagnosticFinding -Name $tempName -Severity Default -Format List -InputObject $definition

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
                    $receiverFinding = New-SPDiagnosticFinding -Name $receiver -Severity Default -Format Table -InputObject $definition
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
                
                $finding.ChildFindings.Add($definitionFinding)
    
            }
   

        }
    
        return $finding
    }
    
    function Get-UsageAndHealthDataCollectionProxyDiagnosticFinding()
    {
        $finding = New-SPDiagnosticFinding -Name $script:UsageAndHealthDataCollectionProxyName -Severity Default -Format List
        $finding.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/administration/configure-usage-and-health-data-collection"
    
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
                    $finding.WarningMessage += "Status is Disabled. You may need to Provision the Usage and Health Data Collection Proxy"
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
        $finding = New-SPDiagnosticFinding -Name "EventType Definitions" -Severity Default -Format Table
    
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
                $eventFinding = New-SPDiagnosticFinding -Name $name -Severity Default -Format List -InputObject $event
                $eventFinding.Severity = [SPDiagnostics.Severity]::Informational
                $eventFinding.WarningMessage = "$name is not enabled, this will impact reports relying on $name data. This can be safely ignored for some event types"
                $finding.ChildFindings.Add($eventFinding)
            }

        }
        return $finding
    }
    
    Function Get-EventStoreFolderInfoDiagnosticFinding($ssa)
    {
        $finding = New-SPDiagnosticFinding -Name "Event Store Folder" -Severity Default
    
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
        $finding = New-SPDiagnosticFinding -Name $findingName -Severity Default -Format List 
    
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
            $permissionFinding = New-SPDiagnosticFinding -Name "Permissions for $path" -Severity Default -Format Table 
           
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
    
        $items = get-childitem -Path $path -ErrorAction SilentlyContinue -Recurse | Select-Object Name, CreationTime, LastAccessTime,LastWriteTime,Attributes | Sort-Object LastWriteTime -Descending
    
        if($null -ne $items)
        {
            $EventStoreContentFinding =  New-SPDiagnosticFinding -Name "$findingName Contents" -Severity Default -Format Table -InputObject $items 
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
            $finding = New-SPDiagnosticFinding -Name "Account Membership" -Severity Default -Format Table -InputObject $collection
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
        $finding = New-SPDiagnosticFinding -Name "Usage Analytics Timerjob Information" -Severity Default -Format List 
    
        if($null -eq $script:ssa)
        {
            $finding.WarningMessage = "No SSA Present, There will be no Usage Analytics Timer Job"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
        
        $usageAnalyticsJobName = "Usage Analytics Timer Job for Search Application " + $script:ssa.Id
        $usageJob = Get-SPTimerJob | Where-Object{$_.Name -eq $usageAnalyticsJobName}
    
        if($usageJob)
        {
            $finding.InputObject = $usageJob
            $AnalysisInfoFinding = New-SPDiagnosticFinding -Name "Analysis Information from TimerJob" -Severity Default -Format List -InputObject $usageJob.GetAnalysisInfo()
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
        $finding = New-SPDiagnosticFinding -Name "AnalyticsJobDefinition Jobs" -Severity Default -Format List 
    
        if($null -eq $script:ssa)
        {
            $finding.WarningMessage = "No SSA Present, There will be no Usage Analytics Timer Job"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
    
    
        $jobs = get-sptimerjob | Where-Object{$_.TypeName -like "Microsoft.Office.Server.Search.Analytics.AnalyticsJobDefinition"}
    
        if($null -eq $jobs) 
        {
            $finding.WarningMessage = "Microsoft.Office.Server.Search.Analytics.AnalyticsJobDefinition TimerJob not found"
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            return $finding
        }
    
        foreach($job in $jobs)
        {
            $jobFinding =  New-SPDiagnosticFinding -Name $job.Name -Severity Default -Format List -InputObject $job
    
            $analysisjobs = $job.Analyses 
    
            foreach($analysisjob in $analysisjobs)
            {
                $analysisJobFinding = New-SPDiagnosticFinding -Name $analysisjob.Name -Severity Default -Format List -InputObject $analysisjob
    
                $analysisInfo = $analysisjob.GetAnalysisInfo()
                if($analysisInfo)
                {
                    $AnalysisInfoFinding = New-SPDiagnosticFinding -Name "Analysis Info" -Severity Default -Format List -InputObject $analysisInfo
                    $analysisJobFinding.ChildFindings.Add($AnalysisInfoFinding)
                }
                else {
                    $analysisJobFinding.Severity = [SPDiagnostics.Severity]::Informational
                    $analysisJobFinding.WarningMessage += "No Analysis Info found"
                }

                $analysisConfiguration = $analysisjob.GetAnalysisConfiguration()
                if($analysisConfiguration)
                {
                    $AnalysisConfigurationFinding =  New-SPDiagnosticFinding -Name "Analysis Configuration" -Severity Default -Format Table -InputObject $analysisConfiguration
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

   
    $UsageAndReportFinding = New-SPDiagnosticFinding -Name "Usage Analysis and Reporting Findings" -InputObject $null -Format Table
  
    #$UsageAndReportFinding.ChildFindings.Add((Get-SPDiagnosticFarmFindings))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPAnalyticsTopologyDiagnosticFinding $script:ssa))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPDiagnosticSitePropertiesOfInterest $site))
    $UsageAndReportFinding.ChildFindings.Add((Get-SPDiagnosticOWSTimerService))
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
    
    $afdFinding = New-SPDiagnosticFinding `
        -Name ("Azure Front Door Compatible Ciphers: {0}" -f $ServerName) `
        -Description "Azure Front Door (AFD) serves as a gateway for much of M365, as such most hybrid scenarios require the ability to establish a secure connection to AFD." `
        -ReferenceLink "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq#what-are-the-current-cipher-suites-supported-by-azure-front-door-"

    if($supportedCiphers.Count -le 0)
    {
        $afdFinding.Severity = [SPDiagnostics.Severity]::Warning
        $afdFinding.WarningMessage += "No supported ciphers found to communicate with AFD, if you are currently or intending to use hybrid functionality this should be addressed."
    }
    else
    {
        $afdFinding.InputObject = $supportedCiphers
        $afdFinding.Format = [SPDiagnostics.Format]::Table

        if($priorityWarning)
        {
            #Write-Warning "Priority of Azure Front Door compatible ciphers may be too low"
            $afdFinding.WarningMessage+="Priority of Azure Front Door compatible ciphers may be too low, if you are encountering issues with hybrid functionality this should be investigated."
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
    $finding = New-SPDiagnosticFinding `
        -Name "TLS Configuration" `
        -InputObject $null `
        -Description "These findings are specific to enabling and providing support for TLS 1.2 connections, this is necessary in environments where TLS 1.0/1.1 has been disabled or when enabling hybrid or other functionality that requires connectivity to TLS 1.2 secured resources. Please refer to the reference material for more information."

    $spVersion = getSPVersion
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

    $servers = Get-SPServer | Where-Object {$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    foreach($server in $servers)
    {
        try 
        {
            
            $serverFinding = New-SPDiagnosticFinding `
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


# Main function that calls into building the report and contains the first level findings.
# Keep this clean and organized to make future additions easier
function main
{
    [cmdletbinding()]
    Param()

    if($null -eq (Get-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue) -and $null -eq (Get-Command Get-SPFarm -ErrorAction SilentlyContinue))
    {
        Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue | Out-Null
    }

    if($Help)
    {
        # TODO: HELP
        Write-Host "Help"
        break
    }

    if($PatchInfo)
    {
        $title    = "PatchInfo Warning"
        $prompt = "PatchInfo requires a Nuget Provider and Microsoft's MSI Module to be installed. You may be prompted for this. Continue with PatchInfo?"
        $choices  = "&Yes", "&No"

        $choice = $Host.UI.PromptForChoice($title, $prompt, $choices, 1)
        if ($choice -ne 0) {
            #No
            Write-Host "Disabling PatchInfo Gathering"
            $PatchInfo = $false
        }
    }

    $site = $null

    if([string]::IsNullOrEmpty($siteUrl) -and $UsageAndReporting)
    {
        $siteUrl = Read-Host "Please provide a site url [Default:http://sharepoint]"
        if([String]::IsNullOrEmpty($siteUrl))
        {
            $siteUrl = "http://sharepoint"
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

    $build = GetSPVersion $buildPrefix
    $rootFindingCollection = New-Object SPDiagnostics.FindingCollection[SPDiagnostics.Finding]
    $rootFindingCollection.Add((Get-SPDiagnosticsSupportDateFinding))
    $rootFindingCollection.Add((Get-SPDiagnosticFarmFindings))
    $rootFindingCollection.Add((Get-SPDiagnosticAuthFindings))
    $rootFindingCollection.Add((Get-SPDiagnosticSearchFindings))
    
    if($UsageAndReporting -and $site)
    {
        $rootFindingCollection.Add((Get-SPDiagnosticUsageAndReportingInformation $site))
    }

    if($TLS)
    {
        $rootFindingCollection.Add((Get-SPDiagnosticsTlsFinding))
    }

    $htmlContent = Write-DiagnosticReport -Findings $rootFindingCollection

    $fileName = "{0}\SPFarmReport_{1}_{2}" -f $ENV:UserProfile, $build, [datetime]::Now.ToString("yyyy_MM_dd_hh_mm") + ".html"
    Set-Content -Value $htmlContent -LiteralPath $fileName

    Invoke-Item $fileName

    Write-Host ("`n`nScript complete, review the output file at `"{0}`"" -f $fileName) -ForegroundColor Green
}

main
