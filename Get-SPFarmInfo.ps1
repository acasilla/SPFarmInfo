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
    PS C:\> Get-SPFarmInfo.PS1 -SkipSearchHealthCheck -TLS 
    This executes the Get-SPFArmInfo data collection process without the exhaustive search health check and performs additional TLS collect
.INPUTS
    None at this time
.OUTPUTS
    An html report documenting findings.
.NOTES
    General notes
    Version 3.0

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
    [Parameter(Position=1,HelpMessage="Displays the help associated with the SPFarmInfo script")]
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
    [switch]$TLS,

    [Parameter(Position=7,HelpMessage="Saves Output to TEXT format instead of HTML")]
    [switch]$Text,

    [Parameter(Position=8,HelpMessage="Skips appending the SPFarmInfo output with errors collection")]
    [switch]$SkipErrorCollection,

    [Parameter(Position=9,HelpMessage="Skips the initial disclaimer")]
    [switch]$SkipDisclaimer,

    [Parameter(HelpMessage="PII Data in the report will be obfuscated/pseudonomized. This includes Server names, URLs, User Accounts, ... .")]
    [switch]$Obfuscate
)

if([System.IntPtr]::Size -lt 8)
{
    Write-Error "Get-SPFarmInfo Is not supported on x86 Powershell/Powershell ISE instances"
    exit
}

$ScriptVersion="3.0.2305.1103"

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

    #Write-Host ("$((get-Date).ToString('yyyy-MM-dd HH:mm:ss.ffff')) Generating finding -- {0}" -f $Name)
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
                $preContent = "`r`n<details{0}><summary id=`"{1}`" class=`"heading {2}`">{3}</summary><div class=`"finding`">" -f $expandStr, $encodedFindingName, $class, $Finding.Name
            }
            'TEXT'
            {
                $preContent = "#########################################################################################`r`n"
                $preContent += "{0}`r`n" -f $Finding.Name
                $preContent += "#########################################################################################`r`n"
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

        $postContent = $null

        Switch($OutputFormat)
        {
            'HTML'
            {
                $postContent = "</details>"
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
        $Findings, 
        [Parameter(Mandatory=$false)]
        [SPDiagnostics.OutputFormat]$OutputFormat=[SPDiagnostics.OutputFormat]::HTML
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
    
    $html = $null;
    if($OutputFormat -eq [SPDiagnostics.OutputFormat]::HTML)
    {
        $html = "<!DOCTYPE html><head><Title>SPFarmReport - {0}</Title></head><body>" -f $build
        $html+=$globalCss
        $html+="<div id=`"topInfo`">"
        $html+="<h1>SPFarmReport - {0} [{1}]</h1>" -f $build, [Microsoft.SharePoint.Administration.SPFarm]::Local.BuildVersion.ToString()
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
    }


    # Identify "Critical" and "Warning" findings so that they can be promoted
    $criticalFindings = Get-DiagnosticErrorFindings -Findings $Findings -Severity Critical
    $warningFindings = Get-DiagnosticErrorFindings -Findings $Findings -Severity Warning
    $informationalFindings = Get-DiagnosticErrorFindings -Findings $Findings -Severity Informational
    
    # If there are critical findings create a "review-section" for critical findings at the top of the report
    if($criticalFindings.Count -ge 1)
    {
        Switch($OutputFormat)
        {
            'HTML'
            {
                $html+="<div class=`"review-section`" style=`"border-color:red;`"><details open=`"true`"><summary class=`"error heading`">Critical Findings</summary>"
                $html+="<div style=`"padding-left: 30px`">"
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
                $html+="</div></details></div><br>"
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
                $html+="<div class=`"review-section`" style=`"border-color:darkorange`"><details open=`"true`"><summary class=`"warning heading`">Review Items</summary>"
                $html+="<div style=`"padding-left: 30px`">"
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
                $html+="</div></details></div><br>"
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
                $html+="<div class=`"review-section`" style=`"border-color:black`"><details><summary class=`"heading`">Informational Items</summary>"
                $html+="<div style=`"padding-left: 30px`">"
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
                $html+="</div></details></div><br>"
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
            $html+=("<script type=`"text/javascript`">{0}</script>" -f $expandAllJS)
            $html+="</body></html>"
        }
        'TEXT'
        {
            $html+="#########################################################################################`r`n"
        }
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

#endregion

#region SPVersion Function
function Get-SPVersion
{
    [CmdletBinding()]
    param ()
    $farm = [Microsoft.SharePoint.Administration.SPFarm]::Local
    $script:SPFarm = $farm
    $Script:SPFarmBuild = $script:SPFarm.BuildVersion

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
function CheckServicingPolicy ($ServicingPolicies)
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

Function SPSESupportServicePolicy
{
    #ToDo:Adjust values after every monthly CU of SPSE
    $ServiceingPolicies = @()
    # latest version
    #2024/04/09
    #$ServicingPolicy = new-Object psobject
    #$ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,04,09)
    #$ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.15601.20478"
    #$ServiceingPolicies += $ServicingPolicy
    #2024/05/14
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,05,14)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.16130.20420"
    $ServiceingPolicies += $ServicingPolicy
    #2024/04/09
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,04,09)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.16130.20314"
    $ServiceingPolicies += $ServicingPolicy
    #2024/03/12
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,03,12)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.16130.20206"
    $ServiceingPolicies += $ServicingPolicy
    #2024-02/13
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,02,13)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.15601.20478"
    $ServiceingPolicies += $ServicingPolicy
    #2024/01/09
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,01,09)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.15601.20418"
    $ServiceingPolicies += $ServicingPolicy
    #2022/12/12 
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2023,12,12)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.14326.20450"
    $ServiceingPolicies += $ServicingPolicy

    $ServicePolicyFinding = New-DiagnosticFinding -Name "Sharepoint SE Product Servicing Policy" -InputObject $null -Format List
    if (CheckServicingPolicy  $ServiceingPolicies)
    {
        $ServicePolicyFinding.Description +="SharePoint farm is in Product Servicing Policy"
    } else {
        $ServicePolicyFinding.WarningMessage += "This Version of SharePoint Subsription Edition is no longer supported. You must install a later Cumulative Update to be fully supported again."
        $ServicePolicyFinding.ReferenceLink+="https://learn.microsoft.com/en-us/sharepoint/product-servicing-policy/updated-product-servicing-policy-for-sharepoint-server-se"
        $ServicePolicyFinding.Severity = [SPDiagnostics.Severity]::Critical
    }
    return $ServicePolicyFinding 
}

Function SP2019SupportServicePolicy
{
    #ToDo:Adjust values after November 2023 CU of SP 2019
    $ServiceingPolicies = @()
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2024,10,31)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10392.20000"
    $ServiceingPolicies += $ServicingPolicy

    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2023,10,31)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10381.20001"
    $ServiceingPolicies += $ServicingPolicy

    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2022,10,31)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.10368.20022"
    $ServiceingPolicies += $ServicingPolicy

    $ServicePolicyFinding = New-DiagnosticFinding -Name "SharePoint 2019 Product Servicing Policy" -InputObject $null -Format List
    if (CheckServicingPolicy  $ServiceingPolicies)
    {
        $ServicePolicyFinding.Description +="SharePoint farm is in Product Servicing Policy"
    } else {
        $ServicePolicyFinding.WarningMessage += "This Version of SharePoint 2019 is no longer supported. You must install a later Cumulative Update to be fully supported again."
        $ServicePolicyFinding.ReferenceLink+="https://learn.microsoft.com/en-us/SharePoint/product-servicing-policy/updated-product-servicing-policy-for-sharepoint-2019"
        $ServicePolicyFinding.Severity = [SPDiagnostics.Severity]::Critical
    }
    return $ServicePolicyFinding
}

Function SP2016SupportServicePolicy
{
    $ServiceingPolicies = @()
    #ToDo:Adjust values after November 2023 CU of SP 2016
    $ServicingPolicy = new-Object psobject
    $ServicingPolicy | add-member -MemberType NoteProperty -Name SupportEndDate -value (New-Object DateTime 2026,07,14)
    $ServicingPolicy | Add-Member -MemberType NoteProperty -name BuildVersionMin -value "16.0.5161.1000"
    $ServicePolicyFinding = New-DiagnosticFinding -Name "SharePoint 2016 Product Servicing Policy" -InputObject $null -Format List
    $ServiceingPolicies += $ServicingPolicy
    if (CheckServicingPolicy  $ServiceingPolicies)
    {
        $ServicePolicyFinding.Description +="SharePoint farm is in Product Servicing Policy"
    } else {
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

    $endOfSupportInfo = [PSCustomObject]@{
    }
    
    if($build -eq "SPSE")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri "https://go.microsoft.com/fwlink/?LinkId=2198657").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2199, 12, 1), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2199, 12, 1), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $supportDateFinding.ChildFindings.add((SPSESupportServicePolicy))
    }
    elseif($build -eq "2019")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri "https://go.microsoft.com/fwlink/?LinkId=2198656").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2024, 1, 9), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2026, 7,14), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $supportDateFinding.ChildFindings.add((SP2019SupportServicePolicy))

    }
    elseIf($build -eq "2016")
    {
        $endOfSupportNotificationLink = $(New-Object System.Uri  "https://go.microsoft.com/fwlink/?LinkId=2198655").AbsoluteUri
        $mainstreamSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2021, 7, 13), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $endOfSupportDate = [System.TimeZoneInfo]::ConvertTimeToUtc((New-Object DateTime 2026, 7, 14), [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time"));
        $supportDateFinding.ChildFindings.add((SP2016SupportServicePolicy))
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
        $supportDateFinding.WarningMessage += "This version of SharePoint Server is no longer supported."
        $supportDateFinding.WarningMessage += "Microsoft does not accept requests for fixes, design changes, or new features when a product is no longer supported."
        $supportDateFinding.WarningMessage += "Microsoft will not release any updates for this product, not even 'Security' related updates."   

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
            $supportDateFinding.WarningMessage += "This version of SharePoint Server is nearing the end of 'Mainstream' support."
            $supportDateFinding.WarningMessage += "Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' phase."
            $supportDateFinding.WarningMessage += "Microsoft will only release 'Security' related updates in the patching cycle." }
        else
        {
            $endOfSupportSeverityLevel = "Alert";
            $supportDateFinding.Severity = [SPDiagnostics.Severity]::Critical
            $supportDateFinding.WarningMessage += "This version of SharePoint Server is in 'Extended' Support."
            $supportDateFinding.WarningMessage += "Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' phase."
            $supportDateFinding.WarningMessage += "Microsoft will only release 'Security' related updates in the patching cycle."}   
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
                $supportDateFinding.WarningMessage += "This version of SharePoint Server is nearing the end of 'Mainstream' support."
                $supportDateFinding.WarningMessage += "Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' Phase."
                $supportDateFinding.WarningMessage += "Microsoft will only release 'Security' related updates in the patching cycle."
            }
            else
            {
                $endOfSupportSeverityLevel = "Alert";
                $supportDateFinding.Severity = [SPDiagnostics.Severity]::Critical
                $supportDateFinding.WarningMessage += "This version of SharePoint Server is in 'Extended' Support."
                $supportDateFinding.WarningMessage += "Microsoft does not accept requests for fixes, design changes, or new features during the 'Extended Support' Phase."
                $supportDateFinding.WarningMessage += "Microsoft will only release 'Security' related updates in the patching cycle."
            }   
        }
    }
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "SPFarm Build" -Value $build
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Alert" -Value $endOfSupportSeverityLevel
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Mainstream End Date" -Value $mainstreamSupportDateString
        $endOfSupportInfo | Add-Member -MemberType NoteProperty -Name "Extended End Date" -Value $endOfSupportDateString
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
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServersInFarm))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticSQLFindings))    
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServicesOnServer))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticHealthAnalyzerFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticServiceAppInfo))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticTimerAndAdminServiceFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticTimerJobHistoryFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsWebAppsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsAppPoolsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsWebConfigModificationsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsFarmSolutionsFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsFarmFeaturesFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticCertificateFindings))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsDeveloperDashboardSettingsFinding))
    $farmFindings.ChildFindings.Add((Get-SPSessionStateServiceFinding))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticsDCacheFinding))
    $farmFindings.ChildFindings.Add((Get-OfficeOnlineServerFindings))
    $farmFindings.ChildFindings.Add((Get-SPDiagnosticFarmNetworkLatency))
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
        ConfigDbName = $configDb.Name
        ConfigDbId = $configDb.Id
        ConfigDbSql = $(obfuscate $configDb.ServiceInstance.Server.Address "sqlserver")
        ConfigDbInstance = $(obfuscate $configDb.ServiceInstance.Instance "sqlinstance")
    }
    $finding = New-DiagnosticFinding -Name "Farm Info" -Description "Farm build, ULS Location, and config db" -InputObject $retObj -Format List -Expand 

    if($countOfVerboseEx -gt 0 -or $countOfVerboseEx -gt 0 -or $countOfVerboseEvents)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "TraceSeverity is set to VerboseEx on $countOfVerboseEx LogLevel(s). This may cause performance issues." 
        $finding.WarningMessage += "If this loggging is not necessary, reset the logging to default either from Central Administration > Monitoring > Configur Diagnostic Logging"
        $finding.WarningMessage += "or by running the 'Clear-SPLogLevel' command from the SharePoint management shell."
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

function Get-SPDiagnosticsSqlAlias
{
    $servers = Get-SPServer | Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    $serverAliases = @()
    foreach($server in $servers)
    {
        try
        {
            $registryHive  = [Microsoft.Win32.RegistryHive]::LocalMachine
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($registryHive, $server.Name)
            $key = $reg.OpenSubKey("SOFTWARE\\Microsoft\\MSSQLServer\\Client\\ConnectTo")
            $aliases = $key.GetValueNames()
            foreach($alias in $aliases)
            {
                $serverAliases += [PSCustomObject]@{
                    Server = $(obfuscate $server.Name "sqlserver")
                    ServerAlias = $(obfuscate $alias "sqlalias")
                    ConnectionString = $(obfuscate ($key.GetValue($alias).ToString().Replace("DBMSSOCN,", "").Replace("DBNMPNTW,","")) "SQLConnectionString")
                 }
            }
        }
        catch
        {}
    }
    if($serverAliases.Count -ge 1)
    {
        return New-DiagnosticFinding -Name "Sql Aliases" -InputObject $serverAliases -Format Table -Description "SQL Server aliases that are currently configured in cliconfg"
    }
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
                if ($productStatusLevel -ne [SPDiagnostics.Severity]::Critical) {$productStatusLevel = [SPDiagnostics.Severity]::Warning }
                if($productStatus -ieq "UpgradeBlocked" -or $productStatus -ieq "InstallRequired" -or $productStatus -ieq "UpgradeInProgress" )
                {
                    $productStatusLevel = [SPDiagnostics.Severity]::Critical
                }
            }

        }

        $osInfo = Get-SPDiagnosticsOsInfo $svr

        $serverColl+=  [PSCustomObject]@{
            Name = $(Obfuscate $svr.DisplayName "computer")
            Role = $svr.Role
            RoleCompliant = $svr.CompliantWithMinRole
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
    
    $finding = New-DiagnosticFinding -Name "Servers in Farm" -Severity Default -InputObject $serverColl -Format Table -Expand

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
        if ($CustomRoleServers.count -eq 1)
        {
            $finding.WarningMessage += "The server $($($CustomRoleServers[0])) is running in MinRole Custom. Servers in the Custom MinRole are not self healing."
        } else {
            $finding.WarningMessage += "The servers $($($CustomRoleServers -join ",")) are running in MinRole Custom. Servers in the Custom MinRole are not self healing."
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

    $finding.ChildFindings.Add((Get-MissingPatches))

    $sqlAliasFinding = Get-SPDiagnosticsSqlAlias
    if($sqlAliasFinding.InputObject.Count -ge 1)
    {
        $finding.ChildFindings.Add($sqlAliasFinding)
    }

    return $finding
}

function Get-SPDiagnosticsOsInfo
{
    [cmdletbinding()]
    Param([Microsoft.SharePoint.Administration.SPServer]$server)

    try
    {
        $timeZone = $(Get-WMIObject -Class Win32_TimeZone -Computer $server.DisplayName -ErrorAction Stop).Description
        [wmi]$sysInfo = get-wmiobject Win32_ComputerSystem -Namespace "root\CIMV2" -ComputerName $server.DisplayName -ErrorAction Stop
        [wmi]$os = Get-WmiObject Win32_OperatingSystem -Namespace "root\CIMV2" -Computername $server.DisplayName -ErrorAction Stop
        [array]$procs = Get-WmiObject Win32_Processor -Namespace "root\CIMV2" -Computername $server.DisplayName -ErrorAction Stop
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
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Url" -Value $(Obfuscate $URI "url")
    
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
            Add-Member -InputObject $result -MemberType NoteProperty -Name "Url" -Value $(Obfuscate $URI "url")
           
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
        $SPServers =  get-spserver | Where-Object {$_.role -ne "invalid"}
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
                        $pi | Add-Member -MemberType NoteProperty -Name "server" -Value  $(Obfuscate $prodInfo.ServerName "computer")
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

    } else {
        $MissingPatchesFindings.Description ="All SharePoint Servers are on the same patch level for all SharePoint Products"
    }
    return $MissingPatchesFindings
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
                Server = $(Obfuscate $server.Address "computer")
                Service = $service.TypeName
                Status = $service.Status
                Id = $service.Id
            }
        }
    }

    $finding = New-DiagnosticFinding -Name "Services on Server" -InputObject $runningServices -Format Table
    
    $troubleServices = $runningServices | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    if($null -ne $troubleServices)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Warning
        $finding.WarningMessage = "One or more services identified in a starting or stopping state"
    }
    $finding.ChildFIndings.add((Get-SPRequestManagementServiceFinding))
    return $finding
}

function Get-SPRequestManagementServiceFinding()
{
    $RMInstances = get-spserviceinstance | Where-Object {$_.typename -eq "Request Management" }  | Select-Object Typename, @{l="Server";e={$_.Server.Address}}, Status, Id 
    #obfuscate
    foreach ($rmi in $RMInstances)
    {
        $rmi.Server = $(Obfuscate $rmi.server "computer")
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
    $CAWebUrl= ( Get-SPWebApplication -IncludeCentralAdministration | Where-Object { $_.IsAdministrationWebApplication -eq $true}).Url
    $w = get-spweb $CAWebUrl
    $l = $w.lists | Where-Object {$_.basetemplate.value__ -eq 1221}
    $items = $l.GetItems()
    $HAList = $items | Where-Object { ($_["Severity"]) -ne "4 - Success" } 
    
    $MinSeverity="9"
    $HealthAnalyzerEntries = @()
    foreach ($HALe in $HAList)
    {
        $HAEntry = new-object PSObject
        $HAEntry | Add-Member -membertype NoteProperty -Name "Severity" -value $HALe["Severity"]
        $HAEntry | Add-Member -membertype NoteProperty -Name "Category" -value $HALe["Category"]
        $HAEntry | Add-Member -membertype NoteProperty -Name "Description" -Value $HALe.Title 
        $HAEntry | Add-Member -membertype NoteProperty -Name "Failing Servers" -Value $(Obfuscate $HALe["ows_HealthReportServers"] "computer")
        $HAEntry | Add-Member -membertype NoteProperty -Name "Failing Services" -Value $HALe["ows_HealthReportServices"] 
        $HAEntry | Add-Member -membertype NoteProperty -Name "Remedy" -Value ($HALe["Remedy"]).Replace($CAWebUrl,$(Obfuscate $CaWebUrl "url"))
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
    
    #obfuscate
    foreach ($ti in $timerInstances)
    {
        $ti.Server = $(Obfuscate $ti.server "computer")
    }
    
    $timerFinding = New-DiagnosticFinding -Name "Timer Service Instances" -InputObject $timerInstances -Format Table

    if($null -ne $problemTimerInstances)
    {
        $timerFinding.Severity = [SPDiagnostics.Severity]::Critical
        $timerFinding.WarningMessage += "One or more Timer Service Instances is not online"
        $timerFinding.Description+=("Example PowerShell to set the 'Timer Service Instance' object back online.<br/><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guid of disabled object')<br/>`$obj.Status = [Microsoft.SharePoint.Administration.SPObjectStatus]::Online<br/>`$obj.Update()</div>")
        $timerFinding.Description+="Once the above PowerShell is performed the 'SharePoint Timer Service' service on that server must be restarted (within services.msc console)"
        $timerFinding.ReferenceLink += "https://joshroark.com/sharepoint-all-about-one-time-timer-jobs/"       
    }

    
    $adminSvc = $farm.Services | Where-Object{$_.TypeName -eq "Microsoft SharePoint Foundation Administration"}
    $adminInstances = $adminSvc.Instances | Select-Object @{l="Server";e={$_.Server.Address}}, Status, Id
    $problemAdminInstances = $adminInstances | Where-Object{$_.Status -ne [Microsoft.SharePoint.Administration.SPObjectStatus]::Online}
    
     #Obfuscate
     foreach ($ai in $adminInstances)
     {
         $ai.Server = $(Obfuscate $ai.server "computer")
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


    $finding = New-DiagnosticFinding -Name "Timer and Admin Service Instances" -InputObject $null -Format Table
    $finding.Description += "The 'Timer' and 'Admin' Service Instances are critical for proper SP functionality. They are *not* to be confused with the 'Timer' and 'SP Admin' services within 'services.msc' console."
    $finding.Description += "'Services' in the console can be 'running' fine, but if these 'instances' are not Online, then the execution of one-time timer jobs will not function."
    $finding.Description += "This can prevent other service instances from 'provisioning' properly."
    $finding.ChildFindings.Add($timerFinding)
    $finding.ChildFindings.Add($adminFinding)

    return $finding
}


function Get-SPDiagnosticServiceAppInfo
{
    [cmdletbinding()]
    Param()
    $serviceApps = Get-SPServiceApplication | Select-Object DisplayName, TypeName, Id, Status
    $serviceAppFinding = New-DiagnosticFinding -Name "Service Applications" -InputObject $serviceApps -Format Table

    ## Dump out proxies as well
    $proxies = Get-SPServiceApplicationProxy | Select-Object DisplayName, TypeName, Id, Status
    $proxyFinding = New-DiagnosticFinding -Name "Service Application Proxies" -InputObject $proxies -Format Table

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
    $proxyGroupFinding = New-DiagnosticFinding -Name "Proxy Group Associations" -InputObject $proxyGroupObjects -Format Table

    $serviceAppFinding.ChildFindings.Add($proxyFinding)
    $serviceAppFinding.ChildFindings.Add($proxyGroupFinding)
    $serviceAppFinding.ChildFindings.Add((Get-SPDiagnosticsUserProfileFinding))

    $TempserviceAppPool =  get-SPServiceApplicationPool | Select-Object Id, DisplayName, ProcessAccountName
    $ServieAppPools = @()
    foreach ($ap in $TempserviceAppPool)
    {
        $Apo = new-object PSObject
        $apo | add-member -MemberType NoteProperty -Name "ID" -Value $ap.id
        $apo | add-member -MemberType NoteProperty -Name "DisplayName" -Value $ap.DisplayName
        $apo | add-member -MemberType NoteProperty -Name "ProcessAccountName" -Value $(Obfuscate $ap.ProcessAccountName "User")
        $ServieAppPools += $apo
    }

    $spServiceAppPoolFinding = New-DiagnosticFinding -Name "Service Application Pools" -InputObject $ServieAppPools -Format Table
    $serviceAppFinding.ChildFindings.add($spServiceAppPoolFinding)


    return $serviceAppFinding
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

            ##$field = $type.GetField("spsClaimProviderTypeValue", $flags)
            ##$adConnection_spsClaimProviderTypeValue = $field.GetValue($adConnection)

            ##$field = $type.GetField("spsClaimProviderIdValue", $flags)
            ##$adConnection_spsClaimProviderIdValue = $field.GetValue($adConnection)

            $syncConnections += [PSCustomObject]@{
                Name = $(Obfuscate $adConnection.DisplayName "syncConnection")
                Server = $(obfuscate $adConnection_server "DCserver")
                UseSSL = $adConnection_useSSL
                SelectedOUs = $(obfuscate $adConnection_OUs "SyncOU")
                UseDisabledFilter = $adConnection_useDisabledFilter
                LdapFilter = $(obfuscate $adConnection_ldapFilter "ldapfilter")
                #ClaimProviderType = $adConnection_spsClaimProviderTypeValue
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

$Script:ObfuscateList = @()
$Script:ObfuscateTypes= @()

Function Obfuscate ([string]$InputValue, [string]$type)
{
    if (!$Obfuscate)
    {
        return $Inputvalue
    } 
    elseif(([String]::IsNullOrEmpty($inputvalue)) -or ([string]::IsNullOrWhiteSpace($Inputvalue)))
    {
        return $Inputvalue
    }
    else 
    {
        #write-host $InputValue  $type
        if ($Script:ObfuscateTypes.Count -eq 0 -and $Script:ObfuscateList.Count -gt 0)
        {
            foreach ($pe in $Script:ObfuscateList)
            {
                $pt = $Script:ObfuscateTypes | Where-Object {$_.Type -eq $pe.Type.tolower()}
                if ($null -eq $pt)
                {
                    $PT = New-Object psobject
                    $pt | add-Member -membertype NoteProperty -Name "Type" -Value $pe.Type.ToLower()
                    $pt | Add-Member -membertype NoteProperty -Name "NextID" -value 2
                    $Script:ObfuscateTypes += $pt
                } else {
                    $pt.NextID = $pt.NextID + 1
                }
            }
        }

        $type = $type.ToLower()
        foreach ($pe in $Script:ObfuscateList)
        {
            if ($pe.Type -eq $type -and $pe.RealValue -eq $InputValue)
            {
                return $pe.Pseudo
            }
        }
        if (!($PseudoVal))
        {
            $NewPseudoVal = New-Object psobject
            $NewPseudoVal | add-member -MemberType NoteProperty -Name "RealValue" -Value $InputValue
            $NewPseudoVal | add-member -MemberType NoteProperty -Name "Type" -Value $Type

            foreach ($pt in $Script:ObfuscateTypes)
            {
                if ($pt.Type -eq $type)
                {
                    $pseudo = $type + $pt.NextID
                    $pt.NextID = $pt.NextID + 1
                    break
                }
            }
            if (!($pseudo))
            {
                $PT = New-Object psobject
                $pt | add-Member -membertype NoteProperty -Name "Type" -Value $Type
                $pt | Add-Member -membertype NoteProperty -Name "NextID" -value 2
                $Script:ObfuscateTypes += $pt
                $Pseudo = $type + "1"
            }
            $NewPseudoVal | add-member -MemberType NoteProperty -Name "Pseudo" -Value $Pseudo
            $Script:ObfuscateList += $NewPseudoVal
        }
    }
    return $Pseudo
}

#region ExecutionInfo
Function GetDBServerRoles 
{
    $DBServerRoles =@()

    $sqlQuery = " SELECT roles.name as Role FROM sys.server_role_members AS server_role_members `
        INNER JOIN sys.server_principals AS roles ON server_role_members.role_principal_id = roles.principal_id `
        INNER JOIN sys.server_principals AS members ON server_role_members.member_principal_id = members.principal_id `
        where members.name = '" + $env:USERDOMAIN + "\" + $env:USERNAME + "'"

    $configDb = Get-SPDatabase  | Where-Object{$_.TypeName -match "Configuration Database"}
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
    $execInfo | Add-Member -MemberType NoteProperty -Name Computer -Value (Obfuscate $env:COMPUTERNAME -type  "computer")
    $execInfo | Add-Member -MemberType NoteProperty -Name ServerRole -Value (get-spserver -Identity $env:Computername).Role

    $execInfo | Add-Member -MemberType NoteProperty -Name "DataCollection Start" $Script:RunStartTime
    $execInfo | Add-Member -MemberType NoteProperty -Name Time -Value (Get-Date)
    $execInfo | Add-Member -MemberType NoteProperty -Name UTCTime -Value ([DateTime]::UtcNow.ToString('u'))
    $CollectionTime = new-Timespan  -start $Script:RunStartTime -end (Get-Date)
    $execInfo | Add-Member -MemberType NoteProperty -Name "Sript Duration" -Value ( "$([int]$CollectionTime.TotalSeconds) seconds" )

    $execInfo | Add-Member -MemberType NoteProperty -Name User -Value (Obfuscate ($env:USERDNSDOMAIN + "\" + $env:USERNAME) -type "User")
    $execInfo | Add-Member -MemberType NoteProperty -Name DBServerRoles -Value (GetDBServerRoles)
    $execInfo | Add-Member -MemberType NoteProperty -Name FarmAdmin -Value (IsCurrentUserSPFarmAdmin)
    $execInfo | Add-Member -MemberType NoteProperty -Name Elevated -Value (isElevated)

    $ScriptExecutionFindings = New-DiagnosticFinding -Name "Script Execution Info" -InputObject $execInfo -Format List
 
    $execInfoParams = New-Object PsObject
    $execInfoParams | Add-Member -MemberType NoteProperty -Name PatchInfo -Value ($PatchInfo)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name Obfuscated -Value ($Obfuscate)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name UsageAndReporting -Value ($UsageAndReporting)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name SiteUrl -Value ($SiteUrl)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name SkipSearchHealthCheck -Value ($SkipSearchHealthCheck)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name TLS -Value ($TLS)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name Text -Value ($Text)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name SkipErrorCollection -Value ($SkipErrorCollection)
    $execInfoParams | Add-Member -MemberType NoteProperty -Name SkipDisclaimer -Value ($SkipDisclaimer)
 
    $ScriptExecutionParamsFindings = New-DiagnosticFinding -Name "Script Execution Parameters" -InputObject $execInfoParams -Format List
    $ScriptExecutionFindings.ChildFIndings.Add(($ScriptExecutionParamsFindings))
    return $ScriptExecutionFindings
}
#endregion

#endregion HelperFunctions

function Get-SPDiagnosticTimerJobHistoryFinding
{
    [cmdletbinding()]
    Param()
    $servers = Get-SPServer | Where-Object{$_.Role -ne "Invalid"}
    $warningRowCount = 2000000*$servers.Count
    $configDb = Get-SPDatabase  | Where-Object{$_.TypeName -match "Configuration Database"}
    $result = Invoke-SPSqlCommand -spDatabase $configDb -query "select count(1) from dbo.TimerJobHistory with(nolock)" -ErrorAction SilentlyContinue
    $rowCount = $result.Column1[0]

    $result2 = Invoke-SPSqlCommand -spDatabase $configDb -query "Select MIN(EndTime) as Oldest, MAX(EndTime) as Newest from TimerJobHistory with(nolock)" -ErrorAction SilentlyContinue

    $job = Get-SPTimerJob job-delete-job-history

    <#
    $finding.Description+=("<li>Job LastRunTime: {0}</li>" -f $job.LastRunTime)
    $finding.description+=("<li>Oldest record: {0}</li>" -f $result2.Oldest[0])
    $finding.description+=("<li>Newest record: {0}</li>" -f $result2.Newest[0])
    $finding.Description+=("<li>DaysToKeepHistory: {0}</li></ul>" -f $job.DaysToKeepHistory)
    #>

    $finding = New-DiagnosticFinding -Name "TimerJobHistory" -InputObject $null -Format List
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

    $objectCacheName = "Object Cache Users" + " ( " + $(Obfuscate $webapp.Url "url") + " ) "
	$ObjectCacheUserfinding = New-DiagnosticFinding -Name $objectCacheName -Description $null -InputObject $null -Format Table

	$ObjectCacheUsers=@()
	$PSR = new-object psobject
	$PSU = new-Object PSObject

	$webAppProperties = $webapp.Properties
	$webAppPolicies = $webapp.Policies

	$PSR | Add-Member -MemberType NoteProperty -Name "Name" -Value "PortalSuperReader"
	$PSR | Add-Member -MemberType NoteProperty -Name "WebAppProperty" -Value $(Obfuscate $webapp.Properties["portalsuperreaderaccount"] "user")
	$psr | Add-Member -MemberType NoteProperty -Name "DenyAll" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "DenyWrite" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "FullRead" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "FullControl" -Value $false
	$psr | Add-Member -MemberType NoteProperty -Name "Permissions Correct?" -value $false

	$PSU | Add-Member -MemberType NoteProperty -Name "Name" -Value "PortalSuperUser"
	$PSU | Add-Member -MemberType NoteProperty -Name "WebAppProperty" -Value $(Obfuscate $webapp.Properties["portalsuperuseraccount"] "user")
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
    $webApps = Get-SPWebApplication -IncludeCentralAdministration
    foreach($webApp in $webApps)
    {
         $webAppName = "Web Application: '" + $webApp.DisplayName + "' (" + $webApp.Url + ") || (DB Count: " + $webApp.ContentDatabases.Count + " | " + "Site Count: " + $webApp.Sites.Count + ")"

        #Remove  $_ -like "*throttle*" -or $_ -like "*max*" -or  because this is collected separate and returns objects
        #$webAppDetails = $WebApp | Select-Object ($webApp.PSObject.Properties.Name.Where({ $_ -like "ExternalUrlZone" -or $_ -like "UseExternalUrlZoneForAlerts" -or $_ -like "IncomingEmailServerAddress" -or $_ -like "OutboundMailServiceInstance" -or $_ -like "OutboundMailPort" -or $_ -like "OutboundMailEnableSsl" -or $_ -like "RecycleBinEnabled" -or $_ -like "RecycleBinCleanupEnabled" -or $_ -like "RecycleBinRetentionPeriod" -or $_ -like "SecondStageRecycleBinQuota" -or $_ -like "SharePoint2010WorkflowsEnabled" -or $_ -like "DisableCoauthoring"}) | Sort-Object)  -ErrorAction SilentlyContinue
        $webAppDetails = $WebApp | Select-Object ExternalUrlZone, UseExternalUrlZoneForAlerts, IncomingEmailServerAddress, @{N='OutboundMailServiceInstance'; E={$_.OutboundMailServiceInstance.Server.DisplayName}}, OutboundMailPort, OutboundMailEnableSsl, RecycleBinEnabled, RecycleBinCleanupEnabled, RecycleBinRetentionPeriod, SecondStageRecycleBinQuota, SharePoint2010WorkflowsEnabled, DisableCoauthoring | Sort-Object -ErrorAction SilentlyContinue
        $webAppDetails.OutboundMailServiceInstance = $(Obfuscate $webAppDetails.OutboundMailServiceInstance "outgoingmailserver")
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

        #Obfuscate
        $DisplayAAMs=@()
        foreach ($aam in $aams)
        {
            $DisplayAAM = new-object PSObject
            $DisplayAAM | Add-Member -MemberType NoteProperty -Name "Incoming Url" -Value $(Obfuscate $aam.IncomingUrl "url")
            $DisplayAAM | Add-Member -MemberType NoteProperty -Name "Zone" -Value $aam.Zone
            $DisplayAAM | Add-Member -MemberType NoteProperty -Name "PublicURL" -value $(Obfuscate $aam.PublicUrl "url")
            $DisplayAAMs += $DisplayAAM
        }
        $webAppName = "Web Application: '" + $(Obfuscate $webApp.DisplayName "webapp") + "' (" + $(Obfuscate $webApp.Url Url) + ") || (DB Count: " + $webApp.ContentDatabases.Count + " | " + "Site Count: " + $webApp.Sites.Count + ")"
        $webAppFinding = New-DiagnosticFinding -Name $webAppName -InputObject $DisplayAAMs -Format Table


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
                    $iisSettingName = "IIS Settings: " + " -- Zone: " + $aam.Zone + " | Url:  " + $(Obfuscate $aam.PublicUrl "url")
                    $iisSettingsFinding = New-DiagnosticFinding -Name $iisSettingName -InputObject $null -Format List
                    $iisSettingsObj = $iisSettings | Select-Object ServerComment, iispath, PreferredInstanceId, AuthenticationMode, MembershipProvider, RoleManager, AllowAnonymous, EnableClientIntegration, UseWindowsIntegratedAuthentication, UseBasicAuthentication,UseClaimsAuthentication,UseFormsClaimsAuthenticationProvider,UseTrustedClaimsAuthenticationProvider,UseWindowsClaimsAuthenticationProvider, DisableKerberos, ClaimsAuthenticationRedirectionUrl, ClientObjectModelRequiresUseRemoteAPIsPermission
                    $iisSettingsObj.iisPath = $(Obfuscate $IIsSettings.Path "iispath")
                    $iisSettingsObj.ClaimsAuthenticationRedirectionUrl = $(Obfuscate $IIsSettings.ClaimsAuthenticationRedirectionUrl "claimsredirectUrl")

                    # Check for debug flag
                    $compilationDebug = Confirm-DebugCompilationDisabled $iisSettingsObj.ServerComment

                    if([Bool]::TryParse($compilationDebug, [ref]$compilationDebug) -and $compilationDebug)
                    {
                        $iisSettingsFinding.WarningMessage += "Compilation Debug is True in the Web.Config. This will have performance repercussions. "
                        $iisSettingsFinding.Severity = "Warning"
                    }

                    $iisSettingsObj | Add-Member -MemberType NoteProperty -Name "Web.Config Compilation Debug" -Value $compilationDebug

                    $iisSettingsObj.ServerComment = $(Obfuscate $iisSettingsObj.ServerComment "ServerComment")
                    $iisSettingsFinding.InputObject = $iisSettingsObj

                    $iisBindingFinding = New-DiagnosticFinding -Name "IIS Bindings" -InputObject $null -Format List

                    $IISBindingsReport = @()
                    $Sbs = $iisSettings.ServerBindings                    
                    foreach ($sb in $Sbs)
                    {
                        $sbr = new-object PSObject
                        $sbr | Add-Member -MemberType NoteProperty -Name "path" -value $sb.Path # avoid double obfuscation $(obfuscate $sbr.Path "serverbindingpath")
                        $sbr | Add-Member -MemberType NoteProperty -Name "port" -value $sb.Port 
                        $sbr | Add-Member -MemberType NoteProperty -Name "hostheader" -value  $(obfuscate $sb.HostHeader "hostheader")
                        $IISBindingsReport += $sbr

                    }

                    $Sbs = $iisSettings.SecureBindings                    
                    foreach ($sb in $Sbs)
                    {
                        $sbr = new-object PSObject
                        $sbr | Add-Member -MemberType NoteProperty -Name "path" -value $sb.Path # avoid double obfuscation $(obfuscate $sbr.Path "serverbindingpath")
                        $sbr | Add-Member -MemberType NoteProperty -Name "port" -value $sb.Port 
                        $sbr | Add-Member -MemberType NoteProperty -Name "hostheader" -value  $(obfuscate $sb.HostHeader "hostheader")
                        if ($Script:Build -eq "SPSE")
                        {
                            $sbr | Add-Member -MemberType NoteProperty -Name "UseServerNameIndication" -value $sb.UseServerNameIndication 
                            $sbr | Add-Member -MemberType NoteProperty -Name "Certificate" -value $(Obfuscate $sb.Certificate "certificate")
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
		$dbInfo = $webApp.ContentDatabases | Select-Object Name, @{N='SiteCount'; E={$_.CurrentSiteCount}}, Id, Status, BuildVersion,  @{N='DB Server' ; E={$(Obfuscate $_.NormalizedDataSource "dbserver")}} ,@{N="DB Size(GB)"; E={$([string]([System.Math]::Round($_.DiskSizeRequired/1gb,2)))}}, IsReadOnly, IsAttachedToFarm, IsSqlAzure, PreferredTimerServerInstance, @{N='Rbs Enabled'; E={$_.RemoteBlobStorageSettings.Enabled}},  @{N='Rbs Provider'; E={$_.RemoteBlobStorageSettings.ActiveProviderName}}
        $cdbfinding = New-DiagnosticFinding -Name "Content Database(s) Information" -Severity Default -InputObject $dbInfo -Format Table
        $WebAppFinding.ChildFindings.Add($cdbfinding)
        $WebAppFinding.ChildFindings.Add((Get-SPWebAppApplicationPool $webapp))
        $WebAppFinding.ChildFindings.Add((Get-SPWebAppServiceAppProxiesFinding $webapp))
        $webAppFinding.ChildFindings.Add((Get-SPDiagnosticPeoplePickerSettings $webApp))
        $webAppFinding.ChildFindings.Add($WebAppPropertiesFinding)
        $webAppFinding.ChildFindings.Add($peoplePickerFindings)
        $webAppFinding.ChildFindings.Add((Get-SPDiagnosticsBlobCache $webApp))
        $WebAppFinding.ChildFindings.Add((Get-SPDiagnosticsWebAppChangeLogFinding $webApp))
        $WebAppFinding.ChildFindings.Add((Get-SPDiagnosticsMissingSTSHeader $webapp))
        $WebAppFinding.ChildFindings.Add((Get-SPDiagnosticWebAppObjectCacheUserFinding $webapp))
        $WebAppFinding.ChildFindings.Add((Get-SPDiagnosticsWebAppThrottlingFinding $webapp))
        
        ## Check if web app is missing root site collection
        $rootSite = Get-SPSite -Identity $webApp.Url -ErrorAction SilentlyContinue

        if(!$rootSite)
        {
            $webAppFinding.Severity = [SPDiagnostics.Severity]::Warning
            $webAppFinding.WarningMessage += "No root site collection present in web application."
            $webAppFinding.WarningMessage += "Web applications must have a site collection present at their root url."
            $webAppFinding.WarningMessage += "Please create a site collection at $(Obfuscate $($webApp.Url) "url")"
        }

        $rootsite.Close()
        $rootSite.Dispose()
        
        $webAppsFinding.ChildFindings.Add($webAppFinding)
    }
    
    return $webAppsFinding
}

function Get-SPWebAppApplicationPool ($webapp)
{
    $AppPoolInfo = New-Object PsObject @{
    "AppPool Name" = $(obfuscate $webapp.ApplicationPool.Name "apppoolname")
    "AppPool DisplayName" = $(Obfuscate $webapp.ApplicationPool.DisplayName "apppooldisplayname")
    "Status" = $webapp.ApplicationPool.Status
    "AppPool User"= $(obfuscate $webapp.ApplicationPool.Username "user")
    }
    return New-DiagnosticFinding -name "Application Pool" -severity default -InputObject $AppPoolInfo -Format List 
}

function Get-SPDiagnosticsAppPoolsFinding
{
    $AppPoolInfos = @()

    $webapps = Get-SPWebApplication
    foreach ($webapp in $webapps)
    {
        $AppPoolInfo = New-Object PsObject 
        $AppPoolInfo  | Add-Member -MemberType NoteProperty -name  "AppPool Name" -value $(Obfuscate $webapp.ApplicationPool.Name "apppoolname")
        $AppPoolInfo  | Add-Member -MemberType NoteProperty -name  "AppPool DisplayName" -value  $(Obfuscate $webapp.ApplicationPool.DisplayName "apppooldisplayname")
        $AppPoolInfo  | Add-Member -MemberType NoteProperty -name  "Status" -value  $webapp.ApplicationPool.Status
        $AppPoolInfo  | Add-Member -MemberType NoteProperty -name  "WebApplication" -value  $(Obfuscate $WebApp.Name "webapp")
        $AppPoolInfo  | Add-Member -MemberType NoteProperty -name  "AppPool User"-value  $(Obfuscate $webapp.ApplicationPool.Username "user")
        
        $AppPoolInfos += $AppPoolInfo
    }
    $AppPoolsFinding = New-DiagnosticFinding -name "Content Application Pools" -severity default -InputObject $AppPoolInfos -Format Table 

    $NumAppPools = ($appPools.AppPoolName | Sort-Object -unique).count

    if ($NumAppPools -gt 10)
    {
        $AppPoolsFinding.WarningMessage +="More than 10 application pools in the farm. Not more than 10 Appplication Pools should be hosted one 1 Web Frontend Server."
        if ($Script:Build -eq "2013")
        {
            $AppPoolsFinding.ReferenceLink +="https://learn.microsoft.com/en-us/SharePoint/install/software-boundaries-and-limits#web-server-and-application-server-limits"
        } else  {
            $AppPoolsFinding.ReferenceLink +="https://learn.microsoft.com/en-us/sharepoint/install/software-boundaries-limits-2019#sharepoint-server-limits"
        }
    }
    return $AppPoolsFinding
}

function Get-SPWebAppServiceAppProxiesFinding($webapp)
{
    # Service Application ProxyGroup and Proxies
    [string]$Proxies=""
    $ServiceProxy = New-Object PSObject
    #$serviceProxy | Add-Member -MemberType NoteProperty -name WebApp -Value $(Obfuscate $webapp.name "webapp")
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
    $IIS_Bindingfinding = New-DiagnosticFinding -Name "IIS Binding on IIS server $(obfuscate $env:COMPUTERNAME "computer")" -Severity Default -InputObject $null -Format Table

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
                        $bi | Add-Member -MemberType NoteProperty -name "IPAddress" -value $(obfuscate $ip "ipaddress")
                        $bi | Add-Member -MemberType NoteProperty -name "port" -value $(obfuscate $p "port")
                        $bi | Add-Member -MemberType NoteProperty -name "Hostname" -value $(obfuscate $u "url")
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
                            $IIS_Bindingfinding.WarningMessage += "In WebApplication  $(Obfuscate $($WebApp.Name) "webapp") in the $zone zone, the AAM '$(Obfuscate $aam.IncomingUrl "url")' does not exist as an IISBinding"
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
                            $IIS_Bindingfinding.WarningMessage += "In WebApplication $(Obfuscate $($WebApp.Name) "webapp") in the $Zone zone, the IIS Binding '$(obfuscate $($b.BindingInformation) "binding")' is not known in SharePoint as AAM`n"       
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
        -Name ("Change log Configuration ({0})" -f $(Obfuscate $WebApp.Url "url")) `
        -Severity Default `
        -InputObject $changeLogObject `
        -Format List
    
    if ($WebApp.ChangeLogExpirationEnabled -eq $false)
    {
        $ChangeLogFinding.WarningMessage += ("ChangeLog Expiration is not enabled for this web application. This can have an impact on database size. To enable change log expiration use the below PowerShell.")
        $ChangeLogFinding.WarningMessage += ("<div class=`"code`">`$webApp = Get-SPWebApplication -Identity `"{0}`"<br>`$webApp.ChangeLogExpirationEnabled = `$true<br>`$webApp.Update()</div>" -f $(Obfuscate $WebApp.Url "url"))
        $ChangeLogFinding.Severity = [SPDiagnostics.Severity]::Warning
    }
    if ($WebApp.ChangeLogRetentionPeriod.days -lt 14)
    {
        $ChangeLogFinding.WarningMessage += ("The change log in the databases for this web application is only kept for $($WebApp.ChangeLogRetentionPeriod.days) days. This can result in problems with alerts and incremental crawls. To change this use the below PowerShell to set to the desired timeframe (recommended minimum of 14 days).")
        $ChangeLogFinding.WarningMessage += ("<div class=`"code`">`$webApp = Get-SPWebApplication -Identity `"{0}`"<br>`$webApp.ChangeLogRetentionPeriod = New-TimeSpan -Days 30<br>`$webApp.Update()</div>" -f $(Obfuscate $WebApp.Url "url"))
        $ChangeLogFinding.Severity = [SPDiagnostics.Severity]::Warning
    }
    
    if($ChangeLogFinding.Severity -ge [SPDiagnostics.Severity]::Informational)
    {
        return $ChangeLogFinding
    }
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
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxItemsPerThrottledOperation (List View Threshold)" -Value $webApp.MaxItemsPerThrottledOperation
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxItemsPerThrottledOperationOverride (List View Threshold for auditors and administrators)" -Value $webApp.MaxItemsPerThrottledOperationOverride
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxItemsPerThrottledOperationWarningLevel" -Value $webApp.MaxItemsPerThrottledOperationWarningLevel
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "AllowOMCodeOverrideThrottleSettings" -Value $webApp.AllowOMCodeOverrideThrottleSettings
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "UnthrottledPrivilegedOperationWindowEnabled" -Value $webApp.UnthrottledPrivilegedOperationWindowEnabled
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "DailyStartUnthrottledPrivilegedOperationsHour" -Value $webApp.DailyStartUnthrottledPrivilegedOperationsHour
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "DailyStartUnthrottledPrivilegedOperationsMinute" -Value $webApp.DailyStartUnthrottledPrivilegedOperationsMinute
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "DailyUnthrottledPrivilegedOperationsDuration" -Value $webApp.DailyUnthrottledPrivilegedOperationsDuration
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "SyncSiteProvisioningThrottle" -Value $webApp.SyncSiteProvisioningThrottle
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxQueryLookupFields" -Value $webApp.MaxQueryLookupFields
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxListItemRowStorage" -Value $webApp.MaxListItemRowStorage

        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "AlertsMaximum" -Value $webApp.AlertsMaximum
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "AlertsMaximumQuerySet" -Value $webApp.AlertsMaximumQuerySet
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxSizePerCellStorageOperation" -Value $webApp.MaxSizePerCellStorageOperation
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxUniquePermScopesPerList" -Value $webApp.MaxUniquePermScopesPerList
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "CascadeDeleteMaximumItemLimit" -Value $webApp.CascadeDeleteMaximumItemLimit
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaximumFileSize" -Value $webApp.MaximumFileSize

        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxAuditLogTrimmingRetention" -Value $webApp.MaxAuditLogTrimmingRetention
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "UserDefinedWorkflowMaximumComplexity" -Value $webApp.UserDefinedWorkflowMaximumComplexity
        $WebAppThrottleSettings | Add-Member -MemberType NoteProperty -Name "MaxSizeForSelfServiceEvalSiteCreationMB" -Value $webApp.MaxSizeForSelfServiceEvalSiteCreationMB

        $WebAppThrottlingFinding = New-DiagnosticFinding -Name ("WebAppThrottling ({0})" -f $(Obfuscate $WebApp.Url "url"))  -InputObject $WebAppThrottleSettings -Format List

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
        
        $suts = new-object PSObject
        $suts | Add-Member -MemberType NoteProperty -Name "AppPoolConcurrentUpgradeSessionLimit" -Value $webapp.SiteUpgradeThrottleSettings.AppPoolConcurrentUpgradeSessionLimit
        $suts | Add-Member -MemberType NoteProperty -Name "UsageStorageLimit" -Value $webapp.SiteUpgradeThrottleSettings.UsageStorageLimit
        $suts | Add-Member -MemberType NoteProperty -Name "SubwebCountLimit" -Value $webapp.SiteUpgradeThrottleSettings.SubwebCountLimit
        $suts | Add-Member -MemberType NoteProperty -Name "Id" -Value $webapp.SiteUpgradeThrottleSettings.Id
        $suts | Add-Member -MemberType NoteProperty -Name "Status" -Value $webapp.SiteUpgradeThrottleSettings.Status
        $suts | Add-Member -MemberType NoteProperty -Name "DeploymentLocked" -Value $webapp.SiteUpgradeThrottleSettings.DeploymentLocked
        $SiteUpgradeThrottleSettingsFinding = New-DiagnosticFinding -Name "  Site Upgrade Throttling" -Severity Default -InputObject $suts -Format List
        $webAppThrottlingFinding.ChildFindings.Add(($SiteUpgradeThrottleSettingsFinding))

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
                $WebAppHTTPThrottlingFindingPerfs.Description += "HTTP Throttling Performance Counters are not default $($counterDefault[$pm.counter]) for counter '$($pm.Counter)' on server ' $(obfuscate $($env:COMPUTERNAME) "computer")'"
                $WebAppHTTPThrottlingFindingPerfs.Description += "This information is shown when SharePoint servers have a different number of CPUs. And the sever the script is running on has a different number of CPUs than the number of CPUs on the server the Web Application was originally created on."
                $WebAppHTTPThrottlingFindingPerfs.Severity = [SPDiagnostics.Severity]::Informational
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
        $webAppFinding = New-DiagnosticFinding -Name ("Web Config Modifications : {0}" -f $(Obfuscate $webApp.Url "url")) -InputObject $webAppMods -Format Table
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
    $MissingSTSHeaderFinding = New-DiagnosticFinding -name "SharePoint Team Sites Header" -severity default -input $null -Format Table 
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
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Server" -Value (Obfuscate $env:Computername "computer")
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "WebApplication" -Value $(Obfuscate $webapp.Name "webapp")
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "Zone" -Value $Zone
                            $SPTeamServicesHeaderValue | Add-Member -MemberType NoteProperty -Name "SiteName" -Value $(Obfuscate $WebSiteName "websitename")
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
                            $MissingSTSHeaderFinding.Description +="The Website $(obfuscate $webapp.Name "website") is not configured on server $(obfuscate $($env:Computername) "computer")"
                        }
                    }
                }
            }
            if ($headerMissing -and $SiteConfiguredOnThisServer)
            {
                $MissingSTSHeaderFinding.Severity = [SPDiagnostics.Severity]::Warning
                $MissingSTSHeaderFinding.WarningMessage +=("Missing IIS ResponseHeader 'MicrosoftSharePointTeamServices'")
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

function Get-SPDiagnosticsBlobCache ($webapp)
{
    #Blob cache settings in Web.config on local IIS 
    $BlobCachefindings = New-DiagnosticFinding -Name "BlobCache Settings" -Severity Default -InputObject $null -Format list
    if (!(IsElevated))
    {
        $BlobCachefindings.Description += "This data can only be collected when the Script is executed with 'Run as Administrator'"
    } else {

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
                            $BlobCachefinding = New-DiagnosticFinding -Name "BlobCache Setting - Web Application $(Obfuscate $($webapp.name) "webapp") - Zone: $Zone on server $(Obfuscate $env:COMPUTERNAME "computer")" -Severity Default -InputObject $bc -Format list

                            if ($bc.Enabled -eq "False")
                            {
                                $BlobCachefinding.Severity = [SPDiagnostics.Severity]::Informational
                                $BlobCachefinding.Description +="BlobCache not enabled for Web Application $(Obfuscate $($webapp.Name) "webapp") in Zone $Zone on server $(Obfuscate $env:COMPUTERNAME "computer"))."
                                $BlobCachefindings.Description += "A PowerShell script to manage the BlobCache Settings can be downloaded from https://github.com/rainerasbach/ManageBlobCache/blob/main/ManageBlobCache.ps1 "        
                            }

                            $BlobCachefindings.ChildFIndings.Add(($BlobCachefinding))
                        }
                    }
                }
            }
        } else {
            $BlobCachefindings.Description += "This data can't be collected on SharePoint Server 2013"
        }
    }
    return $BlobCachefindings
}
function Get-SPDiagnosticPeoplePickerSettings($webApp)
{
    $SearchActiveDirectoryDomains = [System.String]::Empty
    $DistributionListSearchDomains = [System.String]::Empty
    $ServiceAccountDirectoryPaths = [System.String]::Empty

    #Task 395  - expanding SearchActiveDirectoryDomains
#    foreach($key in $WebApp.PeoplePickerSettings.SearchActiveDirectoryDomains)
#    {
#        $SearchActiveDirectoryDomains += $key.DomainName + ", "
#    }
    foreach($value in $WebApp.PeoplePickerSettings.DistributionListSearchDomains)
    {
        $DistributionListSearchDomains += "'" + $value + "', "
    }
    foreach($value in $WebApp.PeoplePickerSettings.ServiceAccountDirectoryPaths)
    {
        $ServiceAccountDirectoryPaths += "'" + $value + "', "
    }

    $retObj = [PSCustomObject]@{
        #SearchActiveDirectoryDomains need to be expanded since there are properties for each.
        SearchActiveDirectoryDomains = $(obfuscate $SearchActiveDirectoryDomains "peoplepicker_addomains")
        ActiveDirectoryCustomQuery = $WebApp.PeoplePickerSettings.ActiveDirectoryCustomQuery
        ActiveDirectoryCustomFilter = $WebApp.PeoplePickerSettings.ActiveDirectoryCustomFilter
        OnlySearchWithinSiteCollection = $WebApp.PeoplePickerSettings.OnlySearchWithinSiteCollection
        PeopleEditorOnlyResolveWithinSiteCollection = $WebApp.PeoplePickerSettings.PeopleEditorOnlyResolveWithinSiteCollection
        DistributionListSearchDomains = $(Obfuscate $DistributionListSearchDomains "peoplepicker_dlsearchdomains")
        ActiveDirectorySearchTimeout = $WebApp.PeoplePickerSettings.ActiveDirectorySearchTimeout
        NoWindowsAccountsForNonWindowsAuthenticationMode = $WebApp.PeoplePickerSettings.NoWindowsAccountsForNonWindowsAuthenticationMode
        ServiceAccountDirectoryPaths = $(obfuscate $ServiceAccountDirectoryPaths "peoplepicker_serviceaccountdirectorypaths")
        ReferralChasingOption = $WebApp.PeoplePickerSettings.ReferralChasingOption
        ActiveDirectoryRestrictIsolatedNameLevel = $WebApp.PeoplePickerSettings.ActiveDirectoryRestrictIsolatedNameLevel
        NoUpnResolveWhenResolvingEmailAddress = $WebApp.PeoplePickerSettings.NoUpnResolveWhenResolvingEmailAddress
        #Hashtable that is not resolved in the table. If important it should be a separate child finding 
        UpgradedPersistedProperties = $WebApp.PeoplePickerSettings.UpgradedPersistedProperties
    }

    $peoplePickerFindings = New-DiagnosticFinding -Name "People Picker Settings" -Severity Default -InputObject $retObj -Format List
    Foreach($SADD in $WebApp.PeoplePickerSettings.SearchActiveDirectoryDomains)
    {
        $DN = $(Obfuscate $SADD.DomainName "peoplepicker_addomains")

        $SADDProps = [PSCustomObject] @{
            DomainName = $DN
            ShortDomainName = $(obfuscate $SADD.ShortDomainName "peoplepicker_addomains")
            LoginName = $(obfuscate $SADD.LoginName "peoplepicker_LoginName")
            CustomFilter = $(Obfuscate $SADD.CustomFilter "peoplepicker_customfilter")
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

    $finding = New-DiagnosticFinding `
        -Name "Side by Side Patching"  `
        -ReferenceLink "https://blog.stefan-gossner.com/2017/01/10/sharepoint-server-2016-patching-using-side-by-side-functionality-explained/" `
        -InputObject $retObj `
        -Format List
    if($sbsTokenIsCurrent -eq $false)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage = "SideBySideToken is not the current farm build, consider updating the side by side value to the current farm build or disabling side by side functionality."
    }

    return $finding
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
    $globalDeployServers = Get-SPServer | Where-Object{$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
    $wfeDeployServers = @()
    foreach($server in $globalDeployServers)
    {
        $webAppInstance = $server.ServiceInstances | Where-Object{$_.TypeName -match "Microsoft SharePoint Foundation Web Application"}
        if($webAppInstance.Status -eq [Microsoft.SharePoint.Administration.SPObjectStatus]::Online)
        {
            $wfeDeployServers+=$(Obfuscate $server "computer")
        }
    }

    $solutions = Get-SPSolution

    $farmSolutionsFinding = New-DiagnosticFinding `
        -Name "Farm Solutions ($($solutions.Count))" `
        -InputObject $null

    if($solutions.Count -eq 0)
    {
        $farmSolutionsFinding.Description += "No farm solutions present"
        return $farmSolutionsFinding
    }

    foreach($solution in $solutions)
    {
        #Obfuscate "LastOperationDetails" by omitting it since it is not possible to reliably obfuscate this clear text data
        if ($Obfuscate)
        {
            $Sol = $solution | Select-Object Farm, Name, Deployed, DeploymentSTate, SolutionFile,  `
                ContainsGlobalAssembly,ContainsCasPolicy,ContainsWebApplicationResource, SolutionId, IsWebPartPackage, LanguagePacks, `
                Added,LastOperationResult, JobStatus, JobExists, CanSelectForBackup, CanSelectForRestore, TypeName, `
                Displayname, id, Status, Parent, Version, CanBAckupRestoreAsConfiguration, `
                DiskSizeRequired,CanRenameOnrestore 

            $sol.name =$(Obfuscate $solution.Name "solutionName")
            $sol.SolutionFile = $(Obfuscate $solution.SolutionFile "solutionfile")
            $sol.Displayname = $(Obfuscate $solution.DisplayName "solutiondisplayname")

                # Do not include LastOperationDetails

        } 
        else 
        {
            $Sol = $solution | Select-Object Farm, Name, Deployed, DeploymentSTate, SolutionFile,  `
                ContainsGlobalAssembly,ContainsCasPolicy,ContainsWebApplicationResource, SolutionId, IsWebPartPackage, LanguagePacks, `
                Added,LastOperationResult, JobStatus, JobExists, CanSelectForBackup, CanSelectForRestore, TypeName, `
                Displayname, id, Status, Parent, Version, CanBAckupRestoreAsConfiguration, DiskSizeRequired,CanRenameOnrestore, LastOperationDetails
            }

        $solutionFinding = New-DiagnosticFinding `
            -Name ("Farm Solution: {0}" -f $(Obfuscate $solution.Name "spsolution")) `
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
                        $missingDeploymentServers+=$(Obfuscate $deployServer "computer")
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
                        $missingDeploymentServers+=$(Obfuscate $deployServer "computer")
                    }
                }
            }

            $missingServerStr = @()
            foreach($missingDeploymentServer in $missingDeploymentServers)
            {
                $missingServerNames +=$(Obfuscate $missingDeploymentServer.Name "computer")
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
                    $installCmd += $baseCmd + " -WebApplication `"" + $(obfuscate $webApp.Url "url") + "`" [-Force]" -join "<BR>"
                }
            }
            else
            {
                $installCmd += " [-Force]"
            }
            

            $solutionFinding.Severity = [SPDiagnostics.Severity]::Critical
            $solutionFinding.WarningMessage += ("Solution is not deployed to {0} server(s), incomplete solution deployment can cause issues. Please deploy this solutiont to the mentioned servers. To deploy this solution use the Install-SPSolution with the -Local switch on the server(s) where it is missing." -f $missingDeploymentServers.Count, $missingServerStr)
            $solutionFinding.WarningMessage += ("Missing on {0} server(s): {1}" -f $missingDeploymentServers.Count, [string]::Join(", ", $missingServerNames))
            $solutionFinding.ReferenceLink += "https://learn.microsoft.com/en-us/powershell/module/sharepoint-server/install-spsolution?view=sharepoint-server-ps"
            #$solutionFinding.WarningMessage += $installCmd
        }
        
        $deployedServerNames = @()
        foreach($deployedServer in $solution.DeployedServers)
        {
            $deployedServerNames += $(obfuscate $deployedServer.Name "computer")
        }
        $solutionFinding.Description += ("Deployed to {0} server(s): {1}" -f $solution.DeployedServers.Count, [string]::Join(", ", $deployedServerNames))

        $farmSolutionsFinding.ChildFindings.Add($solutionFinding)
    }
    return $farmSolutionsFinding
}

Function Get-SPDiagnosticsFarmFeaturesFinding
{

        $FeaturesFinding = New-DiagnosticFinding -Name "Features" -InputObject $null -Format List 

        $FarmFeatures = get-spfeature | select-Object Id, Displayname, SolutionID,CompatibilityLevel,Version,Scope | where-object {$_.scope -eq "Farm"}
        $FarmFeaturesFinding = New-DiagnosticFinding -Name "  Farm Features ($($FarmFeatures.Count))" -InputObject $FarmFeatures -Format Table 
        $FeaturesFinding.ChildFindings.Add(($FarmFeaturesFinding))

        $webAppFeatures = get-spfeature | select-Object Id, Displayname,SolutionID,CompatibilityLevel,Version,Scope | where-object {$_.scope -eq "webApplication"}
        $WebAppFeaturesFinding = New-DiagnosticFinding -Name "  WebApplication Features ($($webAppFeatures.Count))" -InputObject $webAppFeatures -Format Table 
        $FeaturesFinding.ChildFindings.Add(($WebAppFeaturesFinding))

        $SiteFeatures = get-spfeature | select-Object Id, Displayname,SolutionID,CompatibilityLevel,Version,Scope | where-object {$_.scope -eq "Site"}
        $SiteFeaturesFinding = New-DiagnosticFinding -Name "  Site Features ($($SiteFeatures.Count))" -InputObject $SiteFeatures -Format Table 
        $FeaturesFinding.ChildFindings.Add(($SiteFeaturesFinding))

        $WebFeatures = get-spfeature | select-Object Id, Displayname,SolutionID,CompatibilityLevel,Version,Scope | where-object {$_.scope -eq "Web"}
        $WebFeaturesFinding = New-DiagnosticFinding -Name "  Web Features ($($WebFeatures.Count))" -InputObject $WebFeatures -Format Table 
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
    $sss.Servername = $(Obfuscate $sss.Servername "server")
    
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
        $SSSFinding.WarningMessage+="In multiple SharePoint builds it is not possible to add a new server to a SharePoint farm when the name of the Secure Store Database contains a blank/space charater. It might be necessary to disable the Session State Service and enable it again with a new database having a name without a blank/space."
    }
    return $SSSFinding
}

#endregion

#region Auth

function Get-SPDiagnosticAuthFindings
{
    $authFindings = New-DiagnosticFinding -Name "Authentication" -Severity Default -InputObject $null
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsWebAppAuthSettingsFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPSecurityTokenServiceConfigFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPTrustedIdentityTokenIssuerFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPTrustedSecurityTokenIssuerFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticsSPClaimProviderFinding))
    $authFindings.ChildFindings.Add((Get-SPDiagnosticKerberosFindings)) 


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
                    WebApplication = $(Obfuscate $wa.DisplayName "webapp")
                    Zone = $zone
                    Url = $(Obfuscate $aam.IncomingUrl "url")
                    ClaimsAuthentication = $iisSettings.UseClaimsAuthentication
                    Kerberos = !$iisSettings.DisableKerberos
                    Anonymous =  $iisSettings.AllowAnonymous
                    LoginPage = $iisSettings.ClaimsAuthenticationRedirectionUrl
                    ClaimsAuthenticationProviders = [string]::Join(", ", $providers)
                }

                if($zone -eq "Default" -and !$iisSettings.UseWindowsIntegratedAuthentication)
                {
                    $noWindowsInDefaultZone = $true
                }

                $webAppAuthSettings+=$waAuthEntry
            }
        }
    }
    
    
    $finding = New-DiagnosticFinding -Name "Web application authentication providers" -Severity Default -InputObject $webAppAuthSettings -Format Table
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
    $stsFindingObj = $stsConfig | Select-Object -Property `
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
    
    $finding = New-DiagnosticFinding -Name "Security token service config" -ReferenceLink "https://joshroark.com/sharepoint-users-forced-to-re-authenticate-unexpectedly/" -InputObject $stsFindingObj -Format List

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
    $tipWFM = "https://techcommunity.microsoft.com/t5/microsoft-sharepoint-blog/wfm-certificate-renewal-process-for-sharepoint-2013-2016/ba-p/1332162"
    $tipwfm2 = "https://techcommunity.microsoft.com/t5/microsoft-sharepoint-blog/sharepoint-2013-2016-2019-how-to-replace-expired-workflow/ba-p/1148650"
    
    $Certinfo = $cert | select-object Subject, Thumbprint, NotBefore, NotAfter
    $certinfo.Subject = $(obfuscate $cert.Subject "certsubject")
    $certfinding = New-DiagnosticFinding -Name "$sname Certificate Information" -InputObject $Certinfo -Format Table
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
    foreach($tokenIssuer in $trustedIdentityTokenIssuers)
    {
        $tiProps = $tokenIssuer | Select-Object -Property `
            UseStateToRedirect,
            ProviderUri,
            ProviderSignOutUri,
            DefaultProviderRealm,
            ProviderRealms,
            HasClaimTypeInformation,
            ClaimProviderName,
            UseWReplyParameter,
            UseWHomeRealmParameter,
            GroupClaimType,
            RegisteredIssuerName,
            DefaultClientIdentifier,
            AuthorizationEndPointUri,
            TrustedLoginMethod,
            Scope,
            @{l="IdentityClaim";e={$_.ClaimTypeInformation.DisplayName}},
            Description,
            SigningCertificate,
            MetadataEndpoint,
            IsAutomaticallyUpdated,
            Name,
            DisplayName,
            Id,
            Status            
            
        $findingName = "Trusted Identity Provider: {0}" -f $(obfuscate $tokenIssuer.Name "tokenissuer")
        if($tokenIssuer.TrustedLoginMethod -eq "OpenIdConnect")
        {
            $findingName += " [OIDC]"
        }
        else
        {
            $findingName += " [SAML]"
        }
        
        if ($Obfuscate)
        {
            $tiProps.SigningCertificate="This information cannot be displayed in an obfuscated report"
        }

        $finding = New-DiagnosticFinding -Name $findingName -Severity Default -InputObject $tiProps -Format List
        $claimTypes = $tokenIssuer.ClaimTypeInformation | Select-Object DisplayName, InputClaimType, MappedClaimType, IsIdentityClaim
        $claimMappings = New-DiagnosticFinding -Name "Claim mappings" -InputObject $claimTypes -Format Table
        $cert = $tokenIssuer.SigningCertificate
        $finding.ChildFindings.Add($claimMappings)
        $finding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ($tokenIssuer.name) "TIP"))
        $TrustedIssuerFindings.ChildFindings.Add($finding)
        
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
        $Findings = New-DiagnosticFinding -Name "Trusted Security Token Issuers" -InputObject $null -Format Table
        foreach($tokenIssuer in $trustedSecurityTokenIssuers)
        {
             #Obfuscate
            $tokenIssuerReport = New-Object PSObject @{
                "IsSelfIssuer" = $tokenIssuer.IsSelfIssuer
                "NameId" = $tokenIssuer.NameId
                "RegisteredIssuerName" = $(Obfuscate $tokenIssuer.RegisteredIssuerName "tokenissuerName")
                "AuthorizationEndPointUri" = $(Obfuscate $tokenIssuer.AuthorizationEndPointUri "endpoint")
                "TokenEndPointUri" = $(obfuscate $tokenIssuer.TokenEndPointUri "endpoint")
                "DefaultClientIdentifier" = $tokenIssuer.DefaultClientIdentifier
                # "ScopedClientIdentifier" = $tokenIssuer.ScopedClientIdentifier #Dictionary, not displayed in table
                "IdentityClaimTypeInformation" = $tokenIssuer.IdentityClaimTypeInformation
                "Description" = $tokenIssuer.Description
                "SigningCertificate" = $tokenIssuer.SigningCertificate #Will be removed for obfuscated report
                "AdditionalSigningCertificates" = $tokenIssuer.AdditionalSigningCertificates
                "MetadataEndPoint" = $(Obfuscate $tokenIssuer.MetadataEndPoint "endpoint")
                "IsAutomaticallyUpdated" = $tokenIssuer.IsAutomaticallyUpdated
                "Name" = $(Obfuscate $tokenIssuer.Name "tokenissuer")
                "TypeName" = $tokenIssuer.TypeName
                "DisplayName" = $(Obfuscate $tokenIssuer.DisplayName "tokenissuer")
                "Id" = $tokenIssuer.Id
                "Status" = $tokenIssuer.Status
                "Parent" = $tokenIssuer.Parent
                "Version" = $tokenIssuer.Version
                "DeploymentLocked" = $tokenIssuer.DeploymentLocked
                # "Properties" = $tokenIssuer.Properties #Hashtable
                "Farm" = $(obfuscate $tokenIssuer.Farm "spfarm")
                # "UpgradedPersistedProperties" = $tokenIssuer.UpgradedPersistedProperties #hashable
            }
            if ($Obfuscate)
            {
                $tokenIssuerReport.SigningCertificate ="This information cannot be displayed in an obfuscated report."
            }

            $tokenIssuerFinding = New-DiagnosticFinding -Name $tokenIssuer.Name -InputObject $tokenIssuerReport -Format List
            
            #check Cert
            $cert = $tokenIssuer.SigningCertificate
            if ($tokenIssuer.Name -eq "00000005-0000-0000-c000-000000000000")
            {
                $tokenIssuerFinding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ( $(Obfuscate $tokenIssuer.Name "tokenissuer")) "WFM"))
            } else {
                $tokenIssuerFinding.ChildFindings.Add((Get-SPDiagnosticFindingCertInfo $cert ( $(Obfuscate $tokenIssuer.Name "tokenissuer")) ""))
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
    return $finding
}


#endregion 

#region Kerberos

$Script:missingAES=$false
Function Get-SPDiagnosticKerberosFindings
{

    $KerberosFindings = New-DiagnosticFinding -Name "Kerberos configuration" -InputObject $null -Format List
    
    if (!(IsElevated))
    {
        $KerberosFindings.Description += "Kerberos Diagnostis can only be executed when the script is executed with 'Run as Administrator'."

    } else {

        $KerberosFindings.Description +="This information is also provided when the SharePoint farm does not use Kerberos Authentication."
        $KerberosFindings.ChildFindings.Add((ValidateSQLServiceAccounts))
        $KerberosFindings.ChildFindings.Add((ValidateSPAppPoolAccounts))

        #if ($KerberosFindings.WarningMessage)
        #{
        #    $KerberosFindings.WarningMessage ="Run the following command as Domain Administrator to correct the Kerberos configuration for SharePoint and SQL Server<BR><BR>" +  $KerberosFindings.WarningMessage
        #}

        if ($Script:missingAES)
        {
            $KerberosFindings.Severity = = [SPDiagnostics.Severity]::Warning
            $Kerberosfindings.referenceLink += "https://learn.microsoft.com/en-us/sharepoint/troubleshoot/security/configuration-to-support-kerberos-aes-encryption"
            $Kerberosfindings.WarningMessage += "Since the release of the November 2022 Security Updates Windows enforces AES128 or AES256 encryption of Kerberos tickets.`
                This must be explicitely allowed for each account that authenticates with Kerberos."
            $Kerberosfindings.WarningMessage += "Run the following commands as Domain administrator to create the required Service Principle names and/or enable AES128 or AES256 encryption for Kerberos tickets."
    #            It is possible that no user can access SQL server when this change is enforced via policy and AES encryption is not enable for the SQL service accounts."
        }
    }
    return $KerberosFindings
}


#region AppPool AdHelper Functions
Function GetAdUserEntry($samaccountName)
{
    $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
    #$search.filter = "(servicePrincipalName=*)"
    $search.filter = "(samAccountName=$samaccountName)"
    $result = $search.FindOne()
    $userEntry = $result.GetDirectoryEntry()
    return $userEntry
}
    
Function GetSPNsForAccount($Userobj,$SPNType)
{
    [string[]]$spns= @()
    if ($userObj.ServicePrincipalName)
    {
        foreach($SPN in $userObj.servicePrincipalName)
        {
            if ($SPN.StartsWith($SPNType))
            {
                $spns += $SPN
            }
        }
    }
    return $spns
}

Function ValidateAESForAccount($SamAccountName, $aesType)
{
    $AES_128 = 0x8
    $AES_256 = 0x10
    $userobj = GetAdUserEntry $samAccountName

    if ($userobj)
    {
        $EncryptionTypes=$userobj.properties.Item('msds-supportedencryptiontypes')[0]
         if (($aesType -eq 128) -and ($EncryptionTypes -band $AES_128))
        {
            return $true
        }
        elseif (($aestype -eq 256) -and ($EncryptionTypes -band $AES_256))
        {
            return $true
        } 
        elseif (($aestype -eq "both") -and ($EncryptionTypes -band $AES_256) -and ($EncryptionTypes -band $AES_128))
        {
            return $true
        } 
        elseif (($aestype -eq "one") -and (($EncryptionTypes -band $AES_256) -or ($EncryptionTypes -band $AES_128)))
        {
            return $true
        } 
    } else {
        $Kerberosfindings.WarningMessage +=  "Cannot find user: $SamAccountName"
    }
    return $false
}

#endregion Ad Helper Functions

Function ValidateServiceAccount($samAccountName,$SPNType=$null, $ServerName )
{
    $AccountKerberosInfos= @()

    $UserEntry = GetAdUserEntry $samAccountName
    if ($UserEntry)
    {
        if ($spnType) 
        {
            $spns = GetSPNsForAccount -userobj $UserEntry -SPNType $SPNType
            if ($spns)
            {
                foreach ($spn in $spns)
                {
                    $AccountKerberosInfo=New-Object PSObject
                    $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name Account -Value $(Obfuscate $samAccountName "samaccountname")
                    $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name SPN  -Value $(Obfuscate $spn  "spn")

                    $aes128=ValidateAESForAccount -SamAccountName $samAccountName -aesType 128
                    $aes256=ValidateAESForAccount -SamAccountName $samAccountName -aesType 256

                    $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name AES128  -Value $aes128
                    $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name AES256  -Value $aes256
                    $AccountKerberosInfos+=$AccountKerberosInfo
                }
            } else {
                $AccountKerberosInfo=New-Object PSObject
                $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name Account -Value $(Obfuscate $samAccountName "samaccountname")
                $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name SPN  -Value "N/A"

                $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name AES128  -Value "N/A"
                $AccountKerberosInfo | Add-Member -MemberType NoteProperty -Name AES256  -Value "N/A"
                $AccountKerberosInfos+=$AccountKerberosInfo

                $SQLKerberosfindings.WarningMessage += "Missing $SPNType Service Principle name for account $(Obfuscate $samaccountname "SamAccountName")"
                if ($ServerName)
                {
                    $SQLKerberosfindings.WarningMessage += "Run the following command as Domain Administrator: SetSPN -s $SPNType/$(Obfuscate $ServerName "computer") $(Obfuscate $SamAccountName "SamAccountName")"
                    $Kerberosfindings.WarningMessage += "SetSPN -s $SPNType/$(Obfuscate $ServerName "computer") $(Obfuscate $SamAccountName "SamAccountName")"
                }
            }
        }
    } else {
        $SQLKerberosfindings.WarningMessage +=  "Can't find account $samaccountname in Active Directory"
    }
    return $AccountKerberosInfos
}

Function ValidateIISBindings($IISBindings, $WebApp)
{
    #Get URL from Binding
    foreach ($b in $IISBindings)
    {
        if ($b.Protocol -match "http")
        {
            $bx = $b.Protocol
            $targetSPN = "HTTP/"
            $u= $b.bindingInformation.split(':')[2]
            if ([String]::IsNullOrEmpty($u)) {$u = $env:COMPUTERNAME}
            $bx = $b.Protocol +"://" + $u
            $targetSPN +=$u
            $p =$b.bindingInformation.split(':')[1]
            if (!($p -eq "80" -or $p -eq "443"))
            {
                $bx += ":" + $p
                $TargetSPN += ":" + $p
            }

            $SamAccountName=$WebApp.ApplicationPool.Username.split('\')[1]

            if (!(ValidateSPNForURLZone -samAccountName $SamAccountName  -targetSPN $targetSPN))
            {
                $SPKerberosfindings.WarningMessage +=  "Missing SPN for Account $(Obfuscate $SamAccountName "samaccountname"): $(Obfuscate $targetSPN "spn") " 
                $SPKerberosfindings.WarningMessage +=  "Run the following command as Domain Administrator: `
                  SetSPN -s $(Obfuscate $targetSPN "spn") $(Obfuscate $SamAccountName "samaccountname")"
                $Kerberosfindings.WarningMessage +="SetSPN -s $(Obfuscate $targetSPN "spn") $(Obfuscate $SamAccountName "samaccountname")"
            } else {
                # Write-Host "Found SPN $TargetSPN for Account $samAccountName for Zone $zone of WebApplication $($webApp.Name) " -f Green
            }
        }
    }
}
Function ValidateSPNForURLZone($samAccountName,$targetSPN)
{
    $UserEntry = GetAdUserEntry $samAccountName
    if ($UserEntry)
    {
        $spns = GetSPNsForAccount -userobj $UserEntry -SPNType HTTP
        if ($spns)
        {
            foreach ($spn in $spns)
            {
                if ($spn -eq $targetSPN)
                {
                    return $true
                }    
            }
        }
    }
    return $false
}

Function ValidateSPAppPoolAccounts()
{
    if ($Script:Build -ne "2013")  #Windows Server 2012 R2 does not have Get-IISSite
    {
        $SPKerberosfindings = New-DiagnosticFinding -Name "SharePoint AppPool Accounts" -InputObject $null -Format Table    
        
        $SPAppPoolAccounts=@()

        # Add WebApp Pool Acounts when at least one zone is using Kerberos    
        foreach ($WebApp in  (Get-SPWebApplication -IncludeCentralAdministration ))
        {
            foreach($zone in [enum]::GetNames("Microsoft.SharePoint.Administration.SPUrlZone"))
            {
                $iisSettings = $WebApp.IisSettings[$zone]
                if($null -ne $iisSettings)
                {
                    if (!($WebApp.IisSettings[$zone].DisableKerberos))
                    {
                        $SPAppPoolAccounts+= $WebApp.ApplicationPool.Username
                        $IISBindings = (Get-IISSite  $iisSettings.ServerComment).Bindings

                        ValidateIISBindings -IISBindings $IISBindings -WebApp $WebApp
                    }
                }
            }
        }

        <# RainerA: Omit SP Service Application Pool accounts for now because we don't now if they are using Kerberos in the first place.
        ValidateIISBindings  -IISBindings ( Get-IISSite "SharePoint Web Services" ).Bindings -WebApp $webapp

        # Get Service AppPool Accounts
        $SpServiceAppPoolAccounts=(get-SPServiceApplicationPool).ProcessAccountName

        # make accounts unique
        $SpServiceAppPoolAccounts = $SpServiceAppPoolAccounts | Sort-Object | Get-unique
        

        $SPAppPoolAccounts += $SpServiceAppPoolAccounts | Sort-Object | Get-unique
        #>

        if ($SpAppPoolAccounts.Count -eq 0)
        {
             $SPKerberosfindings.Description ="SharePoint is not using Kerberos Authentication"
        } 
        else
        {
            $SPAppPoolAccounts = $SPAppPoolAccounts | Sort-Object | Get-unique

            # Check if AES 128 / AES 256 is enabled
            foreach ($SamAccountName in $SPAppPoolAccounts)
            {
                $SamAccountName = $SamAccountName.split('\')[1]
                if (!(ValidateAESForAccount -SamAccountName $SamAccountName -aesType both))
                {
                    $SPKerberosfindings.WarningMessage +=  "$(Obfuscate $($SamAccountName) "samaccountname") is not configured for AES 128 or AES 256 encryption of Kerberos Tickets"
                    $SPKerberosfindings.WarningMessage +=  "Run the following command on a Domain controller as Domain Admin:  `
                      set-aduser $(Obfuscate $($SamAccountName) "samAccountName") -replace @{'msds-supportedencryptiontypes'=24}" 
                    $Kerberosfindings.WarningMessage +=  "set-aduser $(Obfuscate $($SamAccountName) "samAccountName")  -replace @{'msds-supportedencryptiontypes'=24}"
                    $Script:missingAES=$true
                }
            }
        }

        return $SPKerberosfindings
    } # -ne 2013
}

Function ValidateSQLServiceAccounts()
{
    $SQLKerberosfindings = New-DiagnosticFinding -Name "SQL Service Accounts" -InputObject $null -Format Table    
    $SQLAccountsKerberosInfos= @()
    [string[]]$DBServers=@()
    [string[]]$SQLServiceAccounts=@()

    $adbServers = (((Get-SPDatabase).server) | ForEach-Object {$_.address})  | Sort-Object | Get-Unique

    # Content DB server names
    $DBServers = (Get-SPContentDatabase).server | Sort-Object | Get-Unique
    $DBServers += $adbServers
    $DBServers = $DBServers | Sort-Object | Get-Unique

    # Get SQL Service Accounts
    foreach ($dbServer in $DBServers)
    {
        $SPDBs = (get-SPDatabase  | Where-Object {$_.server.name -eq $dbserver})
        if ($SPDBs)
        {
            $SPDB = $SPDBs[0]
            $result = Invoke-SPSqlCommand -spDatabase $spdb -query "SELECT service_account FROM sys.dm_server_services with(nolock) where filename like '%sqlservr.exe%'" -ErrorAction SilentlyContinue
            $result | ForEach-Object {$SQLServiceAccounts += $_[0]}

            $SQLServiceAccounts =  $SQLServiceAccounts | Sort-Object | Get-Unique
            $SQLWithMachineAccount=$false

            foreach ($sa in $SQLServiceAccounts)
            {
                $MissingAESForAccount=$false
                if ($sa.split('\')[0] -eq "NT Service")
                {
                    $SQLWithMachineAccount=$true
                } else {
                    try 
                    {
                        $ServerFQDN = ([System.Net.Dns]::GetHostByName($DBServer)).Hostname
                        $SamAccountName = $sa.split('\')[1]
                        $SQLAccountsKerberosInfos += ValidateServiceAccount -samAccountName $SamAccountName -SPNType MSSQLSvc -ServerName  $ServerFQDN 
                    } catch {
                        $result = Invoke-SPSqlCommand -spDatabase $spdb -query "SELECT @@Servername" -ErrorAction SilentlyContinue
                        $ServerFQDN = ([System.Net.Dns]::GetHostByName($result[0])).Hostname 
                        $SamAccountName = $sa.split('\')[1]
                        $SQLAccountsKerberosInfos += ValidateServiceAccount -samAccountName $SamAccountName -SPNType MSSQLSvc -ServerName  $ServerFQDN 
                    }
                }
            }

            foreach ($ai in $SQLAccountsKerberosInfos)
            {
                if (!($ai.Aes128 -or $ai.Aes256))
                {
                    $MissingAESForAccount=$true
                    $Script:missingAES=$true
                }
            }
            if ($MissingAESForAccount)
            {
                $SQLKerberosfindings.WarningMessage +="$($ai.Account) is not configured for AES encryption of Kerberos Tickets" #$ai.Account is already obfuscated
                $SQLKerberosfindings.WarningMessage +=  "Run the following command on a Domain controller as Domain Admin:  `
                  set-aduser $($ai.Account) -replace @{'msds-supportedencryptiontypes'=24}"
                $Kerberosfindings.WarningMessage +=  "set-aduser $($ai.Account) -replace @{'msds-supportedencryptiontypes'=24}"
                $Script:missingAES=$true
            }
        }
        if($SQLWithMachineAccount)
        {
            $SQLKerberosfindings.WarningMessage +=  "SQL Server is running with machine accounts, Kerberos Authentication is not possible with these accounts"
            $SQLKerberosfindings.WarningMessage +=  "SQL Server is running with machine accounts, No redundent configuration of SQL server possible with this account setup."
        }

    }

    $SQLKerberosfindings.InputObject = $SQLAccountsKerberosInfos
    return $SQLKerberosfindings   
}
#endregion Kerberos

#region SearchTopologyBoundaries
Function Get-SPDiagnosticsSearchTopologyLimits
{

    $AllSearchComponents = @()

    $ssas=Get-SPEnterpriseSearchServiceApplication
    foreach ($ssa in $ssas)
    {
        $topo = Get-SPEnterpriseSearchTopology -Active -SearchApplication $ssa
        $comps = Get-SPEnterpriseSearchComponent -SearchTopology $topo
        foreach ($comp in $comps)
        {
            $SearchComponent = New-Object psobject
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "SSA" $(obfuscate $ssa.Name "SearchServiceApplication")
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "Server" $(Obfuscate $comp.ServerName "computer")
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "ComponentName" $comp.Name
            $SearchComponent | Add-Member -MemberType NoteProperty -Name "ComponentType" $comp.GetType().Name
            $AllSearchComponents +=$SearchComponent
        }
    }

    $searchTopologyLimitsFindings = New-DiagnosticFinding -Name "Search Topology Limits" -Severity Default -InputObject $AllSearchComponents -Format Table

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
    } else {
        $searchTopologyLimitsFindings.Description +="The number of search components per server is within supported boundaries."
    }
    $searchTopologyLimitsFindings.ReferenceLink += "https://learn.microsoft.com/en-us/sharepoint/install/software-boundaries-limits-2019#search-topology-limits"
    return $searchTopologyLimitsFindings
}
#endregion


#region search

function Get-SPDiagnosticSearchFindings
{

    $SSAs = Get-SPEnterpriseSearchServiceApplication  | Sort-Object Name 

    $searchFindings = New-DiagnosticFinding -Name "Search Information" -Severity Default -InputObject $null
    if($null -eq $SSAs -or $SSAs.Count -eq 0)
    {
        $searchFindings.Description+="There are no SSA's in this farm"
        return $searchFindings
    }

    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSASearchService))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSearchTopologyLimits))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSASearchInstances -searchApps $SSAs))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsSSPJobInstances -searchApps $SSAs))
    $searchFindings.ChildFindings.Add((Get-SPDiagnosticsCheckForRoot -searchApps $SSAs))
    $ssaCount = 0
    foreach($ssa in $SSAs)
    {
        $ssaCount++
        $crawlAccount = (New-Object Microsoft.Office.Server.Search.Administration.Content $ssa).DefaultGatheringAccount
        #$ssaName = "SSA " + $ssaCount + ":  " + "<span style='color:#0072c6'>'" + $ssa.Name +"'</span>" + " || <span style='color:gray'>CrawlAccount: " + $crawlAccount + "</span>"
        $ssaName = "SSA " + $ssaCount + ":  " + $(Obfuscate $ssa.Name  "searchserviceapplication")+ " || CrawlAccount: " + $(Obfuscate $crawlAccount "user")
        $ssaFindings = New-DiagnosticFinding -Name $ssaName -Severity Default -InputObject $null   # this could be moved into the Get-SPDiagnosticsSSAObject func
        #$ssaFindings.Description+=("CrawlAccount: " + $(Obfuscate $crawlAccount "username")
        if($ssa.NeedsUpgradeIncludeChildren -eq $true -or $ssa.NeedsUpgrade -eq $true)
        {
            $ssaName = $ssa.DisplayName
            $ssaFindings.Severity = [SPDiagnostics.Severity]::Warning
            $ssaFindings.WarningMessage+="<li style='color:red'>We have detected that the 'SSA' needs to be upgraded!</li>"
            $ssaFindings.WarningMessage+="<li>In order to perform this action, please run the following command: </li>" 
            $ssaFindings.WarningMessage+="<ul style='color:#0072c6'><div class=`"code`">`Upgrade-SPEnterpriseSearchServiceApplication '$ssaName'</div></ul>"
        }
        if($ssa.CloudIndex -eq $True)
        {
            $spoProxy = Get-SPServiceApplicationProxy | Where-Object{$_.TypeName -match "SharePoint Online Application Principal Management Service"}
            $spoTenantUri = $spoProxy.OnlineTenantUri.AbsoluteUri
            $ssaFindings.Description+="<li style='color:#063970'>We have detected this is a Cloud SSA.</li>"
            $ssaFindings.Description+="<li style='color:#063970'>The SPO Tenant is: </li>"
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
    #Todo: Remove this object
    #Todo: Obfuscate SearchCenterUrl, ActiveTopology
    if ($Obfuscate)
    {
        return $null
    } 
    else
    {
        $ssaObjectInfo = $searchApplication | select-object DisplayName, Id, ApplicationName, ApplicationPool, SearchCenterUrl, CloudIndex, DiscoveryMaxRowLimit, AlertsEnabled, AllowPartialResults, CrawlLogCleanupIntervalInDays, DefaultQueryTimeout, MaxQueryTimeout, IndexedSchemaQueryTimeout, IisVirtualDirectoryPath, QuerySuggestionsEnabled, PersonalQuerySuggestionsEnabled, QueryLoggingEnabled, @{N='QLogEnabled'; E={$_.QueryLogSettings.QLogEnabled}}, @{N='QLogCleanupDays'; E={$_.QueryLogSettings.CleanupDays}}, ScsAuthRealm, ScsFlows, HybridTenantMaxQuota, HybridTenantMinQuota, HybridTenantQuotaBufferPercent, Status
        $findings = New-DiagnosticFinding -Name "SSA Object Info" -InputObject $ssaObjectInfo -format list
        return $findings
    }
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
            $finding.Description+=("<ul style='color:#0072c6'><div class=`"code`">`New-SPEnterpriseSearchServiceApplicationProxy -Name '$ssaDisplayName' -SearchApplication '$ssaDisplayName'<br></div></ul>")
            return $finding
        }
        if($ssaPropertiesProperty -ne "UnPartitioned")
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage +="This SSA, $ssaDisplayName, is not set to 'UnPartitioned'."
            $finding.Description += (" If the SSA is partitioned ( this would have been done at creation time ), URLMapping does not take place and will break contextual searches on Web Apps that have been extended to another zone. ( This can impact queries on extended zone URLs, among other search functions) ")
            $finding.Description += 'In order to correct this, either recreate the SSA or set the SSA to "IgnoreTenatization" with the following: '
            $finding.Description += "<ul><div style='color:#0072c6' class=`"code`">`$ssa = Get-SPEnterpriseSearchServiceApplication '$ssaDisplayName'<br>`$ssa.SetProperty('IgnoreTenantization', 1)<br>`$ssa.Update()</div><br/></ul>"
        }
        if($ssaProxyPropertiesProperty -ne "UnPartitioned")
        {
            $finding.Severity = [SPDiagnostics.Severity]::Warning
            $finding.WarningMessage +="The Search Proxy for this SSA is not set to 'UnPartitioned'. "
            $ssaProxyName = $ssaProxy.DisplayName
            $finding.Description +=(" If the proxy is partitioned ( this would have been done at creation time ), URLMapping does not take place and will break contextual searches on Web Apps that have been extended to another zone Property for 'searchProxy.Properties' is set to:  '$ssaProxyPropertiesProperty' ( This can impact queries on extended zone URLs, among other search functions) ")
            $finding.Description += 'In order to correct this, Is is recommended to delete the SSA Proxy and recreate it with the following: '
            $finding.Description += "<ul><div style='color:#0072c6' class=`"code`">`Remove-SPEnterpriseSearchServiceApplicationProxy '$ssaProxyName' -Confirm:$false<br>`New-SPEnterpriseSearchServiceApplicationProxy -Name '$ssaDisplayName' -SearchApplication '$ssaDisplayName'<br></div></ul>"
        }
        
        else
        {
            $finding.Description+=("<li>SSA Properties:  <span style='color:#0072c6'>{0}</span></li>" -f $ssaPropertiesProperty)
            $finding.Description+=("<li>SSA Proxy Properties:  <span style='color:#0072c6'>{0}</span></li>" -f $ssaProxyPropertiesProperty)
        }   
    return $finding
    } else  {
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
    $ssaJobs = Get-SPTimerJob | Where-Object{$_.Name -match $ssaJobNames} | Select-Object DisplayName, Id, Status, LastRunTime, Schedule
    $finding = New-DiagnosticFinding -Name "SSA Related Timer Jobs" -InputObject $ssaJobs -format Table
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
    $finding.Description+=("<ul style='color:#0072c6'><div class=`"code`">`$ssa = Get-SPEnterpriseSearchServiceApplication '$ssaDispName'<br>`$ssa.Status = 'Disabled'<br>`$ssa.Update()<br>`$ssa.Provision()</div></ul>")
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
    #Obfuscate
    $AdminComps = new-object PSObject
    $AdminComps | Add-Member -MemberType NoteProperty -name "Name" -Value $LAC.Name
    $AdminComps | Add-Member -MemberType NoteProperty -name "IndexLocation" -Value $LAC.IndexLocation
    $AdminComps | Add-Member -MemberType NoteProperty -name "Initialized" -Value $LAC.Initialized
    $AdminComps | Add-Member -MemberType NoteProperty -name "ServerName" -Value $(Obfuscate $LAC.Servername "computer")
    $AdminComps | Add-Member -MemberType NoteProperty -name "ServerId" -Value $LAC.ServerID
    $AdminComps | Add-Member -MemberType NoteProperty -name "Server" -Value $LAC.Server

    $finding = New-DiagnosticFinding -Name "Admin Component Info" -InputObject $null -format list
    if($null -eq $searchApplication.SystemManagerLocations)
    {
        $finding.Severity = [SPDiagnostics.Severity]::Critical
        $finding.WarningMessage+="<li>We detect the 'System Manager Location' is empty. The SSA will be broken when this is the case. </li>"
    }
    else
    {
        $sysManagerLocation = $searchApplication.SystemManagerLocations.AbsoluteUri
        $finding.Description+="<li>The 'SystemManagerLocations' is associated with the 'non-legacy' piece of the AdminComponent</li>"
        $finding.Description+="<li>This value should never be empty and the serverName *should* match the 'Legacy Admin Component' below</li>"
        #$finding.Description+="<ul>`$ssa.SystemManagerLocations = " + "<span style='color:#0072c6'>" + $sysManagerLocation + "</span></ul><br/>"
        #Obfuscate
        $server = $sysManagerLocation.ToString().split('/')[2].split(':')[0]
        $ObfuscateServer = Obfuscate $server "computer"
        $sysManagerLocation1=  $sysManagerLocation.ToString().replace($server, $ObfuscateServer)
        $finding.Description+="<ul>`$ssa.SystemManagerLocations = " + "<span style='color:#0072c6'>" + $sysManagerLocation1 + "</span></ul><br/>"
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
                $finding.WarningMessage+='<li>In the ULS on the crawl servers, The following HResult may be observed: 0x80131537.</li>'
                $finding.WarningMessage+='<li>The current property is set to: </li>'
                $finding.WarningMessage+='<ul style="color:darkblue">' + "  {0}" -f $row.Replace(',','<BR>') + '</ul>'
                $finding.WarningMessage+='<li>It should appear like:  </li>'
                $finding.WarningMessage+='<ul style="color:darkblue">' + "  {0}" -f $row.Replace(',','<BR>').replace("net.tcp:///", "net.tcp://servername/") + '</ul>'
                $finding.WarningMessage+='<li>To correct this, remove the incorrectly registered Content Processing Component(s) from the search topology and add them back by a PowerShell script.  </li>'
            }
            else
            {
                $finding.Description+=("<li>" + "  This SSA's ContentDistributor Property is:" + "</li>")
                #$finding.Description+=('<ul style="color:#0072c6">' + "  {0}" -f $row.Replace(',','<BR>') + '</ul>')
                #Obfuscate Split the list first, then handle each server
                $CDistribs = $row.split(',')
                foreach ($cdistrib in $CDistribs)
                {
                    $server = $cdistrib.ToString().split('/')[2].split(':')[0]
                    $ObfuscateServer = $(Obfuscate $server "computer")
                    $row1=  $cdistrib.ToString().replace($server, $ObfuscateServer)
                    $finding.Description+=('<ul style="color:#0072c6">' + "  {0}" -f $row1 + '</ul>')
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

    #Obfuscate
    $ActiveComps = @()
    foreach ($comp in $sComponents)
    {
        $ActiveComp= New-Object psobject
        $ActiveComp | Add-Member -MemberType NoteProperty -Name "ServerName"   -value $(Obfuscate $comp.serverName "computer")
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
    $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $searchApplication.SearchAdminDatabase.Server.Name "dbserver"); DatabaseType = "Administration Database"; DatabaseName = $ssaAdminDb }
    
    if($apcStores.Count -eq 1)
    {
       $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $apcStores[0].Database.Server.Name "dbserver"); DatabaseType = "Analytics Database"; DatabaseName = $apcStores[0].Database.Name }
    }
    else
    {
      foreach($apcStore in $apcStores | Sort-Object -Property Name)
      {
        $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $apcStore.Database.Server.Name "dbserver"); DatabaseType = "Analytics Database"; DatabaseName = $apcStore.Database.Name }
      }
    }
    if($crawlStores.Count -eq 1)
    {
        $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $crawlStores[0].Database.Server.Name "dbserver"); DatabaseType = "Crawl Database"; DatabaseName = $crawlStores[0].Database.Name }
    }
    else
    {
      foreach($crawlStore in $crawlStores | Sort-Object -Property Name)
      {
        $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $crawlStore.Database.Server.Name "dbserver"); DatabaseType = "Crawl Database"; DatabaseName = $crawlStore.Database.Name }
      }
        
    }
    if($linkStores.Count -eq 1)
    {
       $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $linkStores[0].Database.Server.Name "dbserver"); DatabaseType = "Link Database"; DatabaseName = $linkStores[0].Database.Name }
    }
    else
    {
      foreach($linksStore in $linkStores | Sort-Object -Property Name)
      {
        $dbCollection += [pscustomobject]@{DatabaseServer = $(Obfuscate $linksStore.Database.Server.Name "dbserver"); DatabaseType = "Link Database"; DatabaseName = $linksStore.Database.Name }
      }
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
    $findingCollection = New-DiagnosticFinding -name $csFindingName -InputObject $null -Format table
    $contentSources = Get-SPEnterpriseSearchCrawlContentSource -SearchApplication $searchapplication -ErrorAction SilentlyContinue
    foreach ($contentSrc in $contentSources)
    {
        
        $csName =  'Content Source: ' + $(Obfuscate $($contentSrc.Name) "contentsource") + ' || ' + '( ' + 'ID: ' + $contentSrc.ID + ' | ' + ' Type: ' + $contentSrc.Type + ' | ' + ' Behavior: ' + $contentSrc.SharePointCrawlBehavior + ')'
        $csObj = $contentSrc | Select-Object CrawlState, CrawlStatus, ContinuousCrawlStatus, CrawlPriority, SuccessCount, WarningCount, ErrorCount, DeleteCount, CrawlStarted, CrawlCompleted, EnableContinuousCrawls, LevelImportantTotalCount, LevelHighErrorCount, LevelHighRecurringErrorCount, LevelHighTotalCount, LevelImportantRecurringErrorCount, RefreshCrawls 
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
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $(Obfuscate $startUri.AbsoluteUri.ToString() "url")
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
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $(Obfuscate $startUri.AbsoluteUri.ToString() "url")
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "AAMZone" -Value $altUrl.UrlZone
                    $csFinding.WarningMessage +="[" + $altUrl.UrlZone + "] " + $startUri
                    $csFinding.WarningMessage +="--- Non-Default zone may impact Contextual Scopes (e.g. This Site) and other search functionality"
                    $csFinding.Description += "The only URL that should be crawled should be the 'Default Zone Public URL' and it should be Windows Authentication. If crawling both the Default Zone and another Zone URL, the non Default Zone Url should be removed from the start addresses"
                    $csFinding.ReferenceLink +="https://www.ajcns.com/2021/02/problems-crawling-the-non-defaul-zone-for-a-sharepoint-web-application" 
                    $csFinding.Severity = [SPDiagnostics.Severity]::Warning
                    
                  }
                }
              }
          
              if($isRemoteFarm)
              {
                $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $(Obfuscate $startUri.AbsoluteUri.ToString() "url")
                $sAddressColl | Add-Member -MemberType NoteProperty -Name "RemoteFarm" -Value $true
              }
            
            } 
            else 
            {
              if($startUri.Scheme.toString().toLower().startsWith("sps")) 
              {
                 $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $(Obfuscate $startUri.AbsoluteUri.ToString() "url")
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
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $(Obfuscate $startUri.AbsoluteUri.ToString() "url")
                    $sAddressColl | Add-Member -MemberType NoteProperty -Name "Type" -Value "URI"
                }
              }
            }
          }
          else 
          {
            $sAddressColl | Add-Member -MemberType NoteProperty -Name "StartAddress" -Value $(Obfuscate $startUri.AbsoluteUri.ToString() "url")
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
        $csSchedFinding = New-DiagnosticFinding -name "Crawl Schedule | $(Obfuscate $($contentSrc.Name) "contentsource")" -InputObject $csCrawlScheduleColl -Format List

        if(!$contentSrc.EnableContinuousCrawls -and [string]::IsNullOrEmpty($contentSrc.FullCrawlSchedule.Description) -and [string]::IsNullOrEmpty($contentSrc.IncrementalCrawlSchedule.Description))
        {
            ##No crawls are enabled, make a finding severit
            $csSchedFinding.Severity = [SPDiagnostics.Severity]::Informational
            $csSchedFinding.Description += "No crawl schedules found for this content source, without a valid crawl schedule content will not be indexed"
            $csSchedFinding.ReferenceLink += [uri]"https://learn.microsoft.com/en-us/sharepoint/search/add-edit-or-delete-a-content-source"
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
        #Obfuscate
        $SNMs = @()
        foreach ($snmp in $SNM)
        {
            $SNMa = New-Object PSObject @{
                $Source = $(Obfuscate $snmp.Source "ServerNameMappingSource")
                $Target = $(Obfuscate $snmp.Target "ServerNameMappingTarget")
            }
            $SNMs += $SNMa
        }
        $finding = New-DiagnosticFinding -Name "Server Name Mappings" -InputObject $SNMs -format table
    }
    else
    {
        $finding = New-DiagnosticFinding -Name "Server Name Mappings" -InputObject $null -Description "This SSA has no Server Name Mappings" -format list
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
        if($null -ne $crawlrules)
        {
            #Obfuscate
            $crawlRules = @()
            foreach ($cr in $tempcrawlrules)
            {
                $crawlrule = new-object psobject @{
                    "Path" = $(Obfuscate $cr.Path "CrawlRulePath")
                    "Priority" = $cr.Priority
                    "PlugableSecurtiyTrimmer" = $cr.PlugableSecurtiyTrimmer
                    "Type"=$cr.type
                    "AuthenticationType" = cr.AuthenticationType
                    "AccountName"= $(Obfuscate $cr.AccountName "user")
                    "Method"=$cr.Method
                    "AuthenticationPath"=$cr.AuthenticationPath
                    "ErrorPages"=$cr.ErrorPages
                    "SuppressIndexing"=$cr.SuppressIndexing
                    "FollowComplexUrls" =$cr.FollowComplexUrls
                    "CrawlAsHTTP"=$cr.CrawlAsHTTP
                    "IsAdvancedRegularExpression"=$cr.IsAdvancedRegularExpression
                    "ContentClass"=$cr.ContentClass
                }
                $cralwRules += $crawlrule
            }

            $finding = New-DiagnosticFinding -Name "Crawl Rules" -InputObject $crawlrules -format table
        }
        else
        {
            $finding = New-DiagnosticFinding -Name "Crawl Rules" -Description "This SSA has no Crawl Rules defined" -format list -InputObject $null
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
        } else {
            $crawlPolicyFinding.Description +="All Crawl Policies are to default values"
        }

        if ($CrawlPolicyColl.ContinuousCrawlInterval -lt 10)
        {
            $crawlPolicyFinding.WarningMessage += "Continous Crawling Interval is set too low: $($CrawlPolicyColl.ContinuousCrawlInterval) minutes. This can cause very high resource utilization on the farm."
            $crawlPolicyFinding.Severity = [SPDiagnostics.Severity]::critical       
        }

    } 
    catch 
    {
        $crawlPolicyFinding.WarningMessage += "Can't access Search Settings. Search seems to be down in the farm"
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
   ProcessIdentity = $(Obfuscate $searchInstance.ProcessIdentity "user")
   PerformanceLevel = $searchInstance.PerformanceLevel
   ConnectionTimeout = $searchInstance.ConnectionTimeout
   AcknowledgementTimeout = $searchInstance.AcknowledgementTimeout
   IgnoreSSLWarnings = $searchInstance.IgnoreSSLWarnings
   UseCrawlProxyForFederation = $searchInstance.UseCrawlProxyForFederation
   InternetIdentity = $searchInstance.InternetIdentity
   Status = $searchInstance.Status
}
    $finding = New-DiagnosticFinding -Name "'Farm Search' Service Instance" -InputObject $siObj -format List
    
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
    $ssiFinding = New-DiagnosticFinding -Name "'Search\HostController Service' Instances" -InputObject $problemSearchInstanceColl -Format Table

    if($problemSearchInstanceColl.Count -gt 0)
    {
        $ssiFinding.Severity = [SPDiagnostics.Severity]::Critical
        $ssiFinding.WarningMessage = "One or more SearchServiceInstances or HostController Instances are not online "
        $ssiFinding.Description+=("<li>These Service Instances are critical for search to function properly.</li>")
        $ssiFinding.Description+=("<li> If these are Disabled or stuck in a state other than 'Online', then we need to try to start them again to bring to a proper state.</li>")
        $ssiFinding.Description+=("<li> To correct this, consider the following PowerShell command:  </li>")
        $ssiFinding.Description+=('<ul style="color:#0072c6">' + " Start-SPEnterpriseSearchServiceInstance 'serverName'" + "</ul>")
    }
    else
    {
        $ssiFinding.Description+=('<ul style="color:green"> All of the Search related Service Instances are Online!</ul>')
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
        $sspJobFinding.WarningMessage = "One or more 'SSP Job Control' Service Instances are not online "
        $sspJobFinding.Description+=("<li>These Service Instances are critical for search to function properly. They are responsible for allowing the timer jobs, job-application-server-*, to run.</li>")
        $sspJobFinding.Description+=("<li> Those timer jobs 'sync' search related data, so they need to be Online and those jobs need to be running every 1 min</li>")
        $sspJobFinding.Description+=("<li> To get these back 'Online', run the following PowerShell commands:  </li>")
        $sspJobFinding.Description+=("<ul style='color:#0072c6'><div class=`"code`">`$farm = Get-SPFarm<br>`$obj = `$farm.GetObject('guidOfDisabledInstance')<br>`$obj.Status = 'Online'<br>`$obj.Update()</div></ul>")
        
    }
    else
    {
        $sspJobFinding.Description+=('<ul style="color:green"> All of the SSP Job Control Service Instances are Online</ul>')
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

    foreach($ssa in $SSAs)
    {
        $at = Get-SPEnterpriseSearchTopology -SearchApplication $ssa -Active
        $topoCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at
        $components = $topoCompList | Select-Object ServerName -Unique
        $missingRootCollection = @()
        $cRootCollection = @()
        $cRootFinding = New-DiagnosticFinding -Name "'C:\Root' Finding" -InputObject $null -format Table
        foreach($searchServer in $components)
        {
            $rootDirectory = "\\" + $searchServer.ServerName + "\c$\root" 
            if(Test-Path $rootDirectory)
            {
                $cRootCollection +=[PSCustomObject]@{
                   Server = $(obfuscate $searchServer.ServerName "computer")
                   "Missing 'C:\Root' " = 'False'
                   SSA = $ssa.DisplayName
                }
                $cRootFinding.Description += ("<ul style='color:green'> All of the search servers contain the 'C:\Root' folder</ul>")

            }
            else
            {
                $missingRootCollection+=[PSCustomObject]@{
                   Server = $(obfuscate $searchServer.ServerName "computer")
                   "Missing 'C:\Root' " = 'True'
                   SSA = $ssa.DisplayName
                }
                
                $cRootFinding.Severity = [SPDiagnostics.Severity]::Critical
                $cRootFinding.WarningMessage = "One or more Servers are missing the 'C:\root' folder"
                $cRootFinding.Description += ("<li> Each server in the Search Topology should have the 'c:\root' folder.</li>")
                $cRootFinding.Description += ("<li> If the 'C:\root' is missing, your SSA will not provision.</li>")
                $cRootFinding.Description += ("<li> If you are missing this folder, you will need to delete the SSA you are trying to provision, create the 'c:\root' on the server and re-create the SSA</li><br/>")
                $cRootFinding.InputObject = $missingRootCollection
            }
        }
    }
    return $cRootFinding
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
                $response = $(Invoke-WebRequest -Uri $sqssUri -Method Get).StatusDescription
                #$finding.Description+=("<li>" + $sqssUri.ToString() + " -- " + $response.ToString() + "</li>")

                #Obfuscate
                $server = $sqssUri.ToString().split('/')[2].split(':')[0]
                $ObfuscateServer = $(Obfuscate $server "computer")
                $findingString=  $sqssUri.ToString().replace($server, $ObfuscateServer)
                $finding.Description+=("<li>" + $findingString + " -- " + $response.ToString() + "</li>")                

            }
        }
        $finding.Description+=("<ul>" + "  Search Service Endpoints Ok" + "</ul>")
    }
    catch
    {
       #ToDo:Obfuscate 
       $finding.Severity = [SPDiagnostics.Severity]::Warning
       $finding.WarningMessage+=("There was a problem reaching:  {0}" -f $(obfuscate $sqssuri "ssaendpoint") + "</br> " + $_.Exception.Message )
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
                #$finding.Description+=("<li>" + $searchAdminUri.ToString() + " -- " + $response.ToString() + "</li>")
               #Obfuscate
               $server = $searchAdminUri.ToString().split('/')[2].split(':')[0]
               $ObfuscateServer = $(Obfuscate $server "computer")
               $findingString=  $searchAdminUri.ToString().replace($server, $ObfuscateServer)
               $finding.Description+=("<li>" + $findingString + " -- " + $response.ToString() + "</li>")
               
            }
        }
        $finding.Description+=("<ul>" + "  Search Admin Endpoints Ok" + "</ul>")
    }
    catch
    {
        #ToDo: Obfuscate
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
        $script:topologyCompList = Get-SPEnterpriseSearchComponent -SearchTopology $at

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
        $script:componentStateList = Get-SPEnterpriseSearchStatus -SearchApplication $script:ssa -ErrorAction SilentlyContinue

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
                            $AnalyticsEntryFindings.Severity = [SPDiagnostics.Severity]::Warning
                            $AnalyticsEntryFindings.WarningMessage += "Warning: More than three days since last successful run"
                            $script:serviceDegraded = $true                        
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
        foreach($searchComp in ($script:topologyCompList))
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
            $compTemp = $script:compTemplate | Select-Object *
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

    # ------------------------------------------------------------------------------------------------------------------
    # VerifyHostControllerRepository: Verify that Host Controller HA (for dictionary repository) is OK
    # ------------------------------------------------------------------------------------------------------------------
    Function VerifyHostControllerRepository
    {
        $VerifyHostControllerRepositoryFinding =  New-DiagnosticFinding -Name "Host Controller Repository" -Severity Default -InputObject $null -format Table

        # not used Todo: Remove
        #$retObj = [PSCustomObject]@{
        #}

        $highestRepVer = 0
        $hostControllers = 0
        $primaryRepVer = -1
        $hcStat = @()
        $hcs = Get-SPEnterpriseSearchHostController
        foreach ($hc in $hcs)
        {
            $hostControllers += 1
            $repVer = $hc.RepositoryVersion
            $serverName = $(Obfuscate $hc.Server.Name "computer")
            if ($repVer -gt $highestRepVer)
            {
                $highestRepVer = $repVer
            }
            if ($hc.PrimaryHostController)
            {
                $primaryHC = $(Obfuscate $hc.Server.Name "computer")
                $primaryRepVer = $repVer
            }
            if ($repVer -ne -1)
            {
                $hcStat += "        $serverName : $repVer"
            }
        }

        if ($hostControllers -ge 1)
        {
            #Obfuscate
            $SHCS = @()
            foreach ($hcss in $hcs)
            {
                $shc = new-object psobject
                $shc | Add-Member -MemberType NoteProperty -Name "Server" -Value  $(Obfuscate $Hcss.Server.Name "computer")
                $shc | Add-Member -MemberType NoteProperty -Name "PrimaryHostController" -Value $hcss.PrimaryHostController
                $shc | Add-Member -MemberType NoteProperty -Name "Status" -Value $hcss.Status
                $shc | Add-Member -MemberType NoteProperty -Name "ID" -Value $hcss.ID
                $shc | Add-Member -MemberType NoteProperty -Name "RepositoryVersion" -Value $hcss.RepositoryVersion
                $SHCS += $shc
            }

            $VerifyHostControllerRepositoryFinding.Description += "<ul>Primary search host controller (for dictionary repository): $primaryHC</ul>"
            #$VerifyHostControllerRepositoryFinding.Description += "<ul>Primary search host controller (for dictionary repository): $primaryHC</ul>"
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
        #Obfuscate
        $ActiveSearchTopo =@()
        foreach ($sc in $script:compArray)
        {
            $sci=new-object PSObject
            $sci | Add-Member -MemberType NoteProperty -Name "Component" -Value $sc.Component
            $sci | Add-Member -MemberType NoteProperty -Name "Server" -Value $(Obfuscate $sc.Server "computer")
            $sci | Add-Member -MemberType NoteProperty -Name "Partition" -Value $sc.Partition
            $sci | Add-Member -MemberType NoteProperty -Name "State" -Value $sc.State
            $ActiveSearchTopo +=$sci
        }
        $ComponentFindings = New-DiagnosticFinding -Name "Search Topology" -Severity Default -InputObject $ActiveSearchTopo  -Format Table
        #$ComponentFindings = New-DiagnosticFinding -Name "Search Topology" -Severity Default -InputObject $script:compArray  -Format Table
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
                    #Obfuscate
                    foreach ($hi in $hostInfo)
                    {
                        $hi.hostName = $(Obfuscate $hi.hostName "computer") 
                    }

                    $hostinfofindings = New-DiagnosticFinding -Name $hostinfo.hostName -Severity Default -InputObject $hostInfo -Format Table 
                    $MultiComponentServers.ChildFindings.Add($hostinfofindings)
                }
                                
            }
            $SearchTopologyHealthCheck.ChildFindings.Add($MultiComponentServers)
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
        $script:SearchTopologyValues | Add-Member -MemberType NoteProperty -Name "Searchable Items" -Value $script:indexedDocs
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
        $DegradedComponents.WarningMessage+= "    This is normally a transient state during component restart or re-configuration. Re-run the script.</br>"
        
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
                $DegradedComponents.WarningMessage+= "        Will get out of degraded state as soon as new/changed items are being idexed.</br>"
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
    $script:SPFarm = $null
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
    
        $finding = New-DiagnosticFinding -Name "Analytics Topology" -Severity Default -Format List -InputObject $AnalyticsTopology
        
        if($null -ne $AnalyticsTopology)
        {
            $components = $AnalyticsTopology.GetComponents()
            foreach($component in $components)
            {
                $componentFinding = New-DiagnosticFinding -Name $component.Name -Severity Default -Format List -InputObject $component
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
        
        $finding = New-DiagnosticFinding -Name "Site and WebRoot Properties" -Severity Default -InputObject $tempSite -Format Table
        
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
        $tempWeb = $web | Select-Object Url, NoCrawl
        $finding = New-DiagnosticFinding -Name "Web Properties" -Severity Default -InputObject $tempWeb -Format Table
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
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Pool UserName" -Value $(Obfuscate $webApp.ApplicationPool.Username "Username")
        $tempWebApp  | Add-Member -MemberType NoteProperty -Name "Application Managed Account" -Value $(Obfuscate $webApp.ApplicationPool.ManagedAccount "username")
    
        $script:W3WPAppPoolAccount = $(obfuscate $webApp.ApplicationPool.Username "username")
        $finding = New-DiagnosticFinding -Name "WebApp Properties" -Severity Default -InputObject $tempWebApp -Format List
        
        return $finding
    }
    
    function Get-SPDiagnosticOWSTimerService()
    {
        $OWSTimerService = Get-WmiObject -Class Win32_Service | where-object{$_.Name -like "SPTimerV4"}
    
        $finding = New-DiagnosticFinding -Name "OWSTimer/SPTimerV4" -Severity Default -Format List
    
        if($null -ne $OWSTimerService)
        {
            $finding.InputObject = $OWSTimerService
            $Script:TimerServiceAccount  = $(Obfuscate $OWSTimerService.StartName "username")
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
        if($null -eq $SPUsageService)
        {
            $finding.WarningMessage = "There is no SPUsageService. This will prevent .usage logs from being created"
            $finding.Severity = [SPDiagnostics.Severity]::Critical
            return $finding
        }
    
        $finding.InputObject = $SPUsageService
    
        $instances = $SPUsageService.Instances | Select-Object $(Obfuscate Server "computer"), Status, NeedsUpgrade, CanUpgrade, IsBackwardsCompatible, ID, Parent, Version | sort-object Server
    
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
            $instancesFinding = New-DiagnosticFinding -Name "SPUsageService Instances" -Severity Default -Format Table -InputObject $instances
    
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
            $JobHistoryFindingEntries = New-DiagnosticFinding -Name "Most Recent 20 Job History Entries" -Severity Default -Format Table 

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
    
        $JobHistoryFindingEntries = New-DiagnosticFinding -Name "Most Recent 20 Job History Entries On SPUsageService" -Severity Default -Format Table 
        
        $JobHistoryEntries = $SPUsageService.JobHistoryEntries | Sort-Object -Descending StartTime | Select-Object Servername, Status, StartTime, EndTime, ErrorMessage -First 20
    
        $JobHistoryFindingEntries.InputObject = $JobHistoryEntries
    
        $finding.ChildFindings.Add($JobHistoryFindingEntries)
    
        return $finding
    }
    
    function Get-SPUsageDefinitionDiagnosticFinding()
    {
        $finding = New-DiagnosticFinding -Name "SPUsageDefinitions" -Severity Default -Format Table
        $definitions = Get-SPUsageDefinition
        $finding.InputObject = $definitions | Select-Object Name, Status, Enabled, EnableReceivers, Retention, DaysToKeepData, DaysToKeepUsageFiles, UsageDatabaseEnabled, TableName, MaxTotalSizeInBytes, Hidden, Description
    
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
    
        $items = get-childitem -Path $path -ErrorAction SilentlyContinue -Recurse | Select-Object Name, CreationTime, LastAccessTime,LastWriteTime,Attributes | Sort-Object LastWriteTime -Descending
    
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
    
        if($usageJob)
        {
            $finding.InputObject = $usageJob
            $AnalysisInfoFinding = New-DiagnosticFinding -Name "Analysis Information from TimerJob" -Severity Default -Format List -InputObject $usageJob.GetAnalysisInfo()
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
    
    $afdFinding = New-DiagnosticFinding `
        -Name ("Azure Front Door Compatible Ciphers: {0}" -f $ServerName) `
        -Description "Azure Front Door (AFD) serves as a gateway for much of M365, as such most hybrid scenarios require the ability to establish a secure connection to AFD." `
        -ReferenceLink "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq#what-are-the-current-cipher-suites-supported-by-azure-front-door-"

    if($supportedCiphers.Count -le 0)
    {
        $afdFinding.Severity = [SPDiagnostics.Severity]::Warning
        $afdFinding.WarningMessage += "No supported ciphers found to communicate with AFD. If hybrid functionlity is intending to be used, or currently being used, this should be addressed."
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

    $servers = Get-SPServer | Where-Object {$_.Role -ne [Microsoft.SharePoint.Administration.SPServerRole]::Invalid}
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
    } else {

        
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

        } else {
            Use-CacheCluster

            #Get DCache Server Config
            $DCacheHostConfig = $DCacheServers | ForEach-Object { Get-CacheHostConfig -HostName $_ -Port 22233 }

            #Get DCache Server Status
            $DCacheHostStatus = Get-CacheHost

            #Cache Names and Host
            $Caches = Get-Cache

        }

        #CacheHost Status
        # Obfuscate
        $CacheHostStatus = @()
        foreach ($ch in $DCacheHostStatus)
        {
            $chd = New-Object psobject
            $chd | add-Member -MemberType NoteProperty -Name "Hostname" -Value $(Obfuscate $ch.HostName "DistributedCacheHost")
            $chd | add-Member -MemberType NoteProperty -Name "PortNo" -Value $ch.PortNo
            $chd | add-Member -MemberType NoteProperty -Name "ServiceName" -Value $ch.ServiceName
            $chd | add-Member -MemberType NoteProperty -Name "Status" -Value $ch.Status
            $chd | add-Member -MemberType NoteProperty -Name "VersionInfo" -Value $ch.VersionInfo
            $CacheHostStatus += $chd
        }

        $DCacheHStatus = New-DiagnosticFinding -Name "Distributed Cache Host Status" -InputObject $CacheHostStatus -Format Table
        $DCacheFindings.ChildFindings.Add(($DCacheHStatus))


        #CacheHost Configuration
        $CacheHostConfig= @()
        foreach($dchs in $DCacheHostConfig)
        {
            $chs = new-Object PSObject
            $chs | Add-Member -MemberType NoteProperty -Name "HostName" -Value $(Obfuscate $dchs.HostName "DistributedCacheHost")
            $chs | Add-Member -MemberType NoteProperty -Name "ClusterPort" -Value $dchs.ClusterPort
            $chs | Add-Member -MemberType NoteProperty -Name "CachePort" -Value $dchs.CachePort
            $chs | Add-Member -MemberType NoteProperty -Name "ArbitrationPort" -Value $dchs.ArbitrationPort
            $chs | Add-Member -MemberType NoteProperty -Name "ReplicationPort" -Value $dchs.ReplicationPort
            $chs | Add-Member -MemberType NoteProperty -Name "Size" -Value $dchs.Size
            $chs | Add-Member -MemberType NoteProperty -Name "ServiceName" -Value $dchs.ServiceName
            $chs | Add-Member -MemberType NoteProperty -Name "HighWatermark" -Value $dchs.HighWatermark
            $chs | Add-Member -MemberType NoteProperty -Name "LowWatermark" -Value $dchs.LowWatermark
            $chs | Add-Member -MemberType NoteProperty -Name "IsLeadHost" -Value $dchs.IsLeadHost
            $CacheHostConfig += $chs
        }
        $DCacheHConfig = New-DiagnosticFinding -Name "Distributed Cache Host Configuration" -InputObject $CacheHostConfig -Format Table
        if (IsElevated)
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
       $DCacheFindings.ChildFindings.Add(($DCacheHConfig))


        #Individual Cache Statistics
        $DCacheStatitistics = @()
        $DCacheStatisticsFindings = New-DiagnosticFinding -Name "Distributed Cache Statistics" -InputObject $Null -Format Table
        if (!(IsElevated))
        {
            $DCacheStatisticsFindings.Description += "Distributed Cache Statistics can only be executed when the script is running executed with 'Run as Administrator'."

        } else {

            #foreach ($CacheContainerType in [enum]::GetNames("Microsoft.SharePoint.DistributedCaching.Utilities.SPDistributedCacheContainerType"))
            foreach ($Cache in $Caches)
            {

            if ($SPSE)
            {
                $css = Get-SPCacheStatistics -CacheName $cache.CacheName
            } else {
                $css = Get-CacheStatistics -CacheName $cache.CacheName
            }
                $cs = New-Object PSObject 
                $cs | Add-Member -MemberType NoteProperty -Name "Name" -value $cache.CacheName
                $cs | Add-Member -MemberType NoteProperty -Name "Host" -value $(Obfuscate $($cache.HostRegionMap.Keys[0]) "DistributedCacheHost")
                $cs | Add-Member -MemberType NoteProperty -Name "Size" -value $css.Size
                $cs | Add-Member -MemberType NoteProperty -Name "ItemCount" -value $css.ItemCount
                $cs | Add-Member -MemberType NoteProperty -Name "RegionCount" -value $css.RegionCount
                $cs | Add-Member -MemberType NoteProperty -Name "RequestCount" -value $css.RequestCount
                $cs | Add-Member -MemberType NoteProperty -Name "ReadRequestCount" -value $css.ReadRequestCount
                $cs | Add-Member -MemberType NoteProperty -Name "WriteRequestCount" -value $scs.WriteRequestCount
                $cs | Add-Member -MemberType NoteProperty -Name "MissCount" -value $css.MissCount
                $cs | Add-Member -MemberType NoteProperty -Name "IncomingBandwidth" -value $css.IncomingBandwidth
                $cs | Add-Member -MemberType NoteProperty -Name "OutgoingBandwidth" -value  $css.OutgoingBandwidth
                $DCacheStatitistics += $cs
            }
            $DCacheStatisticsFindings.InputObject = $DCacheStatitistics 
        }
        $DCacheFindings.ChildFindings.Add(($DCacheStatisticsFindings))

        #Distributed Cache Client Settings
        $DCacheClientSettingsFindings = New-DiagnosticFinding -Name "Distributed Cache Client Settings" -InputObject $DCacheClientSettings -Format Table
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
                    $cc | Add-Member -MemberType NoteProperty -Name "Host" -value $(Obfuscate $($cache.HostRegionMap.Keys[0])  "DistributedCacheHost")
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
                        $DCacheClientSettingsFindings.WarningMessage +="$($CacheType): The RequestTimeout could be set too low" 
                    }

                    if ($ccs.ChannelOpenTimeOut -lt 3000)
                    {
                        $DCacheClientSettingsFindings.WarningMessage +="$($CacheType): The ChannelOpenTimeout could be set too low" 
                    }

                    if ($ccs.MaxConnectionsToServer -gt 1)
                    {
                        $DCacheClientSettingsFindings.WarningMessage +="$($CacheType): Too many parallel client connections allowed to server" 
                    }
                    $DCacheClientSettings += $cc
                }
            } # else { write-host "unknown Cache Type $CacheType" }
        }
        if ($DCacheClientSettingsFindings.WarningMessage.Count -gt 0)                          
        {
            $DCacheClientSettingsFindings.ReferenceLink = [uri]"https://learn.microsoft.com/en-us/sharepoint/administration/manage-the-distributed-cache-service?tabs=SCS1%2CSCS2%2CSCS3%2CSCS%2CSCS4#fine-tune-the-distributed-cache-service-by-using-a-powershell-script"
            $DCacheClientSettingsFindings.Severity = [SPDiagnostics.Severity]::Informational
        }

        $DCacheClientSettingsFindings.InputObject=$DCacheClientSettings 
        $DCacheFindings.ChildFindings.Add(($DCacheClientSettingsFindings))

        #Ping Test for all DCache Ports
        $DCacheClusterPortTests=@()
        foreach ($DCacheHost in $DCacheHostConfig)
        {
            $ptCluster = Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.ClusterPort
            $ptCache = Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.CachePort
            if ($DCacheServers.Count -gt 1) {$ptArbitration =Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.ArbitrationPort}
            $ptRepl = Test-NetConnection -ComputerName $DCacheHost.HostName -Port $DCacheHost.ReplicationPort

            $DCacheClusterPortTest = new-Object PSObject
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Client" -Value $(Obfuscate $env:COMPUTERNAME "computer")
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Distributed Cache Server" -Value $(Obfuscate $DCacheHost.HostName "DistributedCacheHost")
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "SourceIP" -Value $(Obfuscate $ptCluster.SourceAddress.IPAddress "ipaddress")
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "RemoteIP" -Value $(Obfuscate $ptCluster.RemoteAddress.IPAddressToString "ipaddress")
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Cache Port 22233" -Value $ptCache.TcpTestSucceeded
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Cluster Port 22234" -Value $ptCluster.TcpTestSucceeded
            if ($DCacheServers.Count -eq 1) { $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Arbitration Port 22235" -Value "not tested - Single Server Cluster"}
            else { $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Arbitration Port 22235" -Value $ptArbitration.TCPTestSucceeded }
            $DCacheClusterPortTest | Add-Member -MemberType NoteProperty -Name "Replication Port 22236" -Value $ptRepl.TcpTestSucceeded
            $DCacheClusterPortTests +=$DCacheClusterPortTest
        }
        $DCacheNetworkPortTestFindings = New-DiagnosticFinding -Name "Distributed Cache Network Port Test" -InputObject $DCacheClusterPortTests -Format Table
        $DCacheFindings.ChildFindings.Add(($DCacheNetworkPortTestFindings))
    }
    return $DCacheFindings
}
#endregion #DistributedCache

#region WOPI / Office Online Server
Function Get-OfficeOnlineServerFindings
{
    $OfficeOnlineServerFindings = New-DiagnosticFinding -Name "Office Online Server " -InputObject $null -Format Table
    $WopiBindingsFinding = New-DiagnosticFinding -Name "WOPI Bindings" -InputObject $null -Format Table
    

    $DisplayWopiBindings = @()
    $wopiBindings = Get-SPWopiBinding
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
            $wb | Add-member -memberType NoteProperty -name "ServerName" -value  $(Obfuscate $wopiBinding.ServerName "WopiFarm")
            $wb | Add-member -memberType NoteProperty -name "WopiZone" -value  $WopiBinding.WopiZone           
            $DisplayWopiBindings += $wb
        }
        $WopiBindingsFinding.InputObject = $DisplayWopiBindings

        $WopiZone = new-Object PSObject 
        $WopiZone | Add-Member -memberType NoteProperty -name "WopiZone" -Value $(Get-SPWopiZone)
        $WopiZoneFinding = New-DiagnosticFinding -Name "WOPI Zone" -InputObject $($WopiZone) -Format List
        
        $WopiSuppressions = Get-SPWOPISuppressionSetting
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

            $WopiSuppressions = New-DiagnosticFinding -Name "WOPI Suppressions" -InputObject $WopiSuppressionsReport -Format table
            $WopiSuppressions.Description += "Office Web Apps are disabled for the action, file name extension, or programmatic identifier specified."
            $WopiSuppressions.ReferenceLink += "https://learn.microsoft.com/en-us/powershell/module/sharepoint-server/new-spwopisuppressionsetting?view=sharepoint-server-ps"
        } else {
            $WopiSuppressions = New-DiagnosticFinding -Name "WOPI Suppressions" -InputObject $null -Format list -Description "No WOPI Supressions configured"
        }

        if ((Get-SPWopiZone).Split("-")[1] -eq "http")
        {
            $wt = Test-NetConnection $wopiBindings[0].ServerName -port 80
        } else {
            $wt = Test-NetConnection $wopiBindings[0].ServerName -port 443
        }
        if ($wt.PingSucceeded -or $wt.TcpTestSucceeded)
        {
            $ConObject = new-object psobject
            $ConObject |add-Member -memberType NoteProperty -Name "ComputerName" -Value $(Obfuscate $wt.ComputerName "computer")
            $ConObject |add-Member -memberType NoteProperty -Name "RemoteAddress" -Value $(Obfuscate $wt.RemoteAddress "ipaddress")
            $ConObject |add-Member -memberType NoteProperty -Name "PingSucceeded"  -Value $wt.PingSucceeded
            $ConObject |add-Member -memberType NoteProperty -Name "TcpTestSucceeded" -Value $wt.TcpTestSucceeded
            $ConObject |add-Member -memberType NoteProperty -Name "RemotePort" -Value $wt.RemotePort
        }
        $WopiConnectionTestFinding = New-DiagnosticFinding -Name "WOPI Connection Test" -InputObject $ConObject -Format List

        $OfficeOnlineServerFindings.ChildFindings.add(($WopiBindingsFinding))
        $OfficeOnlineServerFindings.ChildFindings.add(($WopiZoneFinding)) 
        $OfficeOnlineServerFindings.ChildFindings.add(($WopiSuppressions)) 
        $OfficeOnlineServerFindings.ChildFindings.add(($WopiConnectionTestFinding)) 

    } 
    else 
    {
        $OfficeOnlineServerFindings.Description += "No WOPI Bindings configured in farm"
    }
    return $OfficeOnlineServerFindings
}
#endregion WOPI



#region Network Latency
Function Get-SPDiagnosticFarmNetworkLatency()
{
    $servers = (Get-SPServer | select-Object Name).Name
    $NetworkLatency = @()
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
        
        $SQLAliases=@()
        foreach ($sqlAliasName in $AliasNames)
        {
            $RegVal = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo\" -name $sqlAliasName
            $SQLAlias= New-Object PSObject
            $SQLAlias | Add-Member -MemberType NoteProperty -Name "alias" -Value $sqlAliasName
            $SQLAlias | Add-Member -MemberType NoteProperty -Name "server" -Value $RegVal.Split(',')[1]
            $SQLAliases += $SQLAlias
        }

        #replace SQL aliases with server names
        for ($i=0; $i -lt $servers.count; $i++)
        {
            if (!( $Null -eq ($SQLAliases | Where-Object {$_.alias -eq $servers[$i]}).server))
            {
                $servers[$i] = ($SQLAliases | Where-Object {$_.alias -eq $servers[$i]}).server
            }
        }
    }
    #make servers unique
    $servers = $servers | sort-Object -Unique

    foreach ($s in $servers)
    {
        if ($s -ne $env:COMPUTERNAME)
        {
            $serverLatency = New-Object psobject
            $pingRespose = Test-NetConnection -ComputerName $s -ea 0 #-InformationLevel Quiet
            $serverLatency | Add-Member -MemberType NoteProperty -Name "Source" -Value $(Obfuscate $env:COMPUTERNAME "computer")
            $serverLatency | Add-Member -MemberType NoteProperty -Name "Destination" -Value $(Obfuscate $pingRespose.Computername "computer")
            $serverLatency | Add-Member -MemberType NoteProperty -Name "DestinationIP" -Value $(Obfuscate $pingRespose.RemoteAddress "ipaddress")
            $serverLatency | Add-Member -MemberType NoteProperty -Name "PingSucceeded" -Value $pingRespose.PingSucceeded
            $serverLatency | Add-Member -MemberType NoteProperty -Name "RoundTripTime" -Value $pingRespose.PingReplyDetails.RoundtripTime
            $NetworkLatency += $serverLatency
        }
    }
    $NetworkLatencyFinding.InputObject= $NetworkLatency

    foreach ($nl in $NetworkLatency)
    {
        if ([String]::IsNullOrEmpty($nl.DestinationIP))
        {
            $networklatencyFinding.WarningMessage +="Could not resolve address'$($nl.Destination)'. Validate if name resolution is working correctly."            
        }
        elseif ($nl.PingSucceeded -eq $false)
        {
            $networklatencyFinding.WarningMessage +="Ping was not sucessful between servers '$($nl.source)' and '$($nl.Destination)'. Validate if there is no firewall blocking ping between the servers."            
        }

        if ($nl.RoundTripTime -gt 5)
        {
            $networklatencyFinding.WarningMessage +="The ping respose time between the servers '$($nl.source)' and '$($nl.Destination)' is way too high"            
            $networklatencyFinding.Severity =  [SPDiagnostics.Severity]::Critical
        } elseif ($nl.RoundTripTime -gt 2)
        {
            $networklatencyFinding.WarningMessage +="The ping respose time between the servers '$($nl.source)' and '$($nl.Destination)' is too high"            
        }
    }
    return $NetworkLatencyFinding
}
#endregion 

#region Certificates in SPSE
function Get-SPDiagnosticCertificateFindings
{
    if ($Script:Build -ne "SPSE")
    {
        return $null
    } else {
        $CertificateFinding = New-DiagnosticFinding -Name "Managed Certificates" -InputObject $null -Format List
        if (IsElevated)
        {

            #Get all Certifcates in SPSE Cert Store with some properties
            $Certs = Get-SPCertificate | select-Object FriendlyName, CommonName,  NotBefore, NotAfter, Exportable, IsSelfSigned, Status, ID, storeType, Subject  #,AlternativeNames  #SAN is an array
            if ($Certs.Count -eq 0)
            {
                $CertificateFinding.Description += "No Certificates found in the SharePoint Certificate store"
            }

            #Obfuscate
            if ($Script:Obfuscate)
            {
                foreach ($cert in $certs)
                {
                    $cert.Subject = $(Obfuscate $cert.subject "certsubject")
                    $cert.CommonName = $(Obfuscate $cert.CommonName "certcommonname")
                    $cert.FriendlyName = $(Obfuscate $cert.FriendlyName "certfriendlyname")
                }
            }


            #Get the Default settings for Certificates in the Farm
            $certSettings = Get-SPCertificateSettings

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

    $MirrorDB= get-spdatabase | Where-Object {$_.FailoverServer -or $_.FailoverInstance} | Select-Object name, @{N='server';E={$(Obfuscate $_.server "sqlserver")}} , @{N='FailoverServer';E={$(Obfuscate $_.FailoverServer.Name "sqlserver")}}
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

#Region DBCompatibiltyLevel
function Get-GetDBCompatibilityLevelFinding ($DBServer)
{
    $DBCompatibilityLevelFinding = New-DiagnosticFinding -Name "Database Compatibility Level" -InputObject $null -Format Table
        
    $ServerDBS = get-spdatabase | Where-Object {($_.server.name -eq $dbServer) -or ($_.server -eq  $dbServer)}
    $dbs = $ServerDBS.name -join ","
    $dbs = $dbs.replace(",", "','")
    $dbs = "'" + $dbs +"'"
    $sqlquery = "select name, Compatibility_Level from sys.databases where name in ($dbs)"
    
    $dbcompatLevels = Invoke-SPSqlCommand -spDatabase $ServerDBS[0] -query $sqlquery -ErrorAction SilentlyContinue

    $DBCompatibilityLevelFinding.InputObject = $dbcompatLevels | select-Object Name, Compatibility_Level
    return $DBCompatibilityLevelFinding
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
        $SPSrvAccountSQLPerms  | add-member -memberType NoteProperty -name "LoginName" -Value $(Obfuscate $row[0] "user")
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
            $SPSrvAccountsSQLPermsFinding.WarningMessage += "$(Obfuscate $row[0] "user") has Deny Login permissions on SQL server."
            $SPSrvAccountsSQLPermsFinding.Severity=[SPDiagnostics.Severity]::Warning   
        }
        if ($SPSrvAccountSQLPerms.HasAccess -eq 0)
        {
            $SPSrvAccountsSQLPermsFinding.WarningMessage += "$(Obfuscate $row[0] "user") has no Access on SQL server."
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

    $dbServers = ( Get-SPDatabase  | ForEach-Object {$_.parent.server.Address})  | Sort-Object | Get-Unique
    foreach ($dbServer in $DBServers)
    {
        $SPDBs = (get-SPDatabase  | Where-Object {$_.parent.server.name -eq $dbserver})
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

            $SQLServerFinding = New-DiagnosticFinding -Name "SQL Server ($(Obfuscate $dbServer "sqlserver"))" -InputObject $SQLServerData -Format List
            $SQLServerFinding.ChildFindings.Add((Get-SPServiceAccountSQLPerms))

            $SQLServersFinding.ChildFindings.add(($SQLServerFinding))
            $SQLServerFinding.ChildFindings.Add((Get-MirroredDBsFinding))
            $SQLServerFinding.ChildFindings.Add((Get-GetDBCompatibilityLevelFinding $dbServer))

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
                $ClusterName = $(obfuscate $AAG_ClusterInfo[0] "sqlclustername")
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
                    $ClusterMember | add-member -memberType NoteProperty -name "Member name" -value $(Obfuscate $Row[0] "sqlserver")
                    $ClusterMember | add-member -memberType NoteProperty -name "Member type description" -value $Row[2]
                    $ClusterMember | add-member -memberType NoteProperty -name "Member State" -value $Row[4]
                    $ClusterMember | add-member -memberType NoteProperty -name "Member Number of Quroum votes" -value $Row[5]
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
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "Member name" -value $(Obfuscate $Row[0] "sqlserver")
                    $ClusterNetworkInfo | add-member -memberType NoteProperty -name "Network subnet" -value $(Obfuscate $Row[1] "network-subnet")
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
                    $ClusterResource | add-member -memberType NoteProperty -name "Instance Name" -value $(Obfuscate $Row[1] "sqlserver")
                    $ClusterResource | add-member -memberType NoteProperty -name "Node Name" -value $(Obfuscate $Row[2] "sqlserver")
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
                    $ClusterNameIDMap | add-member -memberType NoteProperty -name "AG Name" -value $(obfuscate $Row[0] "agname")
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
                    $GroupName = $(obfuscate $row[1] "AGName")
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
                        $PrimaryReplica = $(obfuscate $row[1] "sqlserver")
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
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "ReplicaServername" -value $(obfuscate $row[2] "sqlserver")
                    $AAGReplicaInfo | add-member -memberType NoteProperty -name "EndPoint URL" -value $(obfuscate $row[3] "sqlendpoint")
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
                        $AAGDB | add-member -memberType NoteProperty -name "Database Name" -value $(obfuscate $row[0] "database")
                        $AAGDB | add-member -memberType NoteProperty -name "Group Database ID" -value $row[1]
                        $AAGDB | add-member -memberType NoteProperty -name "Replica ID" -value $row[2]
                        $AAGDB | add-member -memberType NoteProperty -name "Is Primary" -value $row[3]
                        $AAGDB | add-member -memberType NoteProperty -name "Synchronization Status" -value $row[4]
                        $AAGDB | add-member -memberType NoteProperty -name "Synchronization Health" -value $row[5]
                        $AAGDB | add-member -memberType NoteProperty -name "Database State" -value $row[6]
                        $AAGDB | add-member -memberType NoteProperty -name "Is Suspende" -value $row[7]
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
                    $AAGListener | add-member -memberType NoteProperty -name "IP Address" -value $(obfuscate $row[1] "ipaddress")
                    $AAGListener | add-member -memberType NoteProperty -name "Is DHCP" -value $row[2]
                    $AAGListener | add-member -memberType NoteProperty -name "IP Subnet Mask" -value $row[3]
                    $AAGListener | add-member -memberType NoteProperty -name "Network Subnet Mask" -value $row[4]
                    $AAGListener | add-member -memberType NoteProperty -name "State" -value $row[5]
                    $AAGListener | add-member -memberType NoteProperty -name "DNS Name" -value $(obfuscate $row[6] "dnsname")
                    $AAGListener | add-member -memberType NoteProperty -name "Port" -value $(obfuscate $row[7] "port")
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

            $SQLServerFinding.ChildFindings.add(($SQL_AAG_Finding))
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
        
        -SkipSearchHealthCheck
        This allows skipping the exhaustive health check that the SPFarmInfo scripts. Useful if you're not interested in all the search health details.
        
        -SkipErrorCollection
        This skips the collection of errors generating during script execution from being saved in the report. 

        -Obfuscate
        Obfuscate/Pseudonomize PII data like Server names, User names, URLs, IPAddresses, ... 

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
        $title = "Disclaimer"
        $message = "SPFarmInfo is a data collection tool only. It does not make any changes to the SharePoint Environment."
        $message += "`r`nThis script collects servername, domain names, IP addresses, and account names used by SharePoint Server, similar"
        $message += "`r`nto typical data that would be found in ULS logs." 

        # These are defined here because the options are modified when not using the -obfuscate switch.
        $yes = [System.Management.Automation.Host.ChoiceDescription]::new("&Yes")
        $no = [System.Management.Automation.Host.ChoiceDescription]::new("&No")
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        # if not using the obufscation switch, append to the disclaimer
        if ($Obfuscate)
        {
            $title += "/Obfuscation"
            $message += "`r`n`r`n-Obfuscate detected. The script will make every attempt to obfuscate Servernames, Domain Names, IP Addresses,"
            $message += "`r`n accounts and other PII Data. This data will be stored locally in an obfuscate.xml and obfuscate.csv file."
            $message += "`r`n Manual review of the collected data is still recommended to ensure that no PII is unobfuscated."
        }
        else
        {
            $title += "/No Obfuscation"
            $message += " If this is a concern, consider using the -Obfuscate switch and"
            $message += "`r`nreviewing collected data prior to sending back to Microsoft."
            $DoObfuscation = [System.Management.Automation.Host.ChoiceDescription]::new("&Obfuscate Data")

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no, $DoObfuscation)
        }

        $message += " Continue?"


        $result = $host.UI.PromptForChoice($title, $message, $options,0)

        # Don't continue
        if ($result -eq 1)
        {
            exit
        }

        #obfuscate the data
        if($result -eq 2)
        {
            $Script:obfuscate = $true
        }
    
        
    }
}

# Main function that calls into building the report and contains the first level findings.
# Keep this clean and organized to make future additions easier
function main
{
    [cmdletbinding()]
    Param()

    Write-ScriptDisclaimer

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

    if($Help)
    {
        Get-SPFarmInfoHelp
        break
    }

    $Script:RunStartTime=Get-Date
    $Script:build = Get-SPVersion

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

    #Load the file with the Obfuscation Info from previos run
    $ObfuscateFile = Join-path $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\') "Obfuscate.xml"

    if($Obfuscate)
    {
        if (test-path -LiteralPath $ObfuscateFile)
        {
            $Script:ObfuscateList = Import-Clixml $Obfuscatefile
        }
    }


    $rootFindingCollection = New-Object SPDiagnostics.FindingCollection[SPDiagnostics.Finding]
    $rootFindingCollection.Add((Get-SPDiagnosticSupportDateFinding))
    $rootFindingCollection.Add((Get-SPDiagnosticFarmFindings))
    #$rootFindingCollection.Add((Get-SPDiagnosticSQLFindings))    # move under FarmFindings
    $rootFindingCollection.Add((Get-SPDiagnosticAuthFindings))
    $rootFindingCollection.Add((Get-SPDiagnosticSearchFindings))
    #$rootFindingCollection.Add((Get-SPDiagnosticKerberosFindings)) # move under Authentication
    #$rootFindingCollection.Add((Get-SPDiagnosticCertificateFindings)) # move under FarmFindings
        
    if($UsageAndReporting -and $site)
    {
        $rootFindingCollection.Add((Get-SPDiagnosticUsageAndReportingInformation $site))
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
        # Error collection is not obfuscated when the error occurs, remove it from the output
        if($error.Count -gt 0)
        {
            $errorFinding = New-DiagnosticFinding -Name "Error Collection" -InputObject $Null -Format List
            if ($Obfuscate)
            {
                $errorFinding.Description = "Error reports are not included in obfuscated reports."
            } else {
                $errorFinding.Description = "These are errors generated ONLY during script execution. They do not represent an issue that needs to be resolved"
                $errorFinding.Description += "These are intended to assist with identifying SPFarmInfo script issues"
                $errorFinding.InputObject = $error
            }
            $scriptDiagnosticFinding.ChildFindings.add($errorFinding)
        }
    }

    $rootFindingCollection.Add($scriptDiagnosticFinding)

    $diagnosticContent = $null
    $rootFilname = "SPFarmReport_"

    if($UsageAndReporting)
    {
        $fileName = $rootFilname + "UsageAndReporting_"
    }

    if($TLS)
    {
        $fileName = $rootFilname + "TLS_"
    }

    $fileName = "{0}\$fileName{1}_{2}" -f $ENV:UserProfile, $build, [datetime]::Now.ToString("yyyy_MM_dd_hh_mm")

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
        foreach($server in Get-SPServer)
        {
            $diagnosticContent = $diagnosticContent.Replace($server.Address,$server.EncodedServerId)
            $diagnosticContent = $diagnosticContent.Replace($server.Name,$server.EncodedServerId)
        }
    }

    Set-Content -Value $diagnosticContent -LiteralPath $fileName
    
    if($Obfuscate)
    {
        #Save the list of Obfuscated Data for reuse
        $Script:ObfuscateList | Select-Object Pseudo, RealValue | Sort-Object -Property Pseudo | Format-Table | Tee-Object -FilePath ($ObfuscateFile.replace('.xml', '.csv'))
        $Script:ObfuscateList | Export-Clixml -LiteralPath  $ObfuscateFile -Force
    }


    Invoke-Item $fileName

    Write-Host ("`n`nScript complete, review the output file at `"{0}`"" -f $fileName) -ForegroundColor Green

    #reset ProgressPreference back to original value. Note: This does not work without using $global prefix
    $global:ProgressPreference = $oldProgress
}

main
