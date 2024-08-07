#   This file is part of the MaLDAPtive framework.
#
#   Copyright 2024 Sabajete Elezaj (aka Sabi) <@sabi_elezi>
#         while at Solaris SE <https://solarisgroup.com/>
#         and Daniel Bohannon (aka DBO) <@danielhbohannon>
#         while at Permiso Security <https://permiso.io/>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



function Install-LdapClientWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Install-LdapClientWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Install-LdapClientWinEvent downloads, configures and installs SilkService component of the SilkETW project used for extracting LDAP client-side logs from 'Microsoft-Windows-LDAP-Client' provider in ETW (Event Tracing for Windows).

.PARAMETER Path

Specifies path in which to install SilkETW.

.EXAMPLE

PS C:\> Install-LdapClientWinEvent -Path $env:ProgramFiles -Verbose

VERBOSE: Downloading pre-compiled SilkETW binary: https://github.com/mandiant/SilkETW/releases/download/v0.8/SilkETW_SilkService_v8.zip
VERBOSE: Decompressing SilkETW .zip file: C:\Program Files\SilkETW_SilkService_v8.zip
VERBOSE: Removing SilkETW .zip file: C:\Program Files\SilkETW_SilkService_v8.zip
VERBOSE: Creating YARA rule file: C:\Program Files\SilkETW_SilkService_v8\v8\SilkService\ldap_events_of_interest.yara
VERBOSE: Creating SilkService configuration file: C:\Program Files\SilkETW_SilkService_v8\v8\SilkService\SilkServiceConfig.xml
VERBOSE: Successfully installed SilkService service 'SilkService' executing: C:\Program Files\SilkETW_SilkService_v8\v8\SilkService\SilkService.exe

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $Path = $env:ProgramFiles
    )

    # Output warning message and return from function if OS is not Windows since client-side LDAP event logs only exist on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required event logs only exists on Windows."
    }

    # Define SilkETW, SilkService and SilkService executable paths based on user input -Path parameter.
    $silkEtwPath = Join-Path -Path $Path -ChildPath 'SilkETW_SilkService_v8'
    $silkServicePath = Join-Path -Path $silkEtwPath -ChildPath 'v8\SilkService'
    $silkServiceExePath = Join-Path -Path $silkServicePath -ChildPath 'SilkService.exe'

    # Define SilkService service name.
    $serviceName = 'SilkService'

    # Retrieve executable path of existing SilkService executable if it is already installed as a service.
    $existingSilkServiceExePath = (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).BinaryPathName

    # If SilkService is already installed then output warning and return from function to avoid double installation.
    if ($existingSilkServiceExePath)
    {
        if ($existingSilkServiceExePath -ieq $silkServiceExePath)
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] SilkETW service binary already exists ('$existingSilkServiceExePath') and is installed in the correct path ('$silkServiceExePath') based on user input -Path parameter ('$Path')! Exiting function."
        }
        else
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] SilkETW service binary already exists ('$existingSilkServiceExePath') but at a different path than expected ('$silkServiceExePath') based on user input -Path parameter ('$Path')! Exiting function."
        }

        return
    }

    # If SilkService is not installed then proceed with installation.
    if (-not $existingSilkServiceExePath)
    {
        # Create SilkETW directory if it does not exist.
        if (-not (Test-Path -Path $silkEtwPath))
        {
            Write-Verbose "Creating SilkETW path: $silkEtwPath"
            New-Item -ItemType Directory -Path $silkEtwPath | Out-Null
        }

        # Download pre-compiled release binary v0.8 of SilkETW.
        $silkEtwPrecompiledZipPath = $silkEtwPath + '.zip'
        if (-not (Test-Path -Path $silkEtwPrecompiledZipPath))
        {
            $silkEtwPrecompiledUri = 'https://github.com/mandiant/SilkETW/releases/download/v0.8/SilkETW_SilkService_v8.zip'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Write-Verbose "Downloading pre-compiled SilkETW binary: $silkEtwPrecompiledUri"
            Invoke-WebRequest -Uri $silkEtwPrecompiledUri -UseBasicParsing -OutFile $silkEtwPrecompiledZipPath

            # Output warning and return from function if .zip file not successfully downloaded.
            if (-not (Test-Path -Path $silkEtwPrecompiledZipPath))
            {
                Write-Warning "[$($MyInvocation.MyCommand.Name)] SilkETW .zip file not successfully downloaded from '$silkEtwPrecompiledUri' to '$silkEtwPrecompiledZipPath'! Exiting function."

                return
            }
        }

        # Validate hash of SilkETW .zip file and output warning and return from function if hash mismatch identified.
        if ((Get-FileHash -Path $silkEtwPrecompiledZipPath -Algorithm SHA256).Hash -ne '6C612C406844C72CDE51BCD0660CA6BB704656549043CB5A8B8BBBA5FE3D8DC3')
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] SHA256 hash for SilkETW .zip file '$silkEtwPrecompiledZipPath' does not match what is expected! Exiting function."

            return
        }

        # Decompress pre-compiled SilkETW .zip archive.
        Write-Verbose "Decompressing SilkETW .zip file: $silkEtwPrecompiledZipPath"
        Expand-Archive -Path $silkEtwPrecompiledZipPath -DestinationPath $silkEtwPath -Force

        # Confirm successful expansion and remove pre-compiled SilkETW .zip archive.
        # Otherwise, output warning and return from function if SilkETW service binary does not exist.
        if (Test-Path -Path $silkServiceExePath)
        {
            # Remove pre-compiled SilkETW .zip archive.
            Write-Verbose "Removing SilkETW .zip file: $silkEtwPrecompiledZipPath"
            Remove-Item -Path $silkEtwPrecompiledZipPath
        }
        else
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] SilkETW service binary not found ('$silkServiceExePath')! Exiting function."

            return
        }
    }

    # Define YARA rule file path and content.
    $silkServiceYaraPath = "$silkServicePath\ldap_events_of_interest.yara"
    $silkServiceYaraContent = @'
rule LDAP_Distinguished_Name
{
	strings:
		$eid = "\"EventName\":\"EventID(7)\""
		$msg_01 = "LDAPSPEW request "
		$msg_02 = " is an "
		$msg_03 = " operation for '"
	condition:
		$eid and all of ($msg*)
}

rule LDAP_Filter
{
	strings:
		$eid = "\"EventName\":\"EventID(7)\""
		$msg_01 = "\"Message\":\"\\tLDAPSPEW scope is "
		$msg_02 = ", filter is '"
	condition:
		$eid and all of ($msg*)
}

rule LDAP_Attribute_Header
{
	strings:
		$eid = "\"EventName\":\"EventID(7)\""
		$msg = "\"Message\":\"\\tLDAPSPEW requesting all attributes."
	condition:
		$eid and $msg
}

rule LDAP_Attribute_Value
{
	strings:
		$eid = "\"EventName\":\"EventID(7)\""
		$msg = "\"Message\":\"\\t\\t'"
	condition:
		$eid and $msg
}

rule LDAP_Time_And_Size_Limit
{
	strings:
		$eid = "\"EventName\":\"EventID(1)\""
		$msg = "\"Message\":\"ldap_search called for connection "
	condition:
		$eid and $msg
}
'@

    # Create above YARA rule file if it does not exist or its content needs to be updated.
    $yaraRuleFileDoesNotExist = -not (Test-Path -Path $silkServiceYaraPath) ? $true : $false
    $yaraRuleFileContentMismatch = -not $yaraRuleFileDoesNotExist -and (Compare-Object -ReferenceObject (Get-Content -Path $silkServiceYaraPath -Raw).Trim() -DifferenceObject $silkServiceYaraContent.Trim()) ? $false : $true
    if ($yaraRuleFileDoesNotExist -or $yaraRuleFileContentMismatch)
    {
        Write-Verbose "$($yaraRuleFileDoesNotExist ? 'Creating' : 'Updating') YARA rule file: $silkServiceYaraPath"
        Set-Content -Path $silkServiceYaraPath -Value $silkServiceYaraContent
    }

    # Define JSON output file path if manually invoking SilkETW (not as a service).
    $silkEtwJsonOutputPath = "$silkEtwPath\silkEtw_results_LDAP.json"

    # Define SilkService configuration file path and content specifying LDAP Client events and above YARA file.
    $silkServiceConfigPath = "$silkServicePath\SilkServiceConfig.xml"
    $silkServiceConfigContent = @"
<SilkServiceConfig>
	<ETWCollector>
		<Guid>5ab1adb0-aaaa-bbbb-cccc-ddddeeeeffff</Guid>
		<CollectorType>user</CollectorType>
		<ProviderName>Microsoft-Windows-LDAP-Client</ProviderName>
		<OutputType>eventlog</OutputType>
        <YaraScan>$silkServicePath\</YaraScan>
		<YaraOptions>Matches</YaraOptions>
	</ETWCollector>
	<!--
	<ETWCollector>
		<Guid>5ab1adb0-bbbb-bbbb-bbbb-bbbbbbbbbbbb</Guid>
		<CollectorType>user</CollectorType>
		<ProviderName>Microsoft-Windows-LDAP-Client</ProviderName>
		<OutputType>file</OutputType>
        <Path>$silkEtwJsonOutputPath</Path>
        <YaraScan>$silkServicePath\</YaraScan>
		<YaraOptions>Matches</YaraOptions>
	</ETWCollector>
	-->
</SilkServiceConfig>
"@

    # Create above SilkService configuration file if it does not exist or its content needs to be updated.
    $configFileDoesNotExist = -not (Test-Path -Path $silkServiceConfigPath) ? $true : $false
    $configFileContentMismatch = -not $configFileDoesNotExist -and (Compare-Object -ReferenceObject (Get-Content -Path $silkServiceConfigPath -Raw).Trim() -DifferenceObject $silkServiceConfigContent.Trim()) ? $false : $true
    if ($configFileDoesNotExist -or $configFileContentMismatch)
    {
        Write-Verbose "$($configFileDoesNotExist ? 'Creating' : 'Updating') SilkService configuration file: $silkServiceConfigPath"
        Set-Content -Path $silkServiceConfigPath -Value $silkServiceConfigContent
    }

    # Output warning and return from function if current user is not an administrator since administrator access is required to create a new service.
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Cannot install SilkService service since current user is not an administrator! Exiting function."

        return
    }

    # Install SilkService service.
    $newService = New-Service -Name $serviceName -BinaryPathName $silkServiceExePath -StartupType Manual

    # Output status of final installation step.
    # Output warning and return from function if service installation unsuccessful.
    if (-not $newService)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Failed to install SilkService service '$serviceName' executing: $silkServiceExePath"

        return
    }
    else
    {
        # Attempt to start newly-installed SilkService.
        $newService | Start-Service

        if ($newService.Status -ieq 'Running')
        {
            Write-Verbose "Successfully installed SilkService service '$serviceName' executing: $silkServiceExePath"
        }
        else
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] Successfully installed SilkService service '$serviceName' but failed to start it by executing: $silkServiceExePath"
        }
    }
}


function Get-LdapNormalizedWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Get-LdapNormalizedWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: New-XPathFilter, Get-LdapServerNormalizedWinEvent, Get-LdapClientNormalizedWinEvent
Optional Dependencies: None

.DESCRIPTION

Get-LdapNormalizedWinEvent retrieves and normalizes client- and server-side LDAP events from 'SilkService-Log' and 'Directory Service' event logs, respectively, based on input start and end times.

.PARAMETER StartTime

Specifies earliest generation time of events to retrieve from event logs.

.PARAMETER EndTime

Specifies latest generation time of events to retrieve from event logs.

.PARAMETER Source

(Optional) Specifies client- and/or server-side LDAP event log sources be queried.

.PARAMETER RetryCount

(Optional) Specifies number of potential times to re-query each event log if no results returned.

.PARAMETER RetryBackoffInMilliseconds

(Optional) Specifies retry backoff time (in milliseconds) to wait between any potential re-query attempts.

.PARAMETER RetryEventCreationTimespanIncreaseInSeconds

(Optional) Specifies time (in seconds) to iteratively add to input end time between any potential re-query attempts to accommodate potential delay in event log generation.

.EXAMPLE

PS C:\> $startTime = Get-Date
PS C:\> $res = '(|(!(!OId.00001.2.840.113556.1.000004.1=D*a*m*n*)(aNR=kr\62)(FOO=BAR)))' | ILQ -SearchRoot 'LDAP://  dC  =  WinDOM\41IN  ,  oID.000.9.2342.19200300.100.001.25  =  "LocaL" ' -AttributeList @('0002.5.4.3','1337','*','nAMe')
PS C:\> $endTime = Get-Date
PS C:\> Start-Sleep -Seconds 5
PS C:\> $logObj = Get-LdapNormalizedWinEvent -StartTime $startTime -EndTime $endTime
PS C:\> [System.Array] $logObj.Client + $logObj.Server | Select-Object ProviderName,SearchFilter,ScopeOfSearch,DistinguishedName,AttributeList | Format-Table

ProviderName                                    SearchFilter                                                            ScopeOfSearch DistinguishedName                                                AttributeList
------------                                    ------------                                                            ------------- -----------------                                                -------------
Microsoft-Windows-LDAP-Client                   (|(!(!OId.00001.2.840.113556.1.000004.1=D*a*m*n*)(aNR=kr\62)(FOO=BAR))) Subtree       dC  =WinDOM\41IN  ,oID.000.9.2342.19200300.100.001.25  ="LocaL"  {0002.5.4.3, 1337, *, name…}
Microsoft-Windows-ActiveDirectory_DomainService  ( | ( ! ( !  (name=D*a*m*n*) ) )  (aNR=krb)  (UNDEFINED) )             Subtree       DC=WinDOMAIN,DC=LocaL                                            {[all_with_list]cn, name}

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 5
PS C:\> $endTime = Get-Date
PS C:\> $logObj = Get-LdapNormalizedWinEvent -StartTime $startTime -EndTime $endTime -Verbose
PS C:\> [System.Array] $logObj.Client + $logObj.Server

VERBOSE: [Get-LdapNormalizedWinEvent -Source Server] Re-invoking Get-LdapServerNormalizedWinEvent 1 of 5 times (startTime=07/28/2024 22:13:37, endTime=07/28/2024 22:13:42).

VERBOSE: [Get-LdapNormalizedWinEvent -Source CLIENT] Re-invoking Get-LdapClientNormalizedWinEvent 1 of 5 times (startTime=07/28/2024 22:13:37, endTime=07/28/2024 22:13:42).

TimeCreated       : 7/28/2024 10:13:37 PM
EID               : 7
ProviderName      : Microsoft-Windows-LDAP-Client
ProviderId        : 099614a5-5dd7-4788-8bc9-e29f43db28fc
LogName           : SilkService-Log
Level             : 4
LevelDisplayName  : Information
MachineName       : WIN-DBOCOMPNAME.windomain.local
UserId            :
ProcessName       : pwsh
ProcessId         : 3668
ThreadId          : 2648
AttributeList     : {oId.0000001.2.840.000000113556.1.4.000001          , objectCategory, doesNotExist, *…}
DistinguishedName : 0.9.2342.19200300.100.1.25   =WinDOM\41IN  ,oID.0000.0009.2342.19200300.0000100.1.25   ="LocaL"
ScopeOfSearch     : Subtree
SearchFilter      :    (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)
                    ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))

TimeCreated       : 7/28/2024 10:13:37 PM
EID               : 1644
ProviderName      : Microsoft-Windows-ActiveDirectory_DomainService
ProviderId        : 0e8478c5-3605-4e8c-8497-1e730c959516
LogName           : Directory Service
Level             : 4
LevelDisplayName  : Information
MachineName       : WIN-DBOCOMPNAME.windomain.local
UserId            : S-1-5-21-3168475409-2195742205-3749327978-500
ProcessName       :
ProcessId         : 648
ThreadId          : 4408
AttributeList     : {[all_with_list]name, objectCategory}
DistinguishedName : DC=WinDOMAIN,DC=LocaL
ScopeOfSearch     : Subtree
SearchFilter      :  ( &  ( |  (UNDEFINED)  (name=dbo) ( ! ( !  (name=sabi) ) )  (aNR=krb)  (description=Al*m*o*n*d*)  (UNDEFINED) )  (name>==) )

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.DateTime]
        $StartTime,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.DateTime]
        $EndTime,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('client','server')]
        [System.String[]]
        $Source = @('client','server'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RetryCount = 5,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,10000)]
        [System.Int64]
        $RetryBackoffInMilliseconds = 2000,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RetryEventCreationTimespanIncreaseInSeconds = 2
    )

    # Based on -Source input parameter, query and normalize server-side LDAP event logs, looping and delaying based on -RetryCount, -RetryBackoffInMilliseconds
    # and -RetryEventCreationTimespanIncreaseInSeconds input parameters in case event log needs additional time to process incoming LDAP events.
    $ldapServerWinEventNormalizedArr = @()
    if ($Source -icontains 'server')
    {
        $endTimeModified = $endTime

        $doWhileCount = 0
        do
        {
            # After first iteration, introduce delay based on -RetryBackoffInMilliseconds input parameter to give event log additional time to process incoming LDAP events.
            if ($doWhileCount -gt 0)
            {
                Start-Sleep -Milliseconds $RetryBackoffInMilliseconds

                # Increase end timestamp by user input -RetryEventCreationTimespanIncreaseInSeconds parameter seconds to be input into XPath filter generation below.
                $endTimeModified = $endTimeModified.AddSeconds($RetryEventCreationTimespanIncreaseInSeconds)

                Write-Verbose "[$($MyInvocation.MyCommand.Name) -Source Server] Re-invoking Get-LdapServerNormalizedWinEvent $doWhileCount of $RetryCount times (startTime=$startTime, endTime=$endTimeModified)."
            }
            $doWhileCount++

            # Build XPath filter for more precise and efficient event log querying.
            # LDAP queries are issued by a process running directly on the Domain Controller, so for more efficient processing filter only for events issued by current user.
            $filterXPath = New-XPathFilter -EventId 1644 -StartTime $startTime -EndTime $endTimeModified -UserName $env:USERNAME

            # Query and normalize event log results.
            $ldapServerWinEventNormalizedArr = Get-LdapServerNormalizedWinEvent -FilterXPath $filterXPath
        }
        while (-not $ldapServerWinEventNormalizedArr -and ($doWhileCount -le $RetryCount))
    }

    # Based on -Source input parameter, query and normalize client-side LDAP event logs, looping and delaying based on -RetryCount, -RetryBackoffInMilliseconds
    # and -RetryEventCreationTimespanIncreaseInSeconds input parameters in case event log needs additional time to process incoming LDAP events.
    $ldapClientWinEventNormalizedArr = @()
    if ($Source -icontains 'client')
    {
        $endTimeModified = $endTime

        $doWhileCount = 0
        do
        {
            # After first iteration, introduce delay based on -RetryBackoffInMilliseconds input parameter to give event log additional time to process incoming LDAP events.
            if ($doWhileCount -gt 0)
            {
                Start-Sleep -Milliseconds $RetryBackoffInMilliseconds

                # Increase end timestamp by user input -RetryEventCreationTimespanIncreaseInSeconds parameter seconds to be input into XPath filter generation below.
                $endTimeModified = $endTimeModified.AddSeconds($RetryEventCreationTimespanIncreaseInSeconds)

                Write-Verbose "[$($MyInvocation.MyCommand.Name) -Source CLIENT] Re-invoking Get-LdapClientNormalizedWinEvent $doWhileCount of $RetryCount times (startTime=$startTime, endTime=$endTimeModified)."
            }
            $doWhileCount++

            # Build XPath filter for more precise and efficient event log querying.
            $filterXPath = New-XPathFilter -EventId 3 -StartTime $startTime -EndTime $endTimeModified

            # Query and normalize event log results.
            $ldapClientWinEventNormalizedArr = Get-LdapClientNormalizedWinEvent -FilterXPath $filterXPath
        }
        while (-not $ldapClientWinEventNormalizedArr -and ($doWhileCount -le $RetryCount))
    }

    # Return final normalized log results in single object.
    [PSCustomObject] @{
        Client = $ldapClientWinEventNormalizedArr
        Server = $ldapServerWinEventNormalizedArr
    }
}


function Get-LdapClientNormalizedWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Get-LdapClientNormalizedWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertFrom-LdapClientWinEvent, Out-NormalizedLdapClientWinEvent
Optional Dependencies: None

.DESCRIPTION

Get-LdapClientNormalizedWinEvent queries local 'SilkService-Log' event log with input XPath filter to retrieve and normalize client-side LDAP logs.

.PARAMETER FilterXPath

(Optional) Specifies XPath filter string to include when querying local 'SilkService-Log' event log via Get-WinEvent cmdlet.

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 5
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 3 -StartTime $startTime -EndTime $endTime
PS C:\> Get-LdapClientNormalizedWinEvent -FilterXPath $filterXPath

TimeCreated       : 7/28/2024 10:13:37 PM
EID               : 7
ProviderName      : Microsoft-Windows-LDAP-Client
ProviderId        : 099614a5-5dd7-4788-8bc9-e29f43db28fc
LogName           : SilkService-Log
Level             : 4
LevelDisplayName  : Information
MachineName       : WIN-DBOCOMPNAME.windomain.local
UserId            :
ProcessName       : pwsh
ProcessId         : 1468
ThreadId          : 5028
AttributeList     : {oId.0000001.2.840.000000113556.1.4.000001          , objectCategory, doesNotExist, *…}
DistinguishedName : 0.9.2342.19200300.100.1.25   =WinDOM\41IN  ,oID.0000.0009.2342.19200300.0000100.1.25   ="LocaL"
ScopeOfSearch     : Subtree
SearchFilter      :    (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $FilterXPath = 'Event[System[EventID=3]]'
    )

    # Output warning message and return from function if OS is not Windows since Get-WinEvent cmdlet only exists on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required Get-WinEvent cmdlet only exists on Windows."
    }

    # Query local 'SilkService-Log' event log using above XPath filter to retrieve client-side LDAP logs.
    # If no results match the XPath filter then Get-WinEvent throws the following error message: "No events were found that match the specified selection criteria."
    # To avoid this (but display any other potential errors), define "-ErrorAction SilentlyContinue" while capturing any stderr in $ldapClientWinEventErr via "-ErrorVariable 'ldapClientWinEventErr'" input parameter.
    $ldapClientWinEventArr = Get-WinEvent -LogName 'SilkService-Log' -FilterXPath $FilterXPath -ErrorVariable 'ldapClientWinEventErr' -ErrorAction SilentlyContinue

    # If Get-WinEvent generates an error message that is not "No events were found that match the specified selection criteria." then output error message to console host.
    if ($ldapClientWinEventErr.FullyQualifiedErrorId -and ($ldapClientWinEventErr.FullyQualifiedErrorId -cne 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'))
    {
        Write-Host $ldapClientWinEventErr -ForegroundColor Red
    }

    # Parse, normalize and return final LDAP event log properties to facilitate easier comparison between client- and server-side LDAP event logs.
    $ldapClientWinEventArr | ConvertFrom-LdapClientWinEvent | Out-NormalizedLdapClientWinEvent -SkipDefaultEvent
}


function Get-LdapServerNormalizedWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Get-LdapServerNormalizedWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertFrom-LdapServerWinEvent, Out-NormalizedLdapServerWinEvent
Optional Dependencies: None

.DESCRIPTION

Get-LdapServerNormalizedWinEvent queries local 'Directory Service' event log with input XPath filter to retrieve and normalize server-side LDAP logs.

.PARAMETER FilterXPath

(Optional) Specifies XPath filter string to include when querying local 'Directory Service' event log via Get-WinEvent cmdlet.

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 2
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 1644 -StartTime $startTime -EndTime $endTime -UserName $env:USERNAME
PS C:\> Get-LdapServerNormalizedWinEvent -FilterXPath $filterXPath

TimeCreated       : 7/28/2024 10:13:37 PM
EID               : 1644
ProviderName      : Microsoft-Windows-ActiveDirectory_DomainService
ProviderId        : 0e8478c5-3605-4e8c-8497-1e730c959516
LogName           : Directory Service
Level             : 4
LevelDisplayName  : Information
MachineName       : WIN-DBOCOMPNAME.windomain.local
UserId            : S-1-5-21-0123456789-0123456789-0123456789-500
ProcessName       :
ProcessId         : 656
ThreadId          : 3208
AttributeList     : {[all_with_list]name, objectCategory}
DistinguishedName : DC=WinDOMAIN,DC=LocaL
ScopeOfSearch     : Subtree
SearchFilter      :  ( &  ( |  (UNDEFINED)  (name=dbo) ( ! ( !  (name=sabi) ) )  (aNR=krb)  (description=Al*m*o*n*d*)  (UNDEFINED) )  (name>==) )

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $FilterXPath = 'Event[System[EventID=1644]]'
    )

    # Output warning message and return from function if OS is not Windows since Get-WinEvent cmdlet only exists on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required Get-WinEvent cmdlet only exists on Windows."
    }

    # Query local 'Directory Service' event log using above XPath filter to retrieve server-side LDAP logs.
    # If no results match the XPath filter then Get-WinEvent throws the following error message: "No events were found that match the specified selection criteria."
    # To avoid this (but display any other potential errors), define "-ErrorAction SilentlyContinue" while capturing any stderr in $ldapServerWinEventErr via "-ErrorVariable 'ldapServerWinEventErr'" input parameter.
    $ldapServerWinEventArr = Get-WinEvent -LogName 'Directory Service' -FilterXPath $FilterXPath -ErrorVariable 'ldapServerWinEventErr' -ErrorAction SilentlyContinue

    # If Get-WinEvent generates an error message that is not "No events were found that match the specified selection criteria." then output error message to console host.
    if ($ldapServerWinEventErr.FullyQualifiedErrorId -cne 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand')
    {
        Write-Host $ldapServerWinEventErr -ForegroundColor Red
    }

    # Parse, normalize and return final LDAP event log properties to facilitate easier comparison between client- and server-side LDAP event logs.
    $ldapServerWinEventArr | ConvertFrom-LdapServerWinEvent | Out-NormalizedLdapServerWinEvent -SkipDefaultEvent
}


function ConvertFrom-LdapClientWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: ConvertFrom-LdapClientWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

ConvertFrom-LdapClientWinEvent parses raw client-side LDAP logs retrieved from the 'SilkService-Log' event log (ProviderName=Microsoft-Windows-LDAP-Client, ProviderId=099614a5-5dd7-4788-8bc9-e29f43db28fc) EID 7 events via the Get-WinEvent cmdlet, extracting LDAP values from specific events and adding as new properties onto single event to facilitate later aggregation process.

.PARAMETER InputObject

Specifies raw client-side LDAP logs (from the 'SilkService-Log' event log) to convert.

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 5
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 3 -StartTime $startTime -EndTime $endTime
PS C:\> $eventLogRaw = Get-WinEvent -LogName 'SilkService-Log' -FilterXPath $FilterXPath -ErrorVariable 'ldapClientWinEventErr' -ErrorAction SilentlyContinue
PS C:\> $eventLogRaw | ConvertFrom-LdapClientWinEvent

   ProviderName: SilkService Collector

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:33 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Attribute_Value"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Filter"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeName":"Info","T…
7/29/2024 12:49:32 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Distinguished_Name"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(7)","Opcode":0,"OpcodeNam…
7/29/2024 12:49:31 AM            3 Information      {"ProviderGuid":"099614a5-5dd7-4788-8bc9-e29f43db28fc","YaraMatch":["LDAP_Time_And_Size_Limit"],"ProviderName":"Microsoft-Windows-LDAP-Client","EventName":"EventID(1)","Opcode":0,"OpcodeNa…

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 5
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 3 -StartTime $startTime -EndTime $endTime
PS C:\> $eventLogRaw = Get-WinEvent -LogName 'SilkService-Log' -FilterXPath $FilterXPath -ErrorVariable 'ldapClientWinEventErr' -ErrorAction SilentlyContinue
PS C:\> $eventLogParsed = $eventLogRaw | ConvertFrom-LdapClientWinEvent
PS C:\> $eventLogParsed.Where( { $_.Message.Contains('"YaraMatch":["LDAP_Filter"]') } ).PropertiesParsed

ProviderGuid    : 099614a5-5dd7-4788-8bc9-e29f43db28fc
YaraMatch       : {LDAP_Filter}
ProviderName    : Microsoft-Windows-LDAP-Client
EventName       : 7
Opcode          : 0
OpcodeName      : Info
TimeStamp       : 7/29/2024 12:45:10 AM
ThreadID        : 3504
ProcessID       : 2848
ProcessName     : pwsh
PointerSize     : 8
EventDataLength : 265
XmlEventData    : @{ProviderName=Microsoft-Windows-LDAP-Client; ActivityID=c4bf5ad2e1780000ba6cbfc478e1da01; EventName=7; Message=      LDAPSPEW scope is 2, filter is '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
                  ; PID=2848; TID=3504; MSec=6079858.9776; PName=}

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [System.Object[]]
        $InputObject
    )

    begin
    {

    }

    process
    {
        # Iterate over each -InputObject value.
        foreach ($curEvent in $InputObject)
        {
            # Extract all values from current event's "Properties" property, convert from JSON format and add to current event as new property.
            Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'PropertiesParsed' -Value ($curEvent.Properties.Value | ConvertFrom-Json)

            # Discard any event log not from Microsoft-Windows-LDAP-Client provider.
            if ($curEvent.PropertiesParsed.ProviderName -ne 'Microsoft-Windows-LDAP-Client')
            {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Excluding $($curEvent.PropertiesParsed.ProviderName) event log since ProviderName is not Microsoft-Windows-LDAP-Client."

                # Continue to next event in current foreach loop.
                continue
            }

            # Duplicate ActivityID value as property in base object for later grouping purposes.
            Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'PropertiesParsedActivityId' -Value ([System.Guid] $curEvent.PropertiesParsed.XmlEventData.ActivityID)

            # Extract EventName/EID and Message from current event to more accurately parse out additional fields.
            $eid     = [System.Int16]  ($curEvent.PropertiesParsed.XmlEventData.EventName -creplace '[^\d]','')
            $message = [System.String] $curEvent.PropertiesParsed.XmlEventData.Message.Trim()

            # Replace both instances of EventName string with integer representation parsed above.
            $curEvent.PropertiesParsed.EventName              = $eid
            $curEvent.PropertiesParsed.XmlEventData.EventName = $eid

            # Parse out specific LDAP fields contained in a subset of events.
            # Add each value (if found) to current event to be used later for aggregation.
            switch ($curEvent.PropertiesParsed.EventName)
            {
                1 {
                    if ($message -imatch "^ldap_search called for connection 0x[a-f0-9]{8}: DN is (.+)\. SearchScope is 0x([0-9])\. AttributesOnly is 0x([0-9])\. Synchronous is 0x([0-9])\. TimeLimit is (\d+)\. SizeLimit is (\d+)\.$")
                    {
                        # While DistinguishedName is present in current EID 1 event it does not preserve potential trailing whitespace; therefore, extract DistinguishedName from EID 7 later in current switch block.

                        # Extract ScopeOfSearch from above regex match, normalizing ScopeOfSearch's integer value into corresponding string representation.
                        $scopeOfSearch = switch ($Matches[2])
                        {
                            0 { 'Base'     }
                            1 { 'OneLevel' }
                            2 { 'Subtree'  }
                            default {
                                Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                            }
                        }

                        # Extract AttributesOnly and Synchronous from above regex match, normalizing their integer values into corresponding boolean representations.
                        $attributesOnly = switch ($Matches[3])
                        {
                            0 { $false }
                            1 { $true  }
                            default {
                                Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                            }
                        }
                        $synchronous = switch ($Matches[4])
                        {
                            0 { $false }
                            1 { $true  }
                            default {
                                Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                            }
                        }

                        # Extract TimeLimit and SizeLimit from above regex match.
                        $timeLimit = $Matches[5]
                        $sizeLimit = $Matches[6]

                        # Add extracted property values to current event as new properties.
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'ScopeOfSearch'  -Value ([System.String]  $scopeOfSearch)
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'AttributesOnly' -Value ([System.Boolean] $attributesOnly)
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'Synchronous'    -Value ([System.Boolean] $synchronous)
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'TimeLimit'      -Value ([System.Int64]   $timeLimit)
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'SizeLimit'      -Value ([System.Int64]   $sizeLimit)
                    }
                    else
                    {
                        # Ouput unhanded event via Write-Verbose. This should not be reached if recommended LDAP YARA rules are referenced in SilkETW's SilkServiceConfig.xml.
                        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Unhandled event for EID $($curEvent.PropertiesParsed.EventName): $($curEvent.PropertiesParsed.XmlEventData.Message)"
                    }
                }
                7 {
                    if ($message -imatch "^LDAPSPEW request \d+ is an \d+ operation for '([^']+)'$")
                    {
                        # Extract DistinguishedName from above regex match.
                        $distinguishedName = $Matches[1]

                        # Add extracted DistinguishedName value to current event as new property.
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'DistinguishedName' -Value ([System.String] $distinguishedName)
                    }
                    elseif ($message -imatch "^LDAPSPEW scope is (\d+), filter is '(.*)'$")
                    {
                        # Extract SearchFilter from above regex match.
                        $searchFilter = $Matches[2]

                        # Add extracted SearchFilter value to current event as new property.
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'SearchFilter' -Value ([System.String] $searchFilter)
                    }
                    elseif ($message -eq 'LDAPSPEW requesting all attributes.')
                    {
                        # Set AttributeList to placeholder value that will be converted to an empty array in later normalization process.
                        $attributeList = 'NO_ATTRIBUTELIST_DEFINED'

                        # Add AttributeList placeholder value to current event as new property.
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'AttributeList' -Value ([System.String] $attributeList)
                    }
                    elseif ($message -imatch "^'(.*)'$")
                    {
                        # Extract AttributeList value from above regex match.
                        $attributeList = $Matches[1]

                        # Add extracted AttributeList value to current event as new property.
                        Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'AttributeList' -Value ([System.String] $attributeList)
                    }
                    else
                    {
                        # Ouput unhanded event via Write-Verbose. This should not be reached if recommended LDAP YARA rules are referenced in SilkETW's SilkServiceConfig.xml.
                        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Unhandled event for EID $($curEvent.PropertiesParsed.EventName): $($curEvent.PropertiesParsed.XmlEventData.Message)"
                    }
                }
                default {
                    # Ouput unhanded EID via Write-Verbose. This should not be reached if recommended LDAP YARA rules are referenced in SilkETW's SilkServiceConfig.xml.
                    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Unhandled EID: $($curEvent.PropertiesParsed.EventName)"
                }
            }

            # Return current event.
            $curEvent
        }
    }

    end
    {

    }
}


function ConvertFrom-LdapServerWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: ConvertFrom-LdapServerWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

ConvertFrom-LdapServerWinEvent parses raw server-side LDAP logs retrieved from the 'Directory Service' event log (ProviderName=Microsoft-Windows-ActiveDirectory_DomainService, ProviderId=0e8478c5-3605-4e8c-8497-1e730c959516) EID 1644 events via the Get-WinEvent cmdlet, extracting 'Properties' values into name-value pair 'ParsedProperties' object.

.PARAMETER InputObject

Specifies raw server-side LDAP logs (from the 'Directory Service' event log) to convert.

.PARAMETER NormalizeAttributeSelection

(Optional) Specifies that AttributeSelection property values '[all]' and '[all_with_list]' (if present) be normalized to a syntax more correct and more comparable with client-side LDAP logs.

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 2
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 1644 -StartTime $startTime -EndTime $endTime -UserName $env:USERNAME
PS C:\> $eventLogRaw = Get-WinEvent -LogName 'Directory Service' -FilterXPath $FilterXPath -ErrorVariable 'ldapServerWinEventErr' -ErrorAction SilentlyContinue
PS C:\> $eventLogRaw | ConvertFrom-LdapServerWinEvent

   ProviderName: Microsoft-Windows-ActiveDirectory_DomainService

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
7/28/2024 11:41:18 PM         1644 Information      Internal event: A client issued a search operation with the following options. …

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 2
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 1644 -StartTime $startTime -EndTime $endTime -UserName $env:USERNAME
PS C:\> $eventLogRaw = Get-WinEvent -LogName 'Directory Service' -FilterXPath $FilterXPath -ErrorVariable 'ldapServerWinEventErr' -ErrorAction SilentlyContinue
PS C:\> $eventLogParsed = $eventLogRaw | ConvertFrom-LdapServerWinEvent
PS C:\> $eventLogParsed.PropertiesParsed

StartingNode                     : DC=WinDOMAIN,DC=LocaL
Filter                           :  ( &  ( |  (UNDEFINED)  (name=dbo) ( ! ( !  (name=sabi) ) )  (aNR=krb)  (description=Al*m*o*n*d*)  (UNDEFINED) )  (name>==) )
VisitedEntries                   : 3542
ReturnedEntries                  : 2
Client                           : [fe80::1337:db0:abcd:4ca9%6]:54493
ScopeOfSearch                    : Subtree
AttributeSelection               : {[all_with_list]name, objectCategory}
ServerControls                   :
UsedIndexes                      : DNT_index:2368:N;
PagesReferenced                  : 22712
PagesReadFromDisk                : 0
PagesPreReadFromDisk             : 0
PagesDirtied                     : 0
PagesReDirtied                   : 0
SearchTime                       : 15
AttributesPreventingOptimization : none
User                             : WINDOMAIN\dbo

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [System.Object[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $NormalizeAttributeSelection
    )

    begin
    {

    }

    process
    {
        # Iterate over each -InputObject value.
        foreach ($curEvent in $InputObject)
        {
            # Extract all values from current event's "Properties" property.
            $propertyValArr = $curEvent.Properties.Value

            # Set above property values as proper name-value pair based on reversing values as they appear in current event's "Message" property.
            $propertyParsed = [PSCustomObject] @{
                StartingNode       = [System.String] $propertyValArr[0]
                # Filter property adheres to the following spacing rules regardless of actual invoked SearchFilter (this function will not modify this normalization):
                #   1) one space before every GroupStart token (open parenthesis)
                #   2) one space after every GroupEnd token (close parenthesis)
                #   3) one space before and after every BooleanOperator token (e.g. '&','|','!')
                Filter               = [System.String]   $propertyValArr[1]
                VisitedEntries       = [System.Int16]    $propertyValArr[2]
                ReturnedEntries      = [System.Int16]    $propertyValArr[3]
                Client               = [System.String]   $propertyValArr[4]
                ScopeOfSearch        = [System.String]   $propertyValArr[5] -ireplace 'base','Base' -ireplace 'onelevel','OneLevel' -ireplace 'subtree','Subtree'
                AttributeSelection   = [System.String[]] ($propertyValArr[6] -csplit ',').Where( { $_ } )
                ServerControls       = [System.String]   $propertyValArr[7]
                UsedIndexes          = [System.String]   $propertyValArr[8]
                PagesReferenced      = [System.Int16]    $propertyValArr[9]
                PagesReadFromDisk    = [System.Int16]    $propertyValArr[10]
                PagesPreReadFromDisk = [System.Int16]    $propertyValArr[11]
                PagesDirtied         = [System.Int16]    $propertyValArr[12]
                PagesReDirtied       = [System.Int16]    $propertyValArr[13]
                SearchTime           = [System.Int64]    $propertyValArr[14]
                AttributesPreventingOptimization = [System.String] $propertyValArr[15]
                User                 = [System.String]   $propertyValArr[16]
            }

            # If user input -NormalizeAttributeSelection parameter is defined then normalize AttributeSelection property for two specific scenarios.
            if ($PSBoundParameters['NormalizeAttributeSelection'].IsPresent)
            {
                if ($propertyParsed.AttributeSelection.Count -eq 1 -and $propertyParsed.AttributeSelection -ceq '[all]')
                {
                    # Set AttributeSelection to an empty array if the only value present is the string '[all]' since this is the value that is logged if
                    # user input AttributeSelection is '*' or is not defined (functionally both syntaxes return all Attributes).
                    $propertyParsed.AttributeSelection = @()
                }
                elseif ($propertyParsed.AttributeSelection[0].StartsWith('[all_with_list]'))
                {
                    # If user input AttributeSelection is a list containing '*' and at least one defined Attribute then the '*' is logged as the string '[all_with_list]'
                    # prepended to the first Attribute; therefore, replace this prefix on the first Attribute with a standalone '*' Attribute.
                    $propertyParsed.AttributeSelection[0] = $propertyParsed.AttributeSelection[0] -creplace '^\[all_with_list\]',''
                    $propertyParsed.AttributeSelection = [System.Array] '*' + $propertyParsed.AttributeSelection
                }
            }

            # Add parsed property object to current event.
            Add-Member -InputObject $curEvent -MemberType NoteProperty -Name 'PropertiesParsed' -Value $propertyParsed

            # Return current event.
            $curEvent
        }
    }

    end
    {

    }
}


function Out-NormalizedLdapClientWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Out-NormalizedLdapClientWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-NormalizedLdapClientWinEvent normalizes select properties from ConvertFrom-LdapClientWinEvent function output to enable easier comparison between client- and server-side LDAP logs.

.PARAMETER InputObject

Specifies client-side LDAP log output from ConvertFrom-LdapClientWinEvent function to normalize.

.PARAMETER SkipDefaultEvent

(Optional) Specifies defined default LDAP queries be skipped and not returned to avoid unrelated noise during log analysis. These default LDAP queries are issued automatically immediately before each user-input LDAP query is issued via Invoke-LdapQuery function.

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 5
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 3 -StartTime $startTime -EndTime $endTime
PS C:\> $eventLogRaw = Get-WinEvent -LogName 'SilkService-Log' -FilterXPath $FilterXPath -ErrorVariable 'ldapClientWinEventErr' -ErrorAction SilentlyContinue
PS C:\> $eventLogRaw | ConvertFrom-LdapClientWinEvent | Out-NormalizedLdapClientWinEvent -SkipDefaultEvent

TimeCreated       : 7/28/2024 10:13:37 PM
EID               : 7
ProviderName      : Microsoft-Windows-LDAP-Client
ProviderId        : 099614a5-5dd7-4788-8bc9-e29f43db28fc
LogName           : SilkService-Log
Level             : 4
LevelDisplayName  : Information
MachineName       : WIN-DBOCOMPNAME.windomain.local
UserId            :
ProcessName       : pwsh
ProcessId         : 1468
ThreadId          : 5028
AttributeList     : {oId.0000001.2.840.000000113556.1.4.000001          , objectCategory, doesNotExist, *…}
DistinguishedName : 0.9.2342.19200300.100.1.25   =WinDOM\41IN  ,oID.0000.0009.2342.19200300.0000100.1.25   ="LocaL"
ScopeOfSearch     : Subtree
SearchFilter      :    (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [System.Object[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $SkipDefaultEvent
    )

    begin
    {
        # Create array to store all pipelined input before beginning final processing.
        # This is necessary for LDAP client event logs since multiple events must be aggregated into a single object, even if passed into current function via pipeline input.
        $inputObjectArr = @()
    }

    process
    {
        # Append each $InputObject to $inputObjectArr.
        foreach ($curEvent in $InputObject)
        {
            $inputObjectArr += $curEvent
        }
    }

    end
    {
        # Iterate over each -InputObject value stored in $inputObjectArr, grouping based on "PropertiesParsedActivityId" property to extract LDAP values per grouping of related events.
        ($inputObjectArr | Group-Object PropertiesParsedActivityId).ForEach(
        {
            $curInputObjectGroup = $_.Group

            # For current group determine which property should be used as a delimiter between default LDAP query issued before actual LDAP query of interest is issued.
            # This should default to "SizeLimit" property unless it is not present in current set (in which case the "SearchFilter" property is used as the delimiter).
            $delimProp = $curInputObjectGroup.SizeLimit ? 'SizeLimit' : 'SearchFilter'

            # Build first sub-grouping of filtered events based on above delimiter property.
            # Extract first successful grouping since event log events are returned in descending order.
            $curInputObjectGroupFiltered = foreach ($curEvent in $curInputObjectGroup)
            {
                $curEvent

                # Break out of loop if current event contains delimiter property.
                if ($null -ne $curEvent.$delimProp)
                {
                    break
                }
            }

            # Identify primary event from current filtered sub-group for extracting additional non-LDAP event properties.
            $primaryEvent = $curInputObjectGroupFiltered.Where( { $_.SearchFilter } )

            # Continue to next filtered sub-group if no primary event found in current sub-group above.
            if (-not $primaryEvent)
            {
                continue
            }

            # Extract SearchFilter LDAP property from primary event.
            $searchFilter  = $primaryEvent.SearchFilter

            # Extract ScopeOfSearch LDAP property from all events in current filtered sub-group.
            $scopeOfSearch  = $curInputObjectGroupFiltered.ScopeOfSearch

            # Extract DistinguishedName LDAP property from all events in current filtered sub-group.
            $distinguishedName = $curInputObjectGroupFiltered.DistinguishedName

            # Extract AttributeList LDAP property from all events in current filtered sub-group.
            # Remove any potential null values and reverse order since event log events are returned in descending order.
            $attributeList = $curInputObjectGroupFiltered.AttributeList.Where( { $_ } )
            $attributeList = $attributeList[($attributeList.Count - 1)..0]

            # Convert placeholder value from ConvertFrom-LdapClientWinEvent to an empty array to match other data sources.
            if ($attributeList.Contains('NO_ATTRIBUTELIST_DEFINED'))
            {
                $attributeList = @()
            }

            # Build normalized LDAP object for current event so server-side and client-side LDAP data can be easily joined and compared.
            # NOTE: UserId property is present in server-side LDAP logs but not in client-side LDAP logs.
            # NOTE: ProcessName property is present in client-side LDAP logs but not in server-side LDAP logs.
            $ldapNormalizedObj = [PSCustomObject] @{
                TimeCreated       = [System.DateTime] $primaryEvent.PropertiesParsed.TimeStamp
                EID               = [System.Int16]    $primaryEvent.PropertiesParsed.EventName
                ProviderName      = [System.String]   $primaryEvent.PropertiesParsed.ProviderName
                ProviderId        = [System.Guid]     $primaryEvent.PropertiesParsed.ProviderGuid
                LogName           = [System.String]   $primaryEvent.LogName
                Level             = [System.Int16]    $primaryEvent.Level
                LevelDisplayName  = [System.String]   $primaryEvent.LevelDisplayName
                MachineName       = [System.String]   $primaryEvent.MachineName
                UserId            =                   $null
                ProcessName       = [System.String]   $primaryEvent.PropertiesParsed.ProcessName
                ProcessId         = [System.Int64]    $primaryEvent.PropertiesParsed.ProcessId
                ThreadId          = [System.Int64]    $primaryEvent.PropertiesParsed.ThreadId
                AttributeList     = [System.String[]] $attributeList
                DistinguishedName = [System.String]   $distinguishedName
                ScopeOfSearch     = [System.String]   $scopeOfSearch
                SearchFilter      = [System.String]   $searchFilter
            }

            # Return current normalized LDAP object unless it is a defined default LDAP query and -SkipDefaultEvent input parameter switch is defined.
            if (-not `
                (
                    $PSBoundParameters['SkipDefaultEvent'].IsPresent -and `
                    (
                        ($ldapNormalizedObj.SearchFilter -cin @('(objectClass=*)','(objectclass=*)','objectClass=*')) -and `
                        (
                            ($ldapNormalizedObj.ScopeOfSearch -ceq 'Base') -or `
                            (
                                (-not $ldapNormalizedObj.DistinguishedName) -and `
                                (-not $ldapNormalizedObj.ScopeOfSearch)
                            )
                        )
                    )
                )
            )
            {
                # Return current normalized LDAP object.
                $ldapNormalizedObj
            }
        })
    }
}


function Out-NormalizedLdapServerWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Out-NormalizedLdapServerWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Out-NormalizedLdapServerWinEvent normalizes select properties from ConvertFrom-LdapServerWinEvent function output to enable easier comparison between client- and server-side LDAP logs.

.PARAMETER InputObject

Specifies server-side LDAP log output from ConvertFrom-LdapServerWinEvent function to normalize.

.PARAMETER SkipDefaultEvent

(Optional) Specifies defined default LDAP queries be skipped and not returned to avoid unrelated noise during log analysis. These default LDAP queries are issued automatically immediately before each user-input LDAP query is issued via Invoke-LdapQuery function.

.EXAMPLE

PS C:\> $searchFilter = '   (&(|(((doesNotExist=BLA)    (     1.2.840.113556.1.4.1    =dbo)     (!(!oId.0000001.2.840.000000113556.1.4.000001=s\61bi))   (anr=krb)(description=Al*m*o*n*d*)   ))(name:does.Not.Exist.But.Has.Dot:=doesNotMatter))(name>==))   '
PS C:\> $attributeList = @('oId.0000001.2.840.000000113556.1.4.000001          ','objECTcatEGOry','doesNotExist','*')
PS C:\> $searchRoot = 'LDAP:  /  /  0.9.2342.19200300.100.1.25   =  WinDOM\41IN  ,  oID.0000.0009.2342.19200300.0000100.1.25   =  "LocaL"   '
PS C:\> $scope = 'Subtree'
PS C:\> $startTime = Get-Date
PS C:\> $res = Invoke-LdapQuery -SearchFilter $searchFilter -AttributeList $attributeList -SearchRoot $searchRoot -Scope $scope -Count 2
PS C:\> Start-Sleep -Seconds 2
PS C:\> $endTime = Get-Date
PS C:\> $filterXPath = New-XPathFilter -EventId 1644 -StartTime $startTime -EndTime $endTime -UserName $env:USERNAME
PS C:\> $eventLogRaw = Get-WinEvent -LogName 'Directory Service' -FilterXPath $FilterXPath -ErrorVariable 'ldapServerWinEventErr' -ErrorAction SilentlyContinue
PS C:\> $eventLogRaw | ConvertFrom-LdapServerWinEvent | Out-NormalizedLdapServerWinEvent -SkipDefaultEvent

TimeCreated       : 7/28/2024 10:13:37 PM
EID               : 1644
ProviderName      : Microsoft-Windows-ActiveDirectory_DomainService
ProviderId        : 0e8478c5-3605-4e8c-8497-1e730c959516
LogName           : Directory Service
Level             : 4
LevelDisplayName  : Information
MachineName       : WIN-DBOCOMPNAME.windomain.local
UserId            : S-1-5-21-0123456789-0123456789-0123456789-500
ProcessName       :
ProcessId         : 656
ThreadId          : 3208
AttributeList     : {[all_with_list]name, objectCategory}
DistinguishedName : DC=WinDOMAIN,DC=LocaL
ScopeOfSearch     : Subtree
SearchFilter      :  ( &  ( |  (UNDEFINED)  (name=dbo) ( ! ( !  (name=sabi) ) )  (aNR=krb)  (description=Al*m*o*n*d*)  (UNDEFINED) )  (name>==) )

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [System.Object[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $SkipDefaultEvent
    )

    begin
    {

    }

    process
    {
        # Iterate over each -InputObject value.
        foreach ($curEvent in $InputObject)
        {
            # Build normalized LDAP object for current event so server-side and client-side LDAP data can be easily joined and compared.
            # NOTE: UserId property is present in server-side LDAP logs but not in client-side LDAP logs.
            # NOTE: ProcessName property is present in client-side LDAP logs but not in server-side LDAP logs.
            $ldapNormalizedObj = [PSCustomObject] @{
                TimeCreated       = [System.DateTime] $curEvent.TimeCreated
                EID               = [System.Int16]    $curEvent.Id
                ProviderName      = [System.String]   $curEvent.ProviderName
                ProviderId        = [System.Guid]     $curEvent.ProviderId
                LogName           = [System.String]   $curEvent.LogName
                Level             = [System.Int16]    $curEvent.Level
                LevelDisplayName  = [System.String]   $curEvent.LevelDisplayName
                MachineName       = [System.String]   $curEvent.MachineName
                UserId            = [System.String]   $curEvent.UserId
                ProcessName       =                   $null
                ProcessId         = [System.Int64]    $curEvent.ProcessId
                ThreadId          = [System.Int64]    $curEvent.ThreadId
                AttributeList     = [System.String[]] $curEvent.PropertiesParsed.AttributeSelection
                DistinguishedName = [System.String]   $curEvent.PropertiesParsed.StartingNode
                ScopeOfSearch     = [System.String]   $curEvent.PropertiesParsed.ScopeOfSearch
                SearchFilter      = [System.String]   $curEvent.PropertiesParsed.Filter
            }

            # Return current normalized LDAP object unless it is a defined default LDAP query and -SkipDefaultEvent input parameter switch is defined.
            if (-not `
                (
                    $PSBoundParameters['SkipDefaultEvent'].IsPresent -and `
                    ($ldapNormalizedObj.SearchFilter -ceq ' (objectClass=*) ') -and `
                    ($ldapNormalizedObj.ScopeOfSearch -ceq 'Base') -and `
                    (($ldapNormalizedObj.AttributeList -join ',') -cin @('objectClass','gPLink,gPOptions','[all_with_list]nTSecurityDescriptor'))
                )
            )
            {
                # Return current normalized LDAP object.
                $ldapNormalizedObj
            }
        }
    }

    end
    {

    }
}


function New-XPathFilter
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: New-XPathFilter
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

New-XPathFilter converts input parameter(s) into a single XPath filter string for querying Windows event logs via Get-WinEvent cmdlet.

.PARAMETER EventId

(Optional) Specifies EventId value to include in XPath filter.

.PARAMETER StartTime

(Optional) Specifies StartTime value to include in XPath filter.

.PARAMETER EndTime

(Optional) Specifies EndTime value to include in XPath filter.

.PARAMETER UserName

(Optional) Specifies UserName value to include in XPath filter.

.EXAMPLE

PS C:\> New-XPathFilter -UserName 'KosovoOlympicJudoChampion\MajlindaKelmendi'

Event[EventData[Data='KosovoOlympicJudoChampion\MajlindaKelmendi']]

.EXAMPLE

PS C:\> New-XPathFilter -EventId 2020 -UserName 'KosovoOlympicJudoChampion\NoraGjakova'

Event[System[EventID=2020] and EventData[Data='KosovoOlympicJudoChampion\NoraGjakova']]

.EXAMPLE

PS C:\> New-XPathFilter -EventId 1337 -StartTime ([System.DateTime] '2024-07-27') -EndTime ([System.DateTime] '2024-07-28') -UserName 'KosovoOlympicJudoChampion\DistriaKrasniqi'

Event[System[EventID=1337] and System[TimeCreated[timediff(@SystemTime) <= 172809182]] and System[TimeCreated[timediff(@SystemTime) >= 86409184]] and EventData[Data='KosovoOlympicJudoChampion\DistriaKrasniqi']]

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int64]
        $EventId,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.DateTime]
        $StartTime,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.DateTime]
        $EndTime,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $UserName
    )

    # Create array to store XPath filter elements before joining as final filter string at end of current function.
    $filterXPathArr = @()

    # If user input -EventId parameter is defined then append to XPath filter array.
    if ($PSBoundParameters['EventId'])
    {
        $filterXPathArr += "System[EventID=$($PSBoundParameters['EventId'])]"
    }

    # Capture current time for below timestamp/timediff calculations if user input -StartTime and/or -EndTime parameters are defined.
    # This XPath filter syntax for timediff is defined in the following resource: https://community.spiceworks.com/scripts/show/3238-powershell-xpath-generator-for-windows-events
    $curDate = Get-Date

    # If user input -StartTime parameter is defined then append to XPath filter array.
    if ($PSBoundParameters['StartTime'])
    {
        $timeDiff = [System.Math]::Round(($curDate - $PSBoundParameters['StartTime']).TotalMilliseconds) - 1

        $filterXPathArr += "System[TimeCreated[timediff(@SystemTime) <= $timeDiff]]"
    }

    # If user input -EndTime parameter is defined then append to XPath filter array.
    if ($PSBoundParameters['EndTime'])
    {
        $timeDiff = [System.Math]::Round(($curDate - $PSBoundParameters['EndTime']).TotalMilliseconds) + 1

        $filterXPathArr += "System[TimeCreated[timediff(@SystemTime) >= $timeDiff]]"
    }

    # If user input -UserName parameter is defined then append to XPath filter array.
    if ($PSBoundParameters['UserName'])
    {
        # If -UserName does not include a domain then prepend current DNS domain (if it exists).
        if (-not $PSBoundParameters['UserName'].Contains('\') -and $env:USERDOMAIN)
        {
            $UserName = $env:USERDOMAIN + '\' + $PSBoundParameters['UserName']
        }

        $filterXPathArr += "EventData[Data='$UserName']"
    }

    # Join XPath array into final XPath filter string.
    $filterXPath = 'Event[' + ($filterXPathArr -join ' and ') + ']'

    # Return final XPath filter string.
    $filterXPath
}


function Enable-LdapClientWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Enable-LdapClientWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Enable-LdapClientWinEvent enables client-side LDAP event log visibility per process name by adding corresponding tracing registry keys.

.PARAMETER ProcessName

(Optional) Specifies process names for which to enable LDAP event log visibility by adding corresponding tracing registry keys (defaults to current process name).

.EXAMPLE

PS C:\> Enable-LdapClientWinEvent -ProcessName 'pwsh.exe','powershell.exe'

[*] Checking 2 registry key(s) to enable client-side LDAP logging visibility:
[+] HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing\pwsh.exe: (Successfully created key)
[+] HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing\powershell.exe: (Successfully created key)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $ProcessName
    )

    # Output warning message and return from function if OS is not Windows since client-side LDAP event logs only exist on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required event logs only exists on Windows."
    }

    # If user input -ProcessName parameter is not defined then default to name of current process.
    if ($ProcessName.Count -eq 0)
    {
        $ProcessName += (Get-Command -CommandType Application -Name (Get-Process -Id $PID).ProcessName).Name | Select-Object -First 1
    }

    # Ensure user input -ProcessName parameter does not contain duplicates while maintaining its original order.
    $ProcessName = $ProcessName | Select-Object -Unique

    Write-Host '[*] Checking '       -NoNewline -ForegroundColor Cyan
    Write-Host $ProcessName.Count    -NoNewline -ForegroundColor Yellow
    Write-Host ' registry key(s) to' -NoNewline -ForegroundColor Cyan
    Write-Host ' enable'             -NoNewline -ForegroundColor DarkGreen
    Write-Host ' client-side'        -NoNewline -ForegroundColor DarkMagenta
    Write-Host ' LDAP logging visibility:'      -ForegroundColor Cyan

    # Define LDAP tracing registry path (it should always exist but check just in case).
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing'

    if (Test-Path $registryPath)
    {
        # Ensure a registry key exists for each process name.
        foreach ($curProcessName in $ProcessName)
        {
            # Set full registry key path for current process name.
            $newRegistryPath = Join-Path $registryPath $curProcessName

            Write-Host "[+] $registryPath\" -NoNewline -ForegroundColor Cyan
            Write-Host $curProcessName -NoNewline -ForegroundColor Magenta
            Write-Host ": " -NoNewline -ForegroundColor Cyan

            if (Test-Path $newRegistryPath)
            {
                Write-Host ' (Correct value already exists)' -ForegroundColor Blue
            }
            else
            {
                # Create registry key.
                New-Item -Path $registryPath -Name $curProcessName | Out-Null

                if (Test-Path $newRegistryPath)
                {
                    Write-Host '(Successfully created key)' -ForegroundColor Green
                }
                else
                {
                    Write-Host '(Failed to create key)' -ForegroundColor Red
                }
            }
        }
    }
    else
    {
        Write-Warning "Registry path not found (must be manually created): $registryPath"
    }
}


function Disable-LdapClientWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Disable-LdapClientWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Disable-LdapClientWinEvent disables client-side LDAP event log visibility per process name by removing corresponding tracing registry keys.

.PARAMETER ProcessName

(Optional) Specifies process names for which to disable LDAP event log visibility by removing corresponding tracing registry keys (defaults to current process name).

.EXAMPLE

PS C:\> Disable-LdapClientWinEvent -ProcessName 'pwsh.exe','powershell.exe'

[*] Checking 2 registry key(s) to disable client-side LDAP logging visibility:
[+] HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing\pwsh.exe: (Successfully removed key)
[+] HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing\powershell.exe: (Successfully removed key)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $ProcessName
    )

    # Output warning message and return from function if OS is not Windows since client-side LDAP event logs only exist on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required event logs only exists on Windows."
    }

    # If user input -ProcessName parameter is not defined then default to name of current process.
    if ($ProcessName.Count -eq 0)
    {
        $ProcessName += (Get-Command -CommandType Application -Name (Get-Process -Id $PID).ProcessName).Name | Select-Object -First 1
    }

    # Ensure user input -ProcessName parameter does not contain duplicates while maintaining its original order.
    $ProcessName = $ProcessName | Select-Object -Unique

    Write-Host '[*] Checking '       -NoNewline -ForegroundColor Cyan
    Write-Host $ProcessName.Count    -NoNewline -ForegroundColor Yellow
    Write-Host ' registry key(s) to' -NoNewline -ForegroundColor Cyan
    Write-Host ' disable'            -NoNewline -ForegroundColor DarkRed
    Write-Host ' client-side'        -NoNewline -ForegroundColor DarkMagenta
    Write-Host ' LDAP logging visibility:'      -ForegroundColor Cyan

    # Define LDAP tracing registry path (it should always exist but check just in case).
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap\tracing'

    if (Test-Path $registryPath)
    {
        # Ensure a registry key does not exist for each process name.
        foreach ($curProcessName in $ProcessName)
        {
            # Set full registry key path for current process name.
            $newRegistryPath = Join-Path $registryPath $curProcessName

            Write-Host "[-] $registryPath\" -NoNewline -ForegroundColor Cyan
            Write-Host $curProcessName -NoNewline -ForegroundColor Magenta
            Write-Host ": " -NoNewline -ForegroundColor Cyan

            # Remove registry key for current process name (if it exists).
            if (Test-Path $newRegistryPath)
            {
                # Remove registry key.
                Remove-Item -Path $newRegistryPath | Out-Null

                if (Test-Path $newRegistryPath)
                {
                    Write-Host '(Failed to remove key)' -ForegroundColor Red
                }
                else
                {
                    Write-Host '(Successfully removed key)' -ForegroundColor Green
                }
            }
            else
            {
                Write-Host '(Success - key does not exist)' -ForegroundColor Blue
            }
        }
    }
}


function Enable-LdapServerWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Enable-LdapServerWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Enable-LdapServerWinEvent enables server-side LDAP event log visibility by adding corresponding registry keys and values. It is NOT recommended to enable this logging on a production system as it can produce an enormous load on the system.

.PARAMETER RegistryKey

(Optional) Specifies registry key names for which to create and/or ensure correct value to enable server-side LDAP event log visibility.

.EXAMPLE

PS C:\> Enable-LdapServerWinEvent -RegistryKey 15_Field_Engineering,Expensive_Search_Results_Threshold,Inefficient_Search_Results_Threshold

[*] Checking 3 registry key(s) to enable server-side LDAP logging visibility:
[+] HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering: (Successfully updated key value)
[+] HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Expensive Search Results Threshold: (Successfully updated key value)
[+] HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Inefficient Search Results Threshold: (Successfully updated key value)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('15_Field_Engineering','Expensive_Search_Results_Threshold','Inefficient_Search_Results_Threshold')]
        [System.String[]]
        $RegistryKey = @('15_Field_Engineering','Expensive_Search_Results_Threshold','Inefficient_Search_Results_Threshold')
    )

    # Output warning message and return from function if OS is not Windows since server-side LDAP event logs only exist on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required event logs only exists on Windows."
    }

    # Ensure user input -RegistryKey parameter does not contain duplicates while maintaining its original order.
    $RegistryKey = $RegistryKey | Select-Object -Unique

    # Define filtered list of registry keys and their corresponding values required to enable server-side LDAP logging based on user input -RegistryKey parameter.
    $registryKeyObjArr = @(switch ($RegistryKey)
    {
        '15_Field_Engineering' {
            [PSCustomObject] @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
                Name = '15 Field Engineering'
                Value = 5
                Type = 'DWORD'
            }
        }
        'Expensive_Search_Results_Threshold' {
            [PSCustomObject] @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                Name = 'Expensive Search Results Threshold'
                Value = 1
                Type = 'DWORD'
            }
        }
        'Inefficient_Search_Results_Threshold' {
            [PSCustomObject] @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                Name = 'Inefficient Search Results Threshold'
                Value = 1
                Type = 'DWORD'
            }
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    })

    Write-Host '[*] Checking '          -NoNewline -ForegroundColor Cyan
    Write-Host $registryKeyObjArr.Count -NoNewline -ForegroundColor Yellow
    Write-Host ' registry key(s) to'    -NoNewline -ForegroundColor Cyan
    Write-Host ' enable'                -NoNewline -ForegroundColor DarkGreen
    Write-Host ' server-side'           -NoNewline -ForegroundColor DarkMagenta
    Write-Host ' LDAP logging visibility:'         -ForegroundColor Cyan

    # Ensure each registry key is created and set to proper value defined above.
    foreach ($registryKeyObj in $registryKeyObjArr)
    {
        Write-Host "[+] $($registryKeyObj.Path)\" -NoNewline -ForegroundColor Cyan
        Write-Host $registryKeyObj.Name             -NoNewline -ForegroundColor Magenta
        Write-Host ": "                             -NoNewline -ForegroundColor Cyan

        # Retrieve current registry key and key value.
        $curRegistryKey = (Get-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -ErrorAction SilentlyContinue)
        $curRegistryKeyValue = $curRegistryKey.($registryKeyObj.Name)

        # If current registry key is defined then ensure its value is correct; otherwise, create registry key and initialize its value.
        if ($curRegistryKey)
        {
            if ($curRegistryKeyValue -ne $registryKeyObj.Value)
            {
                # Update registry key's value.
                Set-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -Value $registryKeyObj.Value

                # Re-retrieve value of current registry key.
                $curRegistryKeyValue = (Get-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -ErrorAction SilentlyContinue).($registryKeyObj.Name)

                if ($curRegistryKeyValue -eq $registryKeyObj.Value)
                {
                    Write-Host '(Successfully updated key value)' -ForegroundColor Green
                }
                else
                {
                    Write-Host '(Failed to update key value)' -ForegroundColor Red
                }
            }
            else
            {
                Write-Host $curRegistryKeyValue   -NoNewline -ForegroundColor Green
                Write-Host ' (Correct value already exists)' -ForegroundColor Blue
            }
        }
        else
        {
            # Create registry key and initialize its value.
            New-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -Value $registryKeyObj.Value -PropertyType $registryKeyObj.Type -Force | Out-Null

            # Re-retrieve current registry key and key value.
            $curRegistryKey = (Get-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -ErrorAction SilentlyContinue)
            $curRegistryKeyValue = $curRegistryKey.($registryKeyObj.Name)

            if (-not $curRegistryKey)
            {
                Write-Host '(Failed to create key)' -ForegroundColor Red
            }
            else
            {
                if ($curRegistryKeyValue -eq $registryKeyObj.Value)
                {
                    Write-Host '(Successfully created key and set value)' -ForegroundColor Green
                }
                else
                {
                    Write-Host '(Successfully created key but failed to set value)' -ForegroundColor Red
                }
            }
        }
    }
}


function Disable-LdapServerWinEvent
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Disable-LdapServerWinEvent
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Disable-LdapServerWinEvent disables server-side LDAP event log visibility by ensuring corresponding registry keys are not present or have a value of '0'.

.PARAMETER RegistryKey

(Optional) Specifies registry key names for which to ensure are not present or have a value of '0' to disable server-side LDAP event log visibility.

.EXAMPLE

PS C:\> Disable-LdapServerWinEvent -RegistryKey 15_Field_Engineering,Expensive_Search_Results_Threshold,Inefficient_Search_Results_Threshold

[*] Checking 3 registry key(s) to disable server-side LDAP logging visibility:
[-] HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering: (Successfully updated key value to '0')
[-] HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Expensive Search Results Threshold: (Successfully updated key value to '0')
[-] HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\Inefficient Search Results Threshold: (Successfully updated key value to '0')

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('15_Field_Engineering','Expensive_Search_Results_Threshold','Inefficient_Search_Results_Threshold')]
        [System.String[]]
        $RegistryKey = @('15_Field_Engineering','Expensive_Search_Results_Threshold','Inefficient_Search_Results_Threshold')
    )

    # Output warning message and return from function if OS is not Windows since server-side LDAP event logs only exist on Windows.
    if ($IsMacOS -or $IsLinux)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Current OS is not Windows so exiting current function since required event logs only exists on Windows."
    }

    # Ensure user input -RegistryKey parameter does not contain duplicates while maintaining its original order.
    $RegistryKey = $RegistryKey | Select-Object -Unique

    # Define filtered list of registry keys and their corresponding values required to enable server-side LDAP logging based on user input -RegistryKey parameter.
    $registryKeyObjArr = @(switch ($RegistryKey)
    {
        '15_Field_Engineering' {
            [PSCustomObject] @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
                Name = '15 Field Engineering'
                Value = 5
                Type = 'DWORD'
            }
        }
        'Expensive_Search_Results_Threshold' {
            [PSCustomObject] @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                Name = 'Expensive Search Results Threshold'
                Value = 1
                Type = 'DWORD'
            }
        }
        'Inefficient_Search_Results_Threshold' {
            [PSCustomObject] @{
                Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                Name = 'Inefficient Search Results Threshold'
                Value = 1
                Type = 'DWORD'
            }
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    })

    Write-Host '[*] Checking '          -NoNewline -ForegroundColor Cyan
    Write-Host $registryKeyObjArr.Count -NoNewline -ForegroundColor Yellow
    Write-Host ' registry key(s) to'    -NoNewline -ForegroundColor Cyan
    Write-Host ' disable'               -NoNewline -ForegroundColor DarkRed
    Write-Host ' server-side'           -NoNewline -ForegroundColor DarkMagenta
    Write-Host ' LDAP logging visibility:'         -ForegroundColor Cyan

    # Ensure each registry key (if present) is not set to proper value defined above (default to 0).
    foreach ($registryKeyObj in $registryKeyObjArr)
    {
        Write-Host "[-] $($registryKeyObj.Path)\" -NoNewline -ForegroundColor Cyan
        Write-Host $registryKeyObj.Name             -NoNewline -ForegroundColor Magenta
        Write-Host ": "                             -NoNewline -ForegroundColor Cyan

        # Retrieve current registry key and key value.
        $curRegistryKey = (Get-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -ErrorAction SilentlyContinue)
        $curRegistryKeyValue = $curRegistryKey.($registryKeyObj.Name)

        # If current registry key is defined then ensure its value is not correct; otherwise, do nothing if registry key is not defined.
        if ($curRegistryKey)
        {
            if ($curRegistryKeyValue -eq $registryKeyObj.Value)
            {
                # Define new key value to be 0 to disable logging.
                $newKeyValue = 0

                # Update registry key's value.
                Set-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -Value $newKeyValue

                # Re-retrieve value of current registry key.
                $curRegistryKeyValue = (Get-ItemProperty -Path $registryKeyObj.Path -Name $registryKeyObj.Name -ErrorAction SilentlyContinue).($registryKeyObj.Name)

                if ($curRegistryKeyValue -eq $registryKeyObj.Value)
                {
                    Write-Host "(Failed to update key value to '$newKeyValue')" -ForegroundColor Red
                }
                else
                {
                    Write-Host "(Successfully updated key value to '$newKeyValue')" -ForegroundColor Green
                }
            }
            else
            {
                Write-Host $curRegistryKeyValue   -NoNewline -ForegroundColor Green
                Write-Host " (Value is already '$curRegistryKeyValue' so nothing to modify)" -ForegroundColor Blue
            }
        }
        else
        {
            Write-Host '(Success - key does not exist)' -ForegroundColor Blue
        }
    }
}