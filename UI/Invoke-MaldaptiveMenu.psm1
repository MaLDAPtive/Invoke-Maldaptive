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



##########################################################################################################
## All functions in this module are solely for the menu-driven Invoke-Maldaptive exploratory experience ##
## and do not provide any additional obfuscation, deobfuscation or detection functionality.             ##
## This menu-driven experience is included to more easily enable Red and Blue Teamers to explore the    ##
## MaLDAPtive options in a quick and visual manner.                                                     ##
##########################################################################################################


function Invoke-Maldaptive
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Invoke-Maldaptive
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: New-ObfuscationContainer, Show-AsciiArt, Show-HelpMenu, Show-Menu
Optional Dependencies: None

.DESCRIPTION

Invoke-Maldaptive orchestrates the application of all obfuscation, deobfuscation and detection functions to input LDAP SearchFilter in a colorful and visually-pleasing format to demonstrate the effectiveness of layered obfuscation techniques and corresponding detection logic.

.PARAMETER SearchFilter

Specifies initial LDAP SearchFilter to obfuscate, deobfuscate and/or detect.

.PARAMETER SearchFilterPath

Specifies path to initial LDAP SearchFilter to obfuscate, deobfuscate and/or detect (can be local file, UNC-path, or remote URI).

.PARAMETER SearchRoot

(Optional) Specifies LDAP SearchRoot to specify the base of the subtree for constraining the LDAP SearchRequest if testing LDAP SearchFilter.

.PARAMETER AttributeList

(Optional) Specifies LDAP AttributeList to limit properties returned for any matching objects returned by LDAP SearchRequest if testing LDAP SearchFilter.

.PARAMETER Scope

(Optional) Specifies LDAP Scope to limit portions of targeted subtree to be traversed by LDAP SearchRequest if testing LDAP SearchFilter.

.PARAMETER Command

(Optional) Specifies obfuscation, deobfuscation and/or detection command(s) to run against input -SearchFilter or -SearchFilterPath parameter.

.PARAMETER OutputFormat

(Optional - only works if -Command is specified and -NoExit is not specified) Specifies output format of final obfuscated command, with 'string' returning command as string and 'container' returning entire obfuscation container object (which includes all layers of obfuscation).

.PARAMETER NoExit

(Optional) Specifies that the function not exit after running obfuscation, deobfuscation and/or detection commands defined in -Command parameter.

.PARAMETER Quiet

(Optional) Specifies that the function suppress unnecessary output during startup (and during duration of function calls if -Command is specified).

.EXAMPLE

C:\PS> Invoke-Maldaptive

.EXAMPLE

C:\PS> Invoke-Maldaptive -SearchFilter '(|(name=sabi)(name=dbo))'

.EXAMPLE

C:\PS> Invoke-Maldaptive -SearchFilter '(|(name=sabi)(name=dbo))' -Command 'OBFUSCATE\INSERT\WHITESPACE\4' -Quiet -NoExit

.EXAMPLE

C:\PS> Invoke-Maldaptive -SearchFilter '(|(name=sabi)(name=dbo))' -Command 'OBFUSCATE,****,****' -Quiet

((  |  ((((&((   1.2.840.113556.1.4.1=  *)(   1.2.840.113556.1.4.1=  *S\41\42\49*))))((&(( 1;2.143.416556.1;4.4=  *Bo*\*'*))(( 1;2.143.416556.1;4.4=  *)( |1;2.143.416556.1;4.4=  DB*))(( |1;2.143.416556.1;4.4=  *)))     (&(( 1.2.544.113952.1.4.1=  *)( 1.2.544.113952.1.4.1=  Bo*))((& 1.2.544.113952.1.4.1=  *Od))((& 1.2.544.113952.1.4.1=  *))))((&(( !1.2.840.113556.1.4.1=  eS)( 1.2.840.113556.1.4.1   =  *)( 1.2.840.113556.1.4.1   =  *))((!((&(( 1.2.840.113556.1.4.1=  **529)( 1.2.840.113556.1.4.1=  b5**))))))((& 1.2.840.113556.1.4.1=  *DBO**))((& 1.2.840.113556.1.4.1=  *))))))((&((& FhVNYEF6nrHIVFYXZEG=  *)(& FhVNYEF6NrHIVFYXZEG=  ES)))))   )

.EXAMPLE

C:\PS> Invoke-Maldaptive -SearchFilter '(|(name=sabi)(name=dbo))' -Command 'OBFUSCATE\INSERT\WHITESPACE\4,OBFUSCATE\INSERT\PARENTHESIS\*' -OutputFormat container -Quiet

SearchRoot                 : LDAP://DC=contoso,DC=com
AttributeList              : {*}
Scope                      : Subtree
Layer                      : 2
SearchFilter               :  ((   | ((  name=   sabi) (   name=   dbo))  )   )
SearchFilterTokenized      : {Guid: , Depth: 0, Length: 1, Format: NA, IsDefined: , Type: Whitespace, SubType: , 
                             ScopeSyntax: , ScopeApplication: , Content:  , ContentDecoded:  , Guid: , Depth: 0, Length: 
                             1, Format: NA, IsDefined: , Type: GroupStart, SubType: , ScopeSyntax: FilterList, 
                             ScopeApplication: FilterList, Content: (, ContentDecoded: (, Guid: , Depth: 1, Length: 1, 
                             Format: NA, IsDefined: , Type: GroupStart, SubType: , ScopeSyntax: FilterList, 
                             ScopeApplication: FilterList, Content: (, ContentDecoded: (, Guid: , Depth: 1, Length: 3, 
                             Format: NA, IsDefined: , Type: Whitespace, SubType: , ScopeSyntax: , ScopeApplication: , 
                             Content:    , ContentDecoded:    …}
SearchFilterLength         : 50
SearchFilterTokenCount     : 27
FilterCount                : 2
SearchFilterDepth          : 4
SearchFilterMD5            : 44A86C2E8975C67B90C7B5BAA77D3588
SearchFilterOrig           : (|(name=sabi)(name=dbo))
SearchFilterOrigLength     : 24
SearchFilterOrigTokenCount : 13
FilterOrigCount            : 2
SearchFilterOrigDepth      : 2
SearchFilterOrigMD5        : 266567844BAB450896FB73B49291A59A
SearchFilterPath           : N/A
History                    : {@{Layer=0; SearchFilter=(|(name=sabi)(name=dbo)); 
                             SearchFilterTokenized=Maldaptive.LdapTokenEnriched[]; SearchFilterLength=24; 
                             SearchFilterTokenCount=13; FilterCount=2; SearchFilterDepth=2; 
                             SearchFilterMD5=266567844BAB450896FB73B49291A59A; SearchFilterOrig=(|(name=sabi)(name=dbo)); 
                             SearchFilterOrigLength=24; SearchFilterOrigTokenCount=13; FilterOrigCount=2; 
                             SearchFilterOrigDepth=2; SearchFilterOrigMD5=266567844BAB450896FB73B49291A59A; 
                             Function=New-ObfuscationContainer; CommandLineSyntax='(|(name=sabi)(name=dbo))'; 
                             CliSyntax=System.Object[]}, @{Layer=1; SearchFilter= (   | (  name=   sabi) (   name=   dbo) 
                              )   ; SearchFilterTokenized=Maldaptive.LdapTokenEnriched[]; SearchFilterLength=46; 
                             SearchFilterTokenCount=23; FilterCount=2; SearchFilterDepth=2; 
                             SearchFilterMD5=94338F59CF32F41D231458C8CD1CA277; SearchFilterOrig=(|(name=sabi)(name=dbo)); 
                             SearchFilterOrigLength=24; SearchFilterOrigTokenCount=13; FilterOrigCount=2; 
                             SearchFilterOrigDepth=2; SearchFilterOrigMD5=266567844BAB450896FB73B49291A59A; 
                             CommandLineSyntax=Add-RandomWhitespace -RandomNodePercent 100; CliSyntax=System.Object[]; 
                             Function=Add-RandomWhitespace}, @{Layer=2; SearchFilter= ((   | ((  name=   sabi) (   name=  
                              dbo))  )   ); SearchFilterTokenized=Maldaptive.LdapTokenEnriched[]; SearchFilterLength=50; 
                             SearchFilterTokenCount=27; FilterCount=2; SearchFilterDepth=4; 
                             SearchFilterMD5=44A86C2E8975C67B90C7B5BAA77D3588; SearchFilterOrig=(|(name=sabi)(name=dbo)); 
                             SearchFilterOrigLength=24; SearchFilterOrigTokenCount=13; FilterOrigCount=2; 
                             SearchFilterOrigDepth=2; SearchFilterOrigMD5=266567844BAB450896FB73B49291A59A; 
                             CommandLineSyntax=Add-RandomParenthesis -RandomNodePercent 75; CliSyntax=System.Object[]; 
                             Function=Add-RandomParenthesis}}

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [PSCustomObject],
        [System.String],
        [System.Void]
    )]
    [CmdletBinding(DefaultParameterSetName = 'SearchFilter')]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'SearchFilter')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SearchFilter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'SearchFilterPath')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SearchFilterPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $SearchRoot = $global:defaultSearchRoot,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $AttributeList = $global:defaultAttributeList,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Base','OneLevel','Subtree')]
        [System.String]
        $Scope = $global:defaultScope,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Command,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('string','container')]
        [System.String]
        $OutputFormat = 'string',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $NoExit,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Quiet
    )

    # Ensure Invoke-Maldaptive module was properly imported before continuing.
    if (-not (Get-Module -Name Maldaptive))
    {
        # Set path to .psd1 file and encapsulate with quotes if the path contains whitespace for more accurate output to user.
        $psd1Path = Join-Path -Path $scriptDir -ChildPath 'Maldaptive.psd1'
        if ($psd1Path.Contains(' '))
        {
            $psd1Path = "`"$psd1Path`""
        }

        # Output error message and exit if MaLDAPtive module is not loaded.
        Write-Host "`n`nERROR: MaLDAPtive module is not loaded. You must run:" -ForegroundColor Red
        Write-Host "       Import-Module $psd1Path`n`n" -ForegroundColor Yellow
        Start-Sleep -Seconds 5

        exit
    }

    # If both -SearchFilter and -SearchFilterPath input parameters are defined then throw warning message and proceed with only using -SearchFilter.
    if ($PSBoundParameters['SearchFilter'] -and $PSBoundParameters['SearchFilterPath'])
    {
        Write-Warning 'Both -SearchFilter and -SearchFilterPath input parameters are defined. Defaulting to -SearchFilter input parameter.'
    }

    # Store input -SearchFilter or -SearchFilterPath input parameters as CLI commands for automated processing.
    if ($PSBoundParameters['SearchFilter'])
    {
        # Build new obfuscation container.
        $ldapObfContainer = New-ObfuscationContainer -SearchFilter $SearchFilter -SearchRoot:$SearchRoot -AttributeList:$AttributeList -Scope:$Scope

        # Set N/A value in SearchFilterPath property of newly-created obfuscation container.
        $ldapObfContainer.SearchFilterPath = 'N/A'
    }
    elseif ($PSBoundParameters['SearchFilterPath'])
    {
        # Read in $SearchFilter value from -SearchFilterPath (either file on disk or remotely hosted file).
        if ((Test-Path $SearchFilterPath) -or ($userInputOptionValue -imatch '^(http|https):[/\\]'))
        {
            # Check if -SearchFilterPath input parameter is a URL or a directory.
            if ($SearchFilterPath -imatch '^(http|https):[/\\]')
            {
                # SearchFilterPath is a URL.

                # Download content from remote location and set to $SearchFilter variable (overwriting existing value if present).
                $SearchFilter = (New-Object Net.WebClient).DownloadString($SearchFilterPath)

                # Build new obfuscation container.
                $ldapObfContainer = New-ObfuscationContainer -SearchFilter $SearchFilter -SearchRoot:$SearchRoot -AttributeList:$AttributeList -Scope:$Scope

                # Set user-input SEARCHFILTERPATH value into SearchFilterPath property of newly-created obfuscation container.
                $ldapObfContainer.SearchFilterPath = $SearchFilterPath
            }
            elseif ((Get-Item $SearchFilterPath) -is [System.IO.DirectoryInfo])
            {
                # SearchFilterPath is a directory instead of a file.
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' -SearchFilterPath path is a directory instead of a file (' -NoNewline
                Write-Host "$SearchFilterPath" -NoNewline -ForegroundColor Cyan
                Write-Host ").`n" -NoNewline
            }
            else
            {
                # Build new obfuscation container with file content from user-input -SearchFilterPath parameter.
                $ldapObfContainer = New-ObfuscationContainer -Path (Resolve-Path $SearchFilterPath).Path -SearchRoot:$SearchRoot -AttributeList:$AttributeList -Scope:$Scope

                # Set user-input SEARCHFILTERPATH value into SearchFilterPath property of newly-created obfuscation container.
                $ldapObfContainer.SearchFilterPath = (Resolve-Path $SearchFilterPath).Path
            }
        }
        else
        {
            # SearchFilterPath not found (failed Test-Path).
            Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
            Write-Host ' -SearchFilterPath path not found (' -NoNewline
            Write-Host "$SearchFilterPath" -NoNewline -ForegroundColor Cyan
            Write-Host ").`n" -NoNewline
        }
    }
    else
    {
        # Build new obfuscation container with "empty" command (passed as single whitespace to avoid null argument error from New-ObfuscationContainer).
        $ldapObfContainer = New-ObfuscationContainer -SearchFilter ' ' -SearchRoot:$SearchRoot -AttributeList:$AttributeList -Scope:$Scope
    }

    # Append Command to CliCommands if specified by user input.
    if ($PSBoundParameters['Command'])
    {
        # Extract potential concatenated commands while applying special logic if 'SET SEARCHFILTER' command is present to avoid setting an incomplete value.

        # Split -Command value into appropriate sub-commands if applicable.
        $cliCommand = $Command | Split-Command

        # If -Quiet input parameter is defined, create empty Write-Host and Start-Sleep proxy functions to cause any Write-Host or Start-Sleep invocations to do nothing until non-interactive -Command values are finished being processed.
        if ($PSBoundParameters['Quiet'].IsPresent)
        {
            function global:Write-Host {}
            function global:Start-Sleep {}
        }
    }

    # Define options menu to be displayed when 'SHOW OPTIONS' command is entered.
    $optionMenu = @(
        [PSCustomObject] @{ Name = 'SearchFilterPath'  ; Value = $SearchFilterPath; Settable = $true  }
        [PSCustomObject] @{ Name = 'SearchFilter'      ; Value = $SearchFilter    ; Settable = $true  }
        [PSCustomObject] @{ Name = 'SearchRoot'        ; Value = $SearchRoot      ; Settable = $true  }
        [PSCustomObject] @{ Name = 'AttributeList'     ; Value = @($AttributeList); Settable = $true  }
        [PSCustomObject] @{ Name = 'Scope'             ; Value = $Scope           ; Settable = $true  }
        [PSCustomObject] @{ Name = 'CommandLineSyntax' ; Value = @()              ; Settable = $false }
        [PSCustomObject] @{ Name = 'ExecutionCommands' ; Value = @()              ; Settable = $false }
        [PSCustomObject] @{ Name = 'ObfSearchFilter'   ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'FilterCount'       ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'Length'            ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'Depth'             ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'DetectionScore'    ; Value = $null            ; Settable = $false }
        [PSCustomObject] @{ Name = 'DetectionCount'    ; Value = $null            ; Settable = $false }
    )

    # Build interactive menus.
    $lineHeader = '[*] '

    # Main Menu.
    $menuLevel = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'OBFUSCATE  '; Description = '<Obfuscate> LDAP SearchFilter'   }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'DEOBFUSCATE'; Description = '<Deobfuscate> LDAP SearchFilter' }
    )

    # Main\Deobfuscate Menu.
    $menuLevel_Deobfuscate = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'REMOVE'; Description = '<Remove> tokens from existing Filters' }
    )

    # Main\Deobfuscate\Remove Menu.
    $menuLevel_Deobfuscate_Remove = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WHITESPACE             '; Description = 'Randomly remove <Whitespace> tokens'                                                         }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'PARENTHESIS            '; Description = 'Randomly remove <Parenthesis> tokens'                                                        }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'EXTENSIBLEMATCHFILTER  '; Description = 'Randomly remove <Extensible Match Filter> tokens'                                            }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'BOOLEANOPERATOR        '; Description = 'Randomly remove <Boolean Operator> tokens'                                                   }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'BOOLEANOPERATORINVERTED'; Description = 'Randomly remove <Inverted Boolean Operator> tokens'                                          }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = 'WILDCARD               '; Description = 'Randomly remove <Wildcard> characters from value of eligible filters'; Attribute = '(lossy)' }
    )

    # Define arguments required by all obfuscation functions to properly track modification(s) and return result as appropriately formatted LdapTokenEnriched[] for UI highlighting purposes.
    # These arguments will be executed but not included in CommandLineSyntax property tracking or UI since they are only used when invoking functions from current Invoke-Maldaptive UI function.
    $requiredFunctionPrefixArgumentsToHideFromUI = '$searchFilter | '
    $requiredFunctionSuffixArgumentsToHideFromUI = ' -Target LdapTokenEnriched -TrackModification'

    # Main\Deobfuscate\Remove\Whitespace Menu.
    $descriptionPrefix = 'Randomly remove <Whitespace> tokens'
    $menuLevel_Deobfuscate_Remove_Whitespace = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1  '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2  '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 50'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3  '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 75'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4  '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWhitespace -RandomNodePercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\Remove\Parenthesis Menu.
    $descriptionPrefix = 'Randomly remove <Parenthesis> tokens'
    $menuLevel_Deobfuscate_Remove_Parenthesis = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1  '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomParenthesis -RandomNodePercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2  '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomParenthesis -RandomNodePercent 50'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3  '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomParenthesis -RandomNodePercent 75'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4  '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomParenthesis -RandomNodePercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\Remove\ExtensibleMatchFilter Menu.
    $descriptionPrefix = 'Randomly remove <Extensible Match Filter> tokens'
    $menuLevel_Deobfuscate_Remove_ExtensibleMatchFilter = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1  '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomExtensibleMatchFilter -RandomNodePercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2  '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomExtensibleMatchFilter -RandomNodePercent 50'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3  '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomExtensibleMatchFilter -RandomNodePercent 75'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4  '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomExtensibleMatchFilter -RandomNodePercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\Remove\BooleanOperator Menu.
    $descriptionPrefix = 'Randomly remove <Boolean Operator> tokens'
    $menuLevel_Deobfuscate_Remove_BooleanOperator = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1  '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperator -RandomNodePercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2  '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperator -RandomNodePercent 50'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3  '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperator -RandomNodePercent 75'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4  '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperator -RandomNodePercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\Remove\BooleanOperatorInverted Menu.
    $descriptionPrefix = 'Randomly remove <Inverted Boolean Operator> tokens'
    $menuLevel_Deobfuscate_Remove_BooleanOperatorInverted = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1  '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperatorInversion -RandomNodePercent 25'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2  '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperatorInversion -RandomNodePercent 50'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3  '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperatorInversion -RandomNodePercent 75'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4  '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomBooleanOperatorInversion -RandomNodePercent 100' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Main\Deobfuscate\Remove\Wildcard Menu.
    $descriptionPrefix = 'Randomly remove <Wildcard> characters from value of eligible filters'
    $menuLevel_Deobfuscate_Remove_Wildcard = @(
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '1  '; Description = "$descriptionPrefix -  25%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 25 -RandomCharPercent 20'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '2  '; Description = "$descriptionPrefix -  50%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 50 -RandomCharPercent 40'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '3  '; Description = "$descriptionPrefix -  75%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 75 -RandomCharPercent 60'  + $requiredFunctionSuffixArgumentsToHideFromUI }
        [PSCustomObject] @{ LineHeader = $lineHeader; Option = '4  '; Description = "$descriptionPrefix - 100%"; FunctionCall = $requiredFunctionPrefixArgumentsToHideFromUI + 'Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 80' + $requiredFunctionSuffixArgumentsToHideFromUI }
    )

    # Input options to display non-interactive menus or to perform actions.
    $allInputOptionMenu = [PSCustomObject] @{
        Tutorial         = [PSCustomObject] @{ Option = @('tutorial')                            ; Description = '<Tutorial> of how to use this tool          ' }
        ShowHelp         = [PSCustomObject] @{ Option = @('help','get-help','?','-?','/?','menu'); Description = 'Show this <Help> Menu                       ' }
        ShowOption       = [PSCustomObject] @{ Option = @('show options','show','options')       ; Description = '<Show options> for payload to obfuscate     ' }
        ClearScreen      = [PSCustomObject] @{ Option = @('clear','clear-host','cls')            ; Description = '<Clear> screen                              ' }
        CopyToClipboard  = [PSCustomObject] @{ Option = @('copy','clip','clipboard')             ; Description = '<Copy> ObfSearchFilter to clipboard         ' }
        OutputTree       = [PSCustomObject] @{ Option = @('tree')                                ; Description = 'Print <Tree> format of ObfSearchFilter      ' }
        OutputToDisk     = [PSCustomObject] @{ Option = @('out')                                 ; Description = 'Write ObfSearchFilter <Out> to disk         ' }
        ExportToDisk     = [PSCustomObject] @{ Option = @('export')                              ; Description = '<Export> LdapObfContainer CliXml to disk    ' }
        ExecuteCommand   = [PSCustomObject] @{ Option = @('exec','execute','test','run')         ; Description = '<Execute> ObfSearchFilter locally           ' }
        FindEvil         = [PSCustomObject] @{ Option = @('detect','find-evil')                  ; Description = '<Detect> Obfuscation in ObfSearchFilter     ' }
        ResetObfuscation = [PSCustomObject] @{ Option = @('reset')                               ; Description = '<Reset> ALL obfuscation for ObfSearchFilter ' }
        UndoObfuscation  = [PSCustomObject] @{ Option = @('undo')                                ; Description = '<Undo> LAST obfuscation for ObfSearchFilter ' }
        BackMenu         = [PSCustomObject] @{ Option = @('back','cd ..')                        ; Description = 'Go <Back> to previous obfuscation menu      ' }
        Exit             = [PSCustomObject] @{ Option = @('quit','exit')                         ; Description = '<Quit> Invoke-Maldaptive                    ' }
        HomeMenu         = [PSCustomObject] @{ Option = @('home','main')                         ; Description = 'Return to <Home> Menu                       ' }
    }

    # Display animated ASCII art and banner if -Quiet in parameter is not specified.
    if (-not $PSBoundParameters['Quiet'].IsPresent)
    {
        # Obligatory ASCII Art.
        Write-Host ''
        Show-AsciiArt -Animated
        Start-Sleep -Milliseconds 1500

        # Show Help Menu once at beginning of script.
        Show-HelpMenu -InputOptionMenu $allInputOptionMenu
    }

    # Main loop for user interaction. Show-Menu function displays current function along with acceptable input options (defined in arrays instantiated above).
    # User input and validation is handled within Show-Menu.
    $userResponse = ''
    while ($allInputOptionMenu.Exit.Option -inotcontains ([System.String] $userResponse))
    {
        $userResponse = ([System.String] $userResponse).Trim()

        if ($allInputOptionMenu.HomeMenu.Option -icontains ([System.String] $userResponse))
        {
            $userResponse = ''
        }

        # Display menu if it is defined in a menu variable with $userResponse in the variable name.
        $menuVariable = (Get-Variable -Name "MenuLevel$userResponse" -ErrorAction SilentlyContinue).Value
        if (-not $menuVariable)
        {
            Write-Error "The variable MenuLevel$userResponse does not exist."

            $userResponse = 'quit'
        }
        else {
            $menuResponse = Show-Menu -Menu $menuVariable -MenuName $userResponse -OptionMenu $optionMenu -InputOptionMenu $allInputOptionMenu -LdapObfContainer $ldapObfContainer -CliCommand:$cliCommand

            # Parse out next menu response from user and LdapObfContainer and potential remaining CliCommand returned from Show-Menu function above.
            $userResponse     = [System.String]   $menuResponse.UserResponse.ToLower()
            $ldapObfContainer = [PSCustomObject]  $menuResponse.LdapObfContainer
            $cliCommand       = [System.String[]] $menuResponse.CliCommand

            # Temporarily output message if OBFUSCATE menu is traversed explaining the intentional delayed release timeline for the MaLDAPtive obfuscation module.
            if ($userResponse -ceq '_obfuscate')
            {
                Write-Host "`nWARNING: " -NoNewline -ForegroundColor Red
                Write-Host 'Obfuscation module is complete but will be released at a later time (estimated EOY 2024).'
                Write-Host '         This is meant to give fellow defenders a headstart in implementing defensive measures like:'
                Write-Host '         [+] ' -NoNewline -ForegroundColor Cyan
                Write-Host 'Orchestrating client- and server-side LDAP logging'
                Write-Host '         [+] ' -NoNewline -ForegroundColor Cyan
                Write-Host 'Automating invocation of ' -NoNewline
                Write-Host 'Find-Evil -Summarize' -NoNewline -ForegroundColor Green
                Write-Host ' to evaluate MaLDAPtive detection ruleset'

                # Blank out current user response so calling function will not attempt to load a non-existent menu variable.
                $userResponse = ''
            }
        }

        if (($userResponse -eq 'quit') -and $PSBoundParameters['Command'] -and -not $PSBoundParameters['NoExit'].IsPresent)
        {
            # Return current obfuscated command as a string or return the entire command container based on -OutputFormat input parameter value.
            switch ($OutputFormat)
            {
                'string' {
                    return $ldapObfContainer.SearchFilter.Trim("`n")
                }
                'container' {
                    return $ldapObfContainer
                }
                default
                {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }
        }
    }
}


# Get location of this script no matter what the current directory is for the process executing this script.
$scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)


function Show-Menu
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Show-Menu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: 'Split-Command', 'New-ObfuscationContainer', 'Add-ObfuscationLayer', 'Out-LdapObject', 'Show-HelpMenu', 'Show-OptionsMenu', 'Show-Tutorial', 'Find-Evil', 'Show-EvilSummary', 'Remove-ObfuscationLayer', 'Invoke-LdapQuery'
Optional Dependencies: None

.DESCRIPTION

Show-Menu displays current menu with obfuscation navigation and application options for Invoke-Maldaptive and handles interactive user input loop.

.PARAMETER Menu

Specifies menu options to display, with acceptable input options parsed out of this array.

.PARAMETER MenuName

(Optional) Specifies menu header display and breadcrumb used in the interactive prompt display.

.PARAMETER OptionMenu

Specifies properties and values to be displayed when 'SHOW OPTIONS' command is entered.

.PARAMETER InputOptionMenu

Specifies all acceptable input options in addition to each menu's specific acceptable inputs (e.g. 'EXIT', 'QUIT', 'BACK', 'HOME', 'MAIN', etc.).

.PARAMETER CliCommand

(Optional) Specifies user input commands during non-interactive CLI usage.

.PARAMETER LdapObfContainer

Specifies obfuscation container from which relevant values will be extracted or modified if needed.

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]
        $Menu,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $MenuName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.Object[]]
        $OptionMenu,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $InputOptionMenu,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $CliCommand,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $LdapObfContainer
    )

    # Boolean for output and execution purposes if current option is designated to execute a command rather than change to a new menu.
    $selectionContainsCommand = $false
    $acceptableInput = @(foreach ($menuLine in $Menu)
    {
        # If FunctionCall property is present in current line then it is a command to execute if selected.
        if ($menuLine.FunctionCall)
        {
            $selectionContainsCommand = $true
        }

        # Return current menu option value.
        $menuLine.Option.Trim()
    })

    $userInput = $null

    # Loop until user inputs valid input.
    while ($acceptableInput -inotcontains $userInput)
    {
        # Format custom breadcrumb prompt.
        Write-Host "`n"
        $breadCrumb = $MenuName.Trim('_')
        if ($breadCrumb.Length -gt 1)
        {
            if ($breadCrumb -ieq 'show options')
            {
                $breadCrumb = 'Show Options'
            }
            if ($MenuName)
            {
                # Handle specific case substitutions from what is ALL CAPS in interactive menu and then correct casing we want to appear in the breadcrumb.
                $breadCrumbCorrectedCasing  = [PSCustomObject] @{
                    oid                     = 'OID'
                    extensiblematchfilter   = 'ExtensibleMatchFilter'
                    filterpresence          = 'FilterPresence'
                    filterrandom            = 'FilterRandom'
                    filterbreakoutrange     = 'FilterBreakoutRange'
                    filterbreakoutwildcard  = 'FilterBreakoutWildcard'
                    bitwiseconversion       = 'BitwiseConversion'
                    bitwisebreakout         = 'BitwiseBreakout'
                    booleanoperator         = 'BooleanOperator'
                    booleanoperatorinverted = 'BooleanOperatorInverted'
                }

                # Perform casing substitutions for any matches in $breadCrumbCorrectedCasing PSCustomObject properties.
                # Otherwise simply upper-case the first character and lower-case all remaining characters.
                $breadCrumbArray = @(foreach ($crumb in $breadCrumb.Split('_'))
                {
                    $breadCrumbCorrectedCasing.$crumb ? $breadCrumbCorrectedCasing.$crumb : $crumb.Substring(0,1).ToUpper() + $crumb.Substring(1).ToLower()
                })
                $breadCrumb = $breadCrumbArray -join '\'
            }
            $breadCrumb = '\' + $breadCrumb
        }

        # Output menu heading.
        $firstLine = "Choose one of the below "

        if ($breadCrumb)
        {
            $firstLine += ($breadCrumb.Trim('\') + ' ')
        }
        Write-Host "$firstLine" -NoNewline

        # Change color and verbiage if selection will execute command.
        if ($selectionContainsCommand)
        {
            Write-Host "options" -NoNewline -ForegroundColor Green
            Write-Host " to" -NoNewline
            Write-Host " APPLY" -NoNewline -ForegroundColor Green
            Write-Host " to current payload" -NoNewline
        }
        else
        {
            Write-Host "options" -NoNewline -ForegroundColor Yellow
        }
        Write-Host ":`n"

        foreach ($menuLine in $Menu)
        {
            $menuLineSpace     = $menuLine.LineHeader
            $menuLineOption    = $menuLine.Option
            $menuLineValue     = $menuLine.Description
            $menuLineAttribute = $menuLine.Attribute

            Write-Host $menuLineSpace -NoNewline

            # If not empty then include breadcrumb in $menuLineOption output (is not colored and will not affect user-input syntax).
            if ($breadCrumb -and $menuLineSpace.StartsWith('['))
            {
                Write-Host ($breadCrumb.ToUpper().Trim('\') + '\') -NoNewline
            }

            # Change color if selection will execute command.
            if ($selectionContainsCommand)
            {
                Write-Host $menuLineOption -NoNewline -ForegroundColor Green
            }
            else
            {
                Write-Host $menuLineOption -NoNewline -ForegroundColor Yellow
            }

            # Add additional coloring to string encapsulated by <> if it exists in $menuLineValue.
            if ($menuLineValue -cmatch '<.*>')
            {
                Write-Host "`t" -NoNewline

                $remainingMenuLineValue = $menuLineValue
                while ($remainingMenuLineValue -cmatch '<[^>]+>')
                {
                    $firstPart  = $remainingMenuLineValue.Substring(0,$remainingMenuLineValue.IndexOf($Matches[0]))
                    $middlePart = $remainingMenuLineValue.Substring(($firstPart.Length + 1),($Matches[0].Length - 2))

                    Write-Host $firstPart -NoNewline
                    Write-Host $middlePart -NoNewline -ForegroundColor Cyan

                    # Set $remainingMenuLineValue as remaining substring so additional highlighting (if present) can occur in current while loop.
                    $remainingIndex = $firstPart.Length + $middlePart.Length + 2
                    if ($remainingIndex -gt $remainingMenuLineValue.Length)
                    {
                        $remainingMenuLineValue = $null
                    }
                    else
                    {
                        $remainingMenuLineValue = $remainingMenuLineValue.Substring($remainingIndex)
                    }
                }

                # Output remaining $remainingMenuLineValue.
                Write-Host $remainingMenuLineValue -NoNewline
            }
            else
            {
                Write-Host "`t$menuLineValue" -NoNewline
            }

            # Output additional description attribute if defined.
            if ($menuLineAttribute)
            {
                Write-Host " $menuLineAttribute" -NoNewline -ForegroundColor DarkRed
            }

            Write-Host ''
        }

        # Prompt for user input with custom breadcrumb prompt.
        Write-Host ''
        if (-not $userInput)
        {
            Write-Host ''
        }
        $userInput = ''

        while (-not $userInput)
        {
            # Output custom prompt.
            Write-Host "Invoke-Maldaptive$breadCrumb> " -NoNewline -ForegroundColor Magenta

            # Get command(s) stored in -CliCommand input parameter and set as next $userInput. Otherwise get interactive user input.
            if (($CliCommand | Measure-Object).Count -gt 0)
            {
                # Retrieve next command stored in -CliCommand input parameter.
                $nextCliCommand = ($CliCommand | Select-Object -First 1).Trim()
                $CliCommand = $CliCommand | Select-Object -Skip 1

                # Set $nextCliCommand retrieved above as current $userInput.
                $userInput = $nextCliCommand

                # Write next command to simulate user entering next command (for display purposes only).
                Write-Host $userInput
            }
            else
            {
                # If parent function's -Command was defined on command line and -NoExit switch was not defined then output final ObfSearchFilter to stdout and quit. Otherwise continue with interactive Invoke-Maldaptive.
                $parentFunctionInvocation = (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly)
                if (($CliCommand.Count -eq 0) -and `
                    $parentFunctionInvocation.BoundParameters['Command'] -and `
                    (
                        $parentFunctionInvocation.BoundParameters['Quiet'].IsPresent -or `
                        -not $parentFunctionInvocation.BoundParameters['NoExit'].IsPresent
                    )
                )
                {
                    if ($parentFunctionInvocation.BoundParameters['Quiet'].IsPresent)
                    {
                        # Remove Write-Host and Start-Sleep proxy functions so that Write-Host and Start-Sleep cmdlets will be called during the remainder of the interactive Invoke-Maldaptive session.
                        Remove-Item -Path Function:Write-Host
                        Remove-Item -Path Function:Start-Sleep

                        # PowerShell has no way to negate an .IsPresent property for a [Switch] so setting it to $false boolean value will cause the desired effect.
                        $parentFunctionInvocation.BoundParameters['Quiet'] = $false

                        # Automatically run 'Show Options' so the user has context of what has successfully been executed.
                        $userInput  = 'show options'
                        $breadCrumb = 'Show Options'
                    }

                    # -NoExit wasn't specified and -Command was, so we will output the result back in the main while loop.
                    if (-not $parentFunctionInvocation.BoundParameters['NoExit'].IsPresent)
                    {
                        $userInput = 'quit'
                    }
                }
                else
                {
                    # Read next command from interactive user input.
                    $userInput = (Read-Host).Trim()
                }

                # Split interactive input into appropriate sub-commands if applicable.
                if ($userInput)
                {
                    $cliCommand = $userInput | Split-Command
                }

                if (($cliCommand | Measure-Object).Count -gt 1)
                {
                    # Reset $userInput so current While loop will be traversed once more and process $userInput command as a -CliCommand.
                    $userInput = ''
                }
                else
                {
                    $cliCommand = @()
                }
            }
        }

        # Trim any leading trailing slashes so it doesn't misinterpret it as a compound command unnecessarily.
        $userInput = $userInput.Trim('/\')

        # Cause $userInput of base menu level directories to automatically work.
        if (($menuLevel.ForEach( { $_.Option.Trim() } ) -icontains $userInput.Split('/\')[0]) -and ($MenuName -ne ''))
        {
            # Prepend current $userInput to $CliCommand array and then set current $userInput to 'home' to automatically handle home directory traversal in multi-command fashion.
            $CliCommand = [System.Array] $userInput.TrimStart() + $CliCommand

            $userInput = 'home'
        }

        # Identify if there is any regex in current non-SET, non-OUT and non-EXPORT $userInput by removing all alphanumeric characters and select special characters.
        # Also handle special **, *** and **** user input use cases to randomly select ONE, ONE-per-menu-level-grouping or ALL eligible options, respectively,
        # in current menu to the deepest level until obfuscation is applied if sub-options are present.
        if ($userInput.Trim() -iin @('**','***','****'))
        {
            # Extract and compute CLI command for all sub-paths with valid obfuscation options.
            $validSubPathOptionObjArr = (Get-Variable -Name "menuLevel$MenuName*").Where( { $_.Value.FunctionCall -ne $null } ).ForEach(
            {
                $curSubPathOption = $_

                # Extract current sub-path option's next menu level name for grouping purposes.
                $nextMenuLevel = $curSubPathOption.Name.Substring("menuLevel$MenuName".Length).TrimStart('_').Split('_')[0]

                # Compute current sub-path option's CLI command syntax.
                $curCliCommand = ($curSubPathOption.Name -replace '^menuLevel','Home' -replace '_','\') + '\' + (Get-Random -InputObject $curSubPathOption.Value.Option)

                # Return current sub-path object.
                [PSCustomObject] @{
                    NextMenuLevel = $nextMenuLevel
                    CliCommand    = $curCliCommand
                }
            } )

            # Return one, one-per-menu-level-grouping or all CLI commands extracted above.
            $cliOptionArr = switch ($userInput.Trim())
            {
                '**' {
                    # Return one random CLI command.
                    Get-Random -InputObject $validSubPathOptionObjArr.CliCommand
                }
                '***' {
                    # Group sub-path object(s) by extracted next menu level name.
                    $validSubPathOptionObjGrouped = $validSubPathOptionObjArr | Group-Object NextMenuLevel

                    # Return one random CLI command from each menu level grouping in shuffled order.
                    Get-Random -InputObject $validSubPathOptionObjGrouped.ForEach( { Get-Random -InputObject $_.Group.CliCommand } ) -Shuffle
                }
                '****' {
                    # Return all CLI command(s) in shuffled order.
                    Get-Random -InputObject $validSubPathOptionObjArr.CliCommand -Shuffle
                }
                default {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }

            # Append CLI option(s) to return to current menu after all CLI obfuscation is completed.
            $cliOptionArr = [System.Array] $cliOptionArr + ("Home$MenuName".Split('_').ForEach( { $_.Substring(0,1).ToString().ToUpper() + $_.Substring(1) } ) -join '\')

            # Split full array of CLI commands in $cliOptionArr into individual commands.
            $cliOptionArrSplit = $cliOptionArr.Split('\')

            # For initial CLI command, skip leading CLI options that just return to the current menu.
            if ($cliOptionArrSplit.ToLower().IndexOf($MenuName.TrimStart('_')) -ne -1)
            {
                $cliOptionArrSplit = $cliOptionArrSplit | Select-Object -Skip ($cliOptionArrSplit.ToLower().IndexOf($MenuName.TrimStart('_').ToLower()) + 1)
            }
            elseif ($cliOptionArrSplit[0] -eq 'Home')
            {
                $cliOptionArrSplit = $cliOptionArrSplit | Select-Object -Skip 1
            }

            # Prepend $cliOptionArrSplit to $CliCommand array.
            $CliCommand = [System.Array] $cliOptionArrSplit + $CliCommand

            # Return current menu response to re-display the current menuLevel options before the updated CliCommand values are input as automated user input.
            # This ordering is primarily for a better user experience visually when entering ** or *** input options.
            return [PSCustomObject] @{
                UserResponse     = $breadCrumb.Replace('\','_')
                LdapObfContainer = $LdapObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif (($userInput -ireplace '[a-z0-9\s+\\/-?]','') -and ($userInput.TrimStart() -inotmatch '^(SET|OUT|EXPORT) '))
        {
            # Create temporary userInputRegex and replace any simple wildcard with .* syntax.
            $userInputRegex = $userInput -csplit '\.\*' -creplace '\*','.*' -join '.*'

            # Prepend userInputRegex with ^ and append with $ if either character is not already present.
            if ($userInputRegex.Trim() -cnotmatch '^(\^|\.\*)')
            {
                $userInputRegex = '^' + $userInputRegex
            }
            if ($userInputRegex.Trim() -cnotmatch '(\$|\.\*)$')
            {
                $userInputRegex = $userInputRegex + '$'
            }

            # See if there are any filtered matches in the current menu.
            try
            {
                $menuFiltered = $acceptableInput.Where( { $_ } ) -imatch $userInputRegex
            }
            catch
            {
                # Output error message if Regular Expression causes error in above filtering step.
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' The current Regular Expression caused the following error:'
                write-host "       $_" -ForegroundColor Red
            }

            # If there are filtered matches in the current menu then randomly choose one for the UserInput value.
            if ($menuFiltered)
            {
                # Randomly select UserInput from filtered options.
                $userInput = (Get-Random -Input $menuFiltered).Trim()

                # Output randomly chosen option (and filtered options selected from) if more than one options were returned from regex.
                if ($menuFiltered.Count -gt 1)
                {
                    # Change color if acceptable option will execute an obfuscation function.
                    if ($selectionContainsCommand)
                    {
                        $colorToOutput = 'Green'
                    }
                    else
                    {
                        $colorToOutput = 'Yellow'
                    }

                    Write-Host "`n`nRandomly selected " -NoNewline
                    Write-Host $userInput -NoNewline -ForegroundColor $colorToOutput
                    write-host ' from the following filtered options: ' -NoNewline

                    for ($i=0; $i -lt $menuFiltered.Count - 1; $i++)
                    {
                        Write-Host $menuFiltered[$i].Trim() -NoNewline -ForegroundColor $colorToOutput
                        Write-Host ', ' -NoNewline
                    }
                    Write-Host $menuFiltered[$menuFiltered.Count - 1].Trim() -ForegroundColor $colorToOutput
                }
            }
        }

        if ($InputOptionMenu.Exit.Option -icontains $userInput)
        {
            # Return next menu response from $userInput and command container $LdapObfContainer defined or updated in this function.
            return [PSCustomObject] @{
                UserResponse     = $userInput
                LdapObfContainer = $LdapObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif ($InputOptionMenu.BackMenu.Option -icontains $userInput)
        {
            # Commands like 'back' that will return user to previous interactive menu.
            if ($breadCrumb.Contains('\'))
            {
                $userInput = $breadCrumb.Substring(0,$breadCrumb.LastIndexOf('\')).Replace('\','_')
            }
            else
            {
                $userInput = ''
            }

            # Return next menu response from $userInput and command container $LdapObfContainer defined or updated in this function.
            return [PSCustomObject] @{
                UserResponse     = $userInput
                LdapObfContainer = $LdapObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif ($InputOptionMenu.HomeMenu.Option -icontains $userInput)
        {
            # Return next menu response from $userInput and command container $LdapObfContainer defined or updated in this function.
            return [PSCustomObject] @{
                UserResponse     = $userInput
                LdapObfContainer = $LdapObfContainer
                CliCommand       = $CliCommand
            }
        }
        elseif ($userInput.ToLower().StartsWith('set '))
        {
            # Extract $userInputOptionName and $userInputOptionValue from $userInput SET command.
            $userInputOptionName  = $null
            $userInputOptionValue = $null
            $hasError = $false

            $userInputMinusSet = $userInput.Substring(4).Trim()
            if (-not $userInputMinusSet.Contains(' '))
            {
                # No value defined after input option name.
                $hasError = $true
                $userInputOptionName = $userInputMinusSet.Trim()
            }
            else
            {
                $userInputOptionName  = $userInputMinusSet.Substring(0,$userInputMinusSet.IndexOf(' ')).Trim().ToLower()
                $userInputOptionValue = $userInputMinusSet.Substring($userInputMinusSet.IndexOf(' ')).Trim()
            }

            # Validate that $userInputOptionName is defined in settable input options defined in -OptionMenu.
            $settableInputOption = $OptionMenu.Where( { $_.Settable } ).Name
            if ($userInputOptionName -iin $settableInputOption)
            {
                # Perform separate validation for $userInputOptionValue before setting value.
                if ($userInputOptionValue.Length -eq 0)
                {
                    # No OPTIONVALUE was entered after OPTIONNAME.
                    $hasError = $true

                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host ' No value was entered after ' -NoNewline
                    Write-Host $userInputOptionName.ToUpper() -NoNewline -ForegroundColor Cyan
                    Write-Host '.' -NoNewline
                }
                else
                {
                    switch ($userInputOptionName.ToLower())
                    {
                        'searchfilterpath' {
                            if ($userInputOptionValue -and ((Test-Path $userInputOptionValue) -or ($userInputOptionValue -imatch '^(http|https):[/\\]')))
                            {
                                # Reset SearchFilter in case it contained a value.
                                $searchFilter = ''

                                # Check if -SearchFilterPath input parameter is a URL or a directory.
                                if ($userInputOptionValue -imatch '^(http|https):[/\\]')
                                {
                                    # SearchFilterPath is a URL.

                                    # Download content from remote location.
                                    $searchFilter = (New-Object Net.WebClient).DownloadString($userInputOptionValue)

                                    # Build new obfuscation container.
                                    $LdapObfContainer = New-ObfuscationContainer -SearchFilter $searchFilter -SearchRoot:$LdapObfContainer.SearchRoot -AttributeList:$LdapObfContainer.AttributeList -Scope:$LdapObfContainer.Scope

                                    # Set user-input SEARCHFILTERPATH value into SearchFilterPath property of newly-created obfuscation container.
                                    $LdapObfContainer.SearchFilterPath = $userInputOptionValue

                                    Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                    Write-Host 'SearchFilterPath' -NoNewline -ForegroundColor Yellow
                                    Write-Host ' (as URL):' -ForegroundColor Cyan
                                    Write-Host $LdapObfContainer.SearchFilterPath -ForegroundColor Magenta
                                }
                                elseif ((Get-Item $userInputOptionValue) -is [System.IO.DirectoryInfo])
                                {
                                    # SearchFilterPath does not exist.
                                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                    Write-Host ' Path is a directory instead of a file (' -NoNewline
                                    Write-Host "$userInputOptionValue" -NoNewline -ForegroundColor Cyan
                                    Write-Host ").`n" -NoNewline
                                }
                                else
                                {
                                    # Build new obfuscation container with file content from user-input -SearchFilterPath parameter.
                                    $LdapObfContainer = New-ObfuscationContainer -Path (Resolve-Path $userInputOptionValue).Path -SearchRoot:$LdapObfContainer.SearchRoot -AttributeList:$LdapObfContainer.AttributeList -Scope:$LdapObfContainer.Scope

                                    # Set user-input SEARCHFILTERPATH value into SearchFilterPath property of newly-created obfuscation container.
                                    $LdapObfContainer.SearchFilterPath = (Resolve-Path $userInputOptionValue).Path

                                    Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                    Write-Host 'SearchFilterPath' -NoNewline -ForegroundColor Yellow
                                    Write-Host ':' -ForegroundColor Cyan
                                    Write-Host $LdapObfContainer.SearchFilterPath -ForegroundColor Magenta
                                }
                            }
                            else
                            {
                                # SearchFilterPath not found (failed Test-Path).
                                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                Write-Host ' Path not found (' -NoNewline
                                Write-Host "$userInputOptionValue" -NoNewline -ForegroundColor Cyan
                                Write-Host ").`n" -NoNewline
                            }
                        }
                        'searchfilter' {
                            $searchFilter = $userInputOptionValue

                            # Build new obfuscation container.
                            $LdapObfContainer = New-ObfuscationContainer -SearchFilter $searchFilter -SearchRoot:$LdapObfContainer.SearchRoot -AttributeList:$LdapObfContainer.AttributeList -Scope:$LdapObfContainer.Scope

                            # Set N/A value in SearchFilterPath property of newly-created obfuscation container.
                            $LdapObfContainer.SearchFilterPath = 'N/A'

                            Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                            Write-Host 'SearchFilter' -NoNewline -ForegroundColor Yellow
                            Write-Host ':' -ForegroundColor Cyan
                            Out-LdapObject -InputObject $LdapObfContainer.SearchFilter -Format default
                        }
                        'searchroot' {
                            if ($userInputOptionValue -ceq $LdapObfContainer.SearchRoot)
                            {
                                Write-Host "`n`nNothing to update since " -NoNewline -ForegroundColor Cyan
                                Write-Host 'SearchRoot' -NoNewline -ForegroundColor Yellow
                                Write-Host ' is already ' -NoNewline -ForegroundColor Cyan
                                Write-Host $LdapObfContainer.SearchRoot -NoNewline -ForegroundColor Magenta
                                Write-Host '.' -ForegroundColor Cyan
                            }
                            else
                            {
                                # Update SearchRoot property with user-input value.
                                $LdapObfContainer.SearchRoot = $userInputOptionValue

                                Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                Write-Host 'SearchRoot' -NoNewline -ForegroundColor Yellow
                                Write-Host ':' -ForegroundColor Cyan
                                Write-Host $LdapObfContainer.SearchRoot -ForegroundColor Magenta
                            }
                        }
                        'attributelist' {
                            if ($userInputOptionValue -ceq ($LdapObfContainer.AttributeList -join ','))
                            {
                                Write-Host "`n`nNothing to update since " -NoNewline -ForegroundColor Cyan
                                Write-Host 'AttributeList' -NoNewline -ForegroundColor Yellow
                                Write-Host ' is already ' -NoNewline -ForegroundColor Cyan
                                foreach ($attribute in ($LdapObfContainer.AttributeList | Select-Object -SkipLast 1))
                                {
                                    Write-Host $attribute -NoNewline -ForegroundColor Magenta
                                    Write-Host ',' -NoNewline -ForegroundColor Cyan
                                }
                                Write-Host ($LdapObfContainer.AttributeList | Select-Object -Last 1) -NoNewline -ForegroundColor Magenta
                                Write-Host '.' -ForegroundColor Cyan
                            }
                            else
                            {
                                # Update AttributeList property with user-input value.
                                # Do not trim whitespace as it is permitted in certain undocumented cases (e.g. after the OID representation of an Attribute name).
                                $LdapObfContainer.AttributeList = [System.Array] $userInputOptionValue.Split(',').Where( { $_ } )

                                Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                Write-Host 'AttributeList' -NoNewline -ForegroundColor Yellow
                                Write-Host ':' -ForegroundColor Cyan
                                foreach ($attribute in ($LdapObfContainer.AttributeList | Select-Object -SkipLast 1))
                                {
                                    Write-Host $attribute -NoNewline -ForegroundColor Magenta
                                    Write-Host ',' -NoNewline
                                }
                                Write-Host ($LdapObfContainer.AttributeList | Select-Object -Last 1) -ForegroundColor Magenta
                            }
                        }
                        'scope' {
                            # Validate input against permissible options.
                            $permissibleOption = @('Base','OneLevel','Subtree')
                            if ($userInputOptionValue -ieq $LdapObfContainer.Scope)
                            {
                                Write-Host "`n`nNothing to update since " -NoNewline -ForegroundColor Cyan
                                Write-Host 'Scope' -NoNewline -ForegroundColor Yellow
                                Write-Host ' is already ' -NoNewline -ForegroundColor Cyan
                                Write-Host $LdapObfContainer.Scope -NoNewline -ForegroundColor Magenta
                                Write-Host '.' -ForegroundColor Cyan
                            }
                            elseif ($userInputOptionValue -iin $permissibleOption)
                            {
                                # Set Scope to be user input value (where casing matches exact casing in $permissibleOption array defined above).
                                $LdapObfContainer.Scope = $permissibleOption.Where( { $_ -ieq $userInputOptionValue } )

                                Write-Host "`n`nSuccessfully set " -NoNewline -ForegroundColor Cyan
                                Write-Host 'Scope' -NoNewline -ForegroundColor Yellow
                                Write-Host ':' -ForegroundColor Cyan
                                Write-Host $LdapObfContainer.Scope -ForegroundColor Magenta
                            }
                            else
                            {
                                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                                Write-Host " You entered an invalid option. Enter" -NoNewline
                                Write-Host " HELP" -NoNewline -ForegroundColor Yellow
                                Write-Host " for more information."

                                # Output all available/acceptable options for current menu if invalid input was entered.
                                if ($permissibleOption.Count -gt 1)
                                {
                                    $message = 'Valid settable options include:'
                                }
                                else
                                {
                                    $message = 'Valid settable option includes:'
                                }
                                Write-Host "       $message " -NoNewline

                                # Output yellow-colored options corresponding to permissible value(s) for current settable option.
                                for ($i = 0; $i -lt $permissibleOption.Count - 1; $i++)
                                {
                                    Write-Host $permissibleOption[$i].ToUpper() -NoNewline -ForegroundColor Yellow
                                    Write-Host ', ' -NoNewline
                                }
                                Write-Host $permissibleOption[$i].ToUpper() -ForegroundColor Yellow
                            }
                        }
                        default {
                            Write-Error "An invalid OPTIONNAME ($userInputOptionName) was passed to switch block."

                            exit
                        }
                    }
                }
            }
            else
            {
                $hasError = $true

                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host ' OPTIONNAME ' -NoNewline
                Write-Host $userInputOptionName.ToUpper() -NoNewline -ForegroundColor Cyan
                Write-Host ' is not a settable option.' -NoNewline

                Write-Host ' Enter' -NoNewline
                Write-Host ' SHOW OPTIONS' -NoNewline -ForegroundColor Yellow
                Write-Host ' for more details.' -NoNewline
            }

            # Output additional information if any user input error occurred above.
            if ($hasError)
            {
                if ($userInputOptionName -iin $settableInputOption)
                {
                    Write-Host "`n       Correct syntax is" -NoNewline
                    Write-Host " SET $($userInputOptionName.ToUpper()) VALUE" -NoNewline -ForegroundColor Green
                    Write-Host '.' -NoNewline
                }
                else
                {
                    # Output all settable options if invalid input was entered.
                    if($settableInputOption.Count -gt 1)
                    {
                        $message = 'Valid settable options include:'
                    }
                    else
                    {
                        $message = 'Valid settable option includes:'
                    }
                    Write-Host "`n       $message " -NoNewline

                    # Output yellow-colored options corresponding to settable option(s).
                    for ($i = 0; $i -lt $settableInputOption.Count - 1; $i++)
                    {
                        Write-Host $settableInputOption[$i].ToUpper() -NoNewline -ForegroundColor Yellow
                        Write-Host ', ' -NoNewline
                    }
                    Write-Host $settableInputOption[$i].ToUpper() -NoNewline -ForegroundColor Yellow
                }
            }
        }
        elseif ($acceptableInput -icontains $userInput)
        {
            # User input matches $acceptableInput extracted from the current $Menu, so decide if:
            # 1) an obfuscation function needs to be called and remain in current interactive prompt, or
            # 2) return value to enter into a new interactive prompt.

            # Format breadcrumb trail to successfully retrieve the next interactive prompt.
            $userInput = $breadCrumb.Trim('\').Replace('\','_') + '_' + $userInput
            if ($breadCrumb.StartsWith('\'))
            {
                $userInput = '_' + $userInput
            }

            # If the current selection does not contain a command to execute then return to go to another menu. Otherwise continue to execute command.
            if (-not $selectionContainsCommand)
            {
                # User input is not command but menu, so return input to go to next menu and return command container $LdapObfContainer defined or updated in this function.
                return [PSCustomObject] @{
                    UserResponse     = $userInput
                    LdapObfContainer = $LdapObfContainer
                    CliCommand       = $CliCommand
                }
            }

            # Validate that user has set SEARCHFILTER or SEARCHFILTERPATH.
            if (-not $LdapObfContainer.SearchFilter)
            {
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host " Cannot execute obfuscation commands without setting SearchFilter or SearchFilterPath values in SHOW OPTIONS menu. Set these by executing" -NoNewline
                Write-Host ' SET SEARCHFILTER search_filter' -NoNewline -ForegroundColor Green
                Write-Host ' or' -NoNewline
                Write-Host ' SET SEARCHFILTERPATH path_to_search_filter_file_or_URL' -NoNewline -ForegroundColor Green
                Write-Host '.'

                continue
            }
            else
            {
                # Iterate through lines in $Menu to extract command for the current selection in $userInput.
                foreach ($menuLine in $Menu)
                {
                    if ($menuLine.Option.Trim(' ') -eq $userInput.Substring($userInput.LastIndexOf('_') + 1))
                    {
                        $selectedMenuLine = $menuLine

                        continue
                    }
                }

                # Execute command(s) stored in FunctionCall property of current menu line selected by user.
                Get-Random -InputObject $selectedMenuLine.FunctionCall -Count ($selectedMenuLine.FunctionCall | Measure-Object).Count | ForEach-Object {
                    $functionCallScriptBlock = $_

                    # Track previous layer count to ascertain if obfuscation layer is successfully applied in below switch block.
                    $prevLayer = $LdapObfContainer.Layer

                    # Execute current FunctionCall property value, capturing elapsed execution time for output purposes.
                    $functionCallExecElapsedTime = Measure-Command -Expression {
                        # Set $searchFilter variable since command in current FunctionCall property value references this variable as input.
                        $searchFilter = $LdapObfContainer.SearchFilter
                        $obfuscatedSearchFilterTokenized = . ([ScriptBlock]::Create($functionCallScriptBlock))
                    }

                    # Output elapsed time for FunctionCall ScriptBlock invocation above.
                    Write-Host "`nElapsed Time: " -NoNewline
                    Write-Host $functionCallExecElapsedTime -ForegroundColor White

                    # Output warning message if no obfuscation layer was successfully applied in above switch block.
                    if ($LdapObfContainer.SearchFilter -ceq (-join$obfuscatedSearchFilterTokenized.Content))
                    {
                        Write-Host "`nWARNING:" -NoNewline -ForegroundColor Red
                        Write-Host ' No obfuscation applied due to lack of eligibility or low randomization percentage.'
                    }
                    else
                    {
                        # Add current obfuscation layer in History property and update relevant properties in main obfuscation object.
                        $LdapObfContainer = $LdapObfContainer | Add-ObfuscationLayer -SearchFilterTokenized $obfuscatedSearchFilterTokenized

                        # Convert UserInput to CLI syntax then store in CliSyntax property.
                        $cliSyntax = $userInput.Trim('_ ').Replace('_','\')

                        # Store CLI syntax, full Command Line Syntax and function svalues in CliSyntax, CommandLineSyntax and Function properties, respectively.
                        $LdapObfContainer.History[-1].CliSyntax += $cliSyntax
                        $LdapObfContainer.History[-1].CommandLineSyntax = $functionCallScriptBlock.ToString().Replace($requiredFunctionPrefixArgumentsToHideFromUI,'').Replace($requiredFunctionSuffixArgumentsToHideFromUI,'')
                        $LdapObfContainer.History[-1].Function = $functionCallScriptBlock.ToString().Split(' ').Where( { $_ -and (Get-Command -CommandType Function -Name $_ -ErrorAction SilentlyContinue).Name } )[0]

                        # Output syntax of CLI syntax and full command executed in above Switch block.
                        Write-Host "`nExecuted:"
                        Write-Host '  CLI:  ' -NoNewline
                        Write-Host $LdapObfContainer.History[-1].CliSyntax -ForegroundColor Cyan

                        # Split out $searchFilter so it can be output in different color.
                        Write-Host '  Full: ' -NoNewline
                        ($LdapObfContainer.History[-1].CommandLineSyntax -isplit '\$searchFilter').Where( { $_ } ).ForEach(
                        {
                            Write-Host $_ -NoNewline -ForegroundColor Cyan
                        } )
                        Write-Host ''

                        # Output obfuscation result.
                        Write-Host "`nResult:`t"
                        Out-LdapObject -InputObject $LdapObfContainer.History[-1].SearchFilterTokenized
                    }
                }
            }
        }
        else
        {
            if ($InputOptionMenu.ShowHelp.Option -icontains $userInput)
            {
                Show-HelpMenu -InputOptionMenu $InputOptionMenu
            }
            elseif ($InputOptionMenu.ShowOption.Option -icontains $userInput)
            {
                Show-OptionsMenu -Menu $OptionMenu -LdapObfContainer $LdapObfContainer
            }
            elseif ($InputOptionMenu.OutputTree.Option -icontains $userInput)
            {
                if ($LdapObfContainer.SearchFilter)
                {
                    Write-Host ($LdapObfContainer.SearchFilter.StartsWith(' ') ? '' : "`n")
                    Out-LdapObject -InputObject $LdapObfContainer.History[-1].SearchFilterTokenized -SkipModificationHighlighting
                }
                else
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot display tree because you have not set SearchFilter or SearchFilterPath.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " to set SearchFilter or SearchFilterPath."
                }
            }
            elseif ($InputOptionMenu.Tutorial.Option -icontains $userInput)
            {
                Show-Tutorial
            }
            elseif ($InputOptionMenu.ClearScreen.Option -icontains $userInput)
            {
                Clear-Host
            }
            elseif ($InputOptionMenu.FindEvil.Option -icontains $userInput)
            {
                if ($LdapObfContainer.SearchFilter)
                {
                    # Evaluate all Detections in Find-Evil function for current SearchFilter, capturing elapsed execution time for output purposes.
                    $findEvilElapsedTime = Measure-Command -Expression {
                        $detectionSummary = Find-Evil -SearchFilter $LdapObfContainer.SearchFilter -Summarize
                    }

                    # Output elapsed time for Detection evaluation above.
                    Write-Host "`nElapsed Time: " -NoNewline
                    Write-Host $findEvilElapsedTime -ForegroundColor White

                    # Output summary of Detection hit(s).
                    if ($detectionSummary.DetectionCount -eq 0)
                    {
                        # Output warning message if no Detection hits are present.
                        Write-Host "`nWARNING:" -NoNewline -ForegroundColor Red
                        Write-Host ' No detections matched ObfSearchFilter.'
                    }
                    else
                    {
                        # Output syntax of CLI syntax and full command executed in above Switch block.
                        Write-Host "`nExecuted:"
                        Write-Host '  CLI:  ' -NoNewline
                        Write-Host 'FIND-EVIL' -ForegroundColor Cyan
                        Write-Host '  Full: ' -NoNewline
                        Write-Host 'Find-Evil -Summarize | Show-EvilSummary' -ForegroundColor Cyan

                        # Output summary of Detection hit(s).
                        Write-Host "`nResult:`t"
                        Show-EvilSummary -DetectionSummary $detectionSummary -SuppressPadding
                    }  
                }
                else
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot evaluate detections because you have not set SearchFilter or SearchFilterPath.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " to set SearchFilter or SearchFilterPath."
                }
            }
            elseif ($InputOptionMenu.ResetObfuscation.Option -icontains $userInput)
            {
                if (-not $LdapObfContainer.SearchFilter)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " SearchFilter has not been set. There is nothing to reset."
                }
                elseif ($LdapObfContainer.Layer -eq 0)
                {

                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfSearchFilter. There is nothing to reset."
                }
                else
                {
                    # Build new obfuscation container from existing obfuscation container original values.
                    $prevSearchFilterPath = $LdapObfContainer.SearchFilterPath
                    $LdapObfContainer = New-ObfuscationContainer -SearchFilter $LdapObfContainer.History[0].SearchFilter -SearchRoot:$LdapObfContainer.SearchRoot -AttributeList:$LdapObfContainer.AttributeList -Scope:$LdapObfContainer.Scope

                    # Set previous SearchFilterPath value in SearchFilterPath property of newly-created obfuscation container.
                    $LdapObfContainer.SearchFilterPath = $prevSearchFilterPath

                    Write-Host "`n`nSuccessfully reset ObfSearchFilter." -ForegroundColor Cyan
                }
            }
            elseif ($InputOptionMenu.UndoObfuscation.Option -icontains $userInput)
            {
                if (-not $LdapObfContainer.SearchFilter)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " SearchFilter has not been set. There is nothing to undo."
                }
                elseif ($LdapObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfSearchFilter. There is nothing to undo."
                }
                else
                {
                    # Remove last obfuscation layer in History property and update relevant properties in main obfuscation object.
                    $LdapObfContainer = $LdapObfContainer | Remove-ObfuscationLayer

                    Write-Host "`n`nSuccessfully removed last obfuscation layer from ObfSearchFilter." -ForegroundColor Cyan
                }
            }
            elseif (([System.Array] $InputOptionMenu.OutputToDisk.Option + $InputOptionMenu.ExportToDisk.Option) -icontains $userInput.Trim().Split(' ')[0])
            {
                # Handle verbiage if $userInput is OUT versus EXPORT for ObfSearchFilter output versus $ldapObfContainer CliXml export, respectively.
                if ($userInput.Trim().Split(' ')[0] -ieq 'out')
                {
                    $outputObj = [PSCustomObject] @{
                        Type              = 'output'
                        StringPresent     = 'output'
                        StringPresentFull = 'output ObfSearchFilter'
                        StringPastFull    = 'output ObfSearchFilter'
                        DefaultOutputFile = 'Obfuscated_Command.txt'
                    }
                }
                else
                {
                    $outputObj = [PSCustomObject] @{
                        Type              = 'export'
                        StringPresent     = 'export'
                        StringPresentFull = 'export $ldapObfContainer'
                        StringPastFull    = 'exported $ldapObfContainer'
                        DefaultOutputFile = 'Obfuscated_Command_Container.clixml'
                    }
                }

                if (-not $LdapObfContainer.SearchFilter)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " SearchFilter has not been set. There is nothing to $($outputObj.StringPresent)."
                }
                elseif ($LdapObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:"                                               -NoNewline -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS"                                              -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfSearchFilter."
                }
                else
                {
                    # Get file path information from compound user input (e.g. OUT C:\FILENAME.TXT, EXPORT C:\FILENAME.CLIXML).
                    if ($userInput.Trim().Split(' ').Count -gt 1)
                    {
                        # Get file path information from user input.
                        $userInputOutputFilePath = $userInput.Trim().Substring($userInput.Trim().IndexOf(' ')).Trim()
                        Write-Host ''
                    }
                    else
                    {
                        # Get file path information from user interactively.
                        $userInputOutputFilePath = Read-Host "`n`nEnter path for $($outputObj.Type) file (or leave blank for default)"
                    }

                    # Set default file path as Downloads folder depending on OS.
                    $defaultOutputFilePath = Join-Path -Path (($IsLinux -or $IsMacOS) ? $env:HOME : $env:USERPROFILE) -ChildPath 'Downloads'

                    # Decipher if user input a full file path, just a file name or nothing (default).
                    if (-not $userInputOutputFilePath.Trim())
                    {
                        # Set default output file path.
                        $outputFilePath = Join-Path -Path $defaultOutputFilePath -ChildPath $outputObj.DefaultOutputFile
                    }
                    elseif ($userInputOutputFilePath -inotmatch '[/\\]')
                    {
                        # User input is not a file path so treat it as a filename and use default file path as Downloads folder depending on OS.
                        $outputFilePath = Join-Path -Path $defaultOutputFilePath -ChildPath $userInputOutputFilePath.Trim()
                    }
                    else
                    {
                        # User input is a full file path.
                        $outputFilePath = $userInputOutputFilePath.Trim()
                    }

                    # Output/export to disk.
                    switch ($outputObj.Type)
                    {
                        'output' {
                            # Write ObfSearchFilter out to disk.
                            Set-Content -Path $outputFilePath -Value $LdapObfContainer.SearchFilter
                        }
                        'export' {
                            # Export $LdapObfContainer CliXml to disk.
                            Export-CliXml -InputObject $LdapObfContainer -Path $outputFilePath
                        }
                        defaut
                        {
                            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                        }
                    }

                    # Output if file write is successful or not. If successful then use default text file editor to open file.
                    if (Test-Path $outputFilePath)
                    {
                        # Add CliSyntax record.
                        $LdapObfContainer.History[-1].CliSyntax += "$($userInput.Trim().Split(' ')[0].ToLower()) $outputFilePath"

                        Write-Host "`nSuccessfully $($outputObj.StringPastFull) to" -NoNewline -ForegroundColor Cyan
                        Write-Host " $outputFilePath"                               -NoNewline -ForegroundColor Yellow
                        Write-Host "." -ForegroundColor Cyan

                        # Set current command in clipboard depending on OS.
                        if ($IsMacOS)
                        {
                            # Open is a native MacOS binary used for opening user's default text editor for viewing and editing text files.
                            $openPath = (Get-Command -Name open -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($openPath -and (Test-Path -Path $openPath))
                            {
                                # Notes from the open man page:
                                #   -e  Causes the file to be opened with /Applications/TextEdit
                                #   -t  Causes the file to be opened with the default text editor, as determined via LaunchServices
                                # Not defining either of these arguments opens the document in the default application for its type (as determined by LaunchServices).

                                # Defaulting to -t argument to force the user's default text editor to open the file.
                                # This is to prevent the default application from potentially executing the file based on the user's defined file extension when outputting the file.
                                Start-Process -FilePath $openPath -ArgumentList "-t `"$($outputFilePath.Replace('"','\"'))`""
                            }
                            else
                            {
                                Write-Warning "Native 'open' binary not found. This binary is required on macOS to properly handle launching current user's default text editor to open newly created output file."
                            }
                        }
                        elseif ($IsLinux)
                        {
                            # Gedit is the default text editor for the GNOME Desktop for viewing and editing text files.
                            $geditPath = (Get-Command -Name gedit -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($geditPath -and (Test-Path -Path $geditPath))
                            {
                                Start-Process -FilePath $geditPath -ArgumentList "`"$($outputFilePath.Replace('"','\"'))`"" -RedirectStandardError 'stderr'
                            }
                            else
                            {
                                Write-Warning "Native 'gedit' binary not found. This binary is the default text editor for the GNOME Desktop for viewing and editing text files."
                            }
                        }
                        elseif ($IsWindows -or -not ($IsLinux -or $IsMacOS))
                        {
                            # Query current user's default text editor from registry.
                            # Reference: https://stackoverflow.com/questions/61599183/powershell-opening-a-file-in-default-txt-editor
                            $defaultTextEditorRegKeyProp  =  Get-ItemProperty -Path 'Registry::\HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice'
                            $defaultTextEditorRegKeyValue = (Get-ItemProperty -Path "Registry::\HKEY_CLASSES_ROOT\$($defaultTextEditorRegKeyProp.ProgId)\shell\open\command").'(default)'
                            $defaultTextEditorPath = $defaultTextEditorRegKeyValue.Split('%')[0].Trim()

                            # Use current user's default text editor to open output file if binary is present. Otherwise default to notepad.exe.
                            if (Test-Path $defaultTextEditorPath)
                            {
                                $textEditorPath = $defaultTextEditorPath

                                Start-Process -FilePath $textEditorPath -ArgumentList $outputFilePath
                            }
                            else
                            {
                                # Notepad.exe is a native Windows binary used for viewing and editing text files.
                                $notepadPath = (Get-Command -Name notepad.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                                if ($notepadPath -and (Test-Path -Path $notepadPath))
                                {
                                    Start-Process -FilePath $notepadPath -ArgumentList $outputFilePath
                                }
                                else
                                {
                                    Write-Warning "Native 'notepad.exe' binary not found. This binary is the default text editor for viewing text files."
                                }
                            }
                        }
                    }
                    else
                    {
                        Write-Host "`nERROR: Unable to $($outputObj.StringPresentFull) to" -NoNewline -ForegroundColor Red
                        Write-Host " $outputFilePath" -NoNewline -ForegroundColor Yellow
                    }
                }
            }
            elseif ($InputOptionMenu.CopyToClipboard.Option -icontains $userInput)
            {
                if ($LdapObfContainer.Layer -eq 0)
                {
                    Write-Host "`n`nWARNING:" -NoNewline -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfSearchFilter."
                }
                elseif ($LdapObfContainer.SearchFilter)
                {
                    # Copy ObfSearchFilter to clipboard.
                    # Try-Catch block introduced since PowerShell v2.0 without -STA defined will not be able to perform clipboard functionality.
                    try
                    {
                        # Set current command in clipboard depending on OS.
                        if ($IsMacOS)
                        {
                            # pbcopy is a native macOS binary used for copying content to the clipboard since no cmdlet exists in PowerShell Core.
                            $pbcopyPath = (Get-Command -Name pbcopy -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($pbcopyPath -and (Test-Path -Path $pbcopyPath))
                            {
                                $LdapObfContainer.SearchFilter | . $pbcopyPath
                            }
                            else
                            {
                                Write-Warning "Native 'pbcopy' binary not found. This binary is required on macOS to copy text to clipboard since Set-Clipboard cmdlet does not exist in PowerShell Core."
                            }
                        }
                        elseif ($IsLinux)
                        {
                            # xclip is a non-native Linux binary used for copying content to the clipboard since no cmdlet exists in PowerShell Core. It must be manually installed to use the 'clip' functionality in Invoke-Maldaptive.
                            $xclipPath = (Get-Command -Name xclip -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                            if ($xclipPath -and (Test-Path -Path $xclipPath))
                            {
                                # Start xclip as background job since it takes over a minute to run on some Linux distributions even though the clipboard content is set immediately.
                                $jobName = 'Invoke-Maldaptive_xclip'

                                # Remove any previous jobs for this function.
                                Remove-Job -Name $jobName -ErrorAction SilentlyContinue

                                # Start new xclip job in background to continue without waiting.
                                Start-Job -Name $jobName -ScriptBlock ([ScriptBlock]::Create("echo '$($LdapObfContainer.SearchFilter.Replace("'","''"))' | . $xclipPath -iin -selection clipboard")) | Out-Null
                            }
                            else
                            {
                                Write-Warning "Native 'xclip' binary not found. This binary is required on Linux to copy text to clipboard since Set-Clipboard cmdlet does not exist in PowerShell Core. Install xclip on this system. E.g. sudo apt install xclip"
                            }
                        }
                        elseif ($IsWindows -or -not ($IsLinux -or $IsMacOS))
                        {
                            # Differentiate between clipboard options in PowerShell and PowerShell Core.
                            if ($PSVersionTable.PSVersion.Major -le 5)
                            {
                                $null = [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
                                [System.Windows.Forms.Clipboard]::SetText($LdapObfContainer.SearchFilter)
                            }
                            else
                            {
                                Set-Clipboard -Value $LdapObfContainer.SearchFilter
                            }
                        }

                        Write-Host "`n`nSuccessfully copied ObfSearchFilter to clipboard." -ForegroundColor Cyan
                    }
                    catch
                    {
                        $errorMessage = "Clipboard functionality will not work in PowerShell version $($PSVersionTable.PSVersion.Major) unless you add -STA (Single-Threaded Apartment) execution flag to powershell.exe."

                        if ((Get-Command -Name Write-Host).CommandType -ne 'Cmdlet')
                        {
                            # Retrieving Write-Host and Start-Sleep Cmdlets to get around the current proxy functions of Write-Host and Start-Sleep that are overloaded if -Quiet flag was used.
                            . (Get-Command -Name Write-Host -CommandType Cmdlet) "`n`nWARNING: " -NoNewline -ForegroundColor Red
                            . (Get-Command -Name Write-Host -CommandType Cmdlet) $errorMessage -NoNewline

                            if ($LdapObfContainer.History.CliSyntax)
                            {
                                . (Get-Command -Name Start-Sleep -CommandType Cmdlet) -Seconds 2
                            }
                        }
                        else
                        {
                            Write-Host "`n`nWARNING: " -NoNewline -ForegroundColor Red
                            Write-Host $errorMessage

                            if ($LdapObfContainer.History.CliSyntax)
                            {
                                Start-Sleep -Seconds 2
                            }
                        }
                    }

                    $LdapObfContainer.History[-1].CliSyntax += 'clip'
                }
                elseif (-not $LdapObfContainer.SearchFilter)
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " There isn't anything to copy to your clipboard.`n       Just enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " and look at ObfSearchFilter." -NoNewline
                }
            }
            elseif ($InputOptionMenu.ExecuteCommand.Option -icontains $userInput)
            {
                if ($LdapObfContainer.SearchFilter)
                {
                    # Set LDAP query result variable to null so last successful result will not be improperly displayed if current LDAP SearchFilter is invalid.
                    $ldapQueryResult = $null

                    if ($LdapObfContainer.SearchFilter -ceq $LdapObfContainer.History[0].SearchFilter)
                    {
                        Write-Host "`n`nInvoking LDAP SearchRequest (though you haven't obfuscated anything yet):"
                    }
                    else
                    {
                        Write-Host "`n`nInvoking LDAP SearchRequest:"
                    }

                    # Output current LDAP SearchFilter about to be invoked.
                    Out-LdapObject -InputObject $LdapObfContainer.SearchFilterTokenized -SkipModificationHighlighting -Format default
                    Write-Host ''

                    # Invoke LDAP query with current SearchFilter, SearchRoot, AttributeList and Scope values, capturing elapsed execution time for output purposes.
                    $ldapQueryElapsedTime = Measure-Command -Expression {
                        $ldapQueryResult = Invoke-LdapQuery -SearchFilter  $LdapObfContainer.SearchFilter `
                                                            -SearchRoot    $LdapObfContainer.SearchRoot `
                                                            -AttributeList $LdapObfContainer.AttributeList `
                                                            -Scope         $LdapObfContainer.Scope
                    }

                    # Output elapsed time for LDAP query above.
                    Write-Host "`nElapsed Time: " -NoNewline
                    Write-Host $ldapQueryElapsedTime -ForegroundColor White

                    # Output LDAP query results and count.
                    if ($ldapQueryResult.Count -gt 0)
                    {
                        Write-Host "`nResult:`n"
                        Write-Host ($ldapQueryResult | Out-String).Trim() -ForegroundColor Green
                    }

                    Write-Host "`nResult Count: " -NoNewline
                    Write-Host $ldapQueryResult.Count -ForegroundColor Green
                }
                else
                {
                    Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                    Write-Host " Cannot execute because you have not set SearchFilter or SearchFilterPath.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewline -ForegroundColor Yellow
                    Write-Host " to set SearchFilter or SearchFilterPath."
                }
            }
            else
            {
                Write-Host "`n`nERROR:" -NoNewline -ForegroundColor Red
                Write-Host " You entered an invalid option. Enter" -NoNewline
                Write-Host " HELP" -NoNewline -ForegroundColor Yellow
                Write-Host " for more information."

                # If the failed input was part of $CliCommand then cancel out the rest of the concatenated command so it is not further processed.
                if ($CliCommand.Count -gt 0)
                {
                    $CliCommand = @()
                }

                # Output all available/acceptable options for current menu if invalid input was entered.
                if ($acceptableInput.Count -gt 1)
                {
                    $message = 'Valid options for current menu include:'
                }
                else
                {
                    $message = 'Valid option for current menu includes:'
                }
                Write-Host "       $message " -NoNewline

                $counter=0
                foreach ($option in $acceptableInput)
                {
                    $counter++

                    # Change color and verbiage if acceptable options will execute an obfuscation function.
                    $colorToOutput = $selectionContainsCommand ? 'Green' : 'Yellow'

                    Write-Host $option -NoNewline -ForegroundColor $colorToOutput
                    if (($counter -lt $acceptableInput.Length) -and $option)
                    {
                        Write-Host ', ' -NoNewline
                    }
                }
                Write-Host ''
            }
        }
    }

    # Return next menu response from $userInput and command container $LdapObfContainer defined or updated in this function.
    [PSCustomObject] @{
        UserResponse     = $userInput
        LdapObfContainer = $LdapObfContainer
        CliCommand       = $CliCommand
    }
}


function Show-OptionsMenu
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Show-OptionsMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-OptionsMenu displays color-coded options menu for Invoke-Maldaptive function.

.PARAMETER Menu

Specifies object containing list of available menu option values and descriptions to display.

.PARAMETER LdapObfContainer

Specifies obfuscation container from which relevant values will be extracted and displayed about original and current version of LDAP SearchFilter.

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $Menu,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [PSCustomObject]
        $LdapObfContainer
    )

    # Set line header for consistent user experience.
    $lineHeader = '[*] '

    # Set SearchFilter size limit for more consise output formatting.
    $searchFilterDisplaySizeLimit = 100

    # Output menu.
    Write-Host "`n`nSHOW OPTIONS" -NoNewline -ForegroundColor Cyan
    Write-Host ' ::' -NoNewline
    Write-Host ' Yellow' -NoNewline -ForegroundColor Yellow
    Write-Host ' options can be set by entering' -NoNewline
    Write-Host ' SET OPTIONNAME VALUE' -NoNewline -ForegroundColor Green
    Write-Host ".`n"

    # Update each menu option value from obfuscation container before displaying.
    foreach ($option in $Menu)
    {
        switch ($option.Name)
        {
            'SearchFilterPath' {
                $option.Value = $LdapObfContainer.SearchFilterPath
            }
            'SearchFilter' {
                $option.Value = $LdapObfContainer.History[0].SearchFilter
            }
            'SearchRoot' {
                $option.Value = $LdapObfContainer.SearchRoot
            }
            'AttributeList' {
                $option.Value = @($LdapObfContainer.AttributeList)
            }
            'Scope' {
                $option.Value = $LdapObfContainer.Scope
            }
            'CommandlineSyntax' {
                $option.Value = $LdapObfContainer.Layer -gt 0 ? $LdapObfContainer.History.CliSyntax : $null
            }
            'ExecutionCommands' {
                $option.Value = $LdapObfContainer.Layer -gt 0 ? $LdapObfContainer.History.CommandLineSyntax : $null
            }
            'ObfSearchFilter' {
                $option.Value = $LdapObfContainer.Layer -gt 0 ? $LdapObfContainer.SearchFilter : $null
            }
            'FilterCount' {
                $option.Value = $LdapObfContainer.SearchFilter ? $LdapObfContainer.FilterCount : $null
            }
            'Length' {
                $option.Value = $LdapObfContainer.SearchFilter ? $LdapObfContainer.SearchFilterLength : $null
            }
            'Depth' {
                $option.Value = $LdapObfContainer.SearchFilter ? $LdapObfContainer.SearchFilterDepth : $null
            }
            'DetectionScore' {
                $option.Value = $LdapObfContainer.SearchFilter ? (Find-Evil -SearchFilter $LdapObfContainer.SearchFilter -Summarize).TotalScore : $null
            }
            'DetectionCount' {
                $option.Value = $LdapObfContainer.SearchFilter ? (Find-Evil -SearchFilter $LdapObfContainer.SearchFilter -Summarize).DetectionCount : $null
            }
            default {
                Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
            }
        }

        # Output settable options as Yellow.
        Write-Host $lineHeader -NoNewline
        if ($option.Settable)
        {
            Write-Host $option.Name -NoNewline -ForegroundColor Yellow
        }
        else
        {
            Write-Host $option.Name -NoNewline
        }
        Write-Host ': ' -NoNewline

        # Handle coloring and multi-value output for specific menu values.
        switch ($option.Name)
        {
            'FilterCount' {
                Write-Host $option.Value -ForegroundColor Cyan
            }
            'Length' {
                Write-Host $option.Value -ForegroundColor Cyan
            }
            'Depth' {
                Write-Host $option.Value -ForegroundColor Cyan
            }
            'SearchFilter' {
                # Output SearchFilter (unless it is not yet defined).
                if ($option.Value)
                {
                    Out-LdapObject -InputObject $option.Value -SkipModificationHighlighting -Format default
                }
                else
                {
                    Write-Host ''
                }
            }
            'CommandLineSyntax' {
                # CliSyntax output.

                # First set potentially-null CLI field values of -Command and -SearchFilterPath/-SearchFilter.

                # Set -Command field value if it exists.
                $commandSyntax = $null
                if ($option.Value)
                {
                    # Trim the beginning of adjacent command values that share similar starting paths.
                    # E.g. instead of displaying Obfuscate\Insert\Whitespace\1,Obfuscate\Insert\Whitespace\4 display Obfuscate\Insert\Whitespace\1,4.
                    $lastValuePath = $null
                    $commandSyntax = foreach ($curValue in $option.Value)
                    {
                        # Extract leading path of obfuscation command values (excluding non-obfuscation commands like OUT command, etc. where whitespace is present in the command).
                        if ($curValue.Contains('\') -and -not $curValue.Contains(' '))
                        {
                            $curValuePath = $curValue.Substring(0, $curValue.LastIndexOf('\') + 1)

                            # If current command starts with the same path as the last command then remove matching portion of command for simpler output formatting.
                            if ($curValue.StartsWith($lastValuePath))
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Green'; Value = $curValue.Substring($lastValuePath.Length).Replace("'","''") }
                            }
                            else
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Green'; Value = $curValue.Replace("'","''") }
                            }

                            # Keep track of value path for evaluation in following foreach iterations.
                            $lastValuePath = $curValuePath
                        }
                        else
                        {
                            # Output non-obfuscation command as yellow instead of green.
                            [PSCustomObject] @{ ForegroundColor = 'Yellow'; Value = $curValue.Replace("'","''") }
                        }

                        # Set comma delimiter object between each command value.
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';  Value = ',' }
                    }

                    # Remove trailing comma since it is not required.
                    $commandSyntax = $commandSyntax | Select-Object -SkipLast 1

                    $commandSyntax = @(
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';  Value = " -Command '" }
                        $commandSyntax
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';  Value = "'"           }
                    )
                }

                # Set -SearchFilterPath/-SearchFilter field value if it exists.
                $setSyntax = $null
                if ($LdapObfContainer.SearchFilterPath -and ($LdapObfContainer.SearchFilterPath -ne 'N/A'))
                {
                    # Encapsulate SearchFilterPath with quotes if whitespace is present in path.
                    if ($LdapObfContainer.SearchFilterPath.Contains(' '))
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = " -SearchFilterPath '"             }
                            [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $LdapObfContainer.SearchFilterPath }
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = "'"                                }
                        )
                    }
                    else
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';        Value = " -SearchFilterPath "          }
                            [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $LdapObfContainer.SearchFilterPath }
                        )
                    }
                }
                elseif ($LdapObfContainer.History -and $LdapObfContainer.History[0].SearchFilter -and ($LdapObfContainer.SearchFilterPath -eq 'N/A'))
                {
                    # Encapsulate original SearchFilter value in single quotes and handle PowerShell-specific single quote escaping.
                    # If SearchFilter value is too long then change to $searchFilter placeholder for more concise output formatting.
                    if ($LdapObfContainer.History[0].SearchFilter.Replace("'","''").Length -le $searchFilterDisplaySizeLimit)
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = " -SearchFilter '"                                          }
                            [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $LdapObfContainer.History[0].SearchFilter.Replace("'","''") }
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = "'"                                                         }
                        )
                    }
                    else
                    {
                        $setSyntax = @(
                            [PSCustomObject] @{ ForegroundColor = 'Cyan';        Value = ' -SearchFilter ' }
                            [PSCustomObject] @{ ForegroundColor = 'DarkMagenta'; Value = '$searchFilter'   }
                        )
                    }
                }

                # Now set optional CLI field values for fields with non-default values.
                $optionalArgsWithValuesSyntax = @()
                if ($LdapObfContainer.SearchRoot -and $LdapObfContainer.SearchRoot -cne $global:defaultSearchRoot)
                {
                    $optionalArgsWithValuesSyntax += @(
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = " -SearchRoot '"                               }
                        [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $LdapObfContainer.SearchRoot.Replace("'","''") }
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = "'"                                            }
                    )
                }
                if ($LdapObfContainer.AttributeList -and (Compare-Object -ReferenceObject $LdapObfContainer.AttributeList -DifferenceObject $global:defaultAttributeList).Count -gt 0)
                {
                    $optionalArgsWithValuesSyntax += @(
                        [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = ' -AttributeList ' }
                        for ($i = 0; $i -lt $LdapObfContainer.AttributeList.Count; $i++)
                        {
                            $curAttribute = $LdapObfContainer.AttributeList[$i]

                            # Encapsulate attribute value in single quotes only if required.
                            if ($curAttribute -inotmatch '^[a-z0-9]+$')
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = "'" }
                            }

                            [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $curAttribute.Replace("'","''") }

                            # Encapsulate attribute value in single quotes only if required.
                            if ($curAttribute -inotmatch '^[a-z0-9]+$')
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = "'" }
                            }

                            # Add comma delimiter unless last attribute.
                            if ($i -lt ($LdapObfContainer.AttributeList.Count - 1))
                            {
                                [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = ','}
                            }
                        }
                    )
                }
                if ($LdapObfContainer.Scope -and $LdapObfContainer.Scope -cne $global:defaultScope)
                {
                    $optionalArgsWithValuesSyntax += @(
                        [PSCustomObject] @{ ForegroundColor = 'Cyan';    Value = ' -Scope '              }
                        [PSCustomObject] @{ ForegroundColor = 'Magenta'; Value = $LdapObfContainer.Scope }
                    )
                }

                # Set remaining field values.
                $functionName   = [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = 'Invoke-Maldaptive' }
                $argumentSyntax = [PSCustomObject] @{ ForegroundColor = 'Cyan'; Value = ' -Quiet -NoExit'   }

                # Output CLI syntax if set or obfuscation commands are present.
                if ($setSyntax -or $commandSyntax)
                {
                    $cliSyntaxToOutput = ([System.Array] $functionName + $setSyntax + $commandSyntax + $optionalArgsWithValuesSyntax + $argumentSyntax).Where( { $_ } )

                    foreach ($line in $cliSyntaxToOutput)
                    {
                        Write-Host $line.Value -NoNewline -ForegroundColor $line.ForegroundColor
                    }
                    Write-Host ''
                }
                else
                {
                    Write-Host ''
                }
            }
            'ExecutionCommands' {
                if ($option.Value.Count -gt 1)
                {
                    Write-Host ''
                }

                # If SearchFilter is not set or is set but no obfuscation has been applied then skip displaying ExecutionCommands
                # since it will only be setting the SearchFilter in a variable as a string.
                if (-not $LdapObfContainer.SearchFilter -or ($LdapObfContainer.Layer -eq 0))
                {
                    Write-Host ''

                    break
                }

                $counter = 0
                foreach ($executionCommand in $option.Value)
                {
                    $counter++

                    # If initial SearchFilter is too long then skip displaying its instantiation command for more concise output formatting.
                    if (($counter -eq 1) -and (($LdapObfContainer.History[0].SearchFilter).Replace("'","''").Length -gt $searchFilterDisplaySizeLimit))
                    {
                        continue
                    }

                    # Handle output formatting of newline when SHOW OPTIONS is run.
                    if ($counter -eq ($option.Value | Measure-Object).Count)
                    {
                        $noNewLine = $true
                    }
                    else
                    {
                        $noNewLine = $false
                    }

                    # Split out $ldapObfContainer and original -SearchFilter/-SearchFilterPath value so they can be output in different color.
                    if ($option.Value.Count -gt 1)
                    {
                        Write-Host '    ' -NoNewline
                    }

                    # Prepend $executionCommand with prefix arguments for obfuscation commands (skipping first command
                    # which is just SearchFilter string variable instantiation).
                    if ($counter -gt 1)
                    {
                        $executionCommand = $requiredFunctionPrefixArgumentsToHideFromUI + $executionCommand
                    }

                    # Prepend $executionCommand with SearchFilter string variable instantiation syntax.
                    $executionCommand = '$searchFilter = ' + $executionCommand

                    # Split and add additional highlighting for variable placeholders in execution command syntax values.
                    ($executionCommand -isplit '\$searchFilter').Where( { $_ } ) | ForEach-Object {
                        $remainingCommand = $_

                        Write-Host '$searchFilter' -NoNewline -ForegroundColor DarkMagenta

                        # Depending on SearchFilter and SearchFilterPath length, substitute SearchFilter and SearchFilter path syntax
                        # for $searchFilter and $searchFilterPath placeholder for more concise output formatting.
                        if ($remainingCommand -imatch "'$([Regex]::Escape($LdapObfContainer.History[0].SearchFilter).Replace("'","''"))'")
                        {
                            # Split to extract potential encapsulating single quotes.
                            $remainingCommandSplit = $remainingCommand -isplit [Regex]::Escape($Matches[0])

                            # Add encapsulating quotes to split command for proper coloring of output.
                            if (($Matches[0].Length - 2) -le $searchFilterDisplaySizeLimit)
                            {
                                # Add encapsulating single quote.
                                $remainingCommandSplit[0] = $remainingCommandSplit[0] + "'"
                                $remainingCommandSplit[1] = "'" + $remainingCommandSplit[1]
                            }

                            for ($i = 0; $i -lt (($remainingCommandSplit | Measure-Object).Count - 1); $i++)
                            {
                                Write-Host $remainingCommandSplit[$i] -NoNewline -ForegroundColor Cyan

                                # Encapsulate SearchFilter value in single quotes.
                                # If SearchFilter value is too long then change to $searchFilter placeholder for more concise output formatting.
                                if (($Matches[0].Length - 2) -le $searchFilterDisplaySizeLimit)
                                {
                                    # Exclude encapsulating single quotes from $Matches[0] resultant from regex in -isplit command above.
                                    Write-Host $Matches[0].Substring(1,($Matches[0].Length - 2)) -NoNewline -ForegroundColor Magenta
                                }
                                else
                                {
                                    Write-Host '$searchFilter' -NoNewline -ForegroundColor DarkMagenta
                                }
                            }

                            # Save remaining command for further colorized display purposes.
                            $remainingCommand = $remainingCommandSplit[$i]
                        }
                        elseif (($remainingCommand -imatch [Regex]::Escape($LdapObfContainer.SearchFilterPath)) -and ($LdapObfContainer.SearchFilterPath -ne 'N/A'))
                        {
                            # Split to extract potential encapsulating single quotes.
                            if ($Matches[0].Length -le $searchFilterDisplaySizeLimit)
                            {
                                $remainingCommandSplit = $remainingCommand -isplit [Regex]::Escape($Matches[0])
                            }
                            else
                            {
                                $remainingCommandSplit = $remainingCommand -isplit ("'$([Regex]::Escape($Matches[0]))'")
                            }
                            for ($i = 0; $i -lt (($remainingCommandSplit | Measure-Object).Count - 1); $i++)
                            {
                                Write-Host $remainingCommandSplit[$i] -NoNewline -ForegroundColor Cyan

                                # If SearchFilterPath value is too long then change to $searchFilterPath placeholder for more concise output formatting.
                                if ($Matches[0].Length -le $searchFilterDisplaySizeLimit)
                                {
                                    Write-Host $Matches[0] -NoNewline -ForegroundColor Magenta
                                }
                                else
                                {
                                    Write-Host '$searchFilterPath' -NoNewline -ForegroundColor DarkMagenta
                                }
                            }

                            # Save remaining command for further colorized display purposes.
                            $remainingCommand = $remainingCommandSplit[$i]
                        }
                        else
                        {
                            # Save remaining command for further colorized display purposes.
                            $remainingCommand = $_
                        }

                        Write-Host $remainingCommand -NoNewline -ForegroundColor Cyan
                    }
                    Write-Host '' -NoNewline:$noNewLine
                }
                Write-Host ''

                # Output one-liner version of ExecutionCommands below PowerShell-themed comment.
                Write-Host '    # One-liner ExecutionCommand' -ForegroundColor DarkGreen
                Write-Host '    ' -NoNewline

                $counter = 0
                foreach ($executionCommand in $option.Value)
                {
                    $counter++

                    # If initial SearchFilter is too long then skip displaying its instantiation command for more concise output formatting.
                    if ($counter -eq 1)
                    {
                        if ($executionCommand.Replace("'","''").Length -le $searchFilterDisplaySizeLimit)
                        {
                            # Output color-coded SearchFilter variable instantiation.
                            Write-Host "'" -NoNewline -ForegroundColor Cyan
                            Write-Host $executionCommand.Trim("'").Replace("'","''") -NoNewline -ForegroundColor Magenta
                            Write-Host "'" -NoNewline -ForegroundColor Cyan
                        }
                        else
                        {
                            # Output SearchFilter variable placeholder.
                            Write-Host '$searchFilter' -NoNewline -ForegroundColor DarkMagenta
                        }
                    }
                    else
                    {
                        # Output next command in one-liner pipeline syntax.
                        Write-Host " | $executionCommand" -NoNewline -ForegroundColor Cyan
                    }
                }
                Write-Host ''
            }
            'ObfSearchFilter' {
                # Output ObfSearchFilter (unless it is not yet defined).
                if ($option.Value)
                {
                    # Drop to next line if multiple values are present for more aligned output formatting.
                    if ($option.Value -imatch "`n")
                    {
                        Write-Host ''
                    }

                    Out-LdapObject -InputObject $LdapObfContainer.SearchFilterTokenized -SkipModificationHighlighting -Format default
                }
                else
                {
                    Write-Host ''
                }
            }
            'AttributeList' {
                # Output AttributeList, color-coding only the values and not the comma delimiters.
                if ($option.Value)
                {
                    foreach ($attribute in ($option.Value | Select-Object -SkipLast 1))
                    {
                        Write-Host $attribute -NoNewline -ForegroundColor Magenta
                        Write-Host ',' -NoNewline
                    }
                    Write-Host ($option.Value | Select-Object -Last 1) -ForegroundColor Magenta
                }
                else
                {
                    Write-Host ''
                }
            }
            'DetectionScore' {
                Write-Host $option.Value -ForegroundColor ($option.Value -gt 0.0 ? 'Red' : 'Cyan')
            }
            'DetectionCount' {
                Write-Host $option.Value -ForegroundColor ($option.Value -gt 0.0 ? 'Red' : 'Cyan')
            }
            default {
                # If multiple values then output as simplified PowerShell array syntax.
                if ($option.Value.Count -gt 1)
                {
                    Write-Host ($option.Value -join ',') -ForegroundColor Magenta
                }
                else
                {
                    Write-Host $option.Value -ForegroundColor Magenta
                }
            }
        }
    }
}



function Show-HelpMenu
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Show-HelpMenu
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-HelpMenu displays color-coded help menu for Invoke-Maldaptive function.

.PARAMETER InputOptionMenu

Specifies object containing list of available menu option values and descriptions to display.

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]
        $InputOptionMenu
    )

    # Display Help Menu.
    Write-Host "`n`nHELP MENU" -NoNewline -ForegroundColor Cyan
    Write-Host ' :: Available' -NoNewline
    Write-Host ' options' -NoNewline -ForegroundColor Yellow
    Write-Host " shown below:`n"
    foreach ($inputOption in $InputOptionMenu.PSObject.Properties.Where( { $_.Value.Option -and $_.Value.Description } ).Value)
    {
        # Add additional coloring to strings encapsulated by <> if they exist in $inputOption.Description.
        if ($inputOption.Description -cmatch '<.*>')
        {
            Write-Host "`t" -NoNewline
            $remainingDescription = $inputOption.Description
            while ($remainingDescription -cmatch '<[^>]+>')
            {
                $firstPart  = $remainingDescription.Substring(0,$remainingDescription.IndexOf($Matches[0]))
                $middlePart = $remainingDescription.Substring(($firstPart.Length + 1),($Matches[0].Length - 2))
                Write-Host $firstPart -NoNewline
                Write-Host $middlePart -NoNewline -ForegroundColor Cyan

                # Set $remainingDescription as remaining substring so additional highlighting (if present) can occur in current while loop.
                $remainingIndex = $firstPart.Length + $middlePart.Length + 2
                if ($remainingIndex -gt $remainingDescription.Length)
                {
                    $remainingDescription = $null
                }
                else
                {
                    $remainingDescription = $remainingDescription.Substring($remainingIndex)
                }
            }

            # Output remaining $remainingDescription.
            if ($remainingDescription)
            {
                Write-Host $remainingDescription -NoNewline
            }
        }
        else
        {
            Write-Host "`t$($inputOption.Description)" -NoNewline
        }

        # Output yellow-colored options corresponding to above description output.
        for ($i = 0; $i -lt $inputOption.Option.Count - 1; $i++)
        {
            Write-Host $inputOption.Option[$i].ToUpper() -NoNewline -ForegroundColor Yellow
            Write-Host ', ' -NoNewline
        }
        Write-Host $inputOption.Option[$i].ToUpper() -ForegroundColor Yellow
    }
}



function Show-Tutorial
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Show-Tutorial
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-Tutorial displays color-coded tutorial for Invoke-Maldaptive function.

.EXAMPLE

C:\PS> Show-Tutorial

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    Write-Host "`n`nTUTORIAL"                                                                     -NoNewline -ForegroundColor Cyan
    Write-Host " :: Here is a quick tutorial showing you how to get your obfuscation on:"

    Write-Host "`n1) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Load a SearchFilter (SET SEARCHFILTER) or a SearchFilter file path/URL (SET SEARCHFILTERPATH)."
    Write-Host "   SET SEARCHFILTER (&(objectCategory=Person)(|(name=sabi)(name=dbo)))"                      -ForegroundColor Green

    Write-Host "`n2) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Navigate through the obfuscation menus where the options are in"                  -NoNewline
    Write-Host " YELLOW"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host "."
    Write-Host "   GREEN"                                                                         -NoNewline -ForegroundColor Green
    Write-Host " options apply obfuscation."
    Write-Host "   Enter"                                                                         -NoNewline
    Write-Host " BACK"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "CD .."                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host " to go to previous menu &"                                                        -NoNewline
    Write-Host " HOME"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "MAIN"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to go to home menu.`n   E.g. Enter"                                              -NoNewline
    Write-Host " OBFUSCATE"                                                                       -NoNewline -ForegroundColor Yellow
    Write-Host ","                                                                                -NoNewline
    Write-Host " INSERT"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host ","                                                                                -NoNewline
    Write-Host " WHITESPACE"                                                                      -NoNewline -ForegroundColor Yellow
    Write-Host " & then"                                                                          -NoNewline
    Write-Host " 4"                                                                               -NoNewline -ForegroundColor Green
    Write-Host " to apply Whitespace obfuscation."

    Write-Host "`n3)"                                                                             -NoNewline -ForegroundColor Cyan
    Write-Host " Regex & randomization shortcuts can be used in menu traversal.`n   E.g. Enter"   -NoNewline
    Write-Host " HOME\OBF*\(SUB|INS)*\*\"                                                         -NoNewline -ForegroundColor Yellow
    Write-Host "3"                                                                                -NoNewline -ForegroundColor Green
    Write-Host " for a mixture of regex & simple wildcards."
    Write-Host "   E.g. Enter "                                                                   -NoNewline
    Write-Host "**"                                                                               -NoNewline -ForegroundColor Green
    Write-Host ", "                                                                               -NoNewline
    Write-Host "***"                                                                              -NoNewline -ForegroundColor Green
    Write-Host " or "                                                                             -NoNewline
    Write-Host "****"                                                                             -NoNewline -ForegroundColor Green
    Write-Host " to randomly apply one, some or all downstream menu options."

    Write-Host "`n4) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " TEST"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "EXEC"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to test the obfuscated SearchFilter by issuing an LDAP SearchRequest.`n   Enter" -NoNewline
    Write-Host " SHOW"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host " to see the currently obfuscated SearchFilter."

    Write-Host "`n5) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " DETECT"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "FIND-EVIL"                                                                        -NoNewline -ForegroundColor Yellow
    Write-Host " to evaluate all detection rules against obfuscated SearchFilter."

    Write-Host "`n6) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " COPY"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "CLIP"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to copy obfuscated SearchFilter out to your clipboard."
    Write-Host "   Enter"                                                                         -NoNewline
    Write-Host " OUT"                                                                             -NoNewline -ForegroundColor Yellow
    Write-Host " to write obfuscated SearchFilter out to disk."

    Write-Host "   Enter"                                                                         -NoNewline
    Write-Host " EXPORT"                                                                          -NoNewline -ForegroundColor Yellow
    Write-Host " to write obfuscation container (with all obfuscation layers) out to disk."

    Write-Host "`n7) "                                                                            -NoNewline -ForegroundColor Cyan
    Write-Host "Enter"                                                                            -NoNewline
    Write-Host " RESET"                                                                           -NoNewline -ForegroundColor Yellow
    Write-Host " to remove all obfuscation & start over.`n   Enter"                               -NoNewline
    Write-Host " UNDO"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host " to undo last obfuscation layer.`n   Enter"                                       -NoNewline
    Write-Host " HELP"                                                                            -NoNewline -ForegroundColor Yellow
    Write-Host "/"                                                                                -NoNewline
    Write-Host "?"                                                                                -NoNewline -ForegroundColor Yellow
    Write-Host " for help menu."

    Write-Host "`nAnd finally the obligatory `"Don't use this for evil, please`""                 -NoNewline -ForegroundColor Cyan
    Write-Host " :)"                                                                                         -ForegroundColor Green
}


function Split-Command
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Split-Command
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Split-Command splits input command or array of commands joined by commas or slashes as supported by the Invoke-Maldaptive function.

.PARAMETER Command

Specifies command or array of commands joined by commas or slashes to split for input into Invoke-Maldaptive function.

.EXAMPLE

C:\PS> @('Home\Obfuscate\Insert\Whitespace\4,back,Parenthesis\3,3','Home\Obfuscate\Substitute\Hex\3') | Split-Command

Home
Obfuscate
Insert
Whitespace
4
back
Parenthesis
3
3
Home
Obfuscate
Substitute
Hex
3

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.String[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]
        $Command
    )

    begin
    {

    }

    process
    {
        # Iterate over each input command.
        foreach ($curCommand in $Command)
        {
            # Extract potential concatenated commands while applying special logic if 'SET SEARCHFILTER', 'SET SEARCHROOT'
            # or 'SET ATTRIBUTELIST' scenarios are present to avoid potentially setting an incomplete value.
            $firstSplit = $true
            $commandSplit = @($curCommand -isplit ',\s*SET ' | ForEach-Object {
                if ($firstSplit)
                {
                    $firstSplit = $false
                    $_.TrimStart()
                }
                else
                {
                    "SET $($_.TrimStart())"
                }
            })

            # Split on any commas to extract potential additional non-SET concatenated commands.
            # Additionally, for any non-SET command(s), split on slashes to further extract subcommands. E.g. Home\String\1
            @(for ($i = 0; $i -lt $commandSplit.Count; $i++)
            {
                # For 'SET SEARCHFILTER', 'SET SEARCHROOT' or 'SET ATTRIBUTELIST' scenarios where commas can legitimately
                # be found in the value being set then treat entire user input as the value.
                if ($commandSplit[$i] -imatch '^SET\s+(SEARCHFILTER|SEARCHROOT|ATTRIBUTELIST)\s+.*,')
                {
                    # Return remainder of command as single unit since SearchFilter, SearchRoot and AttributeList are
                    # settable properties that can legimately have commas in their values, so splitting on commas would
                    # potentially cause incomplete values to be set.
                    $joinedCommandSplit = $commandSplit[$i..$commandSplit.Count] -join ','

                    # Return joined command.
                    $joinedCommandSplit

                    # Break out of current for loop since all remaining split commands were returned above.
                    break
                }
                else
                {
                    # Split on any remaining commas to extract potential additional non-SET concatenated commands.
                    $commandSplit[$i].Split(',').TrimStart().Where( { $_ } ) | ForEach-Object {
                        # Additionally, for any non-SET/OUT/EXPORT command(s) then split on slashes to further
                        # extract subcommands. E.g. Home\Obfuscate\Insert\Whitespace
                        if ($_ -inotmatch '^\s*(SET|OUT|EXPORT) ')
                        {
                            $_ -csplit '[/\\]'
                        }
                        else
                        {
                            $_
                        }
                    }
                }
            })
        }
    }

    end
    {

    }
}


function Show-AsciiArt
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Show-AsciiArt
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Show-AsciiArt displays static ASCII art title banner and optional animated ASCII art introduction for Invoke-Maldaptive function.

.PARAMETER Animated

(Optional) Specifies that animated ASCII art introduction be displayed before displaying default static ASCII art title banner.

.EXAMPLE

C:\PS> Show-AsciiArt

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
        [Switch]
        $Animated
    )

    # Define output foreground colors for all LdapToken Type property values for outputting ASCII art title banner below as a valid LDAP SearchFilter.
    $colorObj = [PSCustomObject] @{
        CommaDelimiter        = [System.ConsoleColor]::Gray
        Whitespace            = [System.ConsoleColor]::Gray
        GroupStart            = [System.ConsoleColor]::White
        GroupEnd              = [System.ConsoleColor]::White
        BooleanOperator       = [System.ConsoleColor]::Green
        ComparisonOperator    = [System.ConsoleColor]::Cyan
        Attribute             = [System.ConsoleColor]::Magenta
        ExtensibleMatchFilter = [System.ConsoleColor]::Red
        Value                 = [System.ConsoleColor]::Yellow
    }

    # Add dark versions of output foreground colors for RDN (Relative Distinguished Name) subset of above LdapToken Type property values.
    Add-Member -InputObject $colorObj -MemberType NoteProperty -Name RdnCommaDelimiter     -Value ([System.ConsoleColor]::('Dark' + $colorObj.CommaDelimiter))
    Add-Member -InputObject $colorObj -MemberType NoteProperty -Name RdnAttribute          -Value ([System.ConsoleColor]::('Dark' + $colorObj.Attribute))
    Add-Member -InputObject $colorObj -MemberType NoteProperty -Name RdnComparisonOperator -Value ([System.ConsoleColor]::('Dark' + $colorObj.ComparisonOperator))
    Add-Member -InputObject $colorObj -MemberType NoteProperty -Name RdnValue              -Value ([System.ConsoleColor]::('Dark' + $colorObj.Value))

    # Create ASCII art title banner.
    $padding = '    '
    $invokeMaldaptiveAscii = @'
(
    |
    (MM\=    /MM)             (LL|      :DDDDD:=      AAAAA)   (PPP=*)
    (MMM\=  /MMM)             (LL|      :DDDDDD:=    AAA^AAA)  (PPPPPPP    :tt:=   iii)(vvv   vvv=  eeee)
    (MMMM\=/MMMM)   (name= *) (LL|      :DD  \DD:=  AAA/ \AAA) (PP   \PP:tttttttt:=iii)(vvv   vvv= eeeeee)
    (MM=  V   MM)  (aaaav=aa) (LL|      :DD   \DD:=.AA/___\AA.)(PP   /PP:tttttttt:=  *)(vvv   vvv=ee    ee)
    (MM=      MM) (aa' 'a=aa) (LL|      :DD    DD:=(=ANI,ANI=))(PPPPPPP    :tt:=   iii)(vvv   vvv=eeeeeee)
    (MM=      MM)(aa{   }=aa) (LL|      :DD   /DD:=AAA     AAA)(PPPPP      :tt:=   iii) (vvv vvv= eeeeee)
    (MM=      MM) (aa. .a=aa) (LL|_____.:DD__/DD:= AAA     AAA)(PP         :tt:=   iii)  (vvvvv=  ee)
    (MM=      MM)  (aaaa^=aa) (LLLLLLLLL:DDDDDD:=  AAA     AAA)(PP         :tt:=   iii)   (vvv=    ee..ee)
    (MM=      MM)   (aaa =aa) (LLLLLLLLL:DDDDD:=   AAA     AAA)(PP         :tt:=   iii)    (v=      eeee)
    (
        &
        (Tool    := Invoke-Maldaptive)
        (Authors := Sabajete Elezaj (Sabi) & Daniel Bohannon (DBO))
        (Twitter := @sabi_elezi & @danielhbohannon)
        (Github  := https://github.com/MaLDAPtive/Invoke-Maldaptive)
        (Version := 1.0)
        (License := Apache License, Version 2.0)
        (Notes   := if (-not $user.IsCaffeinated) { exit })
    )
)
'@.Split("`n").ForEach( { $padding + $_ } )

    # Create array of index objects for color-coding above ASCII art title banner.
    $indexObj = [PSCustomObject] @{
        0 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        1 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.BooleanOperator       }
        )
        2 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  3; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   8; Length =  5; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  13; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length = 15; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length =  7; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  47; Length =  7; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  54; Length =  5; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  59; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length =  3; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  67; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  68; Length =  1; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  69; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        3 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  4; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   9; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  12; Length =  4; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length = 15; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length =  8; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  48; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  51; Length =  9; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  60; Length =  4; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length = 11; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  75; Length =  4; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  79; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  88; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  97; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart = 100; Length =  4; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 104; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        4 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  5; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  10; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  11; Length =  5; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  21; Length =  4; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  27; Length =  1; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length =  9; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  49; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  52; Length =  9; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  61; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  72; Length = 10; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  82; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  88; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  97; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  99; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 105; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        5 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  2; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   7; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  10; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  4; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  20; Length =  5; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  26; Length =  2; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length = 10; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  50; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  51; Length = 11; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  62; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  72; Length = 10; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  82; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  85; Length =  1; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  88; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  97; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  98; Length =  8; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 106; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        6 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  2; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   7; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  10; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  19; Length =  6; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  26; Length =  2; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length = 10; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  50; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            #
            # Custom dark foreground ConsoleColor value for single RDN Filter value in ASCII art.
            [PSCustomObject] @{ IndexStart =  51; Length =  1; ForegroundColor = $colorObj.RdnAttribute          }
            [PSCustomObject] @{ IndexStart =  52; Length =  1; ForegroundColor = $colorObj.RdnComparisonOperator }
            [PSCustomObject] @{ IndexStart =  53; Length =  3; ForegroundColor = $colorObj.RdnValue              }
            [PSCustomObject] @{ IndexStart =  56; Length =  1; ForegroundColor = $colorObj.RdnCommaDelimiter     }
            [PSCustomObject] @{ IndexStart =  57; Length =  3; ForegroundColor = $colorObj.RdnAttribute          }
            [PSCustomObject] @{ IndexStart =  60; Length =  1; ForegroundColor = $colorObj.RdnComparisonOperator }
            [PSCustomObject] @{ IndexStart =  61; Length =  1; ForegroundColor = $colorObj.RdnValue              }
            #
            [PSCustomObject] @{ IndexStart =  62; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length = 11; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  75; Length =  4; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  79; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  88; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  97; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  98; Length =  7; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 105; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        7 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  2; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   7; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  10; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  18; Length =  7; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  26; Length =  2; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length = 10; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  50; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  51; Length = 11; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  62; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length = 11; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  75; Length =  4; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  79; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  89; Length =  7; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  96; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  98; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 104; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        8 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  2; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   7; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  10; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  19; Length =  6; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  26; Length =  2; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length =  9; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  49; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  51; Length = 11; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  62; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length = 11; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  75; Length =  4; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  79; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  4; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  90; Length =  5; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  95; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  97; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 100; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        9 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  2; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   7; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  10; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  4; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  20; Length =  5; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  26; Length =  2; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length =  8; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  48; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  51; Length = 11; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  62; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length = 11; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  75; Length =  4; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  79; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  91; Length =  3; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  94; Length =  5; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  99; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 105; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        10 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   5; Length =  2; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =   7; Length =  3; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  10; Length =  6; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  16; Length =  5; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  21; Length =  4; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  25; Length =  1; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  26; Length =  2; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  28; Length =  3; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  31; Length =  9; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  40; Length =  7; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  47; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  51; Length = 11; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  62; Length =  2; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  64; Length = 11; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  75; Length =  4; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  79; Length =  4; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  83; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  86; Length =  6; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =  92; Length =  1; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  93; Length =  7; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart = 100; Length =  4; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart = 104; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        11 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
        )
        12 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.BooleanOperator       }
        )
        13 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length = 17; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  37; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        14 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length = 46; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  66; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        15 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length = 30; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  50; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        16 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length = 47; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  67; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        17 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length =  3; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  23; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        18 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length = 27; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  47; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        19 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  9; ForegroundColor = $colorObj.GroupStart            }
            [PSCustomObject] @{ IndexStart =   9; Length =  8; ForegroundColor = $colorObj.Attribute             }
            [PSCustomObject] @{ IndexStart =  17; Length =  1; ForegroundColor = $colorObj.ExtensibleMatchFilter }
            [PSCustomObject] @{ IndexStart =  18; Length =  2; ForegroundColor = $colorObj.ComparisonOperator    }
            [PSCustomObject] @{ IndexStart =  20; Length = 38; ForegroundColor = $colorObj.Value                 }
            [PSCustomObject] @{ IndexStart =  58; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
        20 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  5; ForegroundColor = $colorObj.GroupStart            }
        )
        21 = @(
            [PSCustomObject] @{ IndexStart =   0; Length =  1; ForegroundColor = $colorObj.GroupStart            }
        )
    }

    # Animated ASCII art to display if user input -Animated switch parameter is defined (e.g. only run during interactive Invoke-Maldaptive function invocation).
    if ($PSBoundParameters['Animated'].IsPresent)
    {
        $arrowAscii = @(
            '  |  '
            '  |  '
            ' \ / '
            '  V  '
        )

        # Show actual obfuscation example generated with this tool.
        Out-LdapObject -Format default -InputObject '(|(MaLDAPtive:¯\_(LDAP)_/¯:=ObFUsc8t10n)(De-Obfuscation &:=De*te)(!c=tion))'
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        Out-LdapObject -Format default -InputObject '(|(!2.5.4.6=t\69On)(c=,%".$)(2.5.4.6=n\69Ot)(mALDAPtIve:¯\_(LdAP)_/¯:=ObFUSc8T10n)(!2...456=byteValue)(!safetyEpisode=t\6ETn)(!hatMonkey=t\69On)(!osmw8fer=4tgsl)(reedwitth=\69nOt)(vlq35oc=tO\69n)(De-ObfUscatIoN &:_{\(_\(>/%:=De*te)(6.9.42=l\69On))'
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line -NoNewline
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        Out-LdapObject -Format default -InputObject '(!(&  (2.5.4.6=t\69On)(   (     !  c=  ,%".$)    ) (!  bud52we=    minuteBoot)(&(      (!  2.5.4.6= n\69Ot)( 2%5.4.6=t\5EDn))   )   ((   !  mALDAPtIve:¯\_(LdAP)_/¯:=ObFUSc8T10n))   (2...456=  byteValue)(safetyEpisode=t\6ETn)  (!    xdpcck= \*# ,$)((      (hatMonkey=t\69On)(  !   5.2.6.4=   ,$".%))  )   (!2.5.4.6  =n\69tO) (! ~} ''=   wod)  (! ( (!  osmw8fer=4tgsl)) )   (      &  (!reedwitth=\69nOt))   (   !bpfk29d=[%"[$)   (   ( (    (!c=$%""\()  (  (!  vlq35oc=  tO\69n)(!  2.564..=partyWeather)   ) ) )  (!   c=ieaoh)   (| (&  (&(|(   !   De-ObfUscatIoN &:_{\(_\(>/%:=De*te) (2.5.4.6 =lty)) ) )  )  ) (!  (     6.9.42  =l\69On)    (2.5.6.4    =itouand))) )  '
        Start-Sleep -Milliseconds 650
        foreach ($line in $arrowAscii)
        {
            Write-Host $line -NoNewline
            Write-Host $line -NoNewline
            Write-Host $line
        }
        Start-Sleep -Milliseconds 100

        Out-LdapObject -Format default -InputObject '((  !(   &     ((|  5.8''4''9>=   AniAni)(|   2.5.4.6=t\49\6F\6E))(!        ostrys=   x\49oN)(    !_-\(+<;|=*)(     |((!(&(   (      !  2.5.4.6<=  ,%\22.\22)(!    c=crewlion)(          |  2.5.4.6   <=     ,%".%))((     !    2.5.4.6>=   ,%".%)  )(  (     !  2.5.4.6<=  ,%".#) ))(    c=hbl))(C=   rpoout) (     !   C=   *)   )    ) (!   bud52we=    minuTEBoOT)   (   (   !  (     6.9.42   =L\49On)    (!ityouhat=  \*""%$\*)   (   (|2.5.6.4       =itouand))))   ( !((         |MAldaPtIvE:¯\_(ldAp)_/¯:=oBFUsC8T10n))   )   (      &  (   |  ((    !  REEDWITTH=  *)(!REedWitTH=\69nOT)  )  )   )   (| SafETYEPISODE= t\4Etn)  (|(    !      xdPcCK=  *)(   !      xdpcck= \*# \2C$))(((         ((   !    c=krge6) (   hatMonkey=t\69On)   (  !     5.2.6.4 =      ,$".%))))  )    (|((&   2.5.4.6     = n\69tM*)(C=@><& ?@#))((   |2.5.4.6      = N\69Tp*)  (   !2.5.4.6     <=n\69tP)(    c=ined)) ((|2.5.4.6     =n\69Tn*))(&  2.5.4.6     <=n\69TM)   ) (  ! ~} ''=   *WoD**)   (!    ( ((!     OsMW8feR= 4t\67S\4C)   )  (!6.5.4.2>=\24%""*)) )   (&(      (|(!  2.5.4.6  >=    n\49oQ)( |  2.5.4.6>= N\49ox)((      C=wovlmeeo)(  | 2.5.4.6>= n\69Ou)   )   (  (  2.5.4.6   <= N\69os)   ))(    &2%5.4.6=     \74\5Edn))   )   (      ! bpFK29D=*[%"**[$)   (!      ( ( !   (!        (&   (( !c=   $%"\22&*)(  !C=$%""**))  (!   C~=o5dq)(!C>=\24%""*)(      !C=IEA\*OF)((!C=\24%"\22\29*)(! 2.5.4.6=o\61EID) )((   !    C=:''?<#)(|C>= $%""&))(!C~=   khkvgq))     (!  ((  &   VlQ35OC=  to\69n*)(|((     !  2.564..=  PARty***hEr)(       c~=sculpturerhythm)   )   (   !  2.564..=  **weA*)))   (       !  labankle<=  Yt)   )  )  ))  ((| ((  &     (!detailevil=  !].!?^{?)((&(     |   (   !   de-oBfUSCaTiOn &:_{\(_\(>/%:=De*te)((       2.5.4.6  =  `=`)   (     !      de-obFuScaTiOn &=*)) (  |  2.5.4.6= |};.)  ((    C= AEIoK\*)  (   &   (    !4.5.2.6  =ieaog*)(   2.5.4.6 =  lt***)(    |2.5.4.6 = *tY)   )) ) )) ) )      )   (!    issvrt=oeaid)(|((    c=yeAzX)(!( (&(!    c=ieAoI*)(  !    c=IE\41Oe*)(( !    C=IEAOF*))  (!C=\*%\*""$)(!    C= IEAoK*)(!2.5.4.6     =nSEC3Recip)( !    C=  ieaod*)( !    C>=  IEaOl)(      c=*)(!    c=ieaog*)(!    c=IeAOl*)  (!C= defaultPwd)(!    c=   IeAoj*)(!    c<=IE\61oD)))))(   (!     C= *)   )))  ) (&   2...456=  BYTevAlUE)) )  )'
        Start-Sleep -Milliseconds 650
        Write-Host ''

        # Write out below string in interactive format.
        Start-Sleep -Milliseconds 100
        foreach ($char in [System.Char[]] 'Invoke-Maldaptive')
        {
            Start-Sleep -Milliseconds (Get-Random -Input @(25..200))
            Write-Host $char -NoNewline -ForegroundColor Green
        }

        Start-Sleep -Milliseconds 900
        Write-Host ""
        Start-Sleep -Milliseconds 300
        Write-Host
    }

    # Display ASCII art title banner based on previously defined array of index objects for color-coding.
    # Iterate over each line's array of index objects.
    foreach ($curLineIndex in $indexObj.PSObject.Properties.Name)
    {
        # Iterate over each substring index object for current line.
        foreach ($curLineIndexObj in $indexObj.$curLineIndex)
        {
            # Output current substring for current line with potential corresponding foreground color.
            $optionalForegroundColor = $curLineIndexObj.ForegroundColor ? @{ ForegroundColor = $curLineIndexObj.ForegroundColor } : @{ }
            Write-Host $invokeMaldaptiveAscii[$curLineIndex].Substring(($padding.Length + $curLineIndexObj.IndexStart),$curLineIndexObj.Length) -NoNewline @optionalForegroundColor
        }

        # Output newline after outputting all substrings for current line above.
        Write-Host ''
    }
}


function New-ObfuscationContainer
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: New-ObfuscationContainer
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-LdapObject
Optional Dependencies: None

.DESCRIPTION

New-ObfuscationContainer creates obfuscation container to store history of LDAP SearchFilter obfuscation layers.

.PARAMETER SearchFilter

Specifies initial LDAP SearchFilter to which future obfuscation layers can be applied.

.PARAMETER SearchFilterPath

Specifies path to file containing initial LDAP SearchFilter to which future obfuscation layers can be applied.

.PARAMETER SearchRoot

(Optional) Specifies LDAP SearchRoot to specify the base of the subtree for constraining the LDAP SearchRequest if testing LDAP SearchFilter.

.PARAMETER AttributeList

(Optional) Specifies LDAP AttributeList to limit properties returned for any matching objects returned by LDAP SearchRequest if testing LDAP SearchFilter.

.PARAMETER Scope

(Optional) Specifies LDAP Scope to limit portions of targeted subtree to be traversed by LDAP SearchRequest if testing LDAP SearchFilter.

.EXAMPLE

C:\PS> New-ObfuscationContainer -SearchFilter '(|(name=sabi)(name=dbo))' -SearchRoot 'LDAP://DC=contoso,DC=com' -AttributeList name,sAMAccountType -Scope Subtree

SearchRoot                 : LDAP://DC=contoso,DC=com
AttributeList              : {name, sAMAccountType}
Scope                      : Subtree
Layer                      : 0
SearchFilter               : (|(name=sabi)(name=dbo))
SearchFilterTokenized      : {Guid: , Depth: 0, Length: 1, Format: NA, IsDefined: , Type: GroupStart, SubType: , 
                             ScopeSyntax: FilterList, ScopeApplication: FilterList, Content: (, ContentDecoded: (, Guid: 
                             282732b0-e229-4f38-8df4-91cd0fbff228, Depth: 1, Length: 1, Format: NA, IsDefined: , Type: 
                             BooleanOperator, SubType: , ScopeSyntax: FilterList, ScopeApplication: FilterList, Content: |, 
                             ContentDecoded: |, Guid: , Depth: 1, Length: 1, Format: NA, IsDefined: , Type: GroupStart, 
                             SubType: , ScopeSyntax: Filter, ScopeApplication: Filter, Content: (, ContentDecoded: (, Guid: 
                             , Depth: 1, Length: 4, Format: String, IsDefined: True, Type: Attribute, SubType: , 
                             ScopeSyntax: , ScopeApplication: , Content: name, ContentDecoded: name…}
SearchFilterLength         : 24
SearchFilterTokenCount     : 13
FilterCount                : 2
SearchFilterDepth          : 2
SearchFilterMD5            : 266567844BAB450896FB73B49291A59A
SearchFilterOrig           : (|(name=sabi)(name=dbo))
SearchFilterOrigLength     : 24
SearchFilterOrigTokenCount : 13
FilterOrigCount            : 2
SearchFilterOrigDepth      : 2
SearchFilterOrigMD5        : 266567844BAB450896FB73B49291A59A
SearchFilterPath           : 
History                    : {@{Layer=0; SearchFilter=(|(name=sabi)(name=dbo)); 
                             SearchFilterTokenized=Maldaptive.LdapTokenEnriched[]; SearchFilterLength=24; 
                             SearchFilterTokenCount=13; FilterCount=2; SearchFilterDepth=2; 
                             SearchFilterMD5=266567844BAB450896FB73B49291A59A; SearchFilterOrig=(|(name=sabi)(name=dbo)); 
                             SearchFilterOrigLength=24; SearchFilterOrigTokenCount=13; FilterOrigCount=2; 
                             SearchFilterOrigDepth=2; SearchFilterOrigMD5=266567844BAB450896FB73B49291A59A; 
                             Function=New-ObfuscationContainer; CommandLineSyntax='(|(name=sabi)(name=dbo))'; 
                             CliSyntax=System.Object[]}}

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [CmdletBinding()]
    [OutputType([System.Object])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'SearchFilter')]
        [System.String[]]
        $SearchFilter,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'SearchFilterPath')]
        [System.IO.FileInfo[]]
        $SearchFilterPath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $SearchRoot = $global:defaultSearchRoot,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $AttributeList = $global:defaultAttributeList,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Base','OneLevel','Subtree')]
        [System.String]
        $Scope = $global:defaultScope
    )

    begin
    {
        # Array that will house single or multiple input SearchFilters.
        $searchFilterArr = @()
    }

    process
    {
        # Handle various input formats to produce the same data format in the $searchFilterArr.
        switch ($PSCmdlet.ParameterSetName)
        {
            'SearchFilterPath' {
                # Read in file path(s) as a string and add to $searchFilterArr.
                foreach ($curPath in $executionContext.SessionState.Path.GetResolvedProviderPathFromProviderPath($SearchFilterPath, 'FileSystem'))
                {
                    # Remove single trailing newline when reading text from file.
                    $searchFilterArr += ([System.IO.File]::ReadAllText($curPath) -creplace "`r`n","`n" -creplace "`n$",'')
                }
            }
            'SearchFilter' {
                # Cast input SearchFilter(s) as a string and add to $searchFilterArr.
                foreach ($curSearchFilter in $SearchFilter)
                {
                    $searchFilterArr += [System.String] $curSearchFilter
                }
            }
        }
    }

    end
    {
        # Iterate over each SearchFilter added to $searchFilterArr in process pipeline above.
        foreach ($curSearchFilter in $searchFilterArr)
        {
            # Handle if initial SearchFilter should be null for creating empty obfuscation container.
            if ($curSearchFilter -eq ' ')
            {
                # PowerShell function's required input parameter does not accept $null or empty string, so we use single whitespace instead as input then change back to empty string.
                $curSearchFilter = ''
            }

            # Perform initial tokenization and calculate LDAP SearchFilter Filter count and depth.
            if ($curSearchFilter)
            {
                # Convert initial SearchFilter string into tokenized SearchFilter.
                $curSearchFilterTokenized = ConvertTo-LdapObject -InputObject $curSearchFilter -Target LdapTokenEnriched

                # Calculate LDAP SearchFilter Filter count.
                $curFilterCount = $curSearchFilterTokenized.Where( { $_ -is [Maldaptive.LdapToken] -and $_.Type -eq [Maldaptive.LdapTokenType]::Attribute } ).Count

                # Calculate LDAP SearchFilter depth, adding 1 since MaLDAPtive LDAP SearchFilter depth starts with 0.
                $curSearchFilterDepth = ($curSearchFilterTokenized.Depth | Measure-Object -Maximum).Maximum + 1
            }
            else
            {
                $curSearchFilterTokenized = @()
                $curFilterCount = 0
                $curSearchFilterDepth = 0
            }

            # Calculate MD5 hash of LDAP SearchFilter.
            $curSearchFilterMD5 = [System.String] (Get-FileHash -InputStream ([System.IO.MemoryStream]::New([System.Text.Encoding]::UTF8.GetBytes($curSearchFilter))) -Algorithm MD5).Hash

            # Return obfuscation container to house each step of obfuscation history.
            [PSCustomObject] @{
                SearchRoot                 = [System.String]   $SearchRoot
                AttributeList              = [System.String[]] $AttributeList
                Scope                      = [System.String]   $Scope

                # Values for current layer.
                Layer                      = [System.Int16]    0
                SearchFilter               = [System.String]   $curSearchFilter
                SearchFilterTokenized      = [Maldaptive.LdapTokenEnriched[]] $curSearchFilterTokenized
                SearchFilterLength         = [System.Int64]    $curSearchFilter.Length
                SearchFilterTokenCount     = [System.Int64]    $curSearchFilterTokenized.Count
                FilterCount                = [System.Int64]    $curFilterCount
                SearchFilterDepth          = [System.Int64]    $curSearchFilterDepth
                SearchFilterMD5            = [System.String]   $curSearchFilterMD5

                # Values for original layer.
                SearchFilterOrig           = [System.String]   $curSearchFilter
                SearchFilterOrigLength     = [System.Int64]    $curSearchFilter.Length
                SearchFilterOrigTokenCount = [System.Int64]    $curSearchFilterTokenized.Count
                FilterOrigCount            = [System.Int64]    $curFilterCount
                SearchFilterOrigDepth      = [System.Int64]    $curSearchFilterDepth
                SearchFilterOrigMD5        = [System.String]   $curSearchFilterMD5

                # Set SearchFilterPath as placeholder property for Invoke-Maldaptive to update if SET SEARCHFILTERPATH is used instead of SET SEARCHFILTER.
                SearchFilterPath           = [System.String]   $null

                # History property is an array that will store all previous obfuscation layers as they are added or removed via Add-ObfuscationLayer and Remove-ObfuscationLayer, respectively.
                History = @(
                    [PSCustomObject] @{
                        # Values for current layer.
                        Layer                      = [System.Int16]  0
                        SearchFilter               = [System.String] $curSearchFilter
                        SearchFilterTokenized      = [Maldaptive.LdapTokenEnriched[]] $curSearchFilterTokenized
                        SearchFilterLength         = [System.Int64]  $curSearchFilter.Length
                        SearchFilterTokenCount     = [System.Int64]  $curSearchFilterTokenized.Count
                        FilterCount                = [System.Int64]  $curFilterCount
                        SearchFilterDepth          = [System.Int64]  $curSearchFilterDepth
                        SearchFilterMD5            = [System.String] $curSearchFilterMD5

                        # Values for original layer.
                        SearchFilterOrig           = [System.String] $curSearchFilter
                        SearchFilterOrigLength     = [System.Int64]  $curSearchFilter.Length
                        SearchFilterOrigTokenCount = [System.Int64]  $curSearchFilterTokenized.Count
                        FilterOrigCount            = [System.Int64]  $curFilterCount
                        SearchFilterOrigDepth      = [System.Int64]  $curSearchFilterDepth
                        SearchFilterOrigMD5        = [System.String] $curSearchFilterMD5

                        # Below field only added for each item in History array property and not stored in overall main properties.
                        Function = [System.String] $MyInvocation.MyCommand.Name

                        # Below two properties are only used when function is called from Invoke-Maldaptive for interactive display purposes.
                        # CommandLineSyntax is assembled in this function, but CliSyntax must be assembled by calling Invoke-Maldaptive function.
                        CommandLineSyntax = [System.String] "'$($curSearchFilter.Replace("'","''"))'"
                        CliSyntax         = [System.Array]  @()
                    }
                )
            }
        }
    }
}


function Add-ObfuscationLayer
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-ObfuscationLayer
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Add-ObfuscationLayer adds input LDAP SearchFilter as additional obfuscation layer into input obfuscation container.

.PARAMETER ObfuscationContainer

Specifies obfuscation container in which to add input LDAP SearchFilter as additional obfuscation layer.

.PARAMETER SearchFilterTokenized

Specifies LDAP SearchFilter to add as additional obfuscation layer into input obfuscation container.

.EXAMPLE

C:\PS> $obfContainer = New-ObfuscationContainer -SearchFilter '(|(name=sabi)(name=dbo))' -SearchRoot 'LDAP://DC=contoso,DC=com' -AttributeList name,sAMAccountType -Scope Subtree
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('(|(name=\73abi)(name=d\62\6F))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer

SearchRoot                 : LDAP://DC=contoso,DC=com
AttributeList              : {name, sAMAccountType}
Scope                      : Subtree
Layer                      : 1
SearchFilter               : (|(name=\73abi)(name=d\62\6F))
SearchFilterTokenized      : {Guid: , Depth: 0, Length: 1, Format: NA, IsDefined: , Type: GroupStart, SubType: , 
                             ScopeSyntax: FilterList, ScopeApplication: FilterList, Content: (, ContentDecoded: (, Guid: 
                             aa7c6456-33d1-49b3-8f49-1d3cd27ca75f, Depth: 1, Length: 1, Format: NA, IsDefined: , Type: 
                             BooleanOperator, SubType: , ScopeSyntax: FilterList, ScopeApplication: FilterList, Content: |, 
                             ContentDecoded: |, Guid: , Depth: 1, Length: 1, Format: NA, IsDefined: , Type: GroupStart, 
                             SubType: , ScopeSyntax: Filter, ScopeApplication: Filter, Content: (, ContentDecoded: (, Guid: 
                             , Depth: 1, Length: 4, Format: String, IsDefined: True, Type: Attribute, SubType: , 
                             ScopeSyntax: , ScopeApplication: , Content: name, ContentDecoded: name…}
SearchFilterLength         : 30
SearchFilterTokenCount     : 13
FilterCount                : 2
SearchFilterDepth          : 2
SearchFilterMD5            : 3C6E9C7C6E5C67959D3F8A69F0A88838
SearchFilterOrig           : (|(name=sabi)(name=dbo))
SearchFilterOrigLength     : 24
SearchFilterOrigTokenCount : 13
FilterOrigCount            : 2
SearchFilterOrigDepth      : 2
SearchFilterOrigMD5        : 266567844BAB450896FB73B49291A59A
SearchFilterPath           : 
History                    : {@{Layer=0; SearchFilter=(|(name=sabi)(name=dbo)); 
                             SearchFilterTokenized=Maldaptive.LdapTokenEnriched[]; SearchFilterLength=24; 
                             SearchFilterTokenCount=13; FilterCount=2; SearchFilterDepth=2; 
                             SearchFilterMD5=266567844BAB450896FB73B49291A59A; SearchFilterOrig=(|(name=sabi)(name=dbo)); 
                             SearchFilterOrigLength=24; SearchFilterOrigTokenCount=13; FilterOrigCount=2; 
                             SearchFilterOrigDepth=2; SearchFilterOrigMD5=266567844BAB450896FB73B49291A59A; 
                             Function=New-ObfuscationContainer; CommandLineSyntax='(|(name=sabi)(name=dbo))'; 
                             CliSyntax=System.Object[]}, @{Layer=1; SearchFilter=(|(name=\73abi)(name=d\62\6F)); 
                             SearchFilterTokenized=Maldaptive.LdapTokenEnriched[]; SearchFilterLength=30; 
                             SearchFilterTokenCount=13; FilterCount=2; SearchFilterDepth=2; 
                             SearchFilterMD5=3C6E9C7C6E5C67959D3F8A69F0A88838; SearchFilterOrig=(|(name=sabi)(name=dbo)); 
                             SearchFilterOrigLength=24; SearchFilterOrigTokenCount=13; FilterOrigCount=2; 
                             SearchFilterOrigDepth=2; SearchFilterOrigMD5=266567844BAB450896FB73B49291A59A; 
                             CommandLineSyntax=; CliSyntax=System.Object[]; Function=}}

.EXAMPLE

C:\PS> $obfContainer = New-ObfuscationContainer -SearchFilter '(|(name=sabi)(name=dbo))' -SearchRoot 'LDAP://DC=contoso,DC=com' -AttributeList name,sAMAccountType -Scope Subtree
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('(|(name=\73abi)(name=d\62\6F))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('  (&  ( ! name=   videosky)   (| (name=   \73abi)(  &name= d\62\6F)(name=\73iba) ))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer.History | Select-Object Layer,FilterCount,SearchFilterLength,SearchFilter

Layer FilterCount SearchFilterLength SearchFilter
----- ----------- ------------------ ------------
    0           2                 24 (|(name=sabi)(name=dbo))
    1           2                 30 (|(name=\73abi)(name=d\62\6F))
    2           4                 83   (&  ( ! name=   videosky)   (| (name=   \73abi)(  &name= d\62\6F)(name=\73iba) ))

.EXAMPLE

C:\PS> $obfContainer = New-ObfuscationContainer -SearchFilter '(|(name=sabi)(name=dbo))' -SearchRoot 'LDAP://DC=contoso,DC=com' -AttributeList name,sAMAccountType -Scope Subtree
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('(|(name=\73abi)(name=d\62\6F))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('  (&  ( ! name=   videosky)   (| (name=   \73abi)(  &name= d\62\6F)(name=\73iba) ))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer.History.ForEach( { $_.SearchFilterTokenized | Out-LdapObject -Format default } )

(|(name=sabi)(name=dbo))
(|(name=\73abi)(name=d\62\6F))
  (&  ( ! name=   videosky)   (| (name=   \73abi)(  &name= d\62\6F)(name=\73iba) ))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]
        $ObfuscationContainer,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapTokenEnriched[]]
        $SearchFilterTokenized
    )

    begin
    {

    }

    process
    {
        # Iterate over each input -ObfuscationContainer object.
        foreach ($curObfuscationContainer in $ObfuscationContainer)
        {
            # Make copy of $curObfuscationContainer PSCustomObject so changes in this function do not affect input -ObfuscationContainer object outside this function.
            $curObfuscationContainer = $curObfuscationContainer.PSObject.Copy()

            # Calculate LDAP SearchFilter Filter count.
            $curFilterCount = $SearchFilterTokenized.Where( { $_ -is [Maldaptive.LdapToken] -and $_.Type -eq [Maldaptive.LdapTokenType]::Attribute } ).Count

            # Calculate LDAP SearchFilter depth, adding 1 since MaLDAPtive LDAP SearchFilter depth starts with 0.
            $curSearchFilterDepth = ($SearchFilterTokenized.Depth | Measure-Object -Maximum).Maximum + 1

            # Update $curObfuscationContainer with new values before returning.
            $curObfuscationContainer.Layer                  = [System.Int16] ($curObfuscationContainer.Layer + 1)
            $curObfuscationContainer.SearchFilter           = [System.String] -join$SearchFilterTokenized.Content
            $curObfuscationContainer.SearchFilterTokenized  = [Maldaptive.LdapTokenEnriched[]] $SearchFilterTokenized
            $curObfuscationContainer.SearchFilterLength     = [System.Int64] $curObfuscationContainer.SearchFilter.Length
            $curObfuscationContainer.SearchFilterTokenCount = [System.Int64] $curObfuscationContainer.SearchFilterTokenized.Count
            $curObfuscationContainer.FilterCount            = [System.Int16] $curFilterCount
            $curObfuscationContainer.SearchFilterDepth      = [System.Int16] $curSearchFilterDepth
            $curObfuscationContainer.SearchFilterMD5        = [System.String] (Get-FileHash -InputStream ([System.IO.MemoryStream]::New([System.Text.Encoding]::UTF8.GetBytes($curObfuscationContainer.SearchFilter))) -Algorithm MD5).Hash

            # Set History property to empty array if it does not exist.
            if (-not $curObfuscationContainer.History)
            {
                $curObfuscationContainer.History = @()
            }

            # Add updated current obfuscation layer to History property array.
            $curObfuscationContainer.History += [PSCustomObject] @{
                # Values for current layer.
                Layer                      = [System.Int16]  $curObfuscationContainer.Layer
                SearchFilter               = [System.String] $curObfuscationContainer.SearchFilter
                SearchFilterTokenized      = [Maldaptive.LdapTokenEnriched[]] $curObfuscationContainer.SearchFilterTokenized
                SearchFilterLength         = [System.Int64]  $curObfuscationContainer.SearchFilterLength
                SearchFilterTokenCount     = [System.Int64]  $curObfuscationContainer.SearchFilterTokenCount
                FilterCount                = [System.Int64]  $curObfuscationContainer.FilterCount
                SearchFilterDepth          = [System.Int64]  $curObfuscationContainer.SearchFilterDepth
                SearchFilterMD5            = [System.String] $curObfuscationContainer.SearchFilterMD5

                # Values for original layer.
                SearchFilterOrig           = [System.String] $curObfuscationContainer.SearchFilterOrig
                SearchFilterOrigLength     = [System.Int64]  $curObfuscationContainer.SearchFilterOrigLength
                SearchFilterOrigTokenCount = [System.Int64]  $curObfuscationContainer.SearchFilterOrigTokenCount
                FilterOrigCount            = [System.Int64]  $curObfuscationContainer.FilterOrigCount
                SearchFilterOrigDepth      = [System.Int64]  $curObfuscationContainer.SearchFilterOrigDepth
                SearchFilterOrigMD5        = [System.String] $curObfuscationContainer.SearchFilterOrigMD5

                # Fields below only added for each item in History array property and not stored in overall main properties above outside History property entries.
                # Below three properties are only used when function is called from Invoke-Maldaptive for interactive display purposes.
                CommandLineSyntax          = [System.String] ''
                CliSyntax                  = [System.Array]  @()
                Function                   = [System.String] ''
            }

            # Return current updated obfuscation container object.
            $curObfuscationContainer
        }
    }

    end
    {

    }  
}


function Remove-ObfuscationLayer
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-ObfuscationLayer
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Remove-ObfuscationLayer removes last LDAP SearchFilter obfuscation layer from input obfuscation container.

.PARAMETER ObfuscationContainer

Specifies obfuscation container from which to remove last LDAP SearchFilter obfuscation layer (if it exists).

.EXAMPLE

C:\PS> $obfContainer = New-ObfuscationContainer -SearchFilter '(|(name=sabi)(name=dbo))' -SearchRoot 'LDAP://DC=contoso,DC=com' -AttributeList name,sAMAccountType -Scope Subtree
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('(|(name=\73abi)(name=d\62\6F))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Add-ObfuscationLayer -SearchFilterTokenized ('  (&  ( ! name=   videosky)   (| (name=   \73abi)(  &name= d\62\6F)(name=\73iba) ))' | ConvertTo-LdapObject -Target LdapTokenEnriched)
C:\PS> $obfContainer = $obfContainer | Remove-ObfuscationLayer
C:\PS> $obfContainer.History | Select-Object Layer,FilterCount,SearchFilterLength,SearchFilter

Layer FilterCount SearchFilterLength SearchFilter
----- ----------- ------------------ ------------
    0           2                 24 (|(name=sabi)(name=dbo))
    1           2                 30 (|(name=\73abi)(name=d\62\6F))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object[]]
        $ObfuscationContainer
    )

    begin
    {

    }

    process
    {
        # Iterate over each input -ObfuscationContainer object.
        foreach ($curObfuscationContainer in $ObfuscationContainer)
        {
            # Handle obfuscation layer removal based on current Layer property count.
            if ($curObfuscationContainer.Layer -eq 0)
            {
                Write-Warning "Current obfuscation container is Layer=0 so no obfuscation layers exist to remove."
            }
            else
            {
                # Make copy of $curObfuscationContainer PSCustomObject so changes in this function do not affect input -ObfuscationContainer object outside this function.
                $curObfuscationContainer = $curObfuscationContainer.PSObject.Copy()

                # Update relevant main values in $curObfuscationContainer from next-to-last History property.
                $curObfuscationContainer.Layer             = $curObfuscationContainer.History[-2].Layer
                $curObfuscationContainer.SearchFilter           = $curObfuscationContainer.History[-2].SearchFilter
                $curObfuscationContainer.SearchFilterTokenized      = $curObfuscationContainer.History[-2].SearchFilterTokenized
                $curObfuscationContainer.SearchFilterLength       = $curObfuscationContainer.History[-2].SearchFilterLength
                $curObfuscationContainer.SearchFilterTokenCount  = $curObfuscationContainer.History[-2].SearchFilterTokenCount
                $curObfuscationContainer.FilterCount      = $curObfuscationContainer.History[-2].FilterCount
                $curObfuscationContainer.SearchFilterDepth      = $curObfuscationContainer.History[-2].SearchFilterDepth
                $curObfuscationContainer.SearchFilterMD5        = $curObfuscationContainer.History[-2].SearchFilterMD5

                # Remove last object in $curObfuscationContainer's History property.
                $curObfuscationContainer.History = @($curObfuscationContainer.History[0..($curObfuscationContainer.History.Count - 2)])
            }

            # Return current updated obfuscation container object.
            $curObfuscationContainer
        }
    }

    end
    {

    }
}


function Get-FunctionInfo
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Get-FunctionInfo
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-FunctionInfo extracts function name and input parameters from input $MyInvocation automatic variable to provide standardized function parameter input the user would enter to replicate the function call. It is used for displaying current function's input parameters for error handling purposes as well as tracking ExecutionCommands values in Invoke-Maldaptive UI.

.PARAMETER MyInvocation

Specifies $MyInvocation automatic variable from which the function name and input parameters will be extracted.

.EXAMPLE

C:\PS> function Out-Test ([System.String] $ArgString, [Int16[]] $ArgIntArray) { Write-Host "`n[Out-Test] -ArgString = $ArgString and ArgIntArray = $ArgIntArray"; $MyInvocation | Get-FunctionInfo }
C:\PS> Out-Test -ArgString "TESTING" -ArgIntArray @(1..3)

[Out-Test] -ArgString = TESTING and ArgIntArray = 1 2 3

Name     ArgArray                                                               ArgString                               CommandLineSyntax                               
----     --------                                                               ---------                               -----------------                               
Out-Test {@{Key=-ArgString; Value=TESTING}, @{Key=-ArgIntArray; Value=@(1..3)}} -ArgString TESTING -ArgIntArray @(1..3) Out-Test -ArgString TESTING -ArgIntArray @(1..3)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.InvocationInfo]
        $MyInvocation
    )

    begin
    {

    }

    process
    {
        # Extract function name, argument(s) (as both array and string) and final commandline argument syntax as a string.
        $functionName = [System.String] $MyInvocation.MyCommand.Name
        $functionArgArray = [System.Object[]] $MyInvocation.BoundParameters.GetEnumerator().Where( { $_.Key -ne 'ObfuscationContainer' } ) | ForEach-Object {
            # Handle cleaner display of array syntax.
            if (($_.Value.GetType().Name -iin @('Int16[]','Int32[]','Int64[]')) -and ($_.Value.Count -gt 1))
            {
                # Handle sorted shorthand array syntax. E.g. 1 2 3 4 5 --> @(1..5) instead of @(1,2,3,4,5)
                $sortedValue = ($_.Value | Sort-Object)
                if (-not (Compare-Object -ReferenceObject @($sortedValue[0]..$sortedValue[-1]) -DifferenceObject $_.Value))
                {
                    [PSCustomObject] @{
                        Key   = [System.String] "-$($_.Key)"
                        Value = [System.String] "@($($sortedValue[0])..$($sortedValue[-1]))"
                    }
                }
                else
                {
                    [PSCustomObject] @{
                        Key   = [System.String] "-$($_.Key)"
                        Value = [System.String] "@($(($_.Value | Sort-Object) -join ','))"
                    }
                }
            }
            elseif (($_.Value.GetType().Name -eq 'Char[]') -and ($_.Value.Count -gt 1))
            {
                $arrayValue = $_.Value | ForEach-Object {
                    if ($_ -eq "'")
                    {
                        "`"$_`""
                    }
                    else
                    {
                        "'$_'"
                    }
                }
                [PSCustomObject] @{
                    Key   = [System.String] "-$($_.Key)"
                    Value = [System.String] "@($($arrayValue -join ','))"
                }
            }
            elseif ($_.Value.GetType().Name.EndsWith('[]') -and ($_.Value.Count -gt 1))
            {
                [PSCustomObject] @{
                    Key   = [System.String] "-$($_.Key)"
                    Value = [System.String] ($_.Value -join ',')
                }
            }
            else
            {
                # For a subset of properties (Command, SearchFilter and SearchFilterPath) encapsulate value in single quotes and perform proper escaping of quotes.
                if ($_.Key -iin @('Command','SearchFilter','SearchFilterPath'))
                {
                    $curValue = "'" + $_.Value.Replace("'","''") + "'"
                }
                else
                {
                    $curValue = $_.Value
                }

                [PSCustomObject] @{
                    Key   = [System.String] "-$($_.Key)"
                    Value = [System.String] $curValue
                }
            }
        }
        $functionArgString = [System.String] ($functionArgArray | ForEach-Object { $_.Key; $_.Value }) -join ' '
        $commandLineSyntax = [System.String] "$functionName $functionArgString"

        # Return extracted function values as PSCustomObject.
        [PSCustomObject] @{
            Name              = $functionName
            ArgArray          = $functionArgArray
            ArgString         = $functionArgString
            CommandLineSyntax = $commandLineSyntax
        }
    }

    end
    {

    }
}