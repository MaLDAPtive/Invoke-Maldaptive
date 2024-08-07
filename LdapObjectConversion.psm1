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



function New-LdapToken
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: New-LdapToken
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

New-LdapToken is a simple wrapper function for C# [Maldaptive.LdapToken]::new() constructor to create new LdapTokens.

.PARAMETER Content

Specifies initial value of new LdapToken's Content property.

.PARAMETER Type

Specifies type of LdapToken to create.

.PARAMETER Start

(Optional) Specifies initial value of new LdapToken's Start property.

.PARAMETER Depth

(Optional) Specifies initial value of new LdapToken's Depth property.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies new LdapToken's Depth property value be set to -1 (e.g. for highlighting where modification occurred).

.EXAMPLE

PS C:\> New-LdapToken -Type Attribute -Content 'sAMAccountName'

Content   : sAMAccountName
Type      : Attribute
SubType   : 
Start     : -1
Length    : 14
Depth     : 0
TokenList : {}

.EXAMPLE

PS C:\> New-LdapToken -Type GroupEnd -Content '(' -Start 13 -Depth 2

Content   : (
Type      : GroupEnd
SubType   : 
Start     : 13
Length    : 1
Depth     : 2
TokenList : {}

.EXAMPLE

PS C:\> New-LdapToken -Type ExtensibleMatchFilter -Content ':caseExactMatch:' -Start 56 -Depth 4 -Target LdapTokenEnriched

TypeBefore             : 
TypeAfter              : 
ScopeSyntax            : 
ScopeApplication       : 
Context.BooleanOperator : 
TokenList              : {}
Guid                   : 
Content                : :caseExactMatch:
Type                   : ExtensibleMatchFilter
SubType                : 
Start                  : 56
Length                 : 16
Depth                  : 4

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [Maldaptive.LdapToken],
        [Maldaptive.LdapTokenEnriched]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $Content,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapTokenType]
        $Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int64]
        $Start = -1,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int64]
        $Depth = 0,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('LdapToken','LdapTokenEnriched')]
        [System.String]
        $Target = 'LdapToken',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    # If user input -TrackModification switch parameter is defined then set Depth property for new LdapToken to -1 for display tracking purposes.
    if ($PSBoundParameters['TrackModification'].IsPresent)
    {
        # If both -TrackModification and -Depth input parameters are defined then output warning message and proceed with -TrackModification.
        if ($PSBoundParameters['Depth'])
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] Both -Depth and -TrackModification input parameters were defined. Defaulting to -TrackModification to set new LdapToken's Depth property to -1 for modification tracking."
        }

        # Set Depth property for new LdapToken to -1 for display tracking purposes.
        $Depth = -1
    }

    # Create and return new LdapToken/LdapTokenEnriched based on user input -Target parameter.
    switch ($Target)
    {
        ([Maldaptive.LdapFormat]::LdapToken) {
            [Maldaptive.LdapToken]::new($Content,$Type,$Start,$Depth)
        }
        ([Maldaptive.LdapFormat]::LdapTokenEnriched) {
            [Maldaptive.LdapTokenEnriched]::new(
                [Maldaptive.LdapToken]::new($Content,$Type,$Start,$Depth)
            )
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    }
}


function Add-LdapToken
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-LdapToken
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Edit-LdapToken
Optional Dependencies: None

.DESCRIPTION

Add-LdapToken adds input LdapToken to input Filter or FilterList LdapBranch, randomly selecting between eligible input locations and updating most relevant properties regarding LdapToken addition.

.PARAMETER LdapBranch

Specifies Filter or FilterList LdapBranch into which LdapToken will be added.

.PARAMETER LdapToken

Specifies LdapToken to add to input LdapBranch.

.PARAMETER Location

Specifies eligible location(s) in LdapBranch's TokenList property in which to insert LdapToken.

.PARAMETER TrackModification

(Optional) Specifies LdapToken's Depth property value be set to -1 (e.g. for highlighting where modification occurred).

.EXAMPLE

PS C:\> $ldapBranch = '(  name=sabi  )' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $ldapTokenBooleanOperator = New-LdapToken -Type BooleanOperator -Content '!'
PS C:\> $ldapBranch.Branch | Add-LdapToken -LdapToken $ldapTokenBooleanOperator -Location after_groupstart,before_attribute
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(  !name=sabi  )

.EXAMPLE

PS C:\> $ldapBranch = '(  (  name=sabi  )  )' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $ldapTokenBooleanOperator = New-LdapToken -Type BooleanOperator -Content '!'
PS C:\> $ldapBranch.Branch | Add-LdapToken -LdapToken $ldapTokenBooleanOperator -Location after_groupstart,before_branch
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(  !(  name=sabi  )  )

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
        [Maldaptive.LdapBranch]
        $LdapBranch,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapToken]
        $LdapToken,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateSet(
            'before_groupstart',           'after_groupstart',
            'before_booleanoperator',      'after_booleanoperator',
            'before_attribute',            'after_attribute',
            'before_extensiblematchfilter','after_extensiblematchfilter',
            'before_comparisonoperator',   'after_comparisonoperator',
            'before_value',                'after_value',
            'before_groupend',             'after_groupend',
            'before_branch',               'afterbranch'
        )]
        [System.String[]]
        $Location,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    # Normalize current branch's Branch property into an object array based on if -LdapBranch is a Filter or FilterList branch.
    $ldapBranchObjArr = ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) ? $LdapBranch.Branch[0].TokenList : $LdapBranch.Branch

    # Remove any user input -Location values that specify an LdapTokenType not found in user input -LdapBranch.
    $locationValidated = @(foreach ($curLocation in $Location)
    {
        # Split current -Location value to extract LdapTokenType suffix component.
        $curLocationLdapTokenType = $curLocation.Split('_')[1]

        # If current -Location's LdapTokenType is found in input -LdapBranch then return current -Location value and continue to next foreach loop iteration.
        if ($curLocationLdapTokenType -iin $ldapBranchObjArr.Type)
        {
            $curLocation

            continue
        }

        # If current -Location's LdapTokenType is not found in input -LdapBranch then perform next-of-kin lookup for current -Location value and (if defined) repeat validation.
        # Next-of-kin logic only applies to LdapTokenType values that are not required for a valid Filter LdapBranch, namely BooleanOperator and ExtensibleMatchFilter LdapBranchTypes.
        $ldapTokenTypeNextOfKinObj = [PSCustomObject] @{
            before_booleanoperator       = 'before_attribute'
            after_booleanoperator        = 'after_groupstart'
            before_extensiblematchfilter = 'before_comparisonoperator'
            after_extensiblematchfilter  = 'after_attribute'
        }

        # If next-of-kin for current -Location not found then continue to next foreach loop iteration.
        if (-not $ldapTokenTypeNextOfKinObj.$curLocation)
        {
            continue
        }

        # Update current -Location value to corresponding next-of-kin value.
        $curLocation = $ldapTokenTypeNextOfKinObj.$curLocation

        # Split current -Location value to extract LdapTokenType suffix component.
        $curLocationLdapTokenType = $curLocation.Split('_')[1]

        # If current -Location's LdapTokenType is found in input -LdapBranch then return current -Location value and continue to next foreach loop iteration.
        if ($curLocationLdapTokenType -iin $ldapBranchObjArr.Type)
        {
            $curLocation

            continue
        }
    } )

    # Output warning message and break out of current function if above validation removes all user input -Location values.
    if (-not $locationValidated)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] User input -Location $(($Location.Count -gt 1) ? 'values do not' : 'value does not') reference any LdapTokenType found in input -LdapBranch."

        break
    }

    # Select random insertion location from validated user input -Location parameter (if multiple values are defined).
    $randomLocation = Get-Random -InputObject $locationValidated

    # Split randomly-selected -Location value into prefix and suffix components.
    $randomLocationSplit = $randomLocation.Split('_')
    $locationModifier = $randomLocationSplit[0]
    $ldapTokenType    = $randomLocationSplit[1]

    # Find first index of LdapToken/LdapBranch type defined in current -Location suffix.
    $insertionIndex = switch ($ldapTokenType)
    {
        'branch' {
            $ldapBranchObjArr.Where( { $_ } ).ForEach( { $_.GetType().Name } ).IndexOf('LdapBranch')
        }
        default
        {
            @($ldapBranchObjArr.Type).IndexOf([Maldaptive.LdapTokenType]::$ldapTokenType)
        }
    }

    # Output warning message and break out of current function if LdapToken type in current -Location value's suffix is not found in -LdapBranch's object array.
    if ($insertionIndex -eq -1)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Index of '$ldapTokenType' LdapToken (extracted from -Location '$randomLocation') not found in input -LdapBranch's object array."

        break
    }

    # If current -Location prefix is 'after' then increment above insertion index.
    if ($locationModifier -ieq 'after')
    {
        $insertionIndex++
    }

    # If optional -TrackModification switch parameter is defined then set extracted LdapToken's Depth property to -1 for modification tracking display purposes.
    if ($PSBoundParameters['TrackModification'].IsPresent)
    {
        $LdapToken.Depth = -1
    }

    # Insert -LdapToken into -LdapBranch's object array at index selected above.
    $ldapBranchObjArr.Insert($insertionIndex,$LdapToken)

    # Simply inserting LdapToken into LdapBranch's object array (.Branch.TokenList for Filter branch and .Branch for FilterList branch) is sufficient
    # since values in this location will be used when reparsing LdapBranch.
    # However, in case the calling function attempts to re-analyze current LdapBranch, propagate current function's addition to related properties
    # based on type of -LdapBranch.
    # It should be noted that for deeper embedded fields like Context.BooleanOperator these changes do not propagate without reparsing entire LdapBranch.
    Edit-LdapToken -LdapBranch $LdapBranch -LdapToken $LdapToken -Content $LdapToken.Content
}


function Remove-LdapToken
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-LdapToken
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Edit-LdapToken
Optional Dependencies: None

.DESCRIPTION

Remove-LdapToken removes input LdapToken from input Filter or FilterList LdapBranch, updating most relevant properties regarding LdapToken removal.

.PARAMETER LdapBranch

Specifies Filter or FilterList LdapBranch from which LdapToken will be removed.

.PARAMETER LdapToken

Specifies LdapToken to remove from input LdapBranch.

.EXAMPLE

PS C:\> $ldapBranch = '(  !name=sabi  )' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $booleanOperatorLdapToken = $ldapBranch.Branch.Branch.TokenDict[[Maldaptive.LdapTokenType]::BooleanOperator]
PS C:\> $ldapBranch.Branch | Remove-LdapToken -LdapToken $booleanOperatorLdapToken
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(  name=sabi  )

.EXAMPLE

PS C:\> $ldapBranch = '(  !(  name=sabi  )  )' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $booleanOperatorLdapToken = $ldapBranch.Branch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
PS C:\> $ldapBranch.Branch | Remove-LdapToken -LdapToken $booleanOperatorLdapToken
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(  (  name=sabi  )  )

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
        [Maldaptive.LdapBranch]
        $LdapBranch,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapToken]
        $LdapToken
    )

    # Normalize current branch's Branch property into an object array based on if -LdapBranch is a Filter or FilterList branch.
    $ldapBranchObjArr = ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) ? $LdapBranch.Branch[0].TokenList : $LdapBranch.Branch

    # Traverse all LdapTokens in -LdapBranch's object array to identify index of -LdapToken for removal.
    $removalIndex = -1
    for ($i = 0; $i -lt $ldapBranchObjArr.Count; $i++)
    {
        $curLdapToken = $ldapBranchObjArr[$i]

        # If current LdapToken matches input -LdapToken then capture index and break out of for loop.
        if (
            ($curLdapToken -is [Maldaptive.LdapToken]     ) -and
            ($curLdapToken.Guid    -ceq $LdapToken.Guid   ) -and
            ($curLdapToken.Start   -ceq $LdapToken.Start  ) -and
            ($curLdapToken.Depth   -ceq $LdapToken.Depth  ) -and
            ($curLdapToken.Type    -ceq $LdapToken.Type   ) -and
            ($curLdapToken.Content -ceq $LdapToken.Content)
        )
        {
            $removalIndex = $i

            break
        }
    }

    # Output warning message and break out of current function if -LdapToken is not found in -LdapBranch's object array.
    if ($removalIndex -eq -1)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] -LdapToken of Type '$($LdapToken.Type)' not found in input -LdapBranch's object array."

        break
    }

    # Invoke Edit-LdapToken function before removing -LdapToken from -LdapBranch since Edit-LdapToken performs lookup of -LdapToken in -LdapBranch to ensure correct LdapToken is modified.

    # Simply removing LdapToken from LdapBranch's object array (.Branch.TokenList for Filter branch and .Branch for FilterList branch) is sufficient
    # since values in this location will be used when reparsing LdapBranch.
    # However, in case the calling function attempts to re-analyze current LdapBranch, propagate current function's removal to related properties
    # based on type of -LdapBranch.
    # It should be noted that for deeper embedded fields like Context.BooleanOperator these changes do not propagate without reparsing entire LdapBranch.
    Edit-LdapToken -LdapBranch $LdapBranch -LdapToken $LdapToken -Content $null

    # Remove -LdapToken from -LdapBranch's object array at index extracted above.
    $ldapBranchObjArr.RemoveAt($removalIndex)

    # If -LdapBranch is a Filter then update -LdapBranch's TokenDict property corresponding to -LdapToken Type property.
    if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
    {
        $LdapBranch.Branch[0].TokenDict[$LdapToken.Type] = $null
    }

    # Update -LdapBranch type from FilterList to Filter if LdapToken removal changes the branch type (e.g. removing encapsulating GroupStart and GroupEnd LdapTokens).
    if (
        ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and
        ($LdapBranch.Branch.Count -eq 1) -and
        ($LdapBranch.Branch[0] -is [Maldaptive.LdapBranch]) -and
        ($LdapBranch.Branch[0].Type -eq [Maldaptive.LdapBranchType]::Filter)
    )
    {
        $LdapBranch.Type = [Maldaptive.LdapBranchType]::Filter
    }
}


function Edit-LdapToken
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Edit-LdapToken
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Edit-LdapToken updates Content property of input LdapToken in input Filter or FilterList LdapBranch, updating most relevant properties regarding LdapToken modification.

.PARAMETER LdapBranch

Specifies Filter or FilterList LdapBranch in which LdapToken will be modified.

.PARAMETER LdapToken

Specifies LdapToken to modify in input LdapBranch.

.PARAMETER Content

Specifies value to update in LdapToken's Content property.

.PARAMETER TrackModification

(Optional) Specifies LdapToken's Depth property value be set to -1 (e.g. for highlighting where modification occurred).

.EXAMPLE

PS C:\> $ldapBranch = '(!  name=sabi  )' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $booleanOperatorLdapToken = $ldapBranch.Branch.Branch.TokenDict[[Maldaptive.LdapTokenType]::BooleanOperator]
PS C:\> $ldapBranch.Branch | Edit-LdapToken -LdapToken $booleanOperatorLdapToken -Content '&'
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(&  name=sabi  )

.EXAMPLE

PS C:\> $ldapBranch = '(  !(  name=sabi  )  )' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $booleanOperatorLdapToken = $ldapBranch.Branch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
PS C:\> $ldapBranch.Branch | Edit-LdapToken -LdapToken $booleanOperatorLdapToken -Content '|'
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(  |(  name=sabi  )  )

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
        [Maldaptive.LdapBranch]
        $LdapBranch,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapToken]
        $LdapToken,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [AllowEmptyString()]
        [System.String]
        $Content,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    # Normalize current branch's Branch property into an object array based on if -LdapBranch is a Filter or FilterList branch.
    $ldapBranchObjArr = ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) ? $LdapBranch.Branch[0].TokenList : $LdapBranch.Branch

    # Traverse all LdapTokens in -LdapBranch's object array to identify index of -LdapToken for modification.
    $modificationIndex = -1
    for ($i = 0; $i -lt $ldapBranchObjArr.Count; $i++)
    {
        $curLdapToken = $ldapBranchObjArr[$i]

        # If current LdapToken matches input -LdapToken then capture index and break out of for loop.
        if (
            ($curLdapToken -is [Maldaptive.LdapToken]     ) -and
            ($curLdapToken.Guid    -ceq $LdapToken.Guid   ) -and
            ($curLdapToken.Start   -ceq $LdapToken.Start  ) -and
            ($curLdapToken.Depth   -ceq $LdapToken.Depth  ) -and
            ($curLdapToken.Type    -ceq $LdapToken.Type   ) -and
            ($curLdapToken.Content -ceq $LdapToken.Content)
        )
        {
            $modificationIndex = $i

            break
        }
    }

    # Output warning message and break out of current function if -LdapToken is not found in -LdapBranch's object array.
    if ($modificationIndex -eq -1)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] -LdapToken of Type '$($LdapToken.Type)' not found in input -LdapBranch's object array."

        break
    }

    # Retrieve -LdapToken from -LdapBranch's object array at index extracted above.
    $curLdapToken = $ldapBranchObjArr[$modificationIndex]

    # Trim any potential whitespace character(s) from a non-Whitespace input -LdapToken or leading whitespace
    # from an Attribute Value input -LdapToken to avoid innaccurate validation checks at end of function.
    # Any addition of whitespace should be done by specifying an input -LdapToken of type Whitespace.
    switch ($LdapToken.Type)
    {
        ([Maldaptive.LdapTokenType]::Whitespace) {
            # Do not trim any whitespace character(s) from a Whitespace input -LdapToken.
        }
        ([Maldaptive.LdapTokenType]::Value) {
            $Content = $Content.TrimStart()
        }
        default {
            $Content = $Content.Trim()
        }
    }

    # Copy input -LdapToken's Content property before modification for validation checks at end of function.
    $ldapTokenContent = $LdapToken.Content

    # Modify extracted LdapToken's Content property with user input -Content value.
    $curLdapToken.Content = $Content

    # If optional -TrackModification switch parameter is defined then set extracted LdapToken's Depth property to -1 for modification tracking display purposes.
    if ($PSBoundParameters['TrackModification'].IsPresent)
    {
        $curLdapToken.Depth = -1
    }

    # Replace extracted LdapToken in -LdapBranch's object array with modified version at index extracted above.
    $ldapBranchObjArr[$modificationIndex] = $curLdapToken

    # Simply modifying LdapToken in LdapBranch's object array (.Branch.TokenList for Filter branch and .Branch for FilterList branch) is sufficient
    # in most cases since values in this location will be used when reparsing LdapBranch.
    # However, in case the calling function attempts to re-analyze current LdapBranch, propagate current function's modification to related properties
    # based on type of -LdapBranch.
    # It should be noted that for deeper embedded fields like Context.BooleanOperator these changes do not propagate without reparsing entire LdapBranch.
    switch ($LdapBranch.Type)
    {
        ([Maldaptive.LdapBranchType]::Filter) {
            # Update -LdapBranch's Content string property based on updated TokenList property values.
            $LdapBranch.Branch[0].Content = -join$ldapBranchObjArr.Content

            # If user input -LdapToken is a Whitespace then break out of function since remaining property updates do not have corresponding Whitespace placeholder.
            if ($LdapToken.Type -eq [Maldaptive.LdapTokenType]::Whitespace)
            {
                break
            }

            # Update -LdapBranch's TokenDict property corresponding to -LdapToken Type property.
            $LdapBranch.Branch[0].TokenDict[$LdapToken.Type] = $curLdapToken

            # Update -LdapBranch's string placeholder corresponding to -LdapToken Type property.
            $LdapBranch.Branch[0].($LdapToken.Type) = $curLdapToken.Content

            # If user input -LdapToken is a BooleanOperator then update -LdapBranch's outer branch BooleanOperator string property.
            if ($LdapToken.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator)
            {
                $LdapBranch.BooleanOperator = $curLdapToken.Content
            }
        }
        ([Maldaptive.LdapBranchType]::FilterList) {
            # If user input -LdapToken is a BooleanOperator then update -LdapBranch's outer branch BooleanOperator string property.
            if ($LdapToken.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator)
            {
                $LdapBranch.BooleanOperator = $curLdapToken.Content
            }
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    }

    # Update BooleanOperator count-related properties in input -LdapBranch for accurate and efficient LDAP limitation checks in calling function
    # without requiring reparsing of entire LdapBranch.
    switch ($LdapToken.Type)
    {
        ([Maldaptive.LdapTokenType]::BooleanOperator) {
            # Create Booleans capturing if input -LdapToken's original Content property and -Content input parameter have a BooleanOperator value defined.
            $ldapTokenHasBooleanOperator = ($ldapTokenContent -and $ldapTokenContent -cin @('&','|','!')) ? $true : $false
            $contentHasBooleanOperator   = ($Content          -and          $Content -cin @('&','|','!')) ? $true : $false

            # Determine if any modification should occur to corresponding BooleanOperator count properties based on if a BooleanOperator value
            # was removed where one already existed, added where one did not exist or modified where one already existed.
            if ($ldapTokenHasBooleanOperator -and -not $contentHasBooleanOperator)
            {
                # BooleanOperator removed where one already existed.
                $booleanOperatorCountModifier = -1
            }
            elseif (-not $ldapTokenHasBooleanOperator -and $contentHasBooleanOperator)
            {
                # BooleanOperator added where one did not exist.
                $booleanOperatorCountModifier = 1
            }
            elseif (($parentFunctionInvocation.MyCommand.Name -eq 'Add-LdapToken') -and $contentHasBooleanOperator)
            {
                # If calling function is Add-LdapToken then calling function added -LdapToken into -LdapBranch's TokenList property then called current
                # function to perform metadata updates and validation checks, so consider this scenario adding a BooleanOperator where one did not exist.
                $booleanOperatorCountModifier = 1
            }
            else
            {
                # BooleanOperator modified where one already existed, so no net change in BooleanOperator count.
                $booleanOperatorCountModifier = 0
            }

            # Perform BooleanOperator count-related property updates if BooleanOperator count modifier defined above.
            if ($booleanOperatorCountModifier)
            {
                # Update BooleanOperator count properties for input -LdapBranch.
                $LdapBranch.BooleanOperatorCountMax        += $booleanOperatorCountModifier
                $LdapBranch.BooleanOperatorLogicalCountMax += $booleanOperatorCountModifier

                # If input -LdapBranch is a FilterList then also update BooleanOperator count properties in non-recursive affected nested LdapBranch(es).
                if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList)
                {
                    # Inspect input FilterList LdapBranch and extract any nested LdapBranch object(s).
                    $nestedLdapBranchArr = $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )

                    # If negation BooleanOperator ('!') was added then only update BooleanOperator count properties in first non-recursive nested LdapBranch.
                    if ($Content -ceq '!')
                    {
                        $nestedLdapBranchArr[0].BooleanOperatorCountMax        += $booleanOperatorCountModifier
                        $nestedLdapBranchArr[0].BooleanOperatorLogicalCountMax += $booleanOperatorCountModifier
                    }
                    else
                    {
                        # Since non-negation BooleanOperator was added then update BooleanOperator count properties in all non-recursive nested LdapBranches.
                        $nestedLdapBranchArr.ForEach(
                        {
                            $_.BooleanOperatorCountMax        += $booleanOperatorCountModifier
                            $_.BooleanOperatorLogicalCountMax += $booleanOperatorCountModifier
                        } )
                    }
                }
            }
        }
        ([Maldaptive.LdapTokenType]::Value) {
            # If user input -LdapToken is an Attribute Value then BooleanOperator count-related property updates only applicable if input -LdapBranch is of type Filter.
            if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
            {
                # Create Booleans capturing if input -LdapToken's original Content property and -Content input parameter have a wildcard character ('*') defined,
                # escaped or unescaped (just not hex encoded).
                $ldapTokenHasWildcard = ($ldapTokenContent -and $ldapTokenContent.Contains('*')) ? $true : $false
                $contentHasWildcard   = ($Content          -and          $Content.Contains('*')) ? $true : $false

                # Determine if any modification should occur to corresponding BooleanOperator count properties based on if an Attribute Value
                # with a wildcard character ('*') defined was removed where one already existed, added where one did not exist or modified where one already existed.
                if ($ldapTokenHasWildcard -and -not $contentHasWildcard)
                {
                    # Attribute Value with wildcard character ('*') defined was removed where one already existed.
                    $booleanOperatorCountModifier = -1
                }
                elseif (-not $ldapTokenHasWildcard -and $contentHasWildcard)
                {
                    # Attribute Value with wildcard character ('*') defined was added where one did not existed.
                    $booleanOperatorCountModifier = 1
                }
                else
                {
                    # Attribute Value with wildcard character ('*') defined was modified where one already existed or neither original nor updated Attribute Value
                    # contained a wildcard character ('*'), so no net change in BooleanOperator count.
                    $booleanOperatorCountModifier = 0
                }

                # Perform BooleanOperator count-related property updates if BooleanOperator count modifier defined above.
                if ($booleanOperatorCountModifier)
                {
                    # Update logical BooleanOperator count property for input -LdapBranch.
                    # Only update logical BooleanOperator count for presence of wildcard character ('*') in Attribute Value since it does not technically increase
                    # the actual count of BooleanOperators but does reduce LDAP's BooleanOperator limit for any one Filter LdapBranch.
                    $LdapBranch.BooleanOperatorLogicalCountMax += $booleanOperatorCountModifier
                }
            }
        }
    }

    # Retrieve MyInvocation automatic variables for parent and grandparent function scopes (if defined) for function-specific exclusions in validation checks below.
    $parentFunctionInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly
    try
    {
        $grandparentFunctionInvocation = Get-Variable -Name MyInvocation -Scope 2 -ValueOnly
    }
    catch
    {
        $grandparentFunctionInvocation = $null
    }

    # Perform additional Filter-specific contextual validation checks regardless of input -LdapToken type.
    # Do not apply these validation checks if two-step "recursive" invocation scenario occurs where current function calls Remove-LdapToken below which then calls current function again.
    if (
        ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) -and
        -not (
            ($grandparentFunctionInvocation.MyCommand.Name -eq $MyInvocation.MyCommand.Name) -and
            ($parentFunctionInvocation.MyCommand.Name -eq 'Remove-LdapToken') <#-and ($LdapToken.Type -eq [Maldaptive.LdapTokenType]::Whitespace)#>
        )
    )
    {
        # Remove potential problematic Whitespace LdapToken(s) if ExtensibleMatchFilter LdapToken is defined in input LdapBranch.
        if ($LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::ExtensibleMatchFilter].Content.Length -gt 0)
        {
            # Extract and remove any potential Whitespace LdapTokens on either side of input Filter -LdapBranch's ComparisonOperator LdapToken.
            $whitespaceLdapTokenToRemoveArr = $LdapBranch.Branch.TokenList.Where({ ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and (@($_.TypeBefore,$_.TypeAfter) -icontains [Maldaptive.LdapTokenType]::ComparisonOperator) } )
            foreach ($whitespaceLdapTokenToRemove in $whitespaceLdapTokenToRemoveArr)
            {
                # Remove existing Whitespace LdapToken from input -LdapBranch.
                Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $whitespaceLdapTokenToRemove
            }
        }

        # Remove potential problematic Whitespace LdapToken if Attribute Value LdapToken in input LdapBranch is the presence value ('*').
        if ($LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::Value].Content -ceq '*')
        {
            # Extract and remove potential Whitespace LdapToken following input Filter -LdapBranch's Attribute Value LdapToken.
            $whitespaceLdapTokenToRemove = $LdapBranch.Branch.TokenList.Where({ ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and ($_.TypeBefore -eq [Maldaptive.LdapTokenType]::Value) } )[0]
            if ($whitespaceLdapTokenToRemove)
            {
                # Remove existing Whitespace LdapToken from input -LdapBranch.
                Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $whitespaceLdapTokenToRemove
            }
        }
    }
}


function Copy-LdapFilter
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Copy-LdapFilter
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-LdapObject, New-LdapToken, Add-LdapToken, Edit-LdapToken, Remove-LdapToken
Optional Dependencies: None

.DESCRIPTION

Copy-LdapFilter copies input Filter LdapBranch and performs addition, modification and/or removal of LdapTokens defined in optional input parameters. Importantly this function preserves significant metadata and potential Whitespace LdapTokens in TokenList property of copied Filter LdapBranch.

.PARAMETER LdapBranch

Specifies Filter LdapBranch which will be copied and potentially modified.

.PARAMETER BooleanOperator

(Optional) Specifies BooleanOperator value to add or update in input Filter LdapBranch. If null then BooleanOperator LdapToken will be removed from input Filter LdapBranch.

.PARAMETER Attribute

(Optional) Specifies Attribute value to add or update in input Filter LdapBranch. If null then Attribute LdapToken will be removed from input Filter LdapBranch.

.PARAMETER ExtensibleMatchFilter

(Optional) Specifies ExtensibleMatchFilter value to add or update in input Filter LdapBranch. If null then ExtensibleMatchFilter LdapToken will be removed from input Filter LdapBranch.

.PARAMETER ComparisonOperator

(Optional) Specifies ComparisonOperator value to add or update in input Filter LdapBranch. If null then ComparisonOperator LdapToken will be removed from input Filter LdapBranch.

.PARAMETER Value

(Optional) Specifies Value value to add or update in input Filter LdapBranch. If null then Value LdapToken will be removed from input Filter LdapBranch.

.EXAMPLE

PS C:\> $ldapBranch = ('( ! name=  sabi)' | ConvertTo-LdapObject -Target LdapBranch).Branch[0]
PS C:\> $ldapBranchCopy = $ldapBranch | Copy-LdapFilter -BooleanOperator '|' -ComparisonOperator '~=' -Value 'dbo'
PS C:\> $ldapBranchCopy | ConvertTo-LdapObject -Target String

( | name~=  dbo)

.EXAMPLE

PS C:\> $ldapBranch = ('( ! name=  sabi)' | ConvertTo-LdapObject -Target LdapBranch).Branch[0]
PS C:\> $ldapBranch | Copy-LdapFilter -BooleanOperator $null -Attribute '1.2.840.113556.1.4.1' -ExtensibleMatchFilter $null -Value 'dbo' | Out-LdapObject

(  1.2.840.113556.1.4.1=  dbo)

.EXAMPLE

PS C:\> $ldapBranch = ('( ! name=  sabi)' | ConvertTo-LdapObject -Target LdapBranch).Branch[0]
PS C:\> $ldapBranch | Copy-LdapFilter -ExtensibleMatchFilter ':caseExactMatch:' | Out-LdapObject

( ! name:caseExactMatch:=sabi)

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
        [Maldaptive.LdapBranch]
        $LdapBranch,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [AllowEmptyString()]
        [System.String]
        $BooleanOperator,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [AllowEmptyString()]
        [System.String]
        $Attribute,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [AllowEmptyString()]
        [System.String]
        $ExtensibleMatchFilter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [AllowEmptyString()]
        [System.String]
        $ComparisonOperator,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [AllowEmptyString()]
        [System.String]
        $Value,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
    $optionalSwitchParameters = @{ }
    $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

    # Deep copy input LdapBranch by reparsing as LdapBranch format.
    # If optional -TrackModification switch parameter is defined then all Depth property values (including nested values) will be set to -1 for modification tracking display purposes.
    $ldapBranchCopy = (ConvertTo-LdapObject -InputObject $LdapBranch -Target LdapBranch @optionalSwitchParameters).Branch[0]

    # Copy subset of metadata properties from input LdapBranch to copied LdapBranch.
    $ldapBranchCopy.Depth                          = $LdapBranch.Depth
    $ldapBranchCopy.DepthMax                       = $LdapBranch.DepthMax
    $ldapBranchCopy.BooleanOperatorCountMax        = $LdapBranch.BooleanOperatorCountMax
    $ldapBranchCopy.BooleanOperatorLogicalCountMax = $LdapBranch.BooleanOperatorLogicalCountMax
    $ldapBranchCopy.Context                        = $LdapBranch.Context

    # Output warning message and return copied LdapBranch without any additional potential modifications if input LdapBranch type is not Filter.
    if ($LdapBranch.Type -ne [Maldaptive.LdapBranchType]::Filter)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Input -LdapBranch is not a Filter LdapBranch, but instead is a $($LdapBranch.Type) LdapBranch. Returning copy of input -LdapBranch without performing any additional potential modifications."

        return $ldapBranchCopy
    }

    # Define mapping of LdapTokenType values to corresponding Location values for use with Add-LdapToken function.
    # If any LdapTokenType value in below mapping does not exist in input LdapBranch then Add-LdapToken will perform next-of-kin checks where applicable.
    $ldapTokenLocationObj = [PSCustomObject] @{
        [Maldaptive.LdapTokenType]::BooleanOperator       = @('after_groupstart'           ,'before_attribute')
        [Maldaptive.LdapTokenType]::Attribute             = @('after_booleanoperator'      ,'before_extensiblematchfilter')
        [Maldaptive.LdapTokenType]::ExtensibleMatchFilter = @('after_attribute'            ,'before_comparisonoperator')
        [Maldaptive.LdapTokenType]::ComparisonOperator    = @('after_extensiblematchfilter','before_value')
        [Maldaptive.LdapTokenType]::Value                 = @('after_comparisonoperator'   ,'before_groupend')
    }

    # Extract array of LdapTokenType values from above mapping object corresponding to current function's optional input parameters.
    $ldapTokenTypeArr = ($ldapTokenLocationObj | Get-Member -MemberType NoteProperty).Name

    # Check for presence of each LdapTokenType in current function's input parameters and (if found) perform corresponding action (add, edit or remove corresponding LdapToken from input LdapBranch).
    foreach ($ldapTokenType in $ldapTokenTypeArr)
    {
        # If current LdapTokenType is not defined in current function's bound input parameters then continue to next LdapTokenType.
        if (-not $PSBoundParameters.ContainsKey($ldapTokenType))
        {
            continue
        }

        # Current LdapTokenType key is present in bound parameters.
        # If current LdapTokenType input parameter has a defined value then either edit or add the value as the corresponding LdapTokenType for input LdapBranch.
        # Otherwise, remove current LdapTokenType (if it exists) from input LdapBranch.
        if ($PSBoundParameters[$ldapTokenType])
        {
            # If input LdapBranch contains current LdapTokenType then edit existing LdapToken.
            # Otherwise create a new LdapToken and add to input LdapBranch.
            if ($ldapBranchCopy.Branch.TokenDict[$ldapTokenType])
            {
                # Modify existing LdapTokenType LdapToken in input LdapBranch.
                Edit-LdapToken -LdapBranch $ldapBranchCopy -LdapToken $ldapBranchCopy.Branch.TokenDict[$ldapTokenType] -Content $PSBoundParameters[$ldapTokenType]
            }
            else
            {
                # Generate current LdapTokenType LdapToken.
                # If optional -TrackModification switch parameter is defined then all Depth property values (including nested values) will be set to -1 for modification tracking display purposes.
                $newLdapToken = New-LdapToken -Type $ldapTokenType -Content $PSBoundParameters[$ldapTokenType] @optionalSwitchParameters

                # Add new LdapTokenType LdapToken to input LdapBranch.
                # Location parameter values extracted from mapping defined at beginning of function for corresponding LdapTokenType.
                Add-LdapToken -LdapBranch $ldapBranchCopy -LdapToken $newLdapToken -Location $ldapTokenLocationObj.$ldapTokenType
            }
        }
        elseif ($ldapBranchCopy.Branch.TokenDict[$ldapTokenType])
        {
            # LdapTokenType defined as an input parameter with a null value and LdapTokenType currently exists in input LdapBranch, so remove from LdapBranch.

            # Remove existing LdapTokenType LdapToken from input LdapBranch.
            Remove-LdapToken -LdapBranch $ldapBranchCopy -LdapToken $ldapBranchCopy.Branch.TokenDict[$ldapTokenType]
        }
    }

    # Return final copied (and potentially modified) Filter LdapBranch.
    $ldapBranchCopy
}


function Join-LdapObject
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Join-LdapObject
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Join-LdapObject appends input LDAP SearchFilter objects (in any format) to input ArrayList while performing any necessary type casting.

.PARAMETER InputObject

Specifies LDAP SearchFilter objects (in any input format) to be appended to input ArrayList.

.PARAMETER InputObjectArr

Specifies ArrayList to store input LDAP SearchFilter objects (in any input format).

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Collections.ArrayList])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]
        $InputObjectArr
    )

    begin
    {

    }

    process
    {
        # Add all pipelined input to -InputObjectArr before beginning final processing.
        if ($InputObject.Count -gt 1)
        {
            # Add all -InputObject objects to -InputObjectArr ArrayList.
            $InputObjectArr.AddRange($InputObject)
        }
        else
        {
            # For String, LdapFilter and LdapBranch scenarios, convert ArrayList or List type to underlying type by assigning -InputObject to its first underlying element.
            if (
                $InputObject.GetType().Name -iin @('ArrayList','List`1') -and
                $InputObject[0].GetType().Name -iin @('String','LdapFilter','LdapBranch')
            )
            {
                $InputObject = $InputObject[0]
            }

            # Throw warning if single -InputObject is not eligible type.
            # This helps detect polluted output streams in new or modified functions.
            $eligibleTypeArr = @('String','LdapToken','LdapTokenEnriched','LdapFilter','LdapBranch')
            if ($InputObject.GetType().Name -inotin $eligibleTypeArr)
            {
                # Retrieve MyInvocation automatic variable for parent function scope.
                $parentFunctionInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly

                Write-Warning "Unhandled -InputObject type '$($InputObject.GetType().Name)' found in $($MyInvocation.MyCommand.Name) function called by $($parentFunctionInvocation.MyCommand.Name) function. Eligible -InputObject types include: $($eligibleTypeArr.ForEach( {"'$_'"} ) -join ',')"
            }

            # Add single -InputObject object to -InputObjectArr ArrayList.
            $InputObjectArr.Add($InputObject) | Out-Null
        }
    }

    end
    {
        # If -InputObjectArr is composed of a single object then create temporary ArrayList, initialize with -InputObjectArr content, then overwrite $InputObjectArr variable.
        # This avoids potential re-casting errors in calling function.
        if ($InputObjectArr.Count -eq 1)
        {
            # Create temporary ArrayList to store -InputObjectArr object.
            $inputObjectArrTemp = [System.Collections.ArrayList]::new()

            # Add single -InputObjectArr object to temporary ArrayList.
            $inputObjectArrTemp.Add($InputObjectArr) | Out-Null

            # Overwrite -InputObjectArr with temporary ArrayList.
            $InputObjectArr = $inputObjectArrTemp
        }

        # Return final result.
        $InputObjectArr
    }
}


function Expand-LdapObject
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Expand-LdapObject
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Expand-LdapObject recursively expands input LDAP SearchFilter objects (in any format) into flattened format.

.PARAMETER InputObject

Specifies LDAP SearchFilter objects (in any input format) to be recursively expanded into flattened format.

.EXAMPLE

PS C:\> '(name=sabi)' | ConvertTo-LdapObject -Target LdapBranch | Expand-LdapObject | Select-Object TypeBefore,TypeAfter,Type,SubType,ScopeSyntax,ScopeApplication,Content,ContentDecoded,Start,Depth | Format-Table

TypeBefore                  TypeAfter               Type SubType ScopeSyntax ScopeApplication Content ContentDecoded Start Depth
----------                  ---------               ---- ------- ----------- ---------------- ------- -------------- ----- -----
                            Attribute         GroupStart              Filter           Filter (       (                  0     0
GroupStart         ComparisonOperator          Attribute                                      name    name               1     0
Attribute                       Value ComparisonOperator                                      =       =                  5     0
ComparisonOperator           GroupEnd              Value                                      sabi    sabi               6     0
Value                                           GroupEnd              Filter           Filter )       )                 10     0

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Iterate over each input object.
        $finalResult = foreach ($curInputObject in $inputObjectArr)
        {
            # Output current object(s) after expanding (where applicable) based on object type.
            switch ($curInputObject.GetType().Name)
            {
                'String' {
                    # Return String as-is.
                    $curInputObject
                }
                'LdapToken' {
                    # Return LdapToken as-is.
                    $curInputObject
                }
                'LdapTokenEnriched' {
                    # Return LdapTokenEnriched as-is.
                    $curInputObject
                }
                'LdapFilter' {
                    # Recursively return all objects in LdapFilter's TokenList property.
                    Expand-LdapObject -InputObject $curInputObject.TokenList
                }
                'LdapBranch' {
                    # Recursively return all objects in LdapBranch's Branch property.
                    Expand-LdapObject -InputObject $curInputObject.Branch
                }
                default {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }
        }

        # Return final result.
        $finalResult
    }
}


function ConvertTo-LdapObject
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: ConvertTo-LdapObject
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, Expand-LdapObject, [Maldaptive.LdapParser] class
Optional Dependencies: None

.DESCRIPTION

ConvertTo-LdapObject converts input LDAP SearchFilter to one of many parsed SearchFilter data formats.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) to be converted to one of many parsed SearchFilter data formats.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies 'Depth' property be set to -1 for all LDAP tokens (even nested RDN tokens) created from -InputObject (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | ConvertTo-LdapObject -Target LdapToken | Format-Table

Content               Type SubType Start Length Depth TokenList
-------               ---- ------- ----- ------ ----- ---------
(               GroupStart             0      1     0 {}
name             Attribute             1      4     0 {}
=       ComparisonOperator             5      1     0 {}
sabi                 Value             6      4     0 {}
)                 GroupEnd            10      1     0 {}

.EXAMPLE

PS C:\> '(name=sabi)' | ConvertTo-LdapObject -Target LdapBranch | ConvertTo-LdapObject -Target String

(name=sabi)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Create ArrayList to store all pipelineed input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Extract base SearchFilter string from $inputObjectArr ArrayList.
        if (($inputObjectArr.Count -eq 1) -and ($inputObjectArr[0].GetType().Name -eq 'String'))
        {
            # If $inputObjectArr ArrayList only contains a single SearchFilter string then no extraction required.
            $searchFilter = $inputObjectArr
        }
        else
        {
            # Extract SearchFilter string by expanding $inputObjectArr ArrayList.
            $searchFilter = -join(Expand-LdapObject -InputObject $inputObjectArr).Content
        }

        # Tokenize extracted base SearchFilter string.
        $searchFilterTokenized = [Maldaptive.LdapParser]::Tokenize($searchFilter)

        # If user input -TrackModification switch parameter is defined then override Depth value of all LdapTokens (and potential nested RDN LdapTokens in TokenList property) to -1.
        # This is used by obfuscation functions to succinctly track any newly added/modified LdapTokens (even nested RDN LdapTokens) for display purposes.
        if ($PSBoundParameters['TrackModification'].IsPresent)
        {
            # Override all LdapToken Depth values to -1.
            foreach ($token in $searchFilterTokenized)
            {
                $token.Depth = -1

                # If current LdapToken's TokenList contains any nested LdapTokens (e.g. RDN or adjacent Whitespace scenario) then override their Depth values to -1.
                foreach ($subToken in $token.TokenList)
                {
                    $subToken.Depth = -1
                }
            }
        }

        # Convert SearchFilter to appropriate parsed format based on user input -Target value.
        $finalResult = switch ($Target)
        {
            ([Maldaptive.LdapFormat]::String) {
                [System.String] $searchFilter
            }
            ([Maldaptive.LdapFormat]::LdapToken) {
                [Maldaptive.LdapToken[]] $searchFilterTokenized
            }
            ([Maldaptive.LdapFormat]::LdapTokenEnriched) {
                [Maldaptive.LdapTokenEnriched[]] [Maldaptive.LdapParser]::ToTokenEnriched($searchFilterTokenized)
            }
            ([Maldaptive.LdapFormat]::LdapFilter) {
                [Maldaptive.LdapFilter[]] [Maldaptive.LdapParser]::ToFilterOnly($searchFilterTokenized)
            }
            ([Maldaptive.LdapFormat]::LdapFilterMerged) {
                # Cast to [System.Object[]] since method returns List<object> containing LdapFilter and LdapTokenEnriched objects.
                [System.Object[]] [Maldaptive.LdapParser]::ToFilter($searchFilterTokenized)
            }
            ([Maldaptive.LdapFormat]::LdapBranch) {
                [Maldaptive.LdapBranch] [Maldaptive.LdapParser]::ToBranch($searchFilterTokenized)
            }
        }

        # Return final result.
        $finalResult
    }
}


function Format-LdapObject
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Format-LdapObject
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Expand-LdapObject
Optional Dependencies: None

.DESCRIPTION

Format-LdapObject converts input LDAP SearchFilter to one of many parsed SearchFilter data formats while optionally maintaining modification tracking.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) to be converted to one of many parsed SearchFilter data formats while optionally maintaining modification tracking.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Format-LdapObject -Target LdapToken | Format-Table

Content               Type SubType Start Length Depth TokenList
-------               ---- ------- ----- ------ ----- ---------
(               GroupStart             0      1     0 {}
name             Attribute             1      4     0 {}
=       ComparisonOperator             5      1     0 {}
sabi                 Value             6      4     0 {}
)                 GroupEnd            10      1     0 {}

.EXAMPLE

PS C:\> '(name=sabi)' | Format-LdapObject -Target LdapBranch | Format-LdapObject -Target String

(name=sabi)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Retrieve MyInvocation automatic variable for parent function scope.
        $parentFunctionInvocation = Get-Variable -Name MyInvocation -Scope 1 -ValueOnly

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure final result is formatted according to user input -Target value.
        # First ensure input object array is first formatted as an array of LdapTokens.
        # Handle single string scenario separately to preserve potential modification tracking data in non-string input formats.
        if (($inputObjectArr.Count -eq 1) -and ($inputObjectArr[0] -is [System.String]))
        {
            $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target LdapToken
        }
        else
        {
            $inputObjectArr = Expand-LdapObject -InputObject $inputObjectArr
        }

        # Remove any objects from input object array that contain a null Content property (e.g. via Remove-Random* deobfuscation functions).
        # This avoids issues when iterating over each index in current input object array and re-parsed version below.
        $inputObjectArr = $inputObjectArr.Where( { $_.Content } )

        # Re-parse modified input object array to re-compute properties (e.g. Depth, Start, Length, etc.).
        # Ensure final result is formatted according to user input -Target value.
        $finalResult = ConvertTo-LdapObject -InputObject (-join$inputObjectArr.Content) -Target $Target

        # If user input -TrackModification switch parameter is defined along with eligible -Target value, add Modified property to all tokens modified in current function.
        # This is primarily for display highlighting in Out-LdapObject function.
        if ($PSBoundParameters['TrackModification'].IsPresent)
        {
            # Define -Target values eligible for -TrackModification logic.
            $eligibleTargetArr = @([Maldaptive.LdapFormat]::LdapToken,[Maldaptive.LdapFormat]::LdapTokenEnriched)

            # Throw warning if ineligible -Target is defined for use with -TrackModification. Otherwise proceed with -TrackModification logic.
            if ($Target -inotin $eligibleTargetArr)
            {
                Write-Warning "Ineligible -Target value '$Target' used in conjunction with -TrackModification switch in $($MyInvocation.MyCommand.Name) function called by $($parentFunctionInvocation.MyCommand.Name) function. Eligible -Target values for use with -TrackModification switch include: $($eligibleTargetArr.ForEach( {"'$_'"} ) -join ',')"
            }
            else
            {
                # Transpose modification tracking from original, pre-converted -InputObject array LdapTokens onto re-parsed $finalResult array.

                # Transpose any nested LdapTokens in Whitespace LdapToken's TokenList property (produced by previous invocation of current function) from original,
                # pre-converted -InputObject array LdapTokens onto re-parsed $finalResult array.
                # This step is necessary if current function is called twice where second invocation would otherwise drop Whitespace TokenList values produced by first invocation.
                for ($i = 0; $i -lt $inputObjectArr.Count; $i++)
                {
                    # If current LdapToken is a Whitespace LdapToken containing adjacent LdapTokens in its TokenList property then copy from -InputObject array to $finalResult array,
                    # casting TokenList contents to LdapTokenEnriched array if currently different type (i.e. LdapToken array).
                    if (($inputObjectArr[$i].Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and $inputObjectArr[$i].TokenList)
                    {
                        # Copy current Whitespace LdapToken's TokenList property contents from -InputObject array to $finalResult array, evaluating each
                        # TokenList object individually to see if cast to LdapTokenEnriched is needed along with manual re-addition of custom Modified
                        # property since this will be lost during LdapTokenEnriched type cast.
                        $finalResult[$i].TokenList = @(foreach ($curTokenListLdapToken in $inputObjectArr[$i].TokenList)
                        {
                            # If current TokenList adjacent Whitespace LdapToken is not of type LdapTokenEnriched then cast it to LdapTokenEnriched and manually re-add
                            # custom Modified property since this will be lost during LdapTokenEnriched type cast.
                            if ($curTokenListLdapToken -isnot [Maldaptive.LdapTokenEnriched])
                            {
                                # Set boolean if current TokenList adjacent Whitespace LdapToken in original, pre-converted -InputObject array was modified in previous function.
                                # This is denoted by either the Modified property being present or the Depth property set to -1.
                                $isModified = ($curTokenListLdapToken.Modified -or ($curTokenListLdapToken.Depth -eq -1)) ? $true : $false

                                # Cast current TokenList adjacent Whitespace LdapToken to LdapTokenEnriched.
                                $curTokenListLdapToken = [Maldaptive.LdapTokenEnriched] $curTokenListLdapToken

                                # If current TokenList adjacent Whitespace LdapToken had Modified property before type cast then re-add it to converted LdapTokenEnriched result.
                                if ($isModified)
                                {
                                    Add-Member -InputObject $curTokenListLdapToken -MemberType NoteProperty -Name 'Modified' -Value $true
                                }
                            }

                            # Return current TokenList adjacent Whitespace LdapToken.
                            $curTokenListLdapToken
                        })
                    }

                    # If current LdapToken is a Value LdapToken whose content is a DN (Distinguished Name) containing parsed RDN (Relative Distinguished Name) LdapTokens in its
                    # TokenList property and one or more of its Whitespace RDN LdapTokens contain adjacent Whitespace LdapTokens in their TokenList properties then copy these nested
                    # Whitespace RDN LdapTokens' TokenList property contents, casting nested TokenList contents to LdapTokenEnriched array if currently different type (i.e. LdapToken array).
                    if (
                        ($inputObjectArr[$i].Type -eq [Maldaptive.LdapTokenType]::Value) -and $inputObjectArr[$i].TokenList -and
                        $inputObjectArr[$i].TokenList.Where( { ($_.Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and $_.TokenList } )
                    )
                    {
                        # Iterate over current Value LdapToken's TokenList, copying nested TokenList property for Whitespace RDN LdapTokens with TokenList property defined.
                        for ($index = 0; $index -lt $inputObjectArr[$i].TokenList.Count; $index++)
                        {
                            # Copy nested TokenList property for Whitespace RDN LdapToken with TokenList property defined.
                            if (($inputObjectArr[$i].TokenList[$index].Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and $inputObjectArr[$i].TokenList[$index].TokenList)
                            {
                                # Copy current nested Whitespace LdapToken's TokenList property contents from -InputObject array to $finalResult array, evaluating each
                                # TokenList object individually to see if cast to LdapTokenEnriched is needed along with manual re-addition of custom Modified
                                # property since this will be lost during LdapTokenEnriched type cast.
                                $finalResult[$i].TokenList[$index].TokenList = @(foreach ($curNestedTokenListLdapToken in $inputObjectArr[$i].TokenList[$index].TokenList)
                                {
                                    # If current nested TokenList adjacent Whitespace LdapToken is not of type LdapTokenEnriched then cast it to LdapTokenEnriched and manually re-add
                                    # custom Modified property since this will be lost during LdapTokenEnriched type cast.
                                    if ($curNestedTokenListLdapToken -isnot [Maldaptive.LdapTokenEnriched])
                                    {
                                        # Set boolean if current nested TokenList adjacent Whitespace LdapToken in original, pre-converted -InputObject array was modified in previous function.
                                        # This is denoted by either the Modified property being present or the Depth property set to -1.
                                        $isModified = ($curNestedTokenListLdapToken.Modified -or ($curNestedTokenListLdapToken.Depth -eq -1)) ? $true : $false

                                        # Cast current nested TokenList adjacent Whitespace LdapToken to LdapTokenEnriched.
                                        $curNestedTokenListLdapToken = [Maldaptive.LdapTokenEnriched] $curNestedTokenListLdapToken

                                        # If current nested TokenList adjacent Whitespace LdapToken had Modified property before type cast then re-add it to converted LdapTokenEnriched result.
                                        if ($isModified)
                                        {
                                            Add-Member -InputObject $curNestedTokenListLdapToken -MemberType NoteProperty -Name 'Modified' -Value $true
                                        }
                                    }

                                    # Return current nested TokenList adjacent Whitespace LdapToken.
                                    $curNestedTokenListLdapToken
                                })
                            }
                        }
                    }
                }

                # If adjacent Whitespace LdapTokens are present then token count will differ between $inputObjectArr and re-parsed $finalResult.
                # Therefore, while using $i to iterate over $inputObjectArr in below for loop, also use $j to track current index for $finalResult
                # which will not advance multiple times for potential adjacent Whitespace LdapTokens like $i will in inner for loop logic.
                $j = -1

                # Iterate over all objects in original, pre-converted -InputObject array.
                for ($i = 0; $i -lt $inputObjectArr.Count; $i++)
                {
                    # Increment $j index to match each step of for loop definition, though $i will have additional increments if adjacent Whitespace LdapTokens are detected.
                    $j++

                    # Set boolean if current LdapToken in original, pre-converted -InputObject array was modified in previous function.
                    # This is denoted by either the Modified property being present or the Depth property set to -1.
                    $isModified = ($inputObjectArr[$i].Modified -or ($inputObjectArr[$i].Depth -eq -1)) ? $true : $false

                    # If current LdapToken is Whitespace check if adjacent Whitespace LdapTokens are present in original -InputObject since they will be merged in re-parsed $finalResult.
                    # If present each adjacent Whitespace LdapToken will be extracted and added to TokenList property of corresponding single Whitespace LdapToken in $finalResult so
                    # modification tracking information can be maintained per LdapToken for display purposes (e.g. for Out-LdapObject function).
                    if (
                        ($inputObjectArr[$i    ].Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and
                        ($inputObjectArr[$i + 1].Type -eq [Maldaptive.LdapTokenType]::Whitespace)
                    )
                    {
                        # Capture all potential adjacent Whitespace LdapTokens as an array.
                        $adjacentLdapTokenWhitespaceArr = @(foreach ($curInputObject in $inputObjectArr[$i..($inputObjectArr.Count - 1)])
                        {
                            # Process next LdapToken if it is a Whitespace LdapToken.
                            if ($curInputObject.Type -eq [Maldaptive.LdapTokenType]::Whitespace)
                            {
                                # If current adjacent Whitespace LdapToken has a Depth of -1 but does not have a Modified property then add it.
                                if (-not $curInputObject.Modified -and ($curInputObject.Depth -eq -1))
                                {
                                    Add-Member -InputObject $curInputObject -MemberType NoteProperty -Name 'Modified' -Value $true
                                }

                                # For proper display purposes have current adjacent Whitespace LdapToken inherit Depth of re-parsed and merged Whitespace LdapToken in $finalResult.
                                $curInputObject.Depth = $finalResult[$j].Depth

                                # Return current adjacent Whitespace LdapToken.
                                $curInputObject
                            }
                            else
                            {
                                # Break out of foreach loop once first non-Whitespace LdapToken is found.
                                break
                            }
                        })

                        # Increment current for loop's $i index by count of additional adjacent Whitespace LdapTokens extracted above.
                        $i += $adjacentLdapTokenWhitespaceArr.Count - 1

                        # Store extracted array of adjacent Whitespace LdapTokens in TokenList property of current merged Whitespace LdapToken in re-parsed $finalResult array.
                        $finalResult[$j].TokenList = $adjacentLdapTokenWhitespaceArr

                        # If user input -Target parameter is LdapTokenEnriched and at least one object in extracted array of adjacent Whitespace tokens is an LdapToken,
                        # manually re-add Modified property to newly converted LdapTokenEnriched objects.
                        if (($Target -eq [Maldaptive.LdapFormat]::LdapTokenEnriched) -and $adjacentLdapTokenWhitespaceArr.Where( { $_.GetType().Name -eq 'LdapToken' } ))
                        {
                            # Iterate over array of adjacent Whitespace LdapTokenEnriched objects, re-adding any Modified properties dropped during automatic type cast.
                            for ($index = 0; $index -lt $finalResult[$j].TokenList.Count; $index++)
                            {
                                # If original LdapToken was modified and current LdapTokenEnriched does not have Modified property then manually add it.
                                if ($adjacentLdapTokenWhitespaceArr[$index].Modified -and -not $finalResult[$j].TokenList[$index].Modified)
                                {
                                    Add-Member -InputObject $finalResult[$j].TokenList[$index] -MemberType NoteProperty -Name 'Modified' -Value $true
                                }
                            }
                        }

                        # If any adjacent Whitespace LdapTokens extracted above are modified then override $isModified Boolean (set before current if block) to force
                        # addition of Modified property boolean value of $true to newly parsed final result later in current function.
                        if ($finalResult[$j].TokenList.Modified -and -not $finalResult[$j].Modified)
                        {
                            $isModified = $true
                        }
                    }

                    # If current object in pre-converted -InputObject array was modified then add Modified property boolean value of $true to newly parsed final result.
                    if ($isModified)
                    {
                        Add-Member -InputObject $finalResult[$j] -MemberType NoteProperty -Name 'Modified' -Value $true

                        # If current object is a Value LdapToken containing additional nested objects in the TokenList property (RDN scenario) then add above Modified
                        # property to modified TokenList object(s).
                        if (($finalResult[$j].Type -eq [Maldaptive.LdapTokenType]::Value) -and $finalResult[$j].TokenList)
                        {
                            # If all or none of the TokenList array RDN LdapTokens are modified then add Modified property to all RDN LdapTokens.
                            # Otherwise iterate over each RDN LdapToken and transpose Modified property only for modified RDN LdapToken(s).
                            $inputObjectArrModifiedTokenListCount = $inputObjectArr[$i].TokenList.Where( { $_.Modified -or ($_.Depth -eq -1) } ).Count
                            if ($inputObjectArrModifiedTokenListCount -iin @(0,$inputObjectArr[$i].TokenList.Count))
                            {
                                # All or none of the TokenList array RDN LdapTokens are modified so add Modified property to all RDN LdapTokens.
                                Add-Member -InputObject $finalResult[$j].TokenList -MemberType NoteProperty -Name 'Modified' -Value $true
                            }
                            else
                            {
                                # Iterate over each RDN LdapToken and transpose Modified property only for modified RDN LdapToken(s).

                                # If adjacent nested RDN Whitespace LdapTokens are present or RDN Whitespace LdapToken is completely removed then token count will differ
                                # between $inputObjectArr's TokenList and re-parsed $finalResult's TokenList.
                                # Therefore, while using $k to iterate over $inputObjectArr's TokenList in below for loop, also use $l to track current index for $finalResult's
                                # TokenList which will not necessarily advance at the same pace as $k in inner for loop logic for either Whitespace LdapToken scenario.
                                $l = -1

                                # Iterate over all nested TokenList RDN LdapTokens in current original, pre-converted -InputObject LdapToken.
                                for ($k = 0; $k -lt $inputObjectArr[$i].TokenList.Count; $k++)
                                {
                                    # Skip current RDN LdapToken if it is an RDN Whitespace LdapToken that has been completely removed.
                                    if ($inputObjectArr[$i].TokenList[$k].Type -eq [Maldaptive.LdapTokenType]::Whitespace -and $inputObjectArr[$i].TokenList[$k].Content.Length -eq 0)
                                    {
                                        continue
                                    }

                                    # Increment $l index to match each step of for loop definition, though $k will have additional increments if nested adjacent Whitespace LdapTokens are detected.
                                    $l++

                                    # Set boolean if current nested RDN LdapToken in original, pre-converted -InputObject array's TokenList was modified in previous function.
                                    # This is denoted by either the Modified property being present or the Depth property set to -1.
                                    $isModified = ($inputObjectArr[$i].TokenList[$k].Modified -or ($inputObjectArr[$i].TokenList[$k].Depth -eq -1)) ? $true : $false

                                    # If current nested RDN LdapToken is Whitespace check if nested adjacent Whitespace LdapTokens are present in original -InputObject RDN LdapToken's
                                    # TokenList property since they will be merged in re-parsed $finalResult.
                                    # If present each nested adjacent RDN Whitespace LdapToken will be extracted and added to TokenList property of corresponding single RDN Whitespace LdapToken
                                    # in $finalResult so modification tracking information can be maintained per RDN LdapToken for display purposes (e.g. for Out-LdapObject function).
                                    if (
                                        ($inputObjectArr[$i].TokenList[$k    ].Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and
                                        ($inputObjectArr[$i].TokenList[$k + 1].Type -eq [Maldaptive.LdapTokenType]::Whitespace)
                                    )
                                    {
                                        # Capture all potential nested adjacent RDN Whitespace LdapTokens as an array.
                                        $adjacentTokenListLdapTokenWhitespaceArr = @(foreach ($curTokenListLdapToken in $inputObjectArr[$i].TokenList[$k..($inputObjectArr[$i].TokenList.Count - 1)])
                                        {
                                            # Process next nested RDN LdapToken if it is an RDN Whitespace LdapToken.
                                            if ($curTokenListLdapToken.Type -eq [Maldaptive.LdapTokenType]::Whitespace)
                                            {
                                                # If current nested adjacent RDN Whitespace LdapToken has a Depth of -1 but does not have a Modified property then add it.
                                                if (-not $curTokenListLdapToken.Modified -and ($curTokenListLdapToken.Depth -eq -1))
                                                {
                                                    Add-Member -InputObject $curTokenListLdapToken -MemberType NoteProperty -Name 'Modified' -Value $true
                                                }

                                                # For proper display purposes have current nested adjacent RDN Whitespace LdapToken inherit Depth of re-parsed and merged nested RDN Whitespace LdapToken in $finalResult.
                                                $curTokenListLdapToken.Depth = $finalResult[$j].TokenList[$l].Depth

                                                # Return current nested adjacent RDN Whitespace LdapToken.
                                                $curTokenListLdapToken
                                            }
                                            else
                                            {
                                                # Break out of foreach loop if first nested non-Whitespace RDN LdapToken is found.
                                                break
                                            }
                                        })

                                        # Increment current for loop's $k index by count of additional nested adjacent RDN Whitespace LdapTokens extracted above.
                                        $k += $adjacentTokenListLdapTokenWhitespaceArr.Count - 1

                                        # Store extracted array of nested adjacent RDN Whitespace LdapTokens in TokenList property of current nested, merged RDN Whitespace LdapToken in re-parsed $finalResult array.
                                        $finalResult[$j].TokenList[$l].TokenList = $adjacentTokenListLdapTokenWhitespaceArr

                                        # If any nested adjacent RDN Whitespace LdapTokens extracted above are modified then override $isModified Boolean (set before current if block) to force
                                        # addition of Modified property boolean value of $true to newly parsed final result later in current function.
                                        if ($adjacentTokenListLdapTokenWhitespaceArr.Modified -and -not $finalResult[$j].TokenList[$l].Modified)
                                        {
                                            $isModified = $true
                                        }
                                    }

                                    # If current nested RDN LdapToken in pre-converted -InputObject array was modified (and does not already have Modified property defined) then add
                                    # Modified property boolean value of $true to current nested RDN LdapToken in newly parsed final result.
                                    if ($isModified -and -not $finalResult[$j].TokenList[$l].Modified)
                                    {
                                        Add-Member -InputObject $finalResult[$j].TokenList[$l] -MemberType NoteProperty -Name 'Modified' -Value $true
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        # Return final result.
        $finalResult
    }
}


function Get-LdapLogicalBooleanOperator
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Get-LdapLogicalBooleanOperator
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-LdapLogicalBooleanOperator calculates and returns logical BooleanOperator value for input array of BooleanOperator characters. This logical value is important for comparing how modifications to BooleanOperator context chain or to the affected LdapBranch (Filter or FilterList) might negatively alter the original LDAP SearchFilter.

.PARAMETER BooleanOperator

Specifies BooleanOperator character(s) for which to evaluate logic BooleanOperator value.

.PARAMETER IgnoreTrailingNegation

(Optional) Specifies trailing negation BooleanOperator ('!') character(s) be removed from -BooleanOperator before calculating logical BooleanOperator value. This is useful when a FilterList LdapBranch has multiple nested LdapBranches and inherits negation BooleanOperator ('!') character(s) from preceding depths, but the desired logical BooleanOperator value is that which applies to all remaining nested LdapBranches and how they relate to one another.

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '&'

&

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '&','!'

!

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '&!'

!

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '&!!'

&

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '!&!!'

!&

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '||!!|!&!!'

!&

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '!|!!!'

!

.EXAMPLE

PS C:\> Get-LdapLogicalBooleanOperator -BooleanOperator '!|!!!' -IgnoreTrailingNegation

!|

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
        [System.Char[]]
        $BooleanOperator,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $IgnoreTrailingNegation
    )

    begin
    {
        # Create ArrayList to store all pipelined input before beginning final processing.
        $booleanOperatorArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $booleanOperatorArr before beginning final processing.
        if ($BooleanOperator.Count -gt 1)
        {
            # Add all -InputObject objects to $booleanOperatorArr ArrayList.
            $booleanOperatorArr.AddRange($BooleanOperator)
        }
        else
        {
            # Add single -InputObject object to $booleanOperatorArr ArrayList.
            $booleanOperatorArr.Add([System.String] $BooleanOperator) | Out-Null
        }
    }

    end
    {
        # Convert Context.BooleanOperator FilterList values to a single string for calculating logical BooleanOperator value.
        $booleanOperatorListStr = -join$booleanOperatorArr

        # Calculate and return final logical BooleanOperator value.
        [Maldaptive.LdapParser]::ToLogicalBooleanOperator($booleanOperatorListStr, $PSBoundParameters['IgnoreTrailingNegation'].IsPresent)
    }
}


function Get-LdapCompatibleBooleanOperator
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Get-LdapCompatibleBooleanOperator
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-LdapObject, Invoke-LdapBranchVisitor, Get-LdapLogicalBooleanOperator
Optional Dependencies: None

.DESCRIPTION

Get-LdapCompatibleBooleanOperator evaluates compatibility of input -BooleanOperator value(s) by simulating their presence in input -LdapBranch and comparing its effect on logical BooleanOperator value of all impacted LdapBranch objects, returning only the compatible -BooleanOperator value(s).

.PARAMETER LdapBranch

Specifies FilterList LdapBranch for which user input -BooleanOperator compatibility simulation will be applied.

.PARAMETER BooleanOperator

Specifies BooleanOperator value(s) to test for compatibility with user input -LdapBranch, supporting both single-character and double-character values to simulate adjacent nested BooleanOperator scenarios.

.PARAMETER Type

Specifies if compatibility checks should be performed solely for user input -LdapBranch or if two-step/double-depth compatibility checks should be performed for -LdapBranch and first nested LdapBranch (with single-character -BooleanOperator values being checked only for nested LdapBranch).

.PARAMETER Action

(Optional) Specifies if user input -BooleanOperator value(s) should be simulated as a simple insertion, replacement or removal of potential directly defined BooleanOperator value(s) in user input -LdapBranch or its first eligible nested FilterList LdapBranch.

.EXAMPLE

PS C:\> $ldapBranch = '(|(((name=dbo))(name=sabi)(name=vagrant)))' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> Get-LdapCompatibleBooleanOperator -LdapBranch $ldapBranch.Branch.Branch[2] -Type current_branch_and_first_nested_branch -Action insert -BooleanOperator '&','|','|&','&|','!!'

!!
&
|
|&

.EXAMPLE

PS C:\> $ldapBranch = '(|(((name=dbo))(name=sabi)(name=vagrant)))' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> Get-LdapCompatibleBooleanOperator -LdapBranch $ldapBranch.Branch.Branch[2] -Type current_branch_and_first_nested_branch -Action insert -BooleanOperator '&','|','|&','&|','!!' -Verbose

VERBOSE: Identified mismatch in logical BooleanOperator value when adding -BooleanOperator '&|' to current impacted LdapBranch's BooleanOperator context chain.
         Original chain: |  => | (logical BooleanOperator)
         Modified chain: |& => & (logical BooleanOperator)
!!
&
|
|&

.EXAMPLE

PS C:\> $ldapBranch = '(|(((name=dbo))(name=sabi)(name=vagrant)))' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> Get-LdapCompatibleBooleanOperator -LdapBranch $ldapBranch.Branch.Branch[2] -Type current_branch_only -Action insert -BooleanOperator '&','|','|&','&|','!!' -Verbose

WARNING: [Get-LdapCompatibleBooleanOperator] User input -Type is 'current_branch_only', so removing double-character user input -BooleanOperator value(s) from compatibility consideration.
VERBOSE: Identified mismatch in logical BooleanOperator value when adding -BooleanOperator '&' to current impacted LdapBranch's BooleanOperator context chain.
         Original chain: |  => | (logical BooleanOperator)
         Modified chain: |& => & (logical BooleanOperator)
|

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
        [ValidateScript( { $_.Type -eq [Maldaptive.LdapBranchType]::FilterList } )]
        [Maldaptive.LdapBranch]
        $LdapBranch,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateSet('&','|','!!','&|','|&','!&','!|')]
        [System.String[]]
        $BooleanOperator,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateSet('current_branch_only','current_branch_and_first_nested_branch','current_branch_and_first_recursive_branch_with_boolean_operator')]
        [System.String]
        $Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('insert','replace','remove')]
        [System.String]
        $Action = 'insert'
    )

    # Remove any potential duplicates in user input -BooleanOperator for more efficient compatibility checks.
    $BooleanOperator = $BooleanOperator | Sort-Object -Unique

    # Perform initial validation checks and error handling based on user input -Type value.
    switch ($Type)
    {
        'current_branch_only' {
            # If user input -Type parameter is defined as 'current_branch_only' then override nested branch variable with current -LdapBranch content.
            # This will force remainder of function to evaluate BooleanOperator compatibility only for -LdapBranch and not the two-step/double-depth compatibility approach.

            # Override nested branch variable with current user input -LdapBranch value.
            $firstNestedLdapBranch = $LdapBranch

            # Output warning message and remove any double-character -BooleanOperator value(s) from compatibility consideration since -Type 'current_branch_only' is defined.
            if ($BooleanOperator.Where( { $_.Length -eq 2 } ))
            {
                Write-Warning "[$($MyInvocation.MyCommand.Name)] User input -Type is 'current_branch_only', so removing double-character user input -BooleanOperator value(s) from compatibility consideration."

                # Remove double-character value(s) from user input -BooleanOperator.
                $BooleanOperator = $BooleanOperator.Where( { $_.Length -ne 2 } )

                # Output warning message and return from function if above step removed all remaining -BooleanOperator values.
                if (-not $BooleanOperator)
                {
                    Write-Warning "[$($MyInvocation.MyCommand.Name)] No more -BooleanOperator values exist after removing double-character user input -BooleanOperator value(s) from compatibility consideration, so returning from function with no compatible -BooleanOperator value(s)."

                    return
                }
            }
        }
        'current_branch_and_first_nested_branch' {
            # Based on the recursive nature of LDAP obfuscation functions, LdapBranch structures are traversed from deepest to shallowest depth.
            # Therefore user input double-character -BooleanOperator values are evaluated for input -LdapBranch and its first nested FilterList
            # LdapBranch, and single-character -BooleanOperator values are evaluated for input -LdapBranch's first nested FilterList LdapBranch.

            # Extract first nested LdapBranch in user input -LdapBranch.
            $firstNestedLdapBranch = $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )[0]

            # Perform error-handling if first nested LdapBranch above does not exist or is not of Type FilterList.
            if (-not $firstNestedLdapBranch)
            {
                # Output warning message and return from function if no nested LdapBranch is found in user input -LdapBranch.
                Write-Warning "[$($MyInvocation.MyCommand.Name)] User input -LdapBranch does not contain any nested LdapBranch, so returning from function with no compatible -BooleanOperator value(s)."

                return
            }
            elseif ($firstNestedLdapBranch.Type -ne [Maldaptive.LdapBranchType]::FilterList)
            {
                # Output warning message and return from function if first nested LdapBranch in user input -LdapBranch is not of Type FilterList.
                Write-Warning "[$($MyInvocation.MyCommand.Name)] First nested LdapBranch in user input -LdapBranch is not of Type FilterList, so returning from function with no compatible -BooleanOperator value(s)."

                return
            }
        }
        'current_branch_and_first_recursive_branch_with_boolean_operator' {
            # Based on the recursive nature of LDAP obfuscation functions, LdapBranch structures are traversed from deepest to shallowest depth.
            # Therefore user input double-character -BooleanOperator values are evaluated for input -LdapBranch and its first recursively
            # extracted eligible nested FilterList LdapBranch, and single-character -BooleanOperator values are evaluated for input -LdapBranch's
            # first recursively extracted eligible nested FilterList LdapBranch.

            # Extract first nested LdapBranch in user input -LdapBranch.
            $firstNestedLdapBranch = $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )[0]

            # Define ScriptBlock logic for Invoke-LdapBranchVisitor function to recursively visit and return all nested Filter LdapBranches or FilterList LdapBranches with
            # BooleanOperator directly defined.
            $scriptBlockEligibleBooleanOperatorLdapBranch = {
                [OutputType([Maldaptive.LdapBranch])]
                param (
                    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                    [Maldaptive.LdapBranch]
                    $LdapBranch
                )

                # Return user input -LdapBranch if it is either a FilterList LdapBranch with a BooleanOperator directly defined (i.e. not inherited) or a Filter LdapBranch.
                # This data will be used to determine if nearest impacted LdapBranch's LdapBranchType (Filter or FilterList) and defined BooleanOperator value are eligible
                # for BooleanOperator inversion based on user input -Scope and -Type parameters, respectively.
                if (
                    ($LdapBranch -is [Maldaptive.LdapBranch]) -and 
                    (
                        (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and $LdapBranch.BooleanOperator) -or
                        ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
                    )
                )
                {
                    $LdapBranch
                }
            }

            # If first nested LdapBranch in user input -LdapBranch does not have a directly defined BooleanOperator LdapToken then recursively visit and return closest eligible LdapBranch.
            if (-not $firstNestedLdapBranch.BooleanOperator)
            {
                # Recursively visit current LdapBranch and return first nested Filter LdapBranch or FilterList LdapBranch with BooleanOperator directly defined.
                $firstNestedLdapBranch = ([Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $firstNestedLdapBranch -ScriptBlock $scriptBlockEligibleBooleanOperatorLdapBranch -Action ReturnFirst))[0]
            }

            # Perform error-handling if first nested LdapBranch above does not exist or is not of type FilterList (or Filter double negation BooleanOperator scenario).
            if (-not $firstNestedLdapBranch)
            {
                # Output warning message and return from function if no nested LdapBranch is found in user input -LdapBranch.
                Write-Warning "[$($MyInvocation.MyCommand.Name)] User input -LdapBranch does not contain any nested LdapBranch, so returning from function with no compatible -BooleanOperator value(s)."

                return
            }
            elseif (
                ($firstNestedLdapBranch.Type -ne [Maldaptive.LdapBranchType]::FilterList) -and
                -not (
                    ($firstNestedLdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) -and
                    (-join@($LdapBranch.BooleanOperator,$firstNestedLdapBranch.BooleanOperator) -ceq '!!') -and
                    ($BooleanOperator -ccontains '!!')
                )
            )
            {
                # Output warning message and return from function if first nested LdapBranch in user input -LdapBranch is not of Type FilterList
                # and is not single exception of Filter LdapBranch in double negation BooleanOperator scenario.
                Write-Warning "[$($MyInvocation.MyCommand.Name)] First nested LdapBranch in user input -LdapBranch is not of Type FilterList and is not single exception of Filter LdapBranch in double negation BooleanOperator scenario, so returning from function with no compatible -BooleanOperator value(s)."

                return
            }
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    }

    # Extract directly defined BooleanOperator LdapToken (if it exists) for user input -LdapBranch and first nested LdapBranch.
    $ldapBranchBooleanOperatorLdapToken            = $LdapBranch.Branch.Where(            { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
    $firstNestedLdapBranchBooleanOperatorLdapToken = $firstNestedLdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

    # Perform error handling if BooleanOperator is directly defined in first nested LdapBranch or user input -LdapBranch without user input -Action 'Replace' or 'Remove'
    # being selected to override existing BooleanOperator.
    if ($Action -inotin @('Replace','Remove'))
    {
        # Output warning message and return from function if BooleanOperator is directly defined in first nested LdapBranch without user input -Action 'Replace' or 'Remove'
        # being selected to override existing BooleanOperator.
        if ($firstNestedLdapBranchBooleanOperatorLdapToken)
        {
            # Adjust LdapBranch verbiage in warning message based on user input -Type parameter.
            $ldapBranchMessage = switch ($Type)
            {
                'current_branch_only' {
                    'User input -LdapBranch'
                }
                'current_branch_and_first_nested_branch' {
                    "User input -LdapBranch's first nested LdapBranch"
                }
                'current_branch_and_first_recursive_branch_with_boolean_operator' {
                    "User input -LdapBranch's first recursively extracted eligible nested LdapBranch"
                }
                default {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }

            Write-Warning "[$($MyInvocation.MyCommand.Name)] $ldapBranchMessage already has BooleanOperator directly defined and user input -Action is not 'Replace' or 'Remove', so returning from function with no compatible -BooleanOperator value(s)."

            return
        }

        # Output warning message and remove any double-character -BooleanOperator value(s) from compatibility consideration if BooleanOperator is directly defined
        # in user input -LdapBranch without user input -Action 'Replace' or 'Remove' being selected to override existing BooleanOperator.
        if ($ldapBranchBooleanOperatorLdapToken -and $BooleanOperator.Where( { $_.Length -eq 2 } ))
        {
            Write-Warning "[$($MyInvocation.MyCommand.Name)] User input -LdapBranch already has BooleanOperator directly defined and user input -Action is not 'Replace' or 'Remove', so removing double-character user input -BooleanOperator value(s) from compatibility consideration."

            # Remove double-character value(s) from user input -BooleanOperator.
            $BooleanOperator = $BooleanOperator.Where( { $_.Length -ne 2 } )
        }
    }

    # Current function relies on each Filter's and applicable FilterList's Context.BooleanOperator property to be accurate to calculate full
    # chain of BooleanOperator values as they apply to each Filter and applicable FilterList based on its position in the SearchFilter.
    # If any new LdapTokens have been manually added anywhere in LdapBranch then Context.BooleanOperator property values can be inaccurate,
    # so reparsing entire SearchFilter is required.
    # However, entire SearchFilter is not available when a recursive function only processes one branch at a time, so current function
    # will use current branch's Context.BooleanOperator property to accurately reconstruct GroupStart and BooleanOperator values leading up
    # to current branch before reparsing and performing validation of logical Context.BooleanOperator chain of each Filter and applicable
    # FilterList LdapBranch inheriting from current branch.

    # Convert user input -LdapBranch to string format.
    $ldapBranchStr = ConvertTo-LdapObject -InputObject $LdapBranch -Target String

    # Using extracted BooleanOperator token(s) above, reconstruct original SearchFilter prefix and suffix strings with accurate depths,
    # minus any additional potential LdapTokens outside current scope.
    $prevPrefixDepth = 0
    $searchFilterPrefix = $LdapBranch.Context.BooleanOperator.FilterListBooleanOperatorTokenList.Where( { $_ } ).ForEach(
    {
        $curBooleanOperator = $_

        # Calculate number of GroupStart tokens between current and previous BooleanOperator.
        $groupStartCount = $curBooleanOperator.Depth - $prevPrefixDepth
        $prevPrefixDepth = $curBooleanOperator.Depth

        # Generate and return GroupStart-padded prefix string followed by current BooleanOperator.
        $groupStartStr = '(' * $groupStartCount
        ($groupStartStr + $curBooleanOperator.Content)
    } )
    $searchFilterSuffix = (')' * $prevPrefixDepth)

    # Join above prefix and suffix to current branch string representation to form an accurate replica of current branch scope for re-parsing.
    $searchFilterReconstructed = -join([System.Array] $searchFilterPrefix + $ldapBranchStr + $searchFilterSuffix)

    # Convert reconstructed SearchFilter string to LdapBranch format so all Context.BooleanOperator property values can be trusted as accurate.
    $ldapBranchReparsed = ConvertTo-LdapObject -InputObject $searchFilterReconstructed -Target LdapBranch

    # Define ScriptBlock logic for Invoke-LdapBranchVisitor function to extract user input -LdapBranch from reparsed SearchFilter.
    $scriptBlockExtractLdapBranch = {
        [OutputType([Maldaptive.LdapBranch])]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [Maldaptive.LdapBranch]
            $LdapBranch,

            [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
            [Maldaptive.LdapBranch]
            $ReferenceLdapBranch
        )

        # Return current LdapBranch if it matches original user input -LdapBranch from calling function.
        if (
            ($LdapBranch                 -is  [Maldaptive.LdapBranch]                ) -and
            ($LdapBranch.Type            -eq  [Maldaptive.LdapBranchType]::FilterList) -and
            ($LdapBranch.BooleanOperator -ceq $ReferenceLdapBranch.BooleanOperator   ) -and
            ($LdapBranch.Branch.Count    -ceq $ReferenceLdapBranch.Branch.Count      ) -and
            ((ConvertTo-LdapObject -InputObject $LdapBranch -Target String) -ceq (ConvertTo-LdapObject -InputObject $ReferenceLdapBranch -Target String))
        )
        {
            $LdapBranch
        }
    }

    # Recursively visit reparsed SearchFilter and extract user input -LdapBranch.
    $ldapBranchReparsed = ([Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $ldapBranchReparsed -ArgumentList @{ ReferenceLdapBranch = $LdapBranch } -ScriptBlock $scriptBlockExtractLdapBranch -Action ReturnFirst))[0]

    # Output warning message and return from function if user input -LdapBranch could not be extracted from reparsed SearchFilter or if
    # more than one LdapBranch matching user input -LdapBranch was extracted from reparsed SearchFilter.
    if (-not $ldapBranchReparsed)
    {
        Write-Warning "[$($MyInvocation.MyCommand.Name)] Could not extract user input -LdapBranch from reparsed SearchFilter."

        return
    }

    # Perform extraction of first nested LdapBranch from reparsed SearchFilter based on user input -Type value.
    switch ($Type)
    {
        'current_branch_only' {
            # If user input -Type parameter is defined as 'current_branch_only' then override reparsed nested branch variable with current reparsed -LdapBranch content.
            # This will force remainder of function to evaluate BooleanOperator compatibility only for -LdapBranch and not the two-step/double-depth compatibility approach.
            $firstNestedLdapBranchReparsed = $ldapBranchReparsed
        }
        'current_branch_and_first_nested_branch' {
            # Extract first nested LdapBranch in user input -LdapBranch extracted from reparsed SearchFilter.
            $firstNestedLdapBranchReparsed = $ldapBranchReparsed.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )[0]
        }
        'current_branch_and_first_recursive_branch_with_boolean_operator' {
            # Extract first nested LdapBranch in user input -LdapBranch extracted from reparsed SearchFilter.
            $firstNestedLdapBranchReparsed = $ldapBranchReparsed.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )[0]

            # If first nested LdapBranch in reparsed user input -LdapBranch does not have a directly defined BooleanOperator LdapToken then recursively visit and return closest eligible LdapBranch.
            if (-not $firstNestedLdapBranchReparsed.BooleanOperator)
            {
                # Recursively visit user input -LdapBranch and return the first nested Filter LdapBranch or FilterList LdapBranch with BooleanOperator directly defined.
                # To avoid potentially returning user input -LdapBranch and to take advantage of performance improvement of -Action ReturnFirst parameter, iterate over
                # each nested LdapBranch until a single eligible LdapBranch result is returned.
                $visitorResultEligibleBooleanOperatorLdapBranch = foreach ($nestedLdapBranch in $ldapBranchReparsed.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))
                {
                    $visitorResultLdapBranch = ([Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $nestedLdapBranch -ScriptBlock $scriptBlockEligibleBooleanOperatorLdapBranch -Action ReturnFirst))[0]

                    # If LdapBranch returned above then return LdapBranch below and break out of foreach loop to skip unnecessary iterations.
                    if ($visitorResultLdapBranch)
                    {
                        $visitorResultLdapBranch

                        break
                    }
                }

                # If eligible LdapBranch returned from recursive visitor above then override reparsed nested branch variable with above recursively retrieved LdapBranch.
                $firstNestedLdapBranchReparsed = $visitorResultEligibleBooleanOperatorLdapBranch ? $visitorResultEligibleBooleanOperatorLdapBranch : $firstNestedLdapBranchReparsed
            }
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    }

    # Extract last FilterList-scope BooleanOperator LdapToken and directly defined BooleanOperator LdapToken (if it exists) for user
    # input -LdapBranch and its first nested LdapBranch.
    $ldapBranchReparsedFilterListBooleanOperator            = $ldapBranchReparsed.Context.BooleanOperator.FilterListBooleanOperator
    $ldapBranchReparsedBooleanOperator                      = $ldapBranchReparsed.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
    $firstNestedLdapBranchReparsedFilterListBooleanOperator = $firstNestedLdapBranchReparsed.Context.BooleanOperator.FilterListBooleanOperator
    $firstNestedLdapBranchReparsedBooleanOperator           = $firstNestedLdapBranchReparsed.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

    # Define ScriptBlock logic for Invoke-LdapBranchVisitor function to extract all Filter and applicable FilterList LdapBranches from reparsed
    # SearchFilter that will be impacted by user input -BooleanOperator value(s) and therefore should be included in compatibility checks.
    $scriptBlockImpactedLdapBranch = {
        [OutputType([Maldaptive.LdapBranch])]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [Maldaptive.LdapBranch]
            $LdapBranch
        )

        # Return current LdapBranch if it is a Filter or FilterList containing more than one nested LdapBranch.
        if (
            ($LdapBranch -is [Maldaptive.LdapBranch]) -and
            (
                ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) -or
                (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ).Count -gt 1))
            )
        )
        {
            $LdapBranch
        }
    }

    # Recursively visit reparsed SearchFilter and extract all Filter and applicable FilterList LdapBranches that will be impacted by user input -BooleanOperator
    # value(s) and therefore should be included in compatibility checks.
    $impactedLdapBranchArr            = [Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $ldapBranchReparsed            -ScriptBlock $scriptBlockImpactedLdapBranch -Action Return)
    $impactedFirstNestedLdapBranchArr = [Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $firstNestedLdapBranchReparsed -ScriptBlock $scriptBlockImpactedLdapBranch -Action Return)

    # Bifurcate above impacted LdapBranch objects into exclusive LdapBranch and inclusive first nested LdapBranch since this delineation will be important for
    # splitting compatibility checks for single-character -BooleanOperator values and (where applicable) double-character -BooleanOperator values.
    $impactedExclusiveLdapBranchBooleanOperatorContextArr            = $impactedLdapBranchArr.Where( { $_.Start -inotin $impactedFirstNestedLdapBranchArr.Start } )
    $impactedInclusiveFirstNestedLdapBranchBooleanOperatorContextArr = $impactedFirstNestedLdapBranchArr

    # Add bifurcation property to above impacted LdapBranch arrays for later delineation.
    # -Force flag sometimes required for inclusive result(s) when -Action current_branch_and_first_recursive_branch_with_boolean_operator is selected since the same
    # LdapBranch can be traversed multiple times by calling function and Bifurcation member should be updated if already present.
    Add-Member -InputObject $impactedExclusiveLdapBranchBooleanOperatorContextArr            -MemberType NoteProperty -Name 'Bifurcation' -Value 'ExclusiveLdapBranch'
    Add-Member -InputObject $impactedInclusiveFirstNestedLdapBranchBooleanOperatorContextArr -MemberType NoteProperty -Name 'Bifurcation' -Value 'InclusiveFirstNestedLdapBranch' -Force

    # Join bifurcated impacted LdapBranch arrays into a single array for BooleanOperator context chain extraction below.
    $impactedLdapBranchArr = [System.Array] $impactedExclusiveLdapBranchBooleanOperatorContextArr + $impactedInclusiveFirstNestedLdapBranchBooleanOperatorContextArr

    # Extract BooleanOperator context chain from each impacted LdapBranch, parsing into prefix, suffix and potential defined BooleanOperator values for
    # user input -LdapBranch and first nested LdapBranch.
    # This format will facilitate precise substitutions for each user input -BooleanOperator value (both single-character and double-character) into each
    # impacted Filter and FilterList LdapBranch's BooleanOperator context chain for logical BooleanOperator evaluation.
    $impactedBooleanOperatorContextObjArr = foreach ($impactedLdapBranch in $impactedLdapBranchArr)
    {
        # Create BooleanOperator context chain for current impacted LdapBranch by concatenating both FilterList- and Filter-scope BooleanOperator TokenList
        # value(s) stored in Filter or FilterList LdapBranch's Context.BooleanOperator property.
        # Filter-scope BooleanOperator values are captured separately in Context.BooleanOperator property for the single Filter inheriting these BooleanOperator
        # values though they are listed as FilterList-scope values in all preceding FilterList branches.
        # If current impacted LdapBranch is a FilterList LdapBranch with a BooleanOperator directly defined then prepend it to the FilterBooleanOperatorTokenList
        # property for the purposes of logical BooleanOperator calculation and validation of the FilterList LdapBranch.
        if (($impactedLdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and $impactedLdapBranch.BooleanOperator)
        {
            # Extract BooleanOperator LdapToken from current impacted FilterList LdapBranch.
            $impactedLdapBranchBooleanOperatorLdapToken = $impactedLdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

            # Prepend extracted BooleanOperator LdapToken to current impacted FilterList LdapBranch's FilterBooleanOperatorTokenList property.
            $impactedLdapBranch.Context.BooleanOperator.FilterBooleanOperatorTokenList = [System.Array] $impactedLdapBranchBooleanOperatorLdapToken + $impactedLdapBranch.Context.BooleanOperator.FilterBooleanOperatorTokenList
        }
        $booleanOperatorContextArr = @(([System.Array] $impactedLdapBranch.Context.BooleanOperator.FilterListBooleanOperatorTokenList + $impactedLdapBranch.Context.BooleanOperator.FilterBooleanOperatorTokenList) | Select-Object Guid,Content)

        # Create object to store BooleanOperator context chain indices for BooleanOperator and FilterListBooleanOperator values (if they are defined) for
        # both user input -LdapBranch and first nested LdapBranch.
        $booleanOperatorContextIndexObj = [PSCustomObject] @{
            LdapBranchFilterListBooleanOperator            = (-not $booleanOperatorContextArr -or -not $ldapBranchReparsedFilterListBooleanOperator           ) ? -1 : $booleanOperatorContextArr.Guid.Guid.IndexOf($ldapBranchReparsedFilterListBooleanOperator.Guid)
            LdapBranchBooleanOperator                      = (-not $booleanOperatorContextArr -or -not $ldapBranchReparsedBooleanOperator                     ) ? -1 : $booleanOperatorContextArr.Guid.Guid.IndexOf($ldapBranchReparsedBooleanOperator.Guid)
            FirstNestedLdapBranchFilterListBooleanOperator = (-not $booleanOperatorContextArr -or -not $firstNestedLdapBranchReparsedFilterListBooleanOperator) ? -1 : $booleanOperatorContextArr.Guid.Guid.IndexOf($firstNestedLdapBranchReparsedFilterListBooleanOperator.Guid)
            FirstNestedLdapBranchBooleanOperator           = (-not $booleanOperatorContextArr -or -not $firstNestedLdapBranchReparsedBooleanOperator          ) ? -1 : $booleanOperatorContextArr.Guid.Guid.IndexOf($firstNestedLdapBranchReparsedBooleanOperator.Guid)
        }

        # Select the highest and lowest BooleanOperator context chain indices for FilterList BooleanOperator and directly defined BooleanOperator in user input
        # -LdapBranch and first nested LdapBranch, respectively.
        $booleanOperatorPrefixDelimIndex = (@($booleanOperatorContextIndexObj.LdapBranchFilterListBooleanOperator           ,$booleanOperatorContextIndexObj.LdapBranchBooleanOperator           ).Where( { $_ -ne -1 } ) | Sort-Object | Select-Object -Last  1)
        $booleanOperatorSuffixDelimIndex = (@($booleanOperatorContextIndexObj.FirstNestedLdapBranchFilterListBooleanOperator,$booleanOperatorContextIndexObj.FirstNestedLdapBranchBooleanOperator).Where( { $_ -ne -1 } ) | Sort-Object | Select-Object -First 1)

        # Extract BooleanOperator context chain prefix and suffix value(s) based on above max/min indices.
        # In below index validations use $null check instead of -not operator since a value of 0 is not $null but would cause -not opeator to evaluate to $true.
        $booleanOperatorPrefix = (-not $booleanOperatorContextArr -or ($booleanOperatorPrefixDelimIndex -eq $null)) ? $null : $booleanOperatorContextArr[0..$booleanOperatorPrefixDelimIndex]
        $booleanOperatorSuffix = (-not $booleanOperatorContextArr -or ($booleanOperatorSuffixDelimIndex -eq $null)) ? $null : $booleanOperatorContextArr[$booleanOperatorSuffixDelimIndex..($booleanOperatorContextArr.Count - 1)]

        # Remove potential duplicates in prefix and suffix based on directly defined BooleanOperator presence or shared BooleanOperator inheritance scenarios.
        $booleanOperatorPrefix = $booleanOperatorPrefix.Where( { $_.Guid -ne $ldapBranchReparsedBooleanOperator.Guid } )
        $booleanOperatorSuffix = $booleanOperatorSuffix.Where( { $_.Guid -inotin ([System.Array] $booleanOperatorPrefix + $ldapBranchReparsedBooleanOperator + $firstNestedLdapBranchReparsedBooleanOperator).Guid } )

        # Codify above extractions and original impacted LdapBranch's Type and Bifurcation properties into a single BooleanOperator context chain object.
        $booleanOperatorContextObj = [PSCustomObject] @{
            Type                       = $impactedLdapBranch.Type
            Bifurcation                = $impactedLdapBranch.Bifurcation
            Prefix                     = -join$booleanOperatorPrefix.Content
            BooleanOperator            = ($booleanOperatorContextIndexObj.LdapBranchBooleanOperator            -eq -1) ? $null : -join$ldapBranchReparsedBooleanOperator.Content
            FirstNestedBooleanOperator = ($booleanOperatorContextIndexObj.FirstNestedLdapBranchBooleanOperator -eq -1) ? $null : -join$firstNestedLdapBranchReparsedBooleanOperator.Content
            Suffix                     = -join$booleanOperatorSuffix.Content
        }

        # Return BooleanOperator context chain object for current impacted LdapBranch.
        $booleanOperatorContextObj
    }

    # Remove potential BooleanOperator context chain duplicates (legitimately common for many LDAP SearchFilters) for more efficient compatibility checks.
    $impactedBooleanOperatorContextObjArr = $impactedBooleanOperatorContextObjArr | Sort-Object ($impactedBooleanOperatorContextObjArr | Get-Member -MemberType NoteProperty).Name -Unique

    # Copy user input -BooleanOperator array value(s) into an ArrayList to enable easier removal (via .Remove method) of any BooleanOperator values
    # that do not pass all compatibility checks below so only remaining, compatible BooleanOperator values are returned to calling function.
    $compatibleBooleanOperatorArr = [System.Collections.ArrayList] $BooleanOperator

    # Iterate over each impacted LdapBranch's BooleanOperator context chain object, performing before-and-after analysis of final logical BooleanOperator
    # value for inclusion of each remaining -BooleanOperator value, honoring previously defined exclusive/inclusive bifurcation when applicable.
    foreach ($curBooleanOperatorContextObj in $impactedBooleanOperatorContextObjArr)
    {
        # Concatenate current BooleanOperator context chain values into a single string for evaluation by Get-LdapLogicalBooleanOperator function below.
        $curBooleanOperatorContextOriginalStr = $curBooleanOperatorContextObj.Prefix + $curBooleanOperatorContextObj.BooleanOperator + $curBooleanOperatorContextObj.FirstNestedBooleanOperator + $curBooleanOperatorContextObj.Suffix

        # Set optional -IgnoreTrailingNegation switch parameter as a hashtable to be used with Get-LdapLogicalBooleanOperator invocation later via splatting if
        # current impacted LdapBranch is of Type FilterList (containing more than one nested LdapBranch based on previous filtering definition).
        # This -IgnoreTrailingNegation switch will be used for FilterList LdapBranches since desired logical BooleanOperator value is being calculated
        # from current FilterList LdapBranch but is meant to be applied to all nested LdapBranches as they relate to one another.
        # Since trailing negation BooleanOperator ('!') values will only apply to current FilterList LdapBranch and not all nested LdapBranches they will
        # be removed when calculating logical BooleanOperator for FilterList LdapBranch's nested LdapBranches.
        $optionalIgnoreTrailingNegationSwitchParameter = ($curBooleanOperatorContextObj.Type -eq [Maldaptive.LdapBranchType]::FilterList) ? @{ IgnoreTrailingNegation = $true } : @{ }

        # Calculate logical BooleanOperator value for original BooleanOperator context chain defined above.
        # Optional -IgnoreTrailingNegation switch parameter will be applied if current branch is FilterList LdapBranch with more than one nested LdapBranches.
        $curLogicalBooleanOperatorOriginal = $curBooleanOperatorContextOriginalStr ? (Get-LdapLogicalBooleanOperator -BooleanOperator $curBooleanOperatorContextOriginalStr @optionalIgnoreTrailingNegationSwitchParameter) : $null

        # Add each remaining user input -BooleanOperator value to current impacted LdapBranch's BooleanOperator context chain and compare the resultant
        # logical BooleanOperator value with the original logical BooleanOperator value.
        # Enumerate temporary copy of remaining user input -BooleanOperator values since a collection cannot be modified while being enumerated.
        $compatibleBooleanOperatorArrCopy = $compatibleBooleanOperatorArr.PSObject.Copy()
        foreach ($curBooleanOperator in $compatibleBooleanOperatorArrCopy)
        {
            # Skip compatibility check for current single-character BooleanOperator value if bifurcation is ExclusiveLdapBranch.
            if (($curBooleanOperator.Length -eq 1) -and ($curBooleanOperatorContextObj.Bifurcation -eq 'ExclusiveLdapBranch'))
            {
                continue
            }

            # Make copy of current BooleanOperator value so the copy can be set to $null in below modified BooleanOperator context chain generation
            # if user input -Action parameter is set to 'Remove'.
            $curBooleanOperatorCopy = $curBooleanOperator

            # If user input -Action parameter is set to 'Remove' then set current BooleanOperator copy to $null to simulate removal in below modified
            # BooleanOperator context chain generation
            if ($Action -eq 'Remove')
            {
                $curBooleanOperatorCopy = $null

                # If -Type parameter is 'current_branch_only' then also set current LdapBranch's directly defined BooleanOperator value to $null.
                if ($Type -eq 'current_branch_only')
                {
                    $curBooleanOperatorContextObj.BooleanOperator = $null
                }
            }

            # Add current -BooleanOperator value to current BooleanOperator context chain, where positioning is based on BooleanOperator's length
            # (i.e. single-character or double-character) and current BooleanOperator context chain's Bifurcation property.
            $curBooleanOperatorContextModifiedStr = switch (@($curBooleanOperator.Length,$curBooleanOperatorContextObj.Bifurcation) -join '_')
            {
                '1_InclusiveFirstNestedLdapBranch' {
                    -join@(
                        $curBooleanOperatorContextObj.Prefix
                        $curBooleanOperatorContextObj.BooleanOperator
                        $curBooleanOperatorCopy
                        $curBooleanOperatorContextObj.Suffix
                    )
                }
                '2_InclusiveFirstNestedLdapBranch' {
                    -join@(
                        $curBooleanOperatorContextObj.Prefix
                        $curBooleanOperatorCopy
                        $curBooleanOperatorContextObj.Suffix
                    )
                }
                '1_ExclusiveLdapBranch' {
                    # Single-character BooleanOperator values are not in scope for compatibility checks for impacted LdapBranch objects in
                    # ExclusiveLdapBranch bifurcation.
                }
                '2_ExclusiveLdapBranch' {
                    # Impacted LdapBranch objects in ExclusiveLdapBranch bifurcation only test leading BooleanOperator character.
                    # No need to test if leading BooleanOperator character is a negation ('!') since it will only apply to (or be inherited by)
                    # the first nested LdapBranch and not any adjacent LdapBranches.
                    -join@(
                        $curBooleanOperatorContextObj.Prefix
                        ($curBooleanOperatorCopy ? $curBooleanOperatorCopy[0] : $null)
                        $curBooleanOperatorContextObj.FirstNestedBooleanOperator
                        $curBooleanOperatorContextObj.Suffix
                    )
                }
            }

            # Calculate logical BooleanOperator value for modified BooleanOperator context chain defined above.
            # Optional -IgnoreTrailingNegation switch parameter will be applied if current branch is FilterList LdapBranch with more than one nested LdapBranches.
            $curLogicalBooleanOperatorModified = $curBooleanOperatorContextModifiedStr ? (Get-LdapLogicalBooleanOperator -BooleanOperator $curBooleanOperatorContextModifiedStr @optionalIgnoreTrailingNegationSwitchParameter) : $null

            # If logical BooleanOperator values for before-and-after BooleanOperator context chains are incompatible then remove current -BooleanOperator value from compatibility ArrayList.
            if (
                (
                    $curLogicalBooleanOperatorOriginal -and
                    ($curLogicalBooleanOperatorModified -cne $curLogicalBooleanOperatorOriginal) -and                  
                    -not (
                        ($curBooleanOperatorContextObj.Type -eq [Maldaptive.LdapBranchType]::Filter) -and
                        ($curLogicalBooleanOperatorOriginal -cin @('&','|'))
                    )
                ) -or
                (-not $curLogicalBooleanOperatorOriginal -and ($curLogicalBooleanOperatorModified -cin @('!','!|','!&')))
            )
            {
                # Remove current -BooleanOperator value from compatibility ArrayList if modification to BooleanOperator context chain produces a different final
                # logical BooleanOperator value when one was originally defined, except if a Filter LdapBranch's logical BooleanOperator value changes between
                # '&' and '|' since these are interchangeable logically for a single Filter LdapBranch and therefore considered compatible.
                $compatibleBooleanOperatorArr.Remove($curBooleanOperator)

                # If -BooleanOperator removed above was last BooleanOperator value in $compatibleBooleanOperatorArrCopy then overwrite $impactedBooleanOperatorContextObjArr
                # array to avoid unnecessary iterations of outer foreach loop.
                if (-not $compatibleBooleanOperatorArr)
                {
                    $impactedBooleanOperatorContextObjArr = @()
                }

                # If -Verbose switch parameter is defined then output additional output regarding current logical BooleanOperator mismatch.
                if ($PSBoundParameters['Verbose'].IsPresent)
                {
                    # Perform additional calculations to align before/after output message to be more readable.
                    $longestBooleanOperator        = @($curBooleanOperatorContextOriginalStr.Length,$curBooleanOperatorContextModifiedStr.Length) | Sort-Object | Select-Object -Last 1
                    $longestLogicalBooleanOperator = @($curLogicalBooleanOperatorOriginal.Length   ,$curLogicalBooleanOperatorModified.Length   ) | Sort-Object | Select-Object -Last 1

                    # Create verbose output message highlighting before/after mismatch in logical BooleanOperator values.
                    $logicalBooleanOperatorMismatchMessage = -join@(
                        "Identified mismatch in logical BooleanOperator value when adding -BooleanOperator '$curBooleanOperator' to current impacted LdapBranch's BooleanOperator context chain."
                        "`n         Original chain: $curBooleanOperatorContextOriginalStr $(' ' * ($longestBooleanOperator - $curBooleanOperatorContextOriginalStr.Length))=> $curLogicalBooleanOperatorOriginal $(' ' * ($longestLogicalBooleanOperator - $curLogicalBooleanOperatorOriginal.Length))(logical BooleanOperator)"
                        "`n         Modified chain: $curBooleanOperatorContextModifiedStr $(' ' * ($longestBooleanOperator - $curBooleanOperatorContextModifiedStr.Length))=> $curLogicalBooleanOperatorModified $(' ' * ($longestLogicalBooleanOperator - $curLogicalBooleanOperatorModified.Length))(logical BooleanOperator)"
                    )

                    Write-Verbose $logicalBooleanOperatorMismatchMessage
                }
            }
        }
    }

    # Return any remaining compatible user input -BooleanOperator value(s).
    return [System.String[]] $compatibleBooleanOperatorArr
}


function Invoke-LdapBranchVisitor
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Invoke-LdapBranchVisitor
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Invoke-LdapBranchVisitor recursively visits and applies user input -ScriptBlock parameter logic against all nested LdapBranch objects in input LdapBranch, either directly modifying or returning information from nested LdapBranch object(s) based on user input -Action parameter.

.PARAMETER InputObject

Specifies LdapBranch to be recursively visited, applying -ScriptBlock logic to each nested LdapBranch based on user input -Action parameter.

.PARAMETER ScriptBlock

Specifies ScriptBlock logic to be invoked for each nested LdapBranch objects.

.PARAMETER ArgumentList

(Optional) Specifies hashtable of arguments to be passed as parameter(s) for -ScriptBlock via splatting.

.PARAMETER Action

Specifies action to be applied to each nested LdapBranch object via user input -ScriptBlock logic, either directly modifying input LdapBranch or returning information output from -ScriptBlock logic.

.PARAMETER TrackModification

(Optional) Specifies LdapToken's Depth property value be set to -1 (e.g. for highlighting where modification occurred) for any LdapToken(s) modified in user input -ScriptBlock parameter logic if -Action Modify is specified.

.EXAMPLE

PS C:\> $ldapBranch = '(|(name=dbo)(name=sabi)(name=vagrant))' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $ldapBranch | Invoke-LdapBranchVisitor -Action Return -ScriptBlock { param($LdapBranch) if ($LdapBranch.Branch.Value -iin @('dbo','sabi')) { $LdapBranch.Branch.Content } }

(name=dbo)
(name=sabi)

.EXAMPLE

PS C:\> $ldapBranch = '(|(name=dbo)(name=sabi)(name=vagrant))' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $ldapBranch | Invoke-LdapBranchVisitor -Action ReturnFirst -ScriptBlock { param($LdapBranch) if ($LdapBranch.Branch.Value -iin @('dbo','sabi')) { $LdapBranch.Branch.Content } }

(name=dbo)

.EXAMPLE

PS C:\> $ldapBranch = '(|(name=dbo)(name=sabi)(name=vagrant))' | ConvertTo-LdapObject -Target LdapBranch
PS C:\> $ldapBranch | Invoke-LdapBranchVisitor -Action Modify -ScriptBlock {
            param($LdapBranch)
            if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
            {
                if ($LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::ComparisonOperator].Content -eq '=')
                {
                    $LdapBranch | Edit-LdapToken -LdapToken $LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::ComparisonOperator] -Content '~='
                }
                if ($LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::Value].Content -eq 'dbo')
                {
                    $LdapBranch | Edit-LdapToken -LdapToken $LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::Attribute] -Content $LdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::Attribute].Content.ToUpper()
                }
            }
        }
PS C:\> $ldapBranch | ConvertTo-LdapObject -Target String

(|(NAME~=dbo)(name~=sabi)(name~=vagrant))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    # If -Action Modify then System.Void is the return type. Otherwise if -Action Return then the return type depends on user input -ScriptBlock logic so setting generically as System.Object.
    [OutputType(
        'System.Void',
        'System.Object'
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Maldaptive.LdapBranch]
        $LdapBranch,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [hashtable]
        $ArgumentList = @{ },

        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [ValidateSet('Return','ReturnFirst','Modify')]
        [System.String]
        $Action,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
    $optionalSwitchParameters = @{ }
    $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

    # Route visitor logic based on user input -Action parameter.
    switch ($Action)
    {
        'Return' {
            # Apply user input -ScriptBlock to current LdapBranch where -ScriptBlock logic will identify and output any object(s) to be returned.
            & $ScriptBlock -LdapBranch $LdapBranch @ArgumentList

            # Recursively invoke function for each nested LdapBranch.
            foreach ($curBranch in $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))
            {
                Invoke-LdapBranchVisitor -LdapBranch $curBranch -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -Action $Action
            }
        }
        'ReturnFirst' {
            # Apply user input -ScriptBlock to current LdapBranch where -ScriptBlock logic will identify and output any object to be returned.
            $ldapBranchScriptBlockResult = & $ScriptBlock -LdapBranch $LdapBranch @ArgumentList

             # If current LdapBranch returned a result above then return first result to stop further recursion.
            if ($ldapBranchScriptBlockResult)
            {
                return $ldapBranchScriptBlockResult | Select-Object -First 1
            }

            # Recursively invoke function for each nested LdapBranch.
            foreach ($curBranch in $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))
            {
                $curBranchVisitorResult = Invoke-LdapBranchVisitor -LdapBranch $curBranch -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -Action $Action

                # If current nested LdapBranch returned a result above then return first result to stop further recursion.
                if ($curBranchVisitorResult)
                {
                    return $curBranchVisitorResult | Select-Object -First 1
                }
            }
        }
        'Modify' {
            # Apply user input -ScriptBlock to current LdapBranch where -ScriptBlock logic will potentially modify input LdapBranch object.
            & $ScriptBlock -LdapBranch $LdapBranch @ArgumentList @optionalSwitchParameters | Out-Null

            # Iterate over each object nested in current LdapBranch, modifying current LdapBranch.
            $LdapBranch.Branch = foreach ($curBranch in $LdapBranch.Branch)
            {
                # Only recursively invoke function for additional nested LdapBranch object(s).
                if ($curBranch -is [Maldaptive.LdapBranch])
                {
                    # If optional -TrackModification switch parameter is defined then pass along to recursive function invocation in case -ScriptBlock uses it for modification tracking display purposes.
                    Invoke-LdapBranchVisitor -LdapBranch $curBranch -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -Action $Action @optionalSwitchParameters
                }
                else
                {
                    # If nested object is not an LdapBranch then return as-is.
                    $curBranch
                }
            }

            # Set boolean to capture if current function invocation is recursive (i.e. current function is called by itself).
            $isRecursive = ($MyInvocation.MyCommand.Name -eq (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly).MyCommand.Name) ? $true : $false

            # If current function invocation is recursive then return current LdapBranch.
            if ($isRecursive)
            {
                $LdapBranch
            }
        }
        default {
            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
        }
    }
}


function ConvertTo-LdapParsedValue
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: ConvertTo-LdapParsedValue
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

ConvertTo-LdapParsedValue parses input Attribute Value string into an array of LdapValueParsed objects, performing hex decoding and adding metadata for each character like character class, case, etc.

.PARAMETER InputObject

Specifies Attribute Value string to parser.

.PARAMETER Rdn

(Optional) Specifies Attribute Value is an RDN (Relative Distinguished Name) so specific parsing logic can be applied. E.g. the escaping of some special characters like '\+' and '\=' is upgraded from a Format of [Maldaptive.LdapValueParsedFormat]::EscapedUnknown to [Maldaptive.LdapValueParsedFormat]::EscapedKnown when present in an RDN.

.EXAMPLE

PS C:\> 'Shq\69p\=Shqip' | ConvertTo-LdapParsedValue | Format-Table

Content ContentDecoded IsDecoded         Format   Class  Case IsPrintable
------- -------------- ---------         ------   -----  ---- -----------
S       S                  False        Default   Alpha Upper        True
h       h                  False        Default   Alpha Lower        True
q       q                  False        Default   Alpha Lower        True
\69     i                   True            Hex   Alpha Lower        True
p       p                  False        Default   Alpha Lower        True
\=      \=                 False EscapedUnknown Special    NA        True
S       S                  False        Default   Alpha Upper        True
h       h                  False        Default   Alpha Lower        True
q       q                  False        Default   Alpha Lower        True
i       i                  False        Default   Alpha Lower        True
p       p                  False        Default   Alpha Lower        True

.EXAMPLE

PS C:\> 'Shq\69p\=Shqip' | ConvertTo-LdapParsedValue -Rdn | Format-Table

Content ContentDecoded IsDecoded       Format   Class  Case IsPrintable
------- -------------- ---------       ------   -----  ---- -----------
S       S                  False      Default   Alpha Upper        True
h       h                  False      Default   Alpha Lower        True
q       q                  False      Default   Alpha Lower        True
\69     i                   True          Hex   Alpha Lower        True
p       p                  False      Default   Alpha Lower        True
\=      \=                 False EscapedKnown Special    NA        True
S       S                  False      Default   Alpha Upper        True
h       h                  False      Default   Alpha Lower        True
q       q                  False      Default   Alpha Lower        True
i       i                  False      Default   Alpha Lower        True
p       p                  False      Default   Alpha Lower        True

.EXAMPLE

PS C:\> -join('1337Shq\69p' | ConvertTo-LdapParsedValue).ContentDecoded

1337Shqip

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([Maldaptive.LdapValueParsed[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Rdn
    )

    begin
    {

    }

    process
    {
        # Iterate over each -InputObject.
        foreach ($curInputObject in $InputObject)
        {
            [Maldaptive.LdapParser]::ParseLdapValue($curInputObject,$PSBoundParameters['Rdn'].IsPresent)
        }
    }

    end
    {

    }
}


function Out-LdapObject
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Out-LdapObject
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Out-LdapObject outputs LDAP SearchFilter with token-specific color-coding, optional highlighting and single-line or tree formatting for simplified readability.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) to format and output.

.PARAMETER Indentation

(Optional) Specifies string to use for indentation, calculated for each line based on each token's depth.

.PARAMETER ShowWhitespace

(Optional) Specifies that Whitespace be highlighted.

.PARAMETER SkipModificationHighlighting

(Optional) Specifies that any modified tokens in LDAP SearchFilter not be highlighted.

.PARAMETER Format

(Optional) Specifies output format for LDAP SearchFilter (e.g. single-line 'default' format versus multi-line 'tree' format).

.PARAMETER PassThru

(Optional) Specifies that LDAP SearchFilter be output to stdout potentially in addition to being output to stdhost.

.PARAMETER Quiet

(Optional) Specifies that LDAP SearchFilter not be output to stdhost (e.g. typically used in conjunction with -PassThru).

.EXAMPLE

PS C:\> '((|(name=sabi)(name=dbo)))' | Out-LdapObject

(
	(
		|
		(name=sabi)
		(name=dbo)
	)
)

.EXAMPLE

PS C:\> '((|(name=sabi)(name=dbo)))' | Out-LdapObject -Indentation '  '

(
  (
    |
    (name=sabi)
    (name=dbo)
  )
)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.Void],
        [System.String]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateScript( { $_ -cmatch '^\s*$' } )]
        [System.String]
        $Indentation = '    ',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $ShowWhitespace,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $SkipModificationHighlighting,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('tree','default')]
        [System.String]
        $Format = 'tree',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $PassThru,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Quiet
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by Format-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapToken

        # If user input -SkipModificationHighlighting switch parameter is not defined then add -TrackModification to relevant function invocations in current function.
        # This ensures highlighting is enabled by default in current function.
        $optionalSwitchParameters = @{ }
        if (-not $PSBoundParameters['SkipModificationHighlighting'])
        {
            $optionalSwitchParameters.Add('TrackModification', $true)
        }

        # Define output foreground colors for all LdapToken Type property values and background colors for tracked modification highlighting.
        $colorObj = [PSCustomObject] @{
            Foreground = [PSCustomObject] @{
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
            Background = [PSCustomObject] @{
                TrackModification     = [System.ConsoleColor]::DarkGray
                ShowWhitespace        = [System.ConsoleColor]::DarkYellow
            }
        }

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Format input $inputObjectArr ArrayList according to user input -Target and optional -TrackModification values.
        # In current function -TrackModification is defined as the absence of user input -SkipModificationHighlighting switch parameter so highlighting is enabled by default.
        # For performance purposes, skip re-formatting if input $inputObjectArr ArrayList is already in correct format since current function does not modify user input -InputObject.
        $isCorrectFormat = (($inputObjectArr.ForEach( { $_.GetType().Name } )) | Sort-Object -Unique) -iin @('LdapToken','LdapTokenEnriched')
        if (-not $isCorrectFormat)
        {
            $inputObjectArr = Format-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget @optionalSwitchParameters
        }

        # Expand any TokenList property values for simpler traversal before outputting.
        # This includes the following two scenarios:
        #   1) RDN scenario where a Value LdapToken contains parsed RDN LdapTokens in TokenList property.
        #   2) Adjacent Whitespace scenario where a merged (from re-parsing) Whitespace LdapToken contains original adjacent Whitespace LdapTokens in TokenList property.
        # Adjacent Whitespace scenario can occur in an ordinary Whitespace LdapToken or nested in an RDN Whitespace LdapToken residing in a Value LdapToken's TokenList property.
        $inputObjectArr = @(foreach ($curToken in $inputObjectArr)
        {
            # Expand TokenList property if present in Value or Whitespace LdapToken.
            if ($curToken.TokenList -and $curToken.Type -iin @([Maldaptive.LdapTokenType]::Value,[Maldaptive.LdapTokenType]::Whitespace))
            {
                # Expand TokenList property, performing double expansion if TokenList contains Whitespace LdapToken with its TokenList property defined.
                $curToken = $curToken.TokenList.Where( { $_ } ).ForEach(
                {
                    # If current TokenList object is a Whitespace LdapToken that also has its TokenList property defined then further expand nested Whitespace LdapTokens.
                    # Otherwise return current TokenList object as-is.
                    ($_.TokenList -and ($_.Type -eq [Maldaptive.LdapTokenType]::Whitespace)) ? $_.TokenList : $_
                } )
            }

            # Return current LdapToken.
            $curToken
        })

        # Track current depth of LdapTokens to properly output newline and indention for tree view.
        $curDepth = -1

        # Iterate over each input LdapToken.
        $stdOutForPassThruArr = for ($i = 0; $i -lt $inputObjectArr.Count; $i++)
        {
            $curToken = $inputObjectArr[$i]

            # Output potential newlines if user input -Format value of 'tree' is defined.
            if ($Format -eq 'tree')
            {
                # If change in depth then output newline with current indentation (unless first LdapToken) and update depth tracker.
                # This should typically only involve BooleanOperator and GroupEnd LdapTokens.
                if ($curToken.Depth -ne $curDepth)
                {
                    # Avoid outputting newline with current indentation if first LdapToken.
                    if ($i -gt 0)
                    {
                        # If unbalanced GroupStart/GroupEnd LdapToken produces negative Depth for current LdapToken, output warning message and override to 0 to avoid error below.
                        if ($curToken.Depth -lt 0)
                        {
                            Write-Warning "LdapToken depth is negative ($($curToken.Depth)) so GroupStart/GroupEnd LdapTokens are not balanced for input SearchFilter."

                            $curToken.Depth = 0
                        }

                        # Define current newline and indentation based on current LdapToken's Depth property.
                        $indentedNewline = "`n$($Indentation * $curToken.Depth)"

                        # Output current newline and indentation to stdhost if user input -Quiet switch parameter is not defined.
                        if (-not $PSBoundParameters['Quiet'].IsPresent)
                        {
                            Write-Host $indentedNewline -NoNewline
                        }

                        # Output current newline and indentation to stdout if user input -PassThru switch parameter is defined.
                        if ($PSBoundParameters['PassThru'].IsPresent)
                        {
                            $indentedNewline
                        }
                    }

                    # Update depth tracker with current LdapToken's Depth.
                    $curDepth = $curToken.Depth
                }
                elseif ($curToken.Type -eq [Maldaptive.LdapTokenType]::GroupStart)
                {
                    # Output newline with current indentation for GroupStart LdapToken even if no change in depth.
                    # This will handle GroupStart LdapTokens associated with a Filter versus a FilterList.
                    # Avoid outputting newline with current indentation if first LdapToken.
                    if ($i -gt 0)
                    {
                        # Define current newline and indentation based on current LdapToken's Depth property.
                        $indentedNewline = "`n$($Indentation * $curToken.Depth)"

                        # Output current newline and indentation to stdhost if user input -Quiet switch parameter is not defined.
                        if (-not $PSBoundParameters['Quiet'].IsPresent)
                        {
                            Write-Host $indentedNewline -NoNewline
                        }

                        # Output current newline and indentation to stdout if user input -PassThru switch parameter is defined.
                        if ($PSBoundParameters['PassThru'].IsPresent)
                        {
                            $indentedNewline
                        }
                    }
                }
            }

            # Output current LdapToken to stdhost if user input -Quiet switch parameter is not defined.
            if (-not $PSBoundParameters['Quiet'].IsPresent)
            {
                # Retrieve foreground color based on current LdapToken's Type property.
                $foregroundColor = $colorObj.Foreground.($curToken.Type)

                # If current LdapToken is an RDN SubType then modify foreground color to dark version of above color (if it is not dark already).
                if (($curToken.SubType -eq [Maldaptive.LdapTokenSubType]::RDN) -and -not $foregroundColor.ToString().StartsWith('Dark') -and [ConsoleColor].GetEnumNames().Contains('Dark' + $foregroundColor))
                {
                    $foregroundColor = [System.ConsoleColor] ('Dark' + $foregroundColor)
                }

                # Create hashtable to house foreground and potential background color for current LdapToken based on LdapToken type and optional user input parameters.
                # This hashtable will be passed to Write-Host cmdlet via splatting.
                # Add foreground color based on current LdapToken's type according to color-coded definition in current function's Begin block.
                $outputColorParameters = @{ }
                $outputColorParameters.Add('ForegroundColor', $foregroundColor)

                # Set boolean to capture if current LdapToken was modified in last obfuscation function unless user input -SkipModificationHighlighting switch parameter is defined.
                $isHighlightModification = ($curToken.Modified -and -not $PSBoundParameters['SkipModificationHighlighting'].IsPresent) ? $true : $false

                # Set boolean to capture if current LdapToken type is Whitespace and if user input -ShowWhitespace switch parameter is defined.
                $isHighlightWhitespace = (($curToken.Type -eq [Maldaptive.LdapTokenType]::Whitespace) -and $PSBoundParameters['ShowWhitespace'].IsPresent) ? $true : $false

                # Potentially add background color based on current LdapToken's potential modification and above booleans based on user input switch parameters.
                if ($isHighlightModification)
                {
                    # Add additional background highlighting for LdapToken(s) modified in last obfuscation function if eligible.
                    $outputColorParameters.Add('BackgroundColor', $colorObj.Background.TrackModification)
                }
                elseif ($isHighlightWhitespace)
                {
                    # If user input -ShowWhitespace switch parameter is defined and current LdapToken is Whitespace then output LdapToken with additional background highlighting.
                    # Preference will be given to modification tracking background color highlighting, if eligible.
                    $outputColorParameters.Add('BackgroundColor', $colorObj.Background.ShowWhitespace)
                }

                # If foreground and background colors are both defined for current LdapToken and are the same color then invert the foreground color to avoid LdapToken from being hidden from view.
                # This should only be the case for modification highlighting (DarkGray background color) of an RDN CommaDelimiter LdapToken (DarkGray foreground color).
                if ($outputColorParameters['BackgroundColor'] -eq $outputColorParameters['ForegroundColor'])
                {
                    $outputColorParameters['ForegroundColor'] = $outputColorParameters['ForegroundColor'].ToString().StartsWith('Dark') ? ([System.ConsoleColor] $outputColorParameters['ForegroundColor'].ToString().Replace('Dark','')) : ([System.ConsoleColor] ('Dark' + $outputColorParameters['ForegroundColor']))
                }

                # Output current LdapToken with designated foreground color and optional background highlighting.
                Write-Host $curToken.Content -NoNewline @outputColorParameters
            }

            # Output current LdapToken to stdout if user input -PassThru switch parameter is defined.
            if ($PSBoundParameters['PassThru'].IsPresent)
            {
                $curToken.Content
            }
        }

        # Output final newline.
        Write-Host ''

        # Return final result to stdout if user input -PassThru switch parameter is defined.
        if ($PSBoundParameters['PassThru'].IsPresent)
        {
            -join$stdOutForPassThruArr
        }
    }
}