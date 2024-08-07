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



function Remove-RandomParenthesis
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-RandomParenthesis
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, Remove-LdapToken
Optional Dependencies: None

.DESCRIPTION

Remove-RandomParenthesis removes encapsulating parentheses from branches in input LDAP SearchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) from which encapsulating parentheses will be removed.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to deobfuscate.

.PARAMETER Scope

(Optional) Specifies eligible scopes (Filter and/or FilterList) for removing encapsulating parentheses to diversify deobfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '((name=sabi))' | Remove-RandomParenthesis

(name=sabi)

.EXAMPLE

PS C:\> '((((|((((((((((((name=sabi))))))))))))(((name=dbo)))))))' | Remove-RandomParenthesis | Remove-RandomParenthesis | Remove-RandomParenthesis | Remove-RandomParenthesis

(|(name=sabi)(name=dbo))

.EXAMPLE

PS C:\> '(|(((name=sabi)))((((name=dbo)((((((name=krbtgt))))))))))' | Remove-RandomParenthesis -RandomNodePercent 100 -Target LdapToken -Scope Filter -TrackModification | Out-LdapObject

(
	|
	(name=sabi)
	(
		(
			(
				(name=dbo)
				(name=krbtgt)
			)
		)
	)
)

.EXAMPLE

PS C:\> '(|(((name=sabi)))((((name=dbo)((((((name=krbtgt))))))))))' | Remove-RandomParenthesis -RandomNodePercent 100 -Target LdapToken -Scope FilterList -TrackModification | Out-LdapObject

(
	|
	(
		(name=sabi)
	)
	(name=dbo)
	(
		(name=krbtgt)
	)
)

.EXAMPLE

PS C:\> '(|(((name=sabi)))((((name=dbo)((((((name=krbtgt))))))))))' | Remove-RandomParenthesis -RandomNodePercent 100 -Target LdapToken -TrackModification | Out-LdapObject

(
	|
	(name=sabi)
	(name=dbo)
	(name=krbtgt)
)

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

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranchType[]]
        $Scope = @([Maldaptive.LdapBranchType]::Filter,[Maldaptive.LdapBranchType]::FilterList),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Set boolean to capture if current function invocation is recursive (i.e. current function is called by itself).
        $isRecursive = ($MyInvocation.MyCommand.Name -eq (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly).MyCommand.Name) ? $true : $false

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create defined input parameter hashtable, not differentiating between bound parameters and default parameter values.
        # Default input parameters for all PowerShell functions (i.e. not defined in function's param block) are excluded via default Position property value of -2147483648.
        # This hashtable will be used for splatting later in function for any potential trampoline helper function invocations.
        $allDefinedParameters = @{ }
        (Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ParameterSets.Parameters.Where(
        {
            (($_.Position -ne -2147483648) -or ($_.ParameterType.Name -eq 'SwitchParameter')) -and (Test-Path -Path "variable:local:$($_.Name)")
        } ).ForEach( { $allDefinedParameters.Add($_.Name, (Get-Variable -Name $_.Name -Scope local -ValueOnly)) } )

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
        # If non-recursive function invocation then ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        if (-not $isRecursive)
        {
            $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget
        }

        # Define core deobfuscation logic in local trampoline helper function to avoid recursion-specific Call Depth Overflow exception.
        # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
        function local:Remove-RandomParenthesisHelper
        {
            [OutputType([Maldaptive.LdapBranch])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Return current object if -RandomNodePercent eligibility not met.
            if (-not $isRandomNodePercent)
            {
                $LdapBranch

                continue
            }

            # Create boolean so additional logic can be applied if input -LdapBranch is base LdapBranch for LDAP SearchFilter.
            $isBaseBranch = (($LdapBranch.Depth -eq 0) -and ($LdapBranch.Index -eq 0)) ? $true : $false

            # Inspect input FilterList LdapBranch and extract any nested LdapBranch object(s).
            $nestedLdapBranchArr = $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )

            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if ($LdapBranch.Type -ne [Maldaptive.LdapBranchType]::FilterList)
            {
                # Override deobfuscation eligibility if input LdapBranch is not a FilterList LdapBranch.
                $isEligible = $false
            }
            elseif ($LdapBranch.BooleanOperator)
            {
                # Override deobfuscation eligibility if input LdapBranch directly contains a BooleanOperator LdapToken.
                $isEligible = $false
            }
            elseif ($isBaseBranch)
            {
                # Override deobfuscation eligibility if input LdapBranch is base branch
                $isEligible = $false
            }
            elseif (
                ($Scope -inotcontains 'Filter') -and
                ($nestedLdapBranchArr.Count -eq 1) -and ($nestedLdapBranchArr[0].Type -eq [Maldaptive.LdapBranchType]::Filter)
            )
            {
                # Override deobfuscation eligibility if Filter not defined in user input -Scope parameter.
                $isEligible = $false
            }
            elseif (
                ($Scope -inotcontains 'FilterList') -and
                (
                    ($nestedLdapBranchArr.Count -gt 1) -or
                    (($nestedLdapBranchArr.Count -eq 1) -and ($nestedLdapBranchArr[0].Type -eq [Maldaptive.LdapBranchType]::FilterList))
                )
            )
            {
                # Override deobfuscation eligibility if FilterList not defined in user input -Scope parameter.
                $isEligible = $false
            }

            # Do not execute -RandomNodePercent eligibility check since already executed at beginning of trampoline helper function for performance purposes.

            # Proceed if eligible for deobfuscation.
            if ($isEligible)
            {
                # Extract existing GroupStart and GroupEnd LdapTokens from input LdapBranch.
                $curGroupStartLdapToken = $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::GroupStart) } )[0]
                $curGroupEndLdapToken   = $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::GroupEnd  ) } )[-1]

                # Remove existing GroupStart and GroupEnd LdapTokens from input LdapBranch.
                Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $curGroupStartLdapToken
                Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $curGroupEndLdapToken
            }

            # Return input LdapBranch since end of trampoline helper function.
            $LdapBranch
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result in non-recursive function invocation.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Step into current object for further processing if it is an LdapBranch of type FilterList.
            if (($curInputObject -is [Maldaptive.LdapBranch]) -and ($curInputObject.Type -eq [Maldaptive.LdapBranchType]::FilterList))
            {
                # Update current FilterList LdapBranch with the recursive invocation of its contents to properly traverse nested branches in descending order.
                # Modify -InputObject parameter in defined input parameter hashtable to reflect current nested branch contents.
                $allDefinedParameters['InputObject'] = $curInputObject.Branch
                $curInputObject.Branch = & $MyInvocation.MyCommand.Name @allDefinedParameters

                # Invoke local trampoline helper function for current FilterList LdapBranch to perform actual deobfuscation logic while avoiding recursion-specific Call Depth Overflow exception.
                # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
                $curInputObject = & ($MyInvocation.MyCommand.Name + 'Helper') -LdapBranch $curInputObject
            }

            # Return current object.
            $curInputObject
        }

        # Format result for current function invocation. If recursive function invocation then return current modified input object array as-is.
        # Otherwise ensure array is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = $isRecursive ? $modifiedInputObjectArr : (Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters)

        # Return final result.
        $finalResult
    }
}


function Remove-RandomBooleanOperator
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-RandomBooleanOperator
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, Invoke-LdapBranchVisitor, Get-LdapCompatibleBooleanOperator, Remove-LdapToken
Optional Dependencies: None

.DESCRIPTION

Remove-RandomBooleanOperator removes random BooleanOperators inside and outside Filter and FilterList branches in input LDAP SearchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) from which random BooleanOperators will be removed.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to deobfuscate.

.PARAMETER Type

(Optional) Specifies eligible BooleanOperator(s) to diversify deobfuscation styles.

.PARAMETER Scope

(Optional) Specifies eligible scopes (Filter and/or FilterList) for removing BooleanOperator(s) to diversify deobfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '(|(|name=sabi)(&name=dbo))' | Remove-RandomBooleanOperator

(|(name=sabi)(name=dbo))

.EXAMPLE

PS C:\> '(|(name=sabi)((!(!name=dbo))))' | Remove-RandomBooleanOperator -RandomNodePercent 75 -Type '!!'

(|(name=sabi)(((name=dbo))))

.EXAMPLE

PS C:\> '(|(&(|(!(!name=sabi)((&name=dbo))))))' | Remove-RandomBooleanOperator -RandomNodePercent 75 -Type '&','!!','&|' -Scope Filter,FilterList -Target LdapToken -TrackModification | Out-LdapObject

(
	|
	(
		(
			(
				(name=sabi)
				(
					(name=dbo)
				)
			)
		)
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

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('&','|','!!','&|','|&')]
        [System.String[]]
        $Type = @('&','|','!!','&|','|&'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranchType[]]
        $Scope = @([Maldaptive.LdapBranchType]::Filter,[Maldaptive.LdapBranchType]::FilterList),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Set boolean to capture if current function invocation is recursive (i.e. current function is called by itself).
        $isRecursive = ($MyInvocation.MyCommand.Name -eq (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly).MyCommand.Name) ? $true : $false

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create defined input parameter hashtable, not differentiating between bound parameters and default parameter values.
        # Default input parameters for all PowerShell functions (i.e. not defined in function's param block) are excluded via default Position property value of -2147483648.
        # This hashtable will be used for splatting later in function for any potential trampoline helper function invocations.
        $allDefinedParameters = @{ }
        (Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ParameterSets.Parameters.Where(
        {
            (($_.Position -ne -2147483648) -or ($_.ParameterType.Name -eq 'SwitchParameter')) -and (Test-Path -Path "variable:local:$($_.Name)")
        } ).ForEach( { $allDefinedParameters.Add($_.Name, (Get-Variable -Name $_.Name -Scope local -ValueOnly)) } )

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
        # If non-recursive function invocation then ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        if (-not $isRecursive)
        {
            $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget
        }

        # Define core deobfuscation logic in local trampoline helper function to avoid recursion-specific Call Depth Overflow exception.
        # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
        function local:Remove-RandomBooleanOperatorHelper
        {
            [OutputType([Maldaptive.LdapBranch])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Inspect input FilterList LdapBranch and extract potential BooleanOperator LdapToken and any nested LdapBranch object(s).
            $ldapBranchBooleanOperatorLdapToken = $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
            $nestedLdapBranchArr                = $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )

            # Iterate over each nested LdapBranch in input LdapBranch.
            # Create boolean so additional logic can be applied to first nested LdapBranch.
            $isFirstNestedBranch = $true
            foreach ($curBranch in $nestedLdapBranchArr)
            {
                # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
                $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

                # Continue to evaluate next object if -RandomNodePercent eligibility not met.
                if (-not $isRandomNodePercent)
                {
                    # Update boolean so potential additional LdapBranch enumerations do not have first-branch logic applied.
                    $isFirstNestedBranch = $false

                    continue
                }

                # If first nested LdapBranch in user input -LdapBranch does not have a directly defined BooleanOperator LdapToken then recursively visit and return closest eligible LdapBranch.
                if (-not $curBranch.BooleanOperator)
                {
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
                        # for BooleanOperator removal based on user input -Scope and -Type parameters, respectively.
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

                    # Recursively visit current LdapBranch and return first nested Filter LdapBranch or FilterList LdapBranch with BooleanOperator directly defined.
                    $curBranch = ([Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $curBranch -ScriptBlock $scriptBlockEligibleBooleanOperatorLdapBranch -Action ReturnFirst))[0]

                    # If no eligible LdapBranch retrieved in recursive visitor above, continue to next foreach loop iteration to process next LdapBranch.
                    if (-not $curBranch)
                    {
                        # Update boolean so potential additional LdapBranch enumerations do not have first-branch logic applied.
                        $isFirstNestedBranch = $false

                        continue
                    }
                }

                # Extract BooleanOperator LdapToken (if defined) for current LdapBranch based on if LdapBranchType is Filter or FilterList.
                $curBranchBooleanOperatorLdapToken = switch ($curBranch.Type)
                {
                    ([Maldaptive.LdapBranchType]::Filter) {
                        $curBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::BooleanOperator]
                    }
                    ([Maldaptive.LdapBranchType]::FilterList) {
                        $curBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
                    }
                }

                # Create bigram string as concatenation of BooleanOperator values from input -LdapBranch and current branch if both are defined.
                $doubleBooleanOperatorStr = ($ldapBranchBooleanOperatorLdapToken -and $curBranchBooleanOperatorLdapToken) ? (-join@($ldapBranchBooleanOperatorLdapToken.Content,$curBranchBooleanOperatorLdapToken.Content)) : $null

                # Copy initial list of eligible FilterList-scope BooleanOperator value(s) defined in user input -Type parameter to test for compatibility in
                # input LdapBranch based on nested LdapBranch count, potential inherited BooleanOperator logic and/or double-BooleanOperator scenario(s).
                $booleanOperatorToValidateArr = $Type

                # Filter BooleanOperator values to those matching BooleanOperator value(s) directly defined in current nested LdapBranch or in
                # input LdapBranch and current nested LdapBranch combined (if both LdapBranches have BooleanOperator LdapTokens directly defined).
                $booleanOperatorToValidateArr = $booleanOperatorToValidateArr.Where( { $_ -cin @($curBranchBooleanOperatorLdapToken.Content,$doubleBooleanOperatorStr) } )

                # If no BooleanOperator values remain after above filtering, continue to next foreach loop iteration to process next LdapBranch.
                if (-not $booleanOperatorToValidateArr)
                {
                    # Update boolean so potential additional LdapBranch enumerations do not have first-branch logic applied.
                    $isFirstNestedBranch = $false

                    continue
                }

                # Route logic based on if current LdapBranch is of type Filter or FilterList.
                switch ($curBranch.Type)
                {
                    ([Maldaptive.LdapBranchType]::Filter) {
                        # Handle potential Filter-scope BooleanOperator deobfuscation applied to current Filter LdapBranch.

                        # Set boolean for generic deobfuscation eligibility.
                        $isEligible = $true

                        # Override above deobfuscation eligibility for specific scenarios.
                        if ($Scope -inotcontains 'Filter')
                        {
                            # Override deobfuscation eligibility if Filter not defined in user input -Scope parameter.
                            $isEligible = $false
                        }
                        elseif (-not $curBranchBooleanOperatorLdapToken)
                        {
                            # Override deobfuscation eligibility if current Filter does not have Filter-scope BooleanOperator defined.
                            $isEligible = $false
                        }

                        # Do not execute -RandomNodePercent eligibility check since already executed at beginning of foreach loop for performance purposes.

                        # Proceed if eligible for deobfuscation.
                        if ($isEligible)
                        {
                            # Exclude non-negation double-BooleanOperator value(s) since they only exist in current function for FilterList scenario to enable addition
                            # of leading BooleanOperator value that is opposite of the input LdapBranch's logical BooleanOperator.
                            $booleanOperatorToValidateArr = $booleanOperatorToValidateArr.Where( { $_ -cnotin @('&|','|&') } )

                            # Exclude negation double-BooleanOperator scenario if current LdapBranch is not the first nested LdapBranch in input LdapBranch.
                            if (-not $isFirstNestedBranch)
                            {
                                $booleanOperatorToValidateArr = $booleanOperatorToValidateArr.Where( { $_ -cne '!!' } )
                            }

                            # Copy remaining BooleanOperator value(s) since no additional validation required for Filter scenario.
                            $eligibleBooleanOperatorArr = $booleanOperatorToValidateArr

                            # If no BooleanOperator values are compatible based on previous checks, continue to next foreach loop iteration to process next LdapBranch.
                            if (-not $eligibleBooleanOperatorArr)
                            {
                                # Update boolean so potential additional LdapBranch enumerations do not have first-branch logic applied.
                                $isFirstNestedBranch = $false

                                continue
                            }

                            # Randomly select final eligible BooleanOperator value(s) for removal.
                            $randomEligibleBooleanOperator = Get-Random -InputObject $eligibleBooleanOperatorArr

                            # Remove existing BooleanOperator LdapToken from current Filter LdapBranch.
                            Remove-LdapToken -LdapBranch $curBranch -LdapToken $curBranchBooleanOperatorLdapToken

                            # If randomly selected BooleanOperator value is a two-character value then also remove existing BooleanOperator LdapToken from input FilterList LdapBranch.
                            if ($randomEligibleBooleanOperator.Length -eq 2)
                            {
                                # Remove existing BooleanOperator LdapToken from input FilterList LdapBranch.
                                Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $ldapBranchBooleanOperatorLdapToken
                            }
                        }
                    }
                    ([Maldaptive.LdapBranchType]::FilterList) {
                        # Handle potential FilterList-scope BooleanOperator deobfuscation applied to current FilterList LdapBranch.

                        # Set boolean for generic deobfuscation eligibility.
                        $isEligible = $true

                        # Override above deobfuscation eligibility for specific scenarios.
                        if ($Scope -inotcontains 'FilterList')
                        {
                            # Override deobfuscation eligibility if FilterList not defined in user input -Scope parameter.
                            $isEligible = $false
                        }
                        elseif (-not $curBranchBooleanOperatorLdapToken)
                        {
                            # Override deobfuscation eligibility if current LdapBranch's Branch property does not have a FilterList-scope
                            # BooleanOperator defined since current function performs BooleanOperator evaluation in a two-step, two-depth
                            # process to facilitate evaluation of double-BooleanOperator eligibility.
                            $isEligible = $false
                        }

                        # Do not execute -RandomNodePercent eligibility check since already executed at beginning of foreach loop for performance purposes.

                        # Proceed if eligible for deobfuscation.
                        if ($isEligible)
                        {
                            # Exclude double-BooleanOperator scenario(s) if current LdapBranch is not the first nested LdapBranch in input LdapBranch.
                            if (-not $isFirstNestedBranch)
                            {
                                $booleanOperatorToValidateArr = $booleanOperatorToValidateArr.Where( { $_ -cnotin @('!!','&|','|&') } )
                            }

                            # Perform compatibility checks for all BooleanOperator values defined above, returning only the value(s) not changing the logical BooleanOperator
                            # value for any descendant impacted LdapBranch to a value incompatible with original logical BooleanOperator.
                            # Divide BooleanOperator(s) by single and double values and perform separate compatibility checks for each BooleanOperator value grouping.
                            $eligibleBooleanOperatorArr = switch ($booleanOperatorToValidateArr.Length | Sort-Object -Unique)
                            {
                                1 {
                                    # Extract array of GUID value(s) from input -LdapBranch's BooleanOperator context chain and remove any potential intermediate BooleanOperator LdapToken(s)
                                    # that may have been removed in previous recursive function invocations from current nested LdapBranch's BooleanOperator context chain.
                                    # This scenario exists when recursive lookup of next eligible nested LdapBranch traverses past an LdapBranch that had its BooleanOperator removed in a
                                    # previous recursive invocation since BooleanOperator Context objects are not recursively updated for all nested LdapBranches for performance purposes
                                    # and since Get-LdapCompatibleBooleanOperator function will rebuild prefix BooleanOperator value(s) from current LdapBranch's BooleanOperator context chain.
                                    $ldapBranchBooleanOperatorContextChainGuidToInclude = [System.Array] $LdapBranch.Branch[0].Context.BooleanOperator.FilterListBooleanOperatorTokenList.Guid + $ldapBranchBooleanOperatorLdapToken.Guid
                                    $curBranch.Context.BooleanOperator.FilterListBooleanOperatorTokenList = [Maldaptive.LdapTokenEnriched[]] $curBranch.Context.BooleanOperator.FilterListBooleanOperatorTokenList.Where( { $_.Guid -iin $ldapBranchBooleanOperatorContextChainGuidToInclude } )

                                    # Perform compatibility checks for single-BooleanOperator value(s).
                                    Get-LdapCompatibleBooleanOperator -LdapBranch $curBranch -Type current_branch_only -Action remove -BooleanOperator $booleanOperatorToValidateArr.Where( { $_.Length -eq 1 } )
                                }
                                2 {
                                    # Perform compatibility checks for double-BooleanOperator value(s).
                                    Get-LdapCompatibleBooleanOperator -LdapBranch $LdapBranch -Type current_branch_and_first_recursive_branch_with_boolean_operator -Action remove -BooleanOperator $booleanOperatorToValidateArr.Where( { $_.Length -eq 2 } )
                                }
                                default {
                                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                                }
                            }

                            # Give preference to eligible single-BooleanOperator value(s) by removing non-negation double-BooleanOperator values if any single-BooleanOperator
                            # value is present since non-negation double-BooleanOperator values only exist in current function to enable removal of leading BooleanOperator
                            # value that is opposite of the input LdapBranch's logical BooleanOperator.
                            if ($eligibleBooleanOperatorArr.Where( { $_.Length -eq 1 } ))
                            {
                                $eligibleBooleanOperatorArr = $eligibleBooleanOperatorArr.Where( { $_ -cnotin @('&|','|&') } )
                            }

                            # If no BooleanOperator values are compatible based on previous checks, continue to next foreach loop iteration to process next LdapBranch.
                            if (-not $eligibleBooleanOperatorArr)
                            {
                                # Update boolean so potential additional LdapBranch enumerations do not have first-branch logic applied.
                                $isFirstNestedBranch = $false

                                continue
                            }

                            # Randomly select final eligible BooleanOperator value(s) for removal.
                            $randomEligibleBooleanOperator = Get-Random -InputObject $eligibleBooleanOperatorArr

                            # Remove existing BooleanOperator LdapToken from current FilterList LdapBranch.
                            Remove-LdapToken -LdapBranch $curBranch -LdapToken $curBranchBooleanOperatorLdapToken

                            # If randomly selected BooleanOperator value is a two-character value then also remove existing BooleanOperator LdapToken from input FilterList LdapBranch.
                            if ($randomEligibleBooleanOperator.Length -eq 2)
                            {
                                # Remove existing BooleanOperator LdapToken from input FilterList LdapBranch.
                                Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $ldapBranchBooleanOperatorLdapToken
                            }
                        }
                    }
                    default {
                        Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                    }
                }

                # Update boolean so potential additional LdapBranch enumerations do not have first-branch logic applied.
                $isFirstNestedBranch = $false
            }

            # Return input LdapBranch since end of trampoline helper function.
            $LdapBranch
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result in non-recursive function invocation.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Step into current object for further processing if it is an LdapBranch of type FilterList.
            if (($curInputObject -is [Maldaptive.LdapBranch]) -and ($curInputObject.Type -eq [Maldaptive.LdapBranchType]::FilterList))
            {
                # Update current FilterList LdapBranch with the recursive invocation of its contents to properly traverse nested branches in descending order.
                # Modify -InputObject parameter in defined input parameter hashtable to reflect current nested branch contents.
                $allDefinedParameters['InputObject'] = $curInputObject.Branch
                $curInputObject.Branch = & $MyInvocation.MyCommand.Name @allDefinedParameters

                # Invoke local trampoline helper function for current FilterList LdapBranch to perform actual deobfuscation logic while avoiding recursion-specific Call Depth Overflow exception.
                # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
                $curInputObject = & ($MyInvocation.MyCommand.Name + 'Helper') -LdapBranch $curInputObject
            }

            # Return current object.
            $curInputObject
        }

        # Format result for current function invocation. If recursive function invocation then return current modified input object array as-is.
        # Otherwise ensure array is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = $isRecursive ? $modifiedInputObjectArr : (Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters)

        # Return final result.
        $finalResult
    }
}


function Remove-RandomBooleanOperatorInversion
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-RandomBooleanOperatorInversion
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, Invoke-LdapBranchVisitor, New-LdapToken, Add-LdapToken, Remove-LdapToken, Edit-LdapToken
Optional Dependencies: None

.DESCRIPTION

Remove-RandomBooleanOperatorInversion removes negation BooleanOperators ('!') inside eligible FilterList branches and inverts all impacted BooleanOperators to maintain equivalent BooleanOperator logic in input LDAP SearchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) from which random negation BooleanOperators ('!') will be removed and inversion logic applied.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to deobfuscate.

.PARAMETER Type

(Optional) Specifies eligible BooleanOperator(s) to invert to diversify deobfuscation styles.

.PARAMETER Scope

(Optional) Specifies eligible scopes (Filter and/or FilterList) to target for BooleanOperator inversion to diversify deobfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '(!(&(!name=sabi)(!name=dbo)))' | Remove-RandomBooleanOperatorInversion

((|(name=sabi)(name=dbo)))

.EXAMPLE

PS C:\> '(&((!(!name=sabi)((!name=dbo)))))' | Remove-RandomBooleanOperatorInversion -RandomNodePercent 100 -Type '!' -Scope Filter,FilterList -Target LdapToken -TrackModification | Out-LdapObject

(
	&
	(
		(
			(name=sabi)
			(
				(!name=dbo)
			)
		)
	)
)

.EXAMPLE

PS C:\> '(!(|(!objectCategory=Person)(!(|(name=sabi)((name=dbo))))))' | Remove-RandomBooleanOperatorInversion -RandomNodePercent 100 -Type '|','&' -Scope FilterList -Target LdapToken -TrackModification | Out-LdapObject

(
	(
		&
		(objectCategory=Person)
		(
			(
				|
				(name=sabi)
				(
					(name=dbo)
				)
			)
		)
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

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('&','|','!')]
        [System.Char[]]
        $Type = @('&','|','!'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranchType[]]
        $Scope = @([Maldaptive.LdapBranchType]::Filter,[Maldaptive.LdapBranchType]::FilterList),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Set boolean to capture if current function invocation is recursive (i.e. current function is called by itself).
        $isRecursive = ($MyInvocation.MyCommand.Name -eq (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly).MyCommand.Name) ? $true : $false

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create defined input parameter hashtable, not differentiating between bound parameters and default parameter values.
        # Default input parameters for all PowerShell functions (i.e. not defined in function's param block) are excluded via default Position property value of -2147483648.
        # This hashtable will be used for splatting later in function for any potential trampoline helper function invocations.
        $allDefinedParameters = @{ }
        (Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ParameterSets.Parameters.Where(
        {
            (($_.Position -ne -2147483648) -or ($_.ParameterType.Name -eq 'SwitchParameter')) -and (Test-Path -Path "variable:local:$($_.Name)")
        } ).ForEach( { $allDefinedParameters.Add($_.Name, (Get-Variable -Name $_.Name -Scope local -ValueOnly)) } )

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
        # If non-recursive function invocation then ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        if (-not $isRecursive)
        {
            $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget
        }

        # Define core deobfuscation logic in local trampoline helper function to avoid recursion-specific Call Depth Overflow exception.
        # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
        function local:Remove-RandomBooleanOperatorInversionHelper
        {
            [OutputType([Maldaptive.LdapBranch])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Inspect input FilterList LdapBranch and extract any nested FilterList LdapBranch object(s) with a negation BooleanOperator ('!') directy defined.
            $ldapBranchFilterListLdapBranchArr = $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapBranch]) -and ($_.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($_.BooleanOperator -ceq '!') } )

            # Iterate over each nested FilterList LdapBranch (with negation BooleanOperator directy defined) in input LdapBranch.
            foreach ($curBranch in $ldapBranchFilterListLdapBranchArr)
            {
                # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
                $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

                # Continue to evaluate next object if -RandomNodePercent eligibility not met.
                if (-not $isRandomNodePercent)
                {
                    continue
                }

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

                # Recursively visit current LdapBranch and return the first nested Filter LdapBranch or FilterList LdapBranch with BooleanOperator directly defined.
                # To avoid potentially returning current LdapBranch and to take advantage of performance improvement of -Action ReturnFirst parameter, iterate over
                # each nested LdapBranch until a single eligible LdapBranch result is returned.
                $firstEligibleBooleanOperatorLdapBranch = foreach ($nestedLdapBranch in $curBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))
                {
                    $visitorResultLdapBranch = ([Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $nestedLdapBranch -ScriptBlock $scriptBlockEligibleBooleanOperatorLdapBranch -Action ReturnFirst))[0]

                    # If LdapBranch returned above then return LdapBranch below and break out of foreach loop to skip unnecessary iterations.
                    if ($visitorResultLdapBranch)
                    {
                        $visitorResultLdapBranch

                        break
                    }
                }

                # Extract BooleanOperator LdapToken (if defined) for eligible LdapBranch affected by potential BooleanOperator inversion based on if LdapBranchType is Filter or FilterList.
                $firstEligibleBooleanOperatorLdapToken = switch ($firstEligibleBooleanOperatorLdapBranch.Type)
                {
                    ([Maldaptive.LdapBranchType]::Filter) {
                        $firstEligibleBooleanOperatorLdapBranch.Branch.TokenDict[[Maldaptive.LdapTokenType]::BooleanOperator]
                    }
                    ([Maldaptive.LdapBranchType]::FilterList) {
                        $firstEligibleBooleanOperatorLdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
                    }
                }

                # Set boolean for generic deobfuscation eligibility.
                $isEligible = $true

                # Override above deobfuscation eligibility for specific scenarios.
                if (-not $firstEligibleBooleanOperatorLdapBranch)
                {
                    # Override deobfuscation eligibility if no Filter LdapBranch or FilterList LdapBranch with defined BooleanOperator exists in current LdapBranch at any nested depth.
                    $isEligible = $false
                }
                elseif ($Scope -inotcontains $firstEligibleBooleanOperatorLdapBranch.Type.ToString())
                {
                    # Override deobfuscation eligibility if first adjacent BooleanOperator-eligible object is an LdapBranchType (e.g. Filter or FilterList) not defined in user input -Scope parameter.
                    $isEligible = $false
                }
                elseif ($Type -cnotcontains $firstEligibleBooleanOperatorLdapToken.Content)
                {
                    # Override deobfuscation eligibility if BooleanOperator in first adjacent BooleanOperator-eligible object is not defined in user input -Type parameter.
                    $isEligible = $false
                }

                # Do not execute -RandomNodePercent eligibility check since already executed at beginning of foreach loop for performance purposes.

                # Proceed if eligible for deobfuscation.
                if ($isEligible)
                {
                    # Recursively visit current LdapBranch and return all nested Filter LdapBranches or FilterList LdapBranches with BooleanOperator directly defined.
                    # More effecient to perform -Action ReturnFirst version of this scriptblock invocation earlier in function and then only perform below more
                    # expensive -Action Return logic only if all previous deobfuscation eligibility checks pass.
                    $visitorResultEligibleBooleanOperatorLdapBranchArr = [Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $curBranch -ScriptBlock $scriptBlockEligibleBooleanOperatorLdapBranch -Action Return)

                    # Remove first returned nested LdapBranch if it is the current LdapBranch.
                    if ($visitorResultEligibleBooleanOperatorLdapBranchArr[0] -eq $curBranch)
                    {
                        $visitorResultEligibleBooleanOperatorLdapBranchArr = $visitorResultEligibleBooleanOperatorLdapBranchArr | Select-Object -Skip 1
                    }

                    # Extract LdapBranch from array of all nested LdapBranches on which BooleanOperator inversion logic will be applied.
                    # Limit full inversion logic to the first LdapBranch in array of eligible nested LdapBranches, skipping any potential FilterList LdapBranch(es) with a negation
                    # BooleanOperator ('!') directly defined since final logical inversion will be applied to first non-negation BooleanOperator and any of its potential nested LdapBranches.
                    $ldapBranchToInvert = $visitorResultEligibleBooleanOperatorLdapBranchArr.Where( { -not (($_.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($_.BooleanOperator -ceq '!')) } )[0]

                    # Define ScriptBlock logic for Invoke-LdapBranchVisitor function to recursively visit and modify all eligible nested LdapBranches with BooleanOperator inversion logic.
                    # All Filter and FilterList LdapBranch non-negation BooleanOperators ('&' or '|') will be inverted, and Filter LdapBranch negation BooleanOperators ('!') will be removed
                    # and any Filter LdapBranch without a BooleanOperator defined or with a non-negation BooleanOperator ('&' or '|') defined will have a negation BooleanOperator ('!') added.
                    $scriptBlockBooleanOperatorInversion = {
                        [OutputType([System.Void])]
                        param (
                            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                            [Maldaptive.LdapBranch]
                            $LdapBranch,

                            [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
                            [Switch]
                            $TrackModification
                        )

                        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
                        $optionalSwitchParameters = @{ }
                        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

                        # Proceed if user input -LdapBranch is either a FilterList LdapBranch with a BooleanOperator directly defined (i.e. not inherited) or a Filter LdapBranch.
                        # For Filter LdapBranch even if no BooleanOperator is defined it is still eligible since inverting an '!' removes the BooleanOperator, and inverting a
                        # Filter LdapBranch without a BooleanOperator defined or with a non-negation BooleanOperator ('&' or '|') defined adds a '!' BooleanOperator.
                        if (
                            (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($LdapBranch.BooleanOperator -cin @('&','|'))) -or
                            ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
                        )
                        {
                            # Define inverted BooleanOperator value based on current BooleanOperator value, inverting the absence of a BooleanOperator with '!' and vice versa.
                            $invertedBooleanOperator = switch ($LdapBranch.BooleanOperator)
                            {
                                '&' { '|' }
                                '|' { '&' }
                                '!' { ''  }
                                ''  { '!' }
                                default {
                                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                                }
                            }

                            # Perform inversion logic based on input LdapBranch type.
                            switch ($LdapBranch.Type)
                            {
                                ([Maldaptive.LdapBranchType]::FilterList) {
                                    # Apply logic for editing existing BooleanOperator LdapToken in FilterList LdapBranch.

                                    # Extract existing BooleanOperator LdapToken from input LdapBranch.
                                    $curBooleanOperatorLdapToken = $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                                    # Modify existing BooleanOperator LdapToken in input LdapBranch.
                                    # If optional -TrackModification switch parameter is defined then BooleanOperator's Depth property value will be set to -1 for modification tracking display purposes.
                                    Edit-LdapToken -LdapBranch $LdapBranch -LdapToken $curBooleanOperatorLdapToken -Content $invertedBooleanOperator @optionalSwitchParameters
                                }
                                ([Maldaptive.LdapBranchType]::Filter) {
                                    # Apply separate logic if Filter LdapBranch needs to add, remove or edit BooleanOperator LdapToken.

                                    # If Filter LdapBranch does not contain a BooleanOperator LdapToken then create and add it.
                                    if (-not $LdapBranch.BooleanOperator)
                                    {
                                        # Generate new BooleanOperator LdapToken.
                                        # If optional -TrackModification switch parameter is defined then BooleanOperator's Depth property value will be set to -1 for modification tracking display purposes.
                                        $newBooleanOperatorLdapToken = New-LdapToken -Type BooleanOperator -Content $invertedBooleanOperator @optionalSwitchParameters

                                        # Add new BooleanOperator LdapToken to input LdapBranch.
                                        Add-LdapToken -LdapBranch $LdapBranch -LdapToken $newBooleanOperatorLdapToken -Location after_groupstart,before_attribute
                                    }
                                    elseif (-not $invertedBooleanOperator)
                                    {
                                        # If Filter LdapBranch contains a BooleanOperator and inverted BooleanOperator value is not defined then remove BooleanOperator.

                                        # Extract existing BooleanOperator LdapToken from input LdapBranch.
                                        $curBooleanOperatorLdapToken = $LdapBranch.Branch[0].TokenList.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                                        # Remove existing BooleanOperator LdapToken from input LdapBranch.
                                        Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $curBooleanOperatorLdapToken
                                    }
                                    else
                                    {
                                        # If Filter LdapBranch contains a non-negation BooleanOperator ('&' or '|') then invert the value by
                                        # replacing inoperative BooleanOperator with negation BooleanOperator ('!').
                                        # This is because a Filter-scope (from a syntactical perspective) BooleanOperator is expanded by the
                                        # LDAP server from, for example, '(&name=dbo)' to '(&(name=dbo))', so technically the Filter does not
                                        # have a BooleanOperator defined; therefore, its inverted value is the negation BooleanOperator ('!').
                                        $invertedBooleanOperator = '!'

                                        # Extract existing BooleanOperator LdapToken from input LdapBranch.
                                        $curBooleanOperatorLdapToken = $LdapBranch.Branch[0].TokenList.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                                        # Modify existing BooleanOperator LdapToken in input LdapBranch.
                                        # If optional -TrackModification switch parameter is defined then BooleanOperator's Depth property value will be set to -1 for modification tracking display purposes.
                                        Edit-LdapToken -LdapBranch $LdapBranch -LdapToken $curBooleanOperatorLdapToken -Content $invertedBooleanOperator @optionalSwitchParameters
                                    }
                                }
                                default {
                                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                                }
                            }
                        }
                    }

                    # Recursively visit and modify all impacted nested LdapBranches with BooleanOperator inversion logic.
                    Invoke-LdapBranchVisitor -LdapBranch $ldapBranchToInvert -ScriptBlock $scriptBlockBooleanOperatorInversion -Action Modify -TrackModification

                    # Finally, remove from current LdapBranch the existing negation BooleanOperator ('!') that initiates above inversion logic applied to all impacted nested LdapBranches.

                    # Extract existing BooleanOperator LdapToken from current LdapBranch.
                    $curBooleanOperatorLdapToken = $curBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                    # Remove existing BooleanOperator LdapToken from current LdapBranch.
                    Remove-LdapToken -LdapBranch $curBranch -LdapToken $curBooleanOperatorLdapToken
                }
            }

            # Return input LdapBranch since end of trampoline helper function.
            $LdapBranch
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result in non-recursive function invocation.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Step into current object for further processing if it is an LdapBranch of type FilterList.
            if (($curInputObject -is [Maldaptive.LdapBranch]) -and ($curInputObject.Type -eq [Maldaptive.LdapBranchType]::FilterList))
            {
                # Update current FilterList LdapBranch with the recursive invocation of its contents to properly traverse nested branches in descending order.
                # Modify -InputObject parameter in defined input parameter hashtable to reflect current nested branch contents.
                $allDefinedParameters['InputObject'] = $curInputObject.Branch
                $curInputObject.Branch = & $MyInvocation.MyCommand.Name @allDefinedParameters

                # Invoke local trampoline helper function for current FilterList LdapBranch to perform actual deobfuscation logic while avoiding recursion-specific Call Depth Overflow exception.
                # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
                $curInputObject = & ($MyInvocation.MyCommand.Name + 'Helper') -LdapBranch $curInputObject
            }

            # Return current object.
            $curInputObject
        }

        # Format result for current function invocation. If recursive function invocation then return current modified input object array as-is.
        # Otherwise ensure array is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = $isRecursive ? $modifiedInputObjectArr : (Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters)

        # Return final result.
        $finalResult
    }
}


function Remove-RandomWhitespace
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-RandomWhitespace
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, ConvertTo-LdapParsedValue, Edit-LdapToken, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Remove-RandomWhitespace removes random whitespace from input LDAP SearchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) from which random whitespace will be removed.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to deobfuscate.

.PARAMETER RandomLength

(Optional) Specifies eligible length(s) for each random whitespace substring removal.

.PARAMETER Type

(Optional) Specifies eligible LdapToken type(s) after which whitespace can be removed.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '  (  name=   sabi)  ' | Remove-RandomWhitespace

(name=sabi)

.EXAMPLE

PS C:\> '  ( |   (  name=   sabi)  (   1.2.840.113556.1.4.1  =  dbo)  )  ' | Remove-RandomWhitespace -RandomNodePercent 100 -RandomLength 10 -Type BooleanOperator,GroupStart,GroupEnd,SearchFilter_Prefix

(|(name=   sabi)(1.2.840.113556.1.4.1  =  dbo))  

.EXAMPLE

PS C:\> '  ( |   (  name=   sabi)  (   1.2.840.113556.1.4.1  =  dbo)(   distinguishedName=   CN   =   krbtgt   ,   CN \20 \20 \20 \20 =    Users   ,   DC   =   windomain  \2C  DC  \3D  local)   )  ' | Remove-RandomWhitespace -RandomNodePercent 100 -RandomLength 10 -Target LdapToken -TrackModification | Out-LdapObject

(
	|
	(name=sabi)
	(1.2.840.113556.1.4.1=dbo)
	(distinguishedName=CN=krbtgt,CN=Users,DC=windomain\2CDC\3Dlocal)
)

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

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(1,100)]
        [System.Int16[]]
        $RandomLength = @(1,2,3),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(
            'SearchFilter_Prefix',
            'GroupStart',
            'BooleanOperator',
            'OID_Attribute',
            'ComparisonOperator',
            'RDN_Attribute',
            'RDN_ComparisonOperator',
            'RDN_Value',
            'RDN_CommaDelimiter',
            'GroupEnd',
            'SearchFilter_Suffix'
        )]
        [System.String[]]
        $Type = @(
            'SearchFilter_Prefix',
            'GroupStart',
            'BooleanOperator',
            'OID_Attribute',
            'ComparisonOperator',
            'RDN_Attribute',
            'RDN_ComparisonOperator',
            'RDN_Value',
            'RDN_CommaDelimiter',
            'GroupEnd',
            'SearchFilter_Suffix'
        ),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapFilterMerged

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

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
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Proceed with deobfuscation evaluation for current object based on if it is an LdapFilter or LdapToken.
            switch ($curInputObject)
            {
                { $_ -is [Maldaptive.LdapToken] } {
                    # Skip current LdapToken if not a Whitespace LdapToken.
                    if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::Whitespace)
                    {
                        continue
                    }

                    # Set boolean for generic deobfuscation eligibility.
                    $isEligible = $true

                    # Override above deobfuscation eligibility for specific scenarios.
                    if (
                        (-not $curInputObject.TypeBefore -and 'SearchFilter_Prefix' -inotin $Type) -or `
                        (-not $curInputObject.TypeAfter  -and 'SearchFilter_Suffix' -inotin $Type)
                    )
                    {
                        # Override deobfuscation eligibility if current object is Whitespace LdapToken as LDAP SearchFilter prefix or suffix
                        # and 'SearchFilter_Prefix' or 'SearchFilter_Suffix', respectively, not defined in user input -Type parameter.
                        $isEligible = $false
                    }
                    elseif (
                        $curInputObject.TypeBefore -and `
                        $curInputObject.TypeAfter -and `
                        $curInputObject.TypeBefore -inotin $Type
                    )
                    {
                        # Override deobfuscation eligibility if current object is Whitespace LdapToken following an LdapToken type
                        # not defined in user input -Type parameter.
                        $isEligible = $false
                    }

                    # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
                    $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

                    # Proceed if eligible for deobfuscation.
                    if ($isEligible -and $isRandomNodePercent)
                    {
                        # Parse current Whitespace LdapToken content so length calculations remain accurate even if whitespace
                        # is represented as hex format ('\20').
                        $curInputObjectParsedArr = ConvertTo-LdapParsedValue -InputObject $curInputObject.Content

                        # Calculate desired shortened length of current Whitespace LdapToken based on user input -RandomLength value.
                        $newWhitespaceLength = $curInputObjectParsedArr.Count - (Get-Random -InputObject $RandomLength)
                        $newWhitespaceLength = $newWhitespaceLength -gt 0 ? $newWhitespaceLength : 0

                        # Modify current Whitespace LdapToken with shortened (or completely removed) value, randomly
                        # choosing between retaining value's prefix or suffix.
                        $firstOrLastWhitespaceCharsToRetain = Get-Random -InputObject @(@{ First = $newWhitespaceLength},@{ Last = $newWhitespaceLength})
                        $curInputObject.Content = -join($curInputObjectParsedArr | Select-Object @firstOrLastWhitespaceCharsToRetain).Content
                        $curInputObject.Length = $curInputObject.Content.Length

                        # If user input -TrackModification switch parameter is defined then set Depth property of current Whitespace LdapToken to -1 for display tracking purposes.
                        if ($PSBoundParameters['TrackModification'].IsPresent)
                        {
                            $curInputObject.Depth = -1
                        }
                    }
                }
                { $_ -is [Maldaptive.LdapFilter] } {
                    # Perform deobfuscation eligibility checks and -RandomNodePercent evaluations for each Whitespace LdapToken
                    # following an eligible LdapToken type defined in user input -Type parameter.
                    # User input -Type 'RDN_*' values will be handled separately in later step since it requires additional
                    # dedicated traversal logic.

                    # Iterate over each LdapToken in current LdapFilter.
                    foreach ($curLdapToken in $curInputObject.TokenList)
                    {
                        # Skip current LdapToken if not a Whitespace LdapToken.
                        if ($curLdapToken.Type -ne [Maldaptive.LdapTokenType]::Whitespace)
                        {
                            continue
                        }

                        # Set boolean for generic deobfuscation eligibility.
                        $isEligible = $true

                        # Override above deobfuscation eligibility for specific scenarios.
                        if (
                            $curLdapToken.TypeBefore -eq [Maldaptive.LdapTokenType]::Attribute -and `
                            -not (
                                $curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Attribute].Format -eq [Maldaptive.LdapTokenFormat]::OID -and `
                                'OID_Attribute' -iin $Type
                            )
                        )
                        {
                            # Override deobfuscation eligibility if current object is Whitespace LdapToken following an Attribute LdapToken
                            # but LdapToken format is not OID and/or 'OID_Attribute' not defined in user input -Type parameter.
                            $isEligible = $false
                        }
                        elseif (
                            $curLdapToken.TypeBefore -inotin $Type -and `
                            $curLdapToken.TypeBefore -ne [Maldaptive.LdapTokenType]::Attribute
                        )
                        {
                            # Override deobfuscation eligibility if current object is Whitespace LdapToken following an LdapToken type not
                            # defined in user input -Type parameter (excluding 'OID_Attribute' scenario handled in previous if block).
                            $isEligible = $false
                        }

                        # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
                        $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

                        # Proceed if eligible for deobfuscation.
                        if ($isEligible -and $isRandomNodePercent)
                        {
                            # Parse current Whitespace LdapToken content so length calculations remain accurate even if whitespace
                            # is represented as hex format ('\20').
                            $curLdapTokenContentParsedArr = ConvertTo-LdapParsedValue -InputObject $curLdapToken.Content

                            # Calculate desired shortened length of current Whitespace LdapToken based on user input -RandomLength value.
                            $newWhitespaceLength = $curLdapTokenContentParsedArr.Count - (Get-Random -InputObject $RandomLength)
                            $newWhitespaceLength = $newWhitespaceLength -gt 0 ? $newWhitespaceLength : 0

                            # Modify current Whitespace LdapToken with shortened (or completely removed) value, randomly
                            # choosing between retaining value's prefix or suffix.
                            $firstOrLastWhitespaceCharsToRetain = Get-Random -InputObject @(@{ First = $newWhitespaceLength},@{ Last = $newWhitespaceLength})
                            $curLdapToken.Content = -join($curLdapTokenContentParsedArr | Select-Object @firstOrLastWhitespaceCharsToRetain).Content
                            $curLdapToken.Length = $curLdapToken.Content.Length

                            # If user input -TrackModification switch parameter is defined then set Depth property of current Whitespace LdapToken to -1 for display tracking purposes.
                            if ($PSBoundParameters['TrackModification'].IsPresent)
                            {
                                $curLdapToken.Depth = -1
                            }
                        }
                    }

                    # Proceed with deobfuscation evaluation for each RDN (Relative Distinguished Name) LdapToken in Value LdapToken type's DN (Distinguished Name) value
                    # if it is defined in Filter and in user input -Type parameter (e.g. -Type 'RDN_*' values).
                    if ($curInputObject.Value -and $curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].TokenList -and ($Type -imatch '^RDN_'))
                    {
                        # Set boolean for generic deobfuscation eligibility.
                        $isEligible = $true

                        # Override above deobfuscation eligibility for specific scenarios.
                        if ($curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].ContentDecoded.Replace('*','') -imatch '^\[?LDAPS?:\s*([/\\]\s*){2}')
                        {
                            # Override deobfuscation eligibility if current Filter's Attribute Value format is a binding string syntax DN (Distinguished Name).
                            # Source: https://docs.microsoft.com/en-us/windows/win32/adsi/ldap-adspath
                            # E.g. (gplink=[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=windomain,DC=local;0])
                            $isEligible = $false
                        }

                        # Proceed if eligible for deobfuscation.
                        if ($isEligible)
                        {
                            # Proceed with deobfuscation evaluation for each RDN (Relative Distinguished Name) LdapToken in Value LdapToken type's DN (Distinguished Name) value.
                            $ldapTokenValueModified = @(for ($i = 0; $i -lt $curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].TokenList.Count; $i++)
                            {
                                $curRdnLdapToken  = $curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].TokenList[$i]
                                $lastRdnLdapToken = $curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].TokenList[$i - 1]

                                # Return and skip current RDN LdapToken if not a Whitespace LdapToken.
                                if ($curRdnLdapToken.Type -ne [Maldaptive.LdapTokenType]::Whitespace)
                                {
                                    # Return current RDN LdapToken.
                                    $curRdnLdapToken

                                    continue
                                }

                                # Set boolean for generic deobfuscation eligibility.
                                $isEligible = $true

                                # Override above deobfuscation eligibility for specific scenarios.
                                if ($Type -inotcontains ('RDN_' + $lastRdnLdapToken.Type))
                                {
                                    # Override deobfuscation eligibility if current object is Whitespace RDN LdapToken following an RDN LdapToken type
                                    # not defined in user input -Type parameter.
                                    $isEligible = $false
                                }

                                # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
                                $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

                                # Proceed if eligible for deobfuscation.
                                if ($isEligible -and $isRandomNodePercent)
                                {
                                    # Parse current Whitespace RDN LdapToken content so length calculations remain accurate even if whitespace
                                    # is represented as hex format ('\20').
                                    $curRdnLdapTokenContentParsedArr = ConvertTo-LdapParsedValue -InputObject $curRdnLdapToken.Content

                                    # Calculate desired shortened length of current Whitespace RDN LdapToken based on user input -RandomLength value.
                                    $newWhitespaceLength = $curRdnLdapTokenContentParsedArr.Count - (Get-Random -InputObject $RandomLength)
                                    $newWhitespaceLength = $newWhitespaceLength -gt 0 ? $newWhitespaceLength : 0

                                    # Modify current Whitespace RDN LdapToken with shortened (or completely removed) value, randomly
                                    # choosing between retaining value's prefix or suffix.
                                    $firstOrLastWhitespaceCharsToRetain = Get-Random -InputObject @(@{ First = $newWhitespaceLength},@{ Last = $newWhitespaceLength})
                                    $curRdnLdapToken.Content = -join($curRdnLdapTokenContentParsedArr | Select-Object @firstOrLastWhitespaceCharsToRetain).Content
                                    $curRdnLdapToken.Length = $curRdnLdapToken.Content.Length

                                    # If user input -TrackModification switch parameter is defined then set Depth property of current Whitespace RDN LdapToken to -1 for display tracking purposes.
                                    if ($PSBoundParameters['TrackModification'].IsPresent)
                                    {
                                        $curRdnLdapToken.Depth = -1
                                    }
                                }

                                # Return current RDN LdapToken.
                                $curRdnLdapToken
                            })

                            # If modification successfully applied to any Whitespace RDN LdapToken above then update current Filter.
                            if ($curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].Content -cne -join$ldapTokenValueModified.Content)
                            {
                                # Update Value LdapToken's Content properties with modified TokenList content.
                                # If optional -TrackModification switch parameter is defined then current LdapToken's Depth property value will be set to -1 for modification tracking display purposes.
                                # This will mark entire Value LdapToken as modified while still preserving per-RDN LdapToken modification tracking for LdapTokens in Value LdapToken's TokenList property.
                                Edit-LdapToken -LdapBranch $curInputObject -LdapToken $curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value] -Content (-join$curInputObject.TokenDict[[Maldaptive.LdapTokenType]::Value].TokenList.Content) @optionalSwitchParameters
                            }
                        }
                    }
                }
                default {
                    Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Remove-RandomWildcard
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-RandomWildcard
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Remove-RandomWildcard removes random wildcards ('*') from input LDAP SearchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) from which random wildcards ('*') will be removed.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to deobfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to deobfuscate.

.PARAMETER Type

(Optional) Specifies eligible wildcard ('*') location(s) in Attribute Values for deobfuscation.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '(name=***sa**bi)' | Remove-RandomWildcard

(name=*sa*bi)

.EXAMPLE

PS C:\> '(name=**Dom***ain Con**tro*llers***)' | Remove-RandomWildcard -Type prefix,suffix

(name=*Dom***ain Con**tro*llers*)

.EXAMPLE

PS C:\> '(&(objectCategory=Person)(|(name=**sab*****i***)(name=d******bo)))' | Remove-RandomWildcard -RandomNodePercent 75 -RandomCharPercent 50 -Type prefix,middle -Target LdapToken -TrackModification | Out-LdapObject

(
	&
	(objectCategory=Person)
	(
		|
		(name=*sab**i***)
		(name=d**bo)
	)
)

.EXAMPLE

PS C:\> '(&(objectCategory=Person)(|(name=**sab*****i***)(name=d******bo)))' | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100

(&(objectCategory=Person)(|(name=*sab*i*)(name=d*bo)))

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

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('prefix','middle','suffix')]
        [System.String[]]
        $Type = @('prefix','middle','suffix'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapToken

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

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
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::Value)
            {
                # Override deobfuscation eligibility if current object is not Value LdapToken.
                $isEligible = $false
            }
            elseif ($curInputObject.Content -cnotmatch '\*{2,}')
            {
                # Override deobfuscation eligibility if current object is not Value LdapToken with 2+ contiguous wildcard characters ('*').
                $isEligible = $false
            }

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for deobfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Split current object into array of substring objects, specifying each substring's eligibility for wildcard character ('*') removal based on user input -Type parameter.
                $valueSubstringObjArr = @()
                if ($curInputObject.Content -cmatch '^\*{2,}$')
                {
                    # Entire value is eligible for deobfuscation regardless of user input -Type parameter since entire value consists of wildcard characters ('*').
                    $valueSubstringObjArr += [PSCustomObject] @{
                        Content  = $curInputObject.Content
                        Eligible = $true
                    }
                }
                else
                {
                    # Extract prefix, middle and suffix substrings from Value LdapToken and store in temporary lookup object.
                    $curInputObject.Content -cmatch '^(?<Prefix>\*+)?(?<Middle>.+?)(?<Suffix>\*+)?$' | Out-Null
                    $curInputObjectContentMatchesObj = [PSCustomObject] @{
                        Prefix = $Matches['Prefix']
                        Middle = $Matches['Middle']
                        Suffix = $Matches['Suffix']
                    }

                    # Evaluate deobfuscation eligibility of extracted prefix, middle (and all its potentially split substrings) and suffix substrings based on user input -Type parameter.
                    if ($curInputObjectContentMatchesObj.Prefix)
                    {
                        $isEligible = (($Type -icontains 'prefix') -and ($curInputObjectContentMatchesObj.Prefix -cmatch '\*{2,}')) ? $true : $false
                        $valueSubstringObjArr += [PSCustomObject] @{
                            Content  = $curInputObjectContentMatchesObj.Prefix
                            Eligible = $isEligible
                        }
                    }
                    if ($curInputObjectContentMatchesObj.Middle)
                    {
                        if ($Type -icontains 'middle')
                        {
                            # Split middle substring into array of substrings delimited by 2+ contiguous wildcard characters ('*').
                            $valueSubstringObjArr += ($curInputObjectContentMatchesObj.Middle -csplit '(\*{2,})').ForEach(
                            {
                                $middleSubstring = $_

                                $isEligible = (($Type -icontains 'middle') -and ($middleSubstring -cmatch '\*{2,}')) ? $true : $false
                                [PSCustomObject] @{
                                    Content  = $middleSubstring
                                    Eligible = $isEligible
                                }
                            } )
                        }
                        else
                        {
                            $valueSubstringObjArr += [PSCustomObject] @{
                                Content  = $curInputObjectContentMatchesObj.Middle
                                Eligible = $false
                            }
                        }
                    }
                    if ($curInputObjectContentMatchesObj.Suffix)
                    {
                        $isEligible = (($Type -icontains 'suffix') -and ($curInputObjectContentMatchesObj.Suffix -cmatch '\*{2,}')) ? $true : $false
                        $valueSubstringObjArr += [PSCustomObject] @{
                            Content  = $curInputObjectContentMatchesObj.Suffix
                            Eligible = $isEligible
                        }
                    }
                }

                # Iterate over each substring object extracted above and for each eligible substring perform potential deobfuscation
                # based on final per-character eligibility check based on user input -RandomCharPercent parameter.
                $valueModified = -join$valueSubstringObjArr.ForEach(
                {
                    $substringObj = $_

                    # If current substring is eligible then perform potential per-character deobfuscation based on user input -RandomCharPercent parameter.
                    if ($substringObj.Eligible)
                    {
                        $substringObj.Content = -join([System.Char[]] $substringObj.Content).ForEach(
                        {
                            $curChar = $_

                            # Set boolean for deobfuscation eligibility based on user input -RandomCharPercent value.
                            $isRandomCharPercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent

                            # Proceed if eligible for deobfuscation.
                            if ($isRandomCharPercent)
                            {
                                # Remove current character.
                                $curChar = ''
                            }

                            $curChar
                        } )

                        # Ensure at least one wildcard is present after above deobfuscation.
                        $substringObj.Content = $substringObj.Content.Length -eq 0 ? '*' : $substringObj.Content
                    }

                    # Return current substring.
                    $substringObj.Content
                } )

                # Update current substring if deobfuscation occurred in above step.
                if ($curInputObject.Content -cne $valueModified)
                {
                    $curInputObject.Content = $valueModified

                    # If user input -TrackModification switch parameter is defined then set Depth property of current Value LdapToken to -1 for display tracking purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Remove-RandomExtensibleMatchFilter
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Remove-RandomExtensibleMatchFilter
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Remove-RandomExtensibleMatchFilter removes undefined ExtensibleMatchFilters from input LDAP SearchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) from which undefined ExtensibleMatchFilters will be removed.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to deobfuscate.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where deobfuscation occurred).

.EXAMPLE

PS C:\> '(name:timeSaved:=sabi)' | Remove-RandomExtensibleMatchFilter

(name=sabi)

.EXAMPLE

PS C:\> '(name:\) ``]:=sabi)' | Remove-RandomExtensibleMatchFilter

(name=sabi)

.EXAMPLE

PS C:\> '(&(name=sabi)(!name:1.3.3.7:=sabi))' | Remove-RandomExtensibleMatchFilter

(&(name=sabi)(!name:.:=sabi))

.EXAMPLE

PS C:\> '(&(|(name:=sabi)(name:caseExactMatch:=dbo)(name:a.b.c.d:=krbtgt))(|(sAMAccountType:1.2.840.113556.1.4.803:=536870912)(sAMAccountType:oId.00001.00002.0000840.000113556.00000001.000004.0000803:=536870912)))' | Remove-RandomExtensibleMatchFilter -RandomNodePercent 100 | Out-LdapObject

(
    &
    (
        |
        (name=sabi)
        (name=dbo)
        (name:.:=krbtgt)
    )
    (
        |
        (sAMAccountType:1.2.840.113556.1.4.803:=536870912)
        (sAMAccountType:.:=536870912)
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

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

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
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Define default redacted value to replace undefined ExtensibleMatchFilter values that contain a period character ('.') since
        # any ExtensibleMatchFilter with a period causes filter to never evaluate to true (even if negated with a BooleanOperator).
        $defaultRedactedExtensibleMatchFilterWithPeriod = ':.:'

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic deobfuscation eligibility.
            $isEligible = $true

            # Override above deobfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::ExtensibleMatchFilter)
            {
                # Override deobfuscation eligibility for LdapToken if it is not an ExtensibleMatchFilter type.
                $isEligible = $false
            }
            elseif (
                $curInputObject.Type -eq [Maldaptive.LdapTokenType]::ExtensibleMatchFilter -and `
                $curInputObject.Context.ExtensibleMatchFilter.Name -cne 'Undefined'
            )
            {
                # Override deobfuscation eligibility for LdapToken if it is an ExtensibleMatchFilter type but is
                # not one of the four exact OID values that Microsoft Active Directory supports.
                # Source: https://github.com/MicrosoftDocs/win32/blob/0e611cdff84ff9f897c59e4e1d2b2d134bc4e133/desktop-src/ADSI/search-filter-syntax.md
                $isEligible = $false
            }
            elseif (
                $curInputObject.Type -eq [Maldaptive.LdapTokenType]::ExtensibleMatchFilter -and `
                $curInputObject.Context.ExtensibleMatchFilter.Name -ceq 'Undefined' -and `
                $curInputObject.Content -ceq $defaultRedactedExtensibleMatchFilterWithPeriod
            )
            {
                # Override deobfuscation eligibility for LdapToken if it is already the default redacted value for
                # an undefined ExtensibleMatchFilter that contains a period charafcter ('.').
                $isEligible = $false
            }

            # Set boolean for deobfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for deobfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Deobfuscate current object by updating its Content property to default redacted value if period character ('.') is present.
                # Otherwise effectively remove current object by setting its Content property to null.
                $curInputObject.Content = $curInputObject.Content.Contains('.') ? $defaultRedactedExtensibleMatchFilterWithPeriod : $null
                $curInputObject.Length = $curInputObject.Content.Length

                # If user input -TrackModification switch parameter is defined then set Depth property of current ExtensibleMatchFilter LdapToken to -1 for display tracking purposes.
                if ($PSBoundParameters['TrackModification'].IsPresent)
                {
                    $curInputObject.Depth = -1
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}