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



function Invoke-LdapQuery
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Invoke-LdapQuery
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Confirm-UnbalancedParenthesis
Optional Dependencies: None

.DESCRIPTION

Invoke-LdapQuery issues LDAP SearchRequest (regardless of current OS) based on input SearchFilter, SearchRoot, AttributeList and Scope, normalizing DirectoryServices.DirectorySearcher output (Windows) and ldapsearch output (macOS and Linux) for seamless integration with later functions (e.g. ConvertFrom-LdapSearchResult).

.PARAMETER SearchFilter

Specifies LDAP SearchFilter to include in LDAP SearchRequest (defines primary search logic).

.PARAMETER SearchRoot

(Optional) Specifies LDAP SearchRoot to include in LDAP SearchRequest (defines starting directory object from which search will begin).

.PARAMETER AttributeList

(Optional) Specifies LDAP AttributeList to include in LDAP SearchRequest (defines attributes/properties to return for each matching object).

.PARAMETER Scope

(Optional) Specifies LDAP Scope to include in LDAP SearchRequest (defines scope of search - e.g. Base, OneLevel, Subtree).

.PARAMETER Count

(Optional) Specifies LDAP SizeLimit to include in LDAP SearchRequest (limits number of records to return).

.EXAMPLE

PS C:\> Invoke-LdapQuery -SearchFilter '(name=Domain *)' -AttributeList memb*,nam* -Count 4

Path                                                                                        Properties
----                                                                                        ----------
LDAP://WIN-DBOCOMPNAME.WINDOMAIN.LOCAL/CN=Domain Admins,CN=Users,DC=windomain,DC=local      {name, memberof, member, adspath}
LDAP://WIN-DBOCOMPNAME.WINDOMAIN.LOCAL/CN=Domain Computers,CN=Users,DC=windomain,DC=local   {adspath, name}
LDAP://WIN-DBOCOMPNAME.WINDOMAIN.LOCAL/OU=Domain Controllers,DC=windomain,DC=local          {adspath, name}
LDAP://WIN-DBOCOMPNAME.WINDOMAIN.LOCAL/CN=Domain Controllers,CN=Users,DC=windomain,DC=local {name, memberof, adspath}

.EXAMPLE

PS C:\> '(|(name=sabi)(name=dbo))' | ILQ

Path                                                                          Properties
----                                                                          ----------
LDAP://WIN-DBOCOMPNAME.WINDOMAIN.LOCAL/CN=dbo,CN=Users,DC=windomain,DC=local  {badpwdcount, pwdlastset, objectguid, description…}
LDAP://WIN-DBOCOMPNAME.WINDOMAIN.LOCAL/CN=sabi,CN=Users,DC=windomain,DC=local {badpwdcount, pwdlastset, objectguid, admincount…}

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Object[]])]
    [Alias('ILQ')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $SearchFilter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $SearchRoot = $global:defaultSearchRoot,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ArgumentCompleter(
            {
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Retrieve all Attribute string and OID values from Dictionary keys.
                $attributeNameArr = [System.Array] [Maldaptive.LdapParser]::ldapAttributeContextDict.Keys + [Maldaptive.LdapParser]::ldapAttributeOidDict.Keys

                # Modify current parameter value (captured at the time the user enters TAB) by normalizing OID (if OID syntax) and appending wildcard character
                # if no wildcard character is found.
                $WordToComplete = [Maldaptive.LdapParser]::IsOid($WordToComplete) ? ([Maldaptive.LdapParser]::NormalizeOid($WordToComplete)) : $WordToComplete
                $WordToComplete = $WordToComplete.Contains('*') ? $WordToComplete : "$WordToComplete*"

                # If current parameter substring was single wildcard character then return all Attribute names (but not OIDs to avoid unnecessary duplication).
                # Otherwise, filter all Attribute names and OIDs with current parameter substring.
                ($WordToComplete -ceq '*') ? ([Maldaptive.LdapParser]::ldapAttributeContextDict.Keys) : $attributeNameArr -ilike $WordToComplete
            }
        )]
        [System.String[]]
        $AttributeList = $global:defaultAttributeList,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Base','OneLevel','Subtree')]
        [System.String]
        $Scope = $global:defaultScope,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateScript( { $_ -gt 0 } )]
        [System.Int16]
        $Count
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::String

        # Create ArrayList to store all pipelined input before beginning final processing.
        $filterArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $filterArr = Join-LdapObject -InputObject $SearchFilter -InputObjectArr $filterArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $SearchFilter = ConvertTo-LdapObject -InputObject $filterArr -Target $requiredInputObjectTarget

        # Handle if -AttributeList input parameter is array of strings, single string with comma-separated attributes, or a combination of both.
        # Gracefully handle potential null values, but do not remove potential duplicate -AttributeList values so as to preserve user's original input.
        # Finally, do not modify any whitespace as it can be valid (e.g. when following OID notation) and is preserved in client-side LDAP logging.
        $AttributeList = $PSBoundParameters['AttributeList'].ForEach( { $_.Split(',').Where( { $_ } ) } )

        # Process user input -AttributeList value(s) by evaluating any potential wildcard characters not manually expanded in tab-completion.

        # Retrieve all Attribute string and OID values from Dictionary keys.
        $attributeNameArr = [System.Array] [Maldaptive.LdapParser]::ldapAttributeContextDict.Keys + [Maldaptive.LdapParser]::ldapAttributeOidDict.Keys

        # Create copy of user input -AttributeList parameter and reset $AttributeList to an empty array to expand and populate in foreach loop below.
        $attributeListCopy = $AttributeList
        $AttributeList = @()

        # Iterate over each Attribute in copy of user input -AttributeList parameter.
        foreach ($attribute in $attributeListCopy)
        {
            # If current Attribute is a single wildcard then add as-is and continue without performing any expansion evaluation.
            if ($attribute -ceq '*')
            {
                $AttributeList += $attribute

                continue
            }

            # Enumerate any matching Attribute name/OID values if wildcard character(s) present in current input Attribute name.
            # Otherwise, -ilike operator will return case-insensitive whole string matches if no wildcard character(s) present.
            try
            {
                # Capture any matching Attributes.
                $attributeMatchArr = $attributeNameArr -ilike $attribute

                # Add any potential matching Attributes above; otherwise add current Attribute as-is.
                $AttributeList += $attributeMatchArr.Count -gt 0 ? $attributeMatchArr : $attribute
            }
            catch
            {
                # Do nothing since Attribute regular expression is invalid.
            }
        }

        # Perform LDAP SearchRequest depending on OS.
        if ($IsLinux -or $IsMacOS)
        {
            # Ensure the presence of ldapsearch, a native *nix binary used for issuing LDAP SearchRequests.
            $ldapsearchPath = (Get-Command -Name ldapsearch -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
            if (-not $ldapsearchPath -or -not (Test-Path -Path $ldapsearchPath))
            {
                # Output warning message and return from function if ldapsearch binary not found.
                Write-Warning "[$($MyInvocation.MyCommand.Name)] Native 'ldapsearch' binary not found. This binary is required on $($IsMacOS ? 'macOS' : 'Linux') to properly issue LDAP SearchRequest."

                return
            }

            # Sensitive connection information (e.g. password) should be defined in ldapsearch syntax/arguments in the global variable $global:ldapsearchConnectionArgs before invoking current function.
            # If $global:ldapsearchConnectionArgs is not defined then output warning message containing these instructions.
            if ($null -eq $global:ldapsearchConnectionArgs)
            {
                $ldapsearchConnectionArgsSample = '$global:ldapsearchConnectionArgs = "-H LDAP://YOUR_FQDN_OR_IP_GOES_HERE:389 -D `"CN=YOUR_USERNAME_GOES_HERE,CN=Users,DC=CONTOSO,DC=LOCAL`" -w `"YOUR_PASSWORD_GOES_HERE`""'
                Write-Warning "[$($MyInvocation.MyCommand.Name)] Global variable `$global:ldapsearchConnectionArgs is not defined.`n         Please define this variable with required connection information to be included in ldapsearch invocation and retry.`n         E.g. $ldapsearchConnectionArgsSample"
            }

            # Slightly modify relevant input parameters for inclusion in ldapsearch command.
            $ldapsearchBaseObject = $SearchRoot -ireplace '^\s*LDAPS?:\s*([/\\]\s*){2}','' -creplace '"','`"'
            $ldapsearchScope = $Scope -ireplace 'Base','base' -ireplace 'OneLevel','one' -ireplace 'Subtree','sub'
            $ldapsearchSearchFilter = $SearchFilter -replace '"','`"`"`"`"'
            $ldapsearchAttributeList = ($AttributeList.Count -eq 1 -and $AttributeList[0] -ceq '*') ? $null : $AttributeList -creplace '"','`"'

            # Encapsulate any AttributeList values containing whitespace in double quotes.
            $ldapsearchAttributeList = $ldapsearchAttributeList.ForEach( { $_.Contains(' ') ? "`"$_`"" : $_ } )

            # If user input -Count parameter is defined then instantiate optional variable for inclusion in ldapsearch command.
            $ldapsearchSizeLimit = $PSBoundParameters['Count'] ? "-z $($PSBoundParameters['Count']) " : ''

            # Construct final ldapsearch command.
            $ldapsearchCmd = "$ldapsearchPath -LLL -x {0} -E pr=2147483647/noprompt $ldapsearchSizeLimit-b `"$ldapsearchBaseObject`" -s $ldapsearchScope `"$ldapsearchSearchFilter`" $ldapsearchAttributeList" -f $global:ldapsearchConnectionArgs

            # Issue LDAP SearchRequest using Invoke-Expression instead of Start-Process due to 10-second delay for the latter cmdlet.
            Write-Verbose $ldapsearchCmd
            $stdout = Invoke-Expression -Command $ldapsearchCmd

            # Split raw ldapsearch output into array of grouped raw lines per returned LDAP object.
            # Fix 78-character ldapsearch stdout line wrap limit with -creplace "`n ",'' below.
            $ldapsearchOutputGrouped = ($stdout -join "`n" -creplace "`n ",'' -csplit "`n`n").Where( { $_ -and ($_.StartsWith('dn: ') -or -not ($_.StartsWith('# refldap') -or $_.StartsWith('# pagedresults'))) } )

            # Parse all properties out of each grouped raw ldapsearch output and convert to final object mimicking System.DirectoryServices.ResultPropertyCollection.
            $ldapsearchObjArr = @(foreach ($ldapsearchOutput in $ldapsearchOutputGrouped)
            {
                # Convert each raw ldapsearch output line into property name-value pair.
                $lineArr = $ldapsearchOutput.Split("`n")
                $propObjArr = @(foreach ($line in $lineArr) {
                    $delim = ': '
                    $delimIndex = $line.IndexOf($delim)

                    # Skip any lines not containing name-value pair syntax.
                    if ($delimIndex -eq -1)
                    {
                        continue
                    }

                    # Set current property object.
                    $propObj = [PSCustomObject] @{
                        Property = $line.Substring(0,$delimIndex)
                        Value = $line.Substring($delimIndex + $delim.Length)
                    }

                    # Perform potential property value conversions for non-string values based on expected property format.
                    if ($propObj.Property.EndsWith(':'))
                    {
                        # Convert byte array values from base64 string to byte array.
                        # Ldapsearch seems to prepend base64 encoded byte array values with an extra colon character.
                        $propObj.Property = $propObj.Property.Substring(0,$propObj.Property.Length - 1)
                        $propObj.Value = ,[System.Byte[]] @([System.Convert]::FromBase64String($propObj.Value))
                    }
                    elseif ($propObj.Value -cin @('TRUE','FALSE'))
                    {
                        $propObj.Value = [System.Boolean] ($propObj.Value -ceq 'TRUE' ? $true : $false)
                    }
                    elseif ($propObj.Value -cmatch '^\d{14}\.\d*Z$')
                    {
                        $propObj.Value = [System.DateTime]::ParseExact($propObj.Value,('yyyyMMddHHmmss.' + $propObj.Value.Split('.')[-1] -creplace '\d','f'),$null)
                    }
                    elseif ($propObj.Value -cmatch '^\d+$')
                    {
                        try
                        {
                            $propObj.Value = [System.Int32] $propObj.Value
                        }
                        catch
                        {
                            $propObj.Value = [System.Int64] $propObj.Value
                        }
                    }

                    # Return current property object.
                    $propObj
                })

                # Group above parsed property information into property hashtable.
                # Exclude dn property since it is automatically returned even if not explicitly specified (and is returned as distinguishedName when explicitly specified).
                $propHashtable = @{ }
                ($propObjArr.Where( { $_.Property -cne 'dn' } ) | Group-Object Property).ForEach(
                {
                    # Extract current property name and value(s).
                    $propName = $_.Name
                    $propVal = $_.Group.Value

                    # Ensure byte array values are added as a single nested array.
                    if ($propVal.GetType().Name -ceq 'Byte[]')
                    {
                        $propVal = [System.Byte[]] @() + , $propVal
                    }

                    # Add current property name and value(s) to property hashtable.
                    $propHashtable.Add($propName,$propVal)
                } )

                # Extract dn property for Path property below.
                $dn = ($propObjArr.Where( { $_.Property -ieq 'dn' } ) | Select-Object -First 1).Value
                $dn = $dn -inotmatch '^\s*LDAPS?:\s*([/\\]\s*){2}' ? 'LDAP://' + $dn : $dn

                # Return final results to mimic System.DirectoryServices.SearchResult.
                [PSCustomObject] @{
                    Path = $dn
                    Properties = $propHashtable
                }
            })

            # Return all parsed and converted results.
            $ldapsearchObjArr
        }
        elseif ($IsWindows -or -not ($IsLinux -or $IsMacOS))
        {
            # Prepend 'LDAP://' to user input -SearchRoot parameter if it does not contain a prefix of 'LDAP://' or 'LDAPS://'.
            if ($SearchRoot -inotmatch '^\s*LDAPS?:\s*([/\\]\s*){2}')
            {
                $SearchRoot = 'LDAP://' + $SearchRoot
            }

            # Correct potential non-capital casing of 'LDAP://' or 'LDAPS://' prefix for user input -SearchRoot parameter.
            if ($SearchRoot -imatch '^\s*LDAPS?:' -and $SearchRoot -cnotmatch '^\s*LDAPS?:')
            {
                $SearchRoot = $SearchRoot -ireplace '^\s*LDAP:','LDAP:' -ireplace '^\s*LDAPS:','LDAPS:'
            }

            # Instantiate DirectorySearcher object, initializing with user input -SearchFilter parameter.
            $searcherObj = New-Object System.DirectoryServices.DirectorySearcher($SearchFilter)

            # Update DirectorySearcher object's SearchRoot and SearchScope properties with user input -SearchRoot and -Scope parameters, respectively.
            $searcherObj.SearchRoot  = $SearchRoot
            $searcherObj.SearchScope = $Scope

            # Update DirectorySearcher object's SizeLimit property with user input -Count parameter (if defined).
            if ($PSBoundParameters['Count'])
            {
                $searcherObj.SizeLimit = $PSBoundParameters['Count']
            }

            # Update DirectorySearcher object's PropertiesToLoad property with user input -AttributeList parameter (if defined).
            if ($PSBoundParameters['AttributeList'])
            {
                $searcherObj.PropertiesToLoad.AddRange($AttributeList)
            }

            # Invoke final search object and return results.
            $searcherObj.FindAll()
        }
    }
}


function ConvertFrom-LdapSearchResult
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: ConvertFrom-LdapSearchResult
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Confirm-UnbalancedParenthesis
Optional Dependencies: None

.DESCRIPTION

ConvertFrom-LdapSearchResult parses input LDAP SearchResult object into functionally equivalent SearchFilter string (and array of property string conversions). This function enables a user to query any random LDAP SearchResult object from Active Directory (e.g. via Invoke-LdapQuery) and convert the object into a functionally equivalent SearchFilter string representation of the object to be converted into a parsed SearchFilter data format via ConvertTo-LdapObject and then further obfuscated before being converted back to a SearchFilter string via ConvertTo-LdapObject and then re-querying Active Directory using the newly obfuscated SearchFilter string to see if resultant SearchResult object is an exact match of the original query's SearchResult object.

.PARAMETER InputObject

Specifies LDAP SearchResult object to convert to a functionally equivalent SearchFilter string (and array of property string conversions).

.EXAMPLE

PS C:\> (Invoke-LdapQuery -SearchFilter '(name=sabi)' | ConvertFrom-LdapSearchResult).SearchFilter

(&(primarygroupid=513)(whenchanged=20230223121843.0Z)(name=sabi)(whencreated=20230223050324.0Z)(distinguishedname=CN=sabi,CN=Users,DC=windomain,DC=local)(|(dscorepropagationdata=20230223121843.0Z)(dscorepropagationdata=16010101000000.0Z))(logoncount=0)(memberof=CN=DomainAdmins,CN=Users,DC=windomain,DC=local)(|(objectclass=top)(objectclass=person)(objectclass=organizationalPerson)(objectclass=user))(admincount=1)(usnchanged=62822)(countrycode=0)(badpwdcount=0)(pwdlastset=133557955529519387)(badpasswordtime=0)(displayname=SabiElezaj)(instancetype=4)(usncreated=62820)(useraccountcontrol=66048)(objectsid=\01\05\00\00\00\00\00\05\15\00\00\00\11\19\DB\BC\FD\5D\E0\82\6A\34\7A\DF\54\04\00\00)(samaccountname=sabi)(codepage=0)(objectcategory=CN=Person,CN=Schema,CN=Configuration,DC=windomain,DC=local)(samaccounttype=805306368)(lastlogon=0)(objectguid=\92\F1\63\0A\91\12\9E\4F\94\FB\D1\4D\6D\8E\DE\BC)(lastlogoff=0)(cn=sabi))

.EXAMPLE

PS C:\> (Invoke-LdapQuery -SearchFilter '(name=sabi)' | ConvertFrom-LdapSearchResult).Properties

GroupStart Attribute             ComparisonOperator Value                                                                                GroupEnd
---------- ---------             ------------------ -----                                                                                --------
(          primarygroupid        =                  513                                                                                  )
(          whenchanged           =                  20230223121843.0Z                                                                    )
(          name                  =                  sabi                                                                                 )
(          whencreated           =                  20230223050324.0Z                                                                    )
(          distinguishedname     =                  CN=sabi,CN=Users,DC=windomain,DC=local                                               )
(|(        dscorepropagationdata =                  20230223121843.0Z                                                                    )
(          dscorepropagationdata =                  16010101000000.0Z                                                                    ))
(          logoncount            =                  0                                                                                    )
(          memberof              =                  CN=Domain Admins,CN=Users,DC=windomain,DC=local                                      )
(|(        objectclass           =                  top                                                                                  )
(          objectclass           =                  person                                                                               )
(          objectclass           =                  organizationalPerson                                                                 )
(          objectclass           =                  user                                                                                 ))
(          admincount            =                  1                                                                                    )
(          usnchanged            =                  62822                                                                                )
(          countrycode           =                  0                                                                                    )
(          badpwdcount           =                  0                                                                                    )
(          pwdlastset            =                  133557955529519387                                                                   )
(          badpasswordtime       =                  0                                                                                    )
(          displayname           =                  Sabi Elezaj                                                                          )
(          instancetype          =                  4                                                                                    )
(          usncreated            =                  62820                                                                                )
(          useraccountcontrol    =                  66048                                                                                )
(          objectsid             =                  \01\05\00\00\00\00\00\05\15\00\00\00\11\19\DB\BC\FD\5D\E0\82\6A\34\7A\DF\54\04\00\00 )
(          samaccountname        =                  sabi                                                                                 )
(          codepage              =                  0                                                                                    )
(          objectcategory        =                  CN=Person,CN=Schema,CN=Configuration,DC=windomain,DC=local                           )
(          samaccounttype        =                  805306368                                                                            )
(          lastlogon             =                  0                                                                                    )
(          objectguid            =                  \92\F1\63\0A\91\12\9E\4F\94\FB\D1\4D\6D\8E\DE\BC                                     )
(          lastlogoff            =                  0                                                                                    )
(          cn                    =                  sabi                                                                                 )

.EXAMPLE

PS C:\> ('(name=sabi)' | Invoke-LdapQuery -AttributeList name,objectClass,objectCategory,memberOf | ConvertFrom-LdapSearchResult).SearchFilter

(&(memberof=CN=Domain Admins,CN=Users,DC=windomain,DC=local)(objectclass=organizationalPerson)(objectcategory=CN=Person,CN=Schema,CN=Configuration,DC=windomain,DC=local)(name=sabi))

.EXAMPLE

PS C:\> ('(name=sabi)' | Invoke-LdapQuery -AttributeList name,objectClass,objectCategory,memberOf | ConvertFrom-LdapSearchResult).Properties

GroupStart Attribute             ComparisonOperator Value                                                                                GroupEnd
---------- ---------             ------------------ -----                                                                                --------
(          memberof              =                  CN=Domain Admins,CN=Users,DC=windomain,DC=local                                      )
(          objectclass           =                  organizationalPerson                                                                 )
(          objectcategory        =                  CN=Person,CN=Schema,CN=Configuration,DC=windomain,DC=local                           )
(          name                  =                  sabi                                                                                 )

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
        $InputObject
    )

    begin
    {

    }

    process
    {
        # Iterate over each -InputObject.
        foreach ($curInputObject in $InputObject)
        {
            # Since current LDAP result object is raw SearchResult object then step into Properties (type ResultPropertyCollection).
            $curInputObject = $curInputObject.Properties

            # Iterate over each property in current LDAP result object.
            $searchFilterObjArr = foreach ($curPropertyName in $curInputObject.Keys)
            {
                # Do not include 'adspath' property since it is not a searchable field in LDAP SearchFilter.
                if ($curPropertyName -eq 'adspath')
                {
                    continue
                }

                # Extract value(s) for current property and convert to string representation.
                $curPropertyValue = $curInputObject.GetEnumerator().Where( { $_.Name -eq $curPropertyName } ).Value
                $curPropertyValueCount = ($curPropertyValue.GetType().Name -eq 'Object[]') ? $curPropertyValue.Count : 1
                for ($i = 0; $i -lt $curPropertyValueCount; $i++)
                {
                    $curPropertyCurValue = ($curPropertyValue.GetType().Name -eq 'Object[]') ? $curPropertyValue[$i] : $curPropertyValue

                    # Create placeholder LDAP filter object with default values (where applicable) to be updated in remainder of function below.
                    $ldapFilterObj = [PSCustomObject] @{
                        GroupStart         = [System.String] '('
                        Attribute          = [System.String] $curPropertyName
                        ComparisonOperator = [System.String] '='
                        Value              =                 $null
                        GroupEnd           = [System.String] ')'
                    }

                    # If current property value is an object array with multiple values then add extra set of encapsulating GroupStart/GroupEnd tokens to current LDAP filter object.
                    if ($curPropertyValue.GetType().Name -eq 'Object[]')
                    {
                        if ($i -eq 0)
                        {
                            # Additionally prepend OR BooleanOperator since any value in Object[] should match.
                            $ldapFilterObj.GroupStart = '(|' + $ldapFilterObj.GroupStart
                        }
                        if ($i -eq ($curInputObject[$curPropertyName].Count - 1))
                        {
                            $ldapFilterObj.GroupEnd = $ldapFilterObj.GroupEnd + ')'
                        }
                    }

                    # Convert current value to equivalent LDAP filter based on property type.
                    switch ($curPropertyCurValue.GetType().Name)
                    {
                        'Byte[]' {
                            # Convert byte array to LDAP-formatted escaped hex string.
                            $ldapFilterValue = '\' + [System.BitConverter]::ToString($curPropertyCurValue).Replace('-','\')

                            # Add converted LDAP filter value to current LDAP filter object.
                            $ldapFilterObj.Value = [System.String] $ldapFilterValue
                        }
                        'Int32' {
                            # Add Integer32 as-is converted to string to current LDAP filter object.
                            $ldapFilterObj.Value = [System.String] $curPropertyCurValue
                        }
                        'Int64' {
                            # Add Integer64 as-is converted to string to current LDAP filter object.
                            $ldapFilterObj.Value = [System.String] $curPropertyCurValue
                        }
                        'DateTime' {
                            # Convert current property DateTime object to LDAP-formatted YMD (year-month-day) string with required trailing Zulu UTC indicator.
                            # Millisecond is not required and is ignored by some LDAP impementations, so milliseconds can be removed, updated, or added in length without affecting LDAP SearchFilter result.
                            $ldapFilterValue = $curPropertyCurValue.ToString('yyyyMMddHHmmss.fZ')

                            # Add converted LDAP filter value to current LDAP filter object.
                            $ldapFilterObj.Value = [System.String] $ldapFilterValue
                        }
                        'String' {
                            # No conversion required for string property.
                            # However, if Attribute name ends with "Path" then backslash character(s) must be hex encoded.
                            $ldapFilterValue = [System.String] $curPropertyCurValue
                            $ldapFilterValue = $ldapFilterObj.Attribute.EndsWith('path','CurrentCultureIgnoreCase') ? $ldapFilterValue.Replace('\','\5C') : $ldapFilterValue

                            # Add converted LDAP filter value to current LDAP filter object.
                            $ldapFilterObj.Value = [System.String] $ldapFilterValue
                        }
                        'Boolean' {
                            # Add Boolean as-is converted to uppercase string (case sensitive for LDAP SearchFilter) to current LDAP filter object.
                            $ldapFilterObj.Value = ([System.String] $curPropertyCurValue).ToUpper()
                        }
                        default {
                            Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                        }
                    }

                    # If LDAP filter value has unbalanced parentheses then hex encode all parenthesis characters.
                    $ldapFilterObj.Value = (Confirm-UnbalancedParenthesis -InputObject $ldapFilterObj.Value) ? $ldapFilterObj.Value.Replace('(','\28').Replace(')','\29') : $ldapFilterObj.Value

                    # Return LDAP filter object for current property-value pair.
                    $ldapFilterObj
                }
            }

            # Convert array of LDAP SearchFilter objects into array of string representations.
            $searchFilterStrArr = foreach ($searchFilterObj in $searchFilterObjArr)
            {
                -join@(
                    $searchFilterObj.GroupStart
                    $searchFilterObj.Attribute
                    $searchFilterObj.ComparisonOperator
                    $searchFilterObj.Value
                    $searchFilterObj.GroupEnd
                )
            }

            # Join LDAP SearchFilter string values and encapsulate with AND BooleanOperator.
            $searchFilterStr = '(&' + -join$searchFilterStrArr + ')'

            # Return final result as PSCustomObject containing both converted array format and final LDAP SearchFilter string representation.
            [PSCustomObject] @{
                SearchFilter = $searchFilterStr
                Properties   = $searchFilterObjArr
            }
        }
    }

    end
    {

    }
}