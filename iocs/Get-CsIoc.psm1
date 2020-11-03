function Get-CsIoc {
<#
    .SYNOPSIS
        Search the custom IOCs in your account

    .PARAMETER TYPE
        Type of the indicator

    .PARAMETER VALUE
        String representation of the indicator

    .PARAMETER AFTER
        Find custom IOCs created after this time (RFC-3339 timestamp)

    .PARAMETER BEFORE
        Find custom IOCs created before this time (RFC-3339 timestamp)

    .PARAMETER POLICY
        Find custom IOCs within a policy [default: 'detect']

    .PARAMETER SOURCE
        Source where this indicator originated

    .PARAMETER SHARE
        Share level of indicator [default: 'red']

    .PARAMETER CREATEDBY
        User who created the custom IOC

    .PARAMETER DELETEDBY
        User who deleted the custom IOC

    .PARAMETER DELETED
        Include deleted IOCs [default: False]

    .PARAMETER LIMIT
        The maximum records to return [default: 500]

    .PARAMETER OFFSET
        The offset to start retrieving records from [default: 0]

    .PARAMETER ALL
        Repeat requests until all results are retrieved
#>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [ValidateSet('domain', 'ipv4', 'ipv6', 'md5', 'sha256')]
        [string] $Type,

        [ValidateLength(1,200)]
        [string] $Value,

        [string] $After,

        [string] $Before,

        [ValidateSet('detect', 'none')]
        [string] $Policy,

        [ValidateLength(1,200)]
        [string] $Source,

        [ValidateSet('red')]
        [string] $Share,

        [string]
        $CreatedBy,

        [string] $DeletedBy,

        [boolean] $Deleted,

        [ValidateRange(1,500)]
        [int] $Limit = 500,

        [int] $Offset,

        [switch] $All
    )
    process{
        $Param = @{
            Uri = '/indicators/queries/iocs/v1?'
            Method = 'get'
            Header = @{
                accept = 'application/json'
                'content-type' = 'application/json'
            }
        }
        switch ($PSBoundParameters.Keys) {
            'Limit' { $Param.Uri += "&limit=$Limit" }
            'Offset' { $Param.Uri += "&offset=$Offset" }
            'Policy' { $Param.Uri += "&policies=$Policy"}
            'Share' { $Param.Uri += "&share_levels=$Share" }
            'Deleted' { $Param.Uri += "&include_deleted=$Deleted" }
            'Type' { $Param.Uri += "&types=$Type" }
            'Value' { $Param.Uri += "&values=$Value" }
            'After' { $Param.Uri += "&from.expiration_timestamp=$After" }
            'Before' { $Param.Uri += "&to.expiration_timestamp=$Before" }
            'Source' { $Param.Uri += "&sources=$Source" }
            'CreatedBy' { $Param.Uri += "&created_by=$CreatedBy" }
            'DeletedBy' { $Param.Uri += "&deleted_by=$DeletedBy" }
            'Debug' { $Param['Debug'] = $true }
            'Verbose' { $Param['Verbose'] = $true }
        }
        if ($All) {
            Join-CsResult -Activity $MyInvocation.MyCommand.Name -Param $Param
        }
        else {
            Invoke-CsAPI @Param
        }
    }
}