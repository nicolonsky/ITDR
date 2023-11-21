#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Get all PIM eligible role assignments for all users and groups in the tenant.

.DESCRIPTION
    Get all PIM eligible role assignments for all users and groups in the tenant and export them to a CSV file.
#>

$outputFileName = 'eligibleRoleAssignments.csv'
$container = 'watchlists'
$storageAccountName = 'stsecopsn01'
$subscriptionId = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

Connect-MgGraph -Identity -NoWelcome
$null = Connect-AzAccount -Identity -SubscriptionId $subscriptionId

$eligibleRoleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty 'roleDefinition', 'principal'

$roleMembers = $eligibleRoleAssignments | ForEach-Object {

    if ($PSItem.Principal.AdditionalProperties['@odata.type'] -match 'group') {
        $roleAssignment = $PSItem
        Get-MgGroupMember -GroupId $roleAssignment.Principal.Id | ForEach-Object {
            [PSCustomObject]@{
                PrincipalId             = $PSItem.Id
                PrincipalType           = $PSItem.AdditionalProperties['@odata.type']
                UserPrincipalName       = $PSItem.AdditionalProperties['userPrincipalName']
                RoleDefinitionId        = $roleAssignment.RoleDefinition.Id
                RoleDefinitionName      = $roleAssignment.RoleDefinition.DisplayName
                DirectoryScopeId        = $roleAssignment.DirectoryScopeId
                AssignmentInheritedFrom = $roleAssignment.Principal.Id
                AssignmentType          = 'Eligible'
            }
        }
    } else {
        [PSCustomObject]@{
            PrincipalId             = $PSItem.Principal.Id
            PrincipalType           = $PSItem.Principal.AdditionalProperties['@odata.type']
            UserPrincipalName       = $PSItem.Principal.AdditionalProperties['userPrincipalName']
            RoleDefinitionId        = $PSItem.RoleDefinition.Id
            RoleDefinitionName      = $PSItem.RoleDefinition.DisplayName
            DirectoryScopeId        = $PSItem.DirectoryScopeId
            AssignmentInheritedFrom = $null
            AssignmentType          = 'Eligible'
        }
    }
}

# Export as CSV
$roleMembers | Export-Csv -Path $outputFileName -NoTypeInformation -Encoding UTF8 -Delimiter ','

# Upload to Storage Account
$azStorageParams = @{
    File      = $outputFileName
    Container = $container
    Context   = (New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount)
}

Set-AzStorageBlobContent @azStorageParams
