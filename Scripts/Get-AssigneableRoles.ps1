
# permanently assigned roles
$roles = Get-MgRoleManagementDirectoryRoleDefinition | Group-Object -Property Id -AsHashTable

# PIM assigned roles
$eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -ExpandProperty 'roleDefinition', 'principal' -All
$permanentAssignments = Get-MgBetaRoleManagementDirectoryRoleAssignment -All


$assignments = $eligibleAssignments + $permanentAssignments

$roleMapping = @{}

foreach ($role in $roles.GetEnumerator()) {
    

    foreach ($assignment in $assignments) {

        if ($roleMapping.ContainsKey($assignment.principalId)) {
            $roleMapping[$assignment.principalId] += [PSCustomObject]@{
                RoleDefinitionId   = $role.Value.Id
                RoleDefinitionName = $role.Value.DisplayName
            }
        } else {
            $roleMapping[$assignment.principalId] = @([PSCustomObject]@{
                    RoleDefinitionId   = $role.Value.Id
                    RoleDefinitionName = $role.Value.DisplayName
                })
        }
    }
}
