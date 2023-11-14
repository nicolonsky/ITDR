$content = Get-Content ./Scripts/demo.json | ConvertFrom-Json | Select-Object -ExpandProperty value | ForEach-Object {

    [PSCustomObject]@{
        PrincipalId        = $_.principalId
        PrincipalType      = $_.principal.'@odata.type' -match 'User' ? 'User' : 'ServicePrincipal'
        UserPrincipalName  = $_.principal.'@odata.type' -match 'User' ? $_.principal.userPrincipalName : $_.principal.displayName
        RoleDefinitionId   = $_.roleDefinitionId
        RoleDefinitionName = $_.roleDefinition.displayName
        DirectoryScopeId   = $_.directoryScopeId
    }
}

# https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition,principal