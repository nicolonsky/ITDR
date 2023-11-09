<#
    .SYNOPSIS
    Enables all applicable Analytic Rules for a Microsoft Sentinel Workspace.

    .DESCRIPTION
    Enables all applicable Analytic Rules  based on the existing connectors for a Microsoft Sentinel Workspace.
#>


$sentinelInfo = @{
    ResourceGroupName = 'security'
    WorkspaceName     = 'la-dev'
}

$excludedConnectors = 'SecurityEvents'

# Get all available connectors
$availableConnectors = Get-AzSentinelDataConnector @sentinelInfo | Select-Object -ExpandProperty Name | Where-Object { $_ -notin $excludedConnectors }

# Identify all applicable rules based on the available connectors
$applicableRules = Get-AzSentinelAlertRuleTemplate @sentinelInfo | Where-Object { $_.Status -eq 'Available' -and $_.RequiredDataConnector.ConnectorId -in $availableConnectors }

# Prompt the user to confirm the rules to enable
$applicableRules | ForEach-Object {
    New-AzSentinelAlertRule @sentinelInfo -Kind $_.Kind -Enabled -Query $_.Query -DisplayName $_.DisplayName -Severity $_.Severity -TriggerOperator $_.TriggerOperator -TriggerThreshold $_.TriggerThreshold -QueryFrequency $_.QueryFrequency -QueryPeriod $_.QueryPeriod
}