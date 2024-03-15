# Entra-LAPS-Password-Retrieval

Query for Windows LAPS account password retrievals in Entra ID.
This can be used to monitor LAPS password access of sensitive assets in an analytics rule in combination with a watchlist.

## Query

```kusto
AuditLogs 
| where TimeGenerated > ago(90d)
| where OperationName == 'Recover device local administrator password'
| mv-expand TargetResources
| extend DeviceName = TargetResources.displayName
| extend DeviceId = TargetResources.id
| extend Actor = iif(isnotempty(InitiatedBy.user.userPrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.appId),
| project TimeGenerated, ActivityDisplayName, Actor, DeviceName, DeviceId
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

