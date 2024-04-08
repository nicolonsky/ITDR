# Entra-Applications-DelegatedConsent

Query for delegated application consent operations and review tha added permissions on app registrations or enterprise apps consented by admins or users.

## Query

```kusto
AuditLogs
| where TimeGenerated > ago(180d)
| where OperationName == "Add delegated permission grant"
| mv-expand TargetResources
| mv-apply mp = TargetResources.modifiedProperties on (
    where mp.displayName =~ 'DelegatedPermissionGrant.Scope'
    | extend NewPermissions = split(trim(@'^"|"\s*$', tostring(mp.newValue)), " ")
    | extend OldPermissions = split(trim(@'^"|"\s*$', tostring(mp.oldValue)), " ")
    )
| mv-apply mp = TargetResources.modifiedProperties on (
    where mp.displayName =~ 'ServicePrincipal.ObjectID'
    | extend AppId = trim(@'"', tostring(mp.newValue))
    )
| extend Actor = iif(isnotempty(InitiatedBy.user), InitiatedBy.user.userPrincipalName, InitiatedBy.app.appId)
| extend ChangedPermissions = set_difference(NewPermissions, OldPermissions)
| lookup (
    AuditLogs 
    | where OperationName == "Consent to application" 
    | mv-expand TargetResources
    | extend AppId = tostring(TargetResources.id)
    | extend AppDisplayName = tostring(TargetResources.displayName)
    | summarize arg_max(TimeGenerated, AppDisplayName) by AppId
    )
    on AppId
| project TimeGenerated, Actor, AppDisplayName, AppId, ChangedPermissions
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications>


### MITRE ATT&CK Tags

* **Tactic:** Privilege Escalation (TA0004)
* **Technique:**
    * Exploitation for Privilege Escalation (T1068)
