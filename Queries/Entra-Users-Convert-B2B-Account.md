# Entra-Users-Convert-B2B-Account

Hunt for conversions of B2B collaboration (guest users) to internal users and vice-versa. Existing directory roles and groups memberships are retained during the conversion process.

## Query

```kusto
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Update user"
| mv-expand TargetResources, TargetResources.modifiedProperties
| mv-apply modified = TargetResources.modifiedProperties on (
    where modified.displayName == "UserType"
    | extend NewUserType = modified.newValue
    | extend OldUserType = modified.oldValue
    | mv-expand parse_json(tostring(NewUserType)), parse_json(tostring(OldUserType)) // KQL Weirdness :)
    )
| mv-apply modified = TargetResources.modifiedProperties on (
    where modified.displayName == "UserPrincipalName"
    | extend NewUserPrincipalName = modified.newValue
    | extend OldUserPrincipalName = modified.oldValue
    | mv-expand
        parse_json(tostring(NewUserPrincipalName)),
        parse_json(tostring(OldUserPrincipalName)) // KQL Weirdness ^2 :)
    )
| extend Actor = iif(isnotempty(InitiatedBy.user.userPrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.appId)
| project
    TimeGenerated,
    OperationName,
    NewUserType,
    OldUserPrincipalName,
    NewUserPrincipalName,
    OldUserType,
    Actor
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/users/convert-external-users-internal>

### MITRE ATT&CK Tags

* **Tactic:** Defense Evasion (TA0005), Persistence (TA0003)
* **Technique:**
    * N/A
