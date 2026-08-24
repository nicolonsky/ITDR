# Entra-TAP-Issuance

KQL query to find and extract details about temporary access pass issuance.

## Query

```kusto
AuditLogs
| where OperationName == 'Admin registered security info'
| where ResultReason has 'temporary access pass'
| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.appId))
| extend IPAddress = tostring(coalesce(InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| mv-expand TargetResources
| extend TargetUserPrincipalName = tostring(TargetResources.userPrincipalName)
| extend TargetUserId = tostring(TargetResources.id)
| mv-expand MP =todynamic(TargetResources.modifiedProperties)
| summarize
    TemporaryAccessPassId =  take_anyif(MP.newValue, MP.displayName has 'TemporaryAccessPass.TemporaryAccessPass.Id'),
    TemporaryAccessPassStartDateTime =  todatetime(take_anyif(MP.newValue, MP.displayName has 'TemporaryAccessPass.TemporaryAccessPass.StartDateTime')),
    TemporaryAccessPassEndTime = todatetime(take_anyif(MP.newValue, MP.displayName has 'TemporaryAccessPass.TemporaryAccessPass.EndTime')),
    TemporaryAccessPassUsage = take_anyif(MP.newValue, MP.displayName has 'TemporaryAccessPass.TemporaryAccessPass.AccessPassUsage')
    by
    TimeGenerated,
    OperationName,
    Actor,
    ActorId,
    CorrelationId,
    TargetUserPrincipalName,
    TargetUserId
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass>

### MITRE ATT&CK Tags

* **Tactic:** Persistence (TA0003) 
* **Technique:**
    * Modify Authentication Process: Multi-Factor Authentication (T1556.006)
    * Valid Accounts: Cloud Accounts (T1078.004)

