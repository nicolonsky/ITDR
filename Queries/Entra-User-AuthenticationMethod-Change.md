# Entra-User-AuthenticationMethod-Change

KQL Query to detect potential account takeover activities within Entra ID via the following activities:

- Password Reset
- Registration of Temporary Access Pass
- Deletion of existing MFA information to re-register MFA when username and password is known

## Query

### Sentinel
```kusto
// 
AuditLogs
| where TimeGenerated > ago(360d)
| where OperationName in~ ("Reset password (by admin)", "Admin registered security info", "Admin deleted security info")
| extend ActorId = coalesce(tostring(InitiatedBy.app.appId), tostring(InitiatedBy.user.id))
| extend ActorDisplayName = coalesce(tostring(InitiatedBy.app.displayName), tostring(InitiatedBy.user.userPrincipalName))
| mv-expand TargetResources
| extend TargetUser = coalesce(TargetResources.userPrincipalName, TargetResources.displayName, TargetResources.id)
| project
    TimeGenerated,
    OperationName,
    ResultDescription,
    TargetUser = '{PII Removed}',
    ActorDisplayName = '{PII Removed}',
    ActorId
```

### Example
![image](https://github.com/nicolonsky/ITDR/assets/32899754/3b10ead0-7124-4ba6-881f-4b8a06756f9e)

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass#create-a-temporary-access-pass>
* <https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userdevicesettings#manage-user-authentication-options>

### MITRE ATT&CK Tags

* **Tactic:** Persistence (TA0003)
* **Technique:**
    * Modify Authentication Process (T1556)
    * Account Manipulation (T1098)
