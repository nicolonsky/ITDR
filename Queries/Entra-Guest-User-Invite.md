# Entra-Guest-User-Invite.md

KQL Query to find guest user additions within Entra ID and the corresponding actor who invited the guest account. B2B guest users can be added by inviting the external user either when user permissions haven't been limited or by Entra ID admins.

## Query

### Sentinel
```kusto
AuditLogs
| where TimeGenerated > ago(360d)
| where OperationName =~ 'Invite external user'
| where Result =~ 'success'
| mv-apply ad = AdditionalDetails on (
    where ad.key =~ 'invitedUserEmailAddress'
    | extend InvitedUserEmailAddress = tostring(ad.value)
    ) 
| project-rename InvitedUserTenantId = AADTenantId
| extend ActorId = coalesce(InitiatedBy.app.appId, InitiatedBy.user.id)
| extend ActorDisplayName = coalesce(InitiatedBy.app.displayName, InitiatedBy.user.userPrincipalName)
| project
    TimeGenerated,
    OperationName,
    InvitedUserEmailAddress,
    InvitedUserTenantId,
    ActorDisplayName,
    ActorId
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/external-id/add-users-administrator>

### MITRE ATT&CK Tags

* **Tactic:** Initial Access (TA0001)
* **Technique:**
    * Valid Accounts: Cloud Accounts (T1078.004)
