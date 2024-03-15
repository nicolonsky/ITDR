# Entra-BitLocker-Recovery-Key-Retrieval

Query to find BitLocker recovery key retrieval operations and parsing of the involved device info from Entra ID.

## Query

```kusto
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Read BitLocker key"
| mv-apply details = AdditionalDetails on (
    where details.key == "AdditionalInfo"
    | extend AdditionalInfo = tostring(details.value)
    )
| parse AdditionalInfo with * "Successfully retrieved BitLocker recovery key associated with key ID: '" RecoveryKeyId: guid "'. Backed up from device: '" DeviceId: guid "'"
| project
    TimeGenerated, 
    ActivityDisplayName,
    Actor = iif(isnotempty(InitiatedBy.user.userPrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.appId),
    DeviceId,
    RecoveryKeyId
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities#view-or-copy-bitlocker-keys>

### MITRE ATT&CK Tags

* **Tactic:** Privilege Escalation (TA0004)
* **Technique:**
    * N/A

