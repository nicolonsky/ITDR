# Entra-Passkey-Registration

Query to find Entra ID passkey registration events and performing a lookup of the attestation guid.

## Query

```kusto
let PassKeys = datatable (AAGuid: string, Name: string)[
    "90a3ccdf-635c-4729-a248-9b709135078f", "Authenticator on iOS",
    "de1e552d-db1d-4423-a619-566b625cdc84", "Authenticator on Android",
];
let AAGuids = externaldata (AAGuid: string, Name: string) ['https://raw.githubusercontent.com/nicolonsky/ITDR/main/Watchlists/aaguids.json'] with (format=multijson);
AuditLogs
| where TimeGenerated > ago(360d)
| where OperationName in~ ("Add Passkey (device-bound)", "Add Passkey (device-bound) security key", "Add FIDO2 security key")
| mv-expand AdditionalDetails
| where AdditionalDetails.key =~ 'AAGuid'
| mv-expand TargetResources
| extend AAGuid = tostring(AdditionalDetails.value)
| extend Actor = coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.user.id)
| extend TargetUser= TargetResources.userPrincipalName
| lookup (union AAGuids, PassKeys) on AAGuid
| extend PassKeyType = coalesce(Name, AAGuid)
| project TimeGenerated, ActivityDisplayName, TargetUser, Actor, PassKeyType, AAGuid
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://nicolasuter.medium.com/have-you-heard-about-passkeys-and-aaguids-4d858680248c>

### MITRE ATT&CK Tags

* **Tactic:** Persistence (TA0003)
* **Technique:**
    * Modify Authentication Process: Multi-Factor Authentication (T1556.006)
