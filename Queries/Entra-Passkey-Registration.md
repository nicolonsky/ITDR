# Entra-Passkey-Registration

Query to find Entra ID passkey registration events and performing a lookup of the attestation guid.

## Query

```kusto
let AAGuids = externaldata (AAGuid: guid, Name: string) ['https://raw.githubusercontent.com/nicolonsky/ITDR/main/Watchlists/aaguids.json'] with (format=multijson);
AuditLogs
| where TimeGenerated > ago(90d)
| where ActivityDisplayName =~ "Add FIDO2 security key"
| mv-apply details = AdditionalDetails on (
    where details.key =~ "AAGuid"
    | extend AAGuid = toguid(details.value)
    )
| extend Actor = InitiatedBy.user.userPrincipalName
| lookup kind=leftouter AAGuids on AAGuid
| project-rename PasskeyName = Name
| project
    TimeGenerated,
    OperationName,
    Actor,
    PasskeyName,
    AAGuid
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

