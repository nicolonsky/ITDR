# MDE-LocalGroup-Membership-Change

KQL Query to detect local group membership changes on Defender for Endpoint monitored clients.

## Query

```kusto
DeviceEvents
| where ActionType in~ ('UserAccountAddedToLocalGroup', 'UserAccountRemovedFromLocalGroup')
// Exclude events initiated by NT Authority\SYSTEM
| where InitiatingProcessAccountSid != @"S-1-5-18"
| extend AF = parse_json(AdditionalFields)
| extend GroupName = AF.GroupName
| extend GroupSid = AF.GroupSid
| project-away AF
| project Timestamp, ActionType, DeviceName, ChangedAccountSID = AccountSid , GroupName , GroupSid , Actor = InitiatingProcessAccountName, DeviceId
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceevents>

### MITRE ATT&CK Tags

* **Tactic:** Persistence (TA0003)
* **Technique:**
    * Account Manipulation (T1098)