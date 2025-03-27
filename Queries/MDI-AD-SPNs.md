# MDI-AD-SPNs

Kerberos authentication uses SPNs to associate a service instance with a service sign-in account. The following KQL query can be used to hunt for queried AD SPNs by clients.


## Query

### Defender XDR

```kusto
IdentityLogonEvents
| where Timestamp > ago(30d)
//| where TimeGenerated > ago(90d)
| where Application =~ 'active directory'
| extend SPN = split(AdditionalFields.Spns, ",")
| where DestinationPort == 88
| mv-expand SPN
| summarize count() by tostring(SPN), DeviceName
| sort by count_ desc 
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
