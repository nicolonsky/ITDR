# MDI-AZUREADSSOACC-Logon

KQL Query to find devices leveraging Entra seamless SSO via AZUREADSSOACC sign-in visible within Defender for Identity. Seamless SSO increases the attack surface of lateral movement capabilities from AD to Entra ID.
If not actively used, seamless sso should be disabled. The following KQL query lists devices leveraging seamless SSO. If devices are Entra joined or hybrid Entra joined seamless sso is not required as they will receive PRTs via the device trust.

You can find the seamless sso configuration state within the Entra ID portal. If enabled, you might want to run the below query to see whether seamless SSO is still used.
![image](https://github.com/user-attachments/assets/f6115707-693b-4b2a-8942-341dae4a27d0)

## Query

### Defender XDR

```kusto
// Detect usage of seamless SSO via AZUREADSSOACC & MDI
// Non down-level Windows devices should be entra (hybrid) joined instead of using seamless SSO
IdentityLogonEvents
| where TimeGenerated > ago(30d)
| where TargetDeviceName == "AZUREADSSOACC"
| summarize LogonCount = count() by DeviceName, TargetDeviceName  //, AccountName
| lookup (DeviceInfo 
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by DeviceName
    )
    on DeviceName
| project DeviceName, TargetDeviceName, LogonCount, OSPlatform, OSVersionInfo//, AccountName
| sort by LogonCount desc nulls last 
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso>
* <https://aadinternals.com/post/on-prem_admin/>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
