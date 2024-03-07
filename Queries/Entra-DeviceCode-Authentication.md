# Entra-DeviceCode-Authentication

Search for Accounts that leveraged Microsoft Entra Device Code Authentication.

This authentication flow is commonly legitimately used for:
* Azure and Microsoft Graph PowerShell by admins
* Device registration of Teams rooms devices

Device Code flow can be abused for device code phishing.

## Query

```kusto
SigninLogs
| where TimeGenerated > ago(180d)
| where AuthenticationProtocol =~ "deviceCode"
// Device Registration Service is used for device registration of Teams Meeting Room Devices
//| where ResourceDisplayName !in~ ("Device Registration Service")
| project UserPrincipalName, AppDisplayName, AppId, ResourceDisplayName, TimeGenerated, ResultType
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* [https://www.blackhillsinfosec.com/dynamic-device-code-phishing/](https://www.blackhillsinfosec.com/dynamic-device-code-phishing/)

### MITRE ATT&CK Tags

* **Tactic:** Credential Access (TA0006)
* **Technique:**
    * T1566 (Phishing)
    * T1528 (Steal Application Access Token)

