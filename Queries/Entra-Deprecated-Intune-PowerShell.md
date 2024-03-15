# Entra-Deprecated-Intune-PowerShell

The Intune PowerShell app is deprecated and should not be used anymore. The following query searches for sign-ins for that particular app. 

> If you are using the Intune PowerShell application ID (d1ddf0e4-d672-4dae-b554-9d5bdfd93547), you will need to update your scripts with a Microsoft Entra ID registered application ID to prevent your scripts from breaking.


## Query

```kusto
let MicrosoftIntunePowerShellAppId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547';
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where AppId == MicrosoftIntunePowerShellAppId
| summarize Count = count() by  UserPrincipalName, AppDisplayName, bin(TimeGenerated, 1d)
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://twitter.com/adamgrosstx/status/1768080130079854992?s=46&t=cGMDSruQc_Wyrem9GPHQdg>
* <https://github.com/microsoftgraph/powershell-intune-samples/tree/master?tab=readme-ov-file#what-you-need-to-do-to-prepare>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A