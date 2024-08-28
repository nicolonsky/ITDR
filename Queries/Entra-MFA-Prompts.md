# Entra-MFA-Prompts

Review users that got MFA prompts due to MFA enforcement and display some context whether the device is present in Entra ID and the corresponding browser. This might also be an indicator that the browser does no work with device based CA or Entra SSO.

## Query

```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement =~ 'multiFactorAuthentication'
| where ResultType == 0
| mv-expand parse_json(AuthenticationDetails)
| extend OperatingSystem = tostring(DeviceDetail.operatingSystem)
| extend isEntraDevice = isnotempty(DeviceDetail.isManaged)
| extend AuthenticationMethod = tostring(AuthenticationDetails.authenticationMethod)
| extend AuthenticationStepResultDetail = tostring(AuthenticationDetails.authenticationStepResultDetail)
| extend Browser = coalesce(DeviceDetail.browser, ClientAppUsed)
| where AuthenticationMethod !~ 'Previously satisfied'
| summarize SignInCount = count() by OperatingSystem, isEntraDevice, AuthenticationMethod, UserPrincipalName, Browser//, AppDisplayName,Browser
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <>


### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
