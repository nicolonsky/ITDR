# Entra-MFA-Prompts

Review users that got MFA prompts due to MFA enforcement and display some context whether the device is present in Entra ID and the corresponding browser. This might also be an indicator that the browser does no work with device based CA or Entra SSO.

## Query

```kusto
SigninLogs
| where TimeGenerated > ago(1d)
// uncomment to only get successful sign-ins
//| where ResultType in (0, 50140)
| where AuthenticationRequirement =~ 'multifactorAuthentication'
| mv-expand parse_json(AuthenticationDetails)
| where AuthenticationDetails.authenticationStepResultDetail !in~ ("MFA requirement satisfied by claim in the token", "First factor requirement satisfied by claim in the token")
| extend OperatingSystem = tostring(DeviceDetail.operatingSystem)
| extend isEntraDevice = isnotempty(DeviceDetail.isManaged)
| extend AuthenticationMethod = tostring(AuthenticationDetails.authenticationMethod)
| extend AuthenticationStepResultDetail = tostring(AuthenticationDetails.authenticationStepResultDetail)
| extend Browser = coalesce(DeviceDetail.browser, ClientAppUsed)
| extend Result = coalesce(ResultDescription, ResultType)
| summarize count() by UserPrincipalName, OperatingSystem, isEntraDevice, Browser, AppDisplayName, Result
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
