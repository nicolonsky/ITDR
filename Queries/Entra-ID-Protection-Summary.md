# Entra-ID-Protection-Summary

KQL queries to summarize recent Entra ID protection sign-in risks e.g. for considering blocking high risk sign-ins from unmanaged devices, unknown locations or countries where a company doesn't operate.

## Report about recent risk detections including details

```kusto
let RiskRating = datatable (RiskLevelDuringSignIn: string, RiskRating: int)[
    "low", 1,
    "medium", 2,
    "high", 3
];
SigninLogs
| where TimeGenerated > ago(90d)
| where RiskDetail !~ "none"
| extend IsManaged = tobool(DeviceDetail.isManaged == 'true')
| extend OS = tostring(DeviceDetail.operatingSystem)
| extend AuthenticationMethod = tostring(MfaDetail.authMethod)
| extend Browser = tostring(DeviceDetail.browser)
| join kind=leftouter RiskRating on RiskLevelDuringSignIn
| sort by RiskRating desc 
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventTypes,
    RiskLevelDuringSignIn,
    IsManaged,
    OS,
    Browser,
    NetworkLocationDetails,
    Location,
    AuthenticationMethod,
    RiskState,
    RiskDetail
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
