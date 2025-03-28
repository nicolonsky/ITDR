# Entra-Identity-Protection-Detection-Timing

Microsoft Entra Identity Protection has both detections which are processed during the sign-in in realtime and offline. The following KQL query surfaces the timing between the sign-in and detection by linking the actual sign-in to the risk event.

## Microsoft Sentinel or Unified SecOps Platform

```kusto
AADUserRiskEvents
| where TimeGenerated > ago(90d)
| join kind=inner  (
    union SigninLogs, AADNonInteractiveUserSignInLogs
    )
    on $left.RequestId == $right.Id
| extend DeviceInfo = parse_json(DeviceDetail_string)
| extend DetectionDiffHours = iif(DetectionTimingType =~ 'Offline', tostring(datetime_diff('hour', TimeGenerated, TimeGenerated1)), DetectionTimingType)
| distinct 
    TimeGenerated,
    UserPrincipalName,
    OperationName,
    RiskLevel,
    RiskEventType,
    ResourceDisplayName,
    DetectionTimingType,
    DetectionDiffHours,
    Category,
    UniqueTokenIdentifier
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks>

### MITRE ATT&CK Tags

* **Tactic:**
    * TA0001: Initial Access
    * TA0006: Credential Access
* **Technique:**
    * T1078.004: Valid Accounts: Cloud Accounts
    * T1539: Steal Web Session Cookie
