# Entra-Conditional-Access-Failure-By-Policy

Review Conditional Access failure for individual policies. Useful for testing new policies in report-only mode before enabling them.

## Query

```kusto
SigninLogs
| mv-expand ConditionalAccessPolicies
// Report Only Mode failures: reportOnlyfailure, Failures in block mode: failure
| where ConditionalAccessPolicies.result =~ "failure"
// Adjust with CA policy name
| where ConditionalAccessPolicies.displayName =~ 'CA003-Global-AttackSurfaceReduction-AllApps-AnyPlatform-Block-LegacyAuth'
| summarize AffectedUsers = dcount(UserPrincipalName)
    by
    AppDisplayName,
    ClientAppUsed
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-applied-conditional-access-policies>


### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
