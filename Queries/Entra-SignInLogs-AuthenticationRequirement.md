# Entra-SignInLogs-AuthenticationRequirement

Query Entra ID users that were in scope of MFA authentication requirement. This is helpful to estimate the impact before enforcing MFA for all users to identify users which didn't frequently complete MFA or have an existing MFA claim within their token.

## Query user with existing MFA Authentication Requirements

```kusto
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationRequirement =~ "multiFactorAuthentication"
| where ResultType == 0
| summarize arg_max(TimeGenerated, *), make_set(AppDisplayName, 10) by UserPrincipalName
| lookup (
    IdentityInfo 
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
) on $left.UserPrincipalName == $right.AccountUPN
| mv-expand parse_json(AuthenticationDetails)
| distinct UserPrincipalName, LastMFARequirement = TimeGenerated, AccessedAppDisplayName= AppDisplayName, MfaMethod = coalesce(tostring(MfaDetail.authMethod), AuthenticationDetails.authenticationMethod), ResultDescription
```

## Query user or apps without existing MFA Authentication Requirements

```kusto
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationRequirement =~ "singleFactorAuthentication"
| where ResultType == 0
| summarize arg_max(TimeGenerated, *), make_set(AppDisplayName, 10) by UserPrincipalName
| lookup (
    IdentityInfo 
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
) on $left.UserPrincipalName == $right.AccountUPN
| mv-expand parse_json(AuthenticationDetails)
| distinct UserPrincipalName, LastMFARequirement = TimeGenerated, AccessedAppDisplayName= AppDisplayName, MfaMethod = coalesce(tostring(MfaDetail.authMethod), AuthenticationDetails.authenticationMethod), ResultDescription
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-find-coverage-gaps#detect-current-usage-for-microsoft-entra-built-in-administrator-roles>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
