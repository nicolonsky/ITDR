# Entra-Conditional-Access-Excluded-Accounts

Review sign-in activities for user accounts excluded from conditional access.

## Query

```kusto
let ConditionalAccessExclusionGroups = dynamic([<CA Exclusion Groups>"]);
let LookBack = 30d;
let ExcludedAccounts = IdentityInfo
    | where TimeGenerated > ago(LookBack)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | where GroupMembership has_any (ConditionalAccessExclusionGroups);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(LookBack)
| where ConditionalAccessStatus != "failure" // Only include successful sign-ins
| where ResultType != "50126" // exclude invalid username or password
| join kind=inner ExcludedAccounts on $left.UserPrincipalName == $right.AccountUPN
| summarize make_set(IPAddress, 100) by UserPrincipalName
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities#view-or-copy-bitlocker-keys>

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information


### MITRE ATT&CK Tags

* **Tactic:** Defense Evasion (TA0005), Persistence (TA0003)
* **Technique:**
    * Modify Authentication Process: Multi-Factor Authentication (T1556.006)
