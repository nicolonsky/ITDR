# Entra-Conditional-Access-Not-Applied

Review sign-in logs where Conditional Access policies were not applied. This is caused by design for some Microsoft backend applications serve as bootstrap apps but can also be caused by Miconfigurations.
To run the query add your exclusion groups for accounts that are not intented to receive any policies.

## Query

```kusto
let ConditionalAccessExclusionGroups = dynamic(["<Display Name of CA Exclusion Group 1>", "<Display Name of CA Exclusion Group 2...>"]);
let LookBack = 90d;
let ExcludedAccounts = IdentityInfo
    | where TimeGenerated > ago(LookBack)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | where GroupMembership has_any (ConditionalAccessExclusionGroups)
    | project AccountUPN;
SigninLogs
| where TimeGenerated > ago(LookBack)
| where ConditionalAccessStatus == "notApplied"
// https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins#special-considerations
| where CrossTenantAccessType !in ("b2bCollaboration", "passthrough", "b2bDirectConnect", "b2bCollaboration, b2bDirectConnect")
| where ResultType == 0
| where Identity != "{PII removed - Tenant Restrictions}"
| where AppDisplayName !in~ (
    "Windows Sign In", // Doesn't support processing of CA-Policies
    "Microsoft Authentication Broker" // Token broker services that enable SSO: Authenticator, Company Portal, Windows WAM
    )
// CA 'Bootstrap' backend resources
| where ResourceDisplayName !in (
    "OCaaS Client Interaction Service", // https://learn.microsoft.com/en-us/answers/questions/793759/conditional-access-policy-that-blocks-sign-ins-fro
    "Microsoft Mobile Application Management", // MAM Bootstrap
    "Azure Multi-Factor Auth Connector", // Backend Service for Push-MFA 
    "Microsoft Intune Checkin",  // Intune Service Communication / Bootstrap 
    "Windows Notification Service",
    "Device Registration Service", // Client App: "Microsoft Device Registration Client" belongs to this backend service
    "AAD Terms Of Use" // TOU interrupt
    )
| where UserPrincipalName !in (ConditionalAccessExclusionGroups)
// Check Microsoft Graph Scopes for Microsoft Graph Resource Access 
// | join kind = leftouter MicrosoftGraphActivityLogs on $left.UniqueTokenIdentifier == $right.SignInActivityId
| summarize count() by AppDisplayName, AppId, ResourceDisplayName
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-applied-conditional-access-policies>


### MITRE ATT&CK Tags

* **Tactic:** Defense Evasion (TA0005), Persistence (TA0003)
* **Technique:**
    * Modify Authentication Process: Multi-Factor Authentication (T1556.006)
