# Entra-SignInLogs-AuthenticationContextDetails

View triggered authentication contexts from Entra Sign-In Logs and enrich with the names of your authentication contexts.

## Query

```kusto
// Add the IDs and descriptions of your authentication context to allow enrichment
let AuthenticationContextInfo = datatable (id:string, displayName:string)[
"c1", "<Name of your authentication context>",
];
SigninLogs
| where TimeGenerated > ago(90d)
| mv-expand AuthenticationContext = parse_json(AuthenticationContextClassReferences)
| where AuthenticationContext.detail =~ "required"
| extend AuthenticationContextId = tostring(AuthenticationContext.id)
| lookup AuthenticationContextInfo on $left.AuthenticationContextId == $right.id
| extend AuthenticationContextName = displayName
| project TimeGenerated, UserPrincipalName, ResourceDisplayName, AuthenticationContextName, AuthenticationContextId, ResultDescription
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context>


### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
