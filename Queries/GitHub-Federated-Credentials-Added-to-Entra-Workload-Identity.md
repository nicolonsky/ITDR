# GitHub-Federated-Credentials-Added-to-Entra-Workload-Identity

Tracking additions of federated credentials to Entra App Registrations aka Workload Identities for GitHub Repositories
Optionally, this can be checked against allowlisted repositories and organizations stored in a watchlist.
Furthermore, the GitRefs can be checked to ensure only main branches or certain tags are allowed for federation.

## Query

```kusto
AuditLogs
| where TimeGenerated > ago(180d)
| where OperationName == "Update application"
| mv-expand TargetResources
| mv-apply ModifiedProperties = TargetResources.modifiedProperties on (
    where ModifiedProperties.displayName == "FederatedIdentityCredentials"
    // Littel workaround as mv expand doesn't work as expected for this array
    | extend FederatedCredentials = parse_json(tostring(ModifiedProperties.newValue))
    | mv-expand FederatedCredentials
    )
// Filter for GitHub Federation
| where FederatedCredentials.Issuer == "https://token.actions.githubusercontent.com"
// Parse Refs
| parse FederatedCredentials.Subject with * "repo:"Organization: string "/"Repository: string ":ref:" GitRefs: string
| extend Actor = iif(isnotempty(InitiatedBy.app), tostring(InitiatedBy.app.displayName), tostring(InitiatedBy.user.userPrincipalName))
| extend ActorId = iif(isnotempty(InitiatedBy.app), tostring(InitiatedBy.app.id), tostring(InitiatedBy.user.id))
| project
    Application = TargetResources.displayName,
    AppId = TargetResources.id,
    Organization,
    Repository,
    GitRefs,
    Actor,
    ActorId
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A