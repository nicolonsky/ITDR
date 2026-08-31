# Entra-Federated-Credentials-Added-to-App-Registration

Tracking additions of federated credentials to Entra App Registrations aka Workload Identities.
Optionally, this can be checked against allowlisted repositories and organizations stored in a watchlist.
Furthermore, the GitRefs can be checked to ensure only main branches or certain tags are allowed for federation.

## Query

```kusto
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Update application"
| mv-expand TargetResources
| extend ServicePrincipalName = tostring(TargetResources.displayName)
| extend ServicePrincipalId = tostring(TargetResources.id)
| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.id))
| extend IpAddress = tostring(coalesce(InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| mv-expand _MP = todynamic(TargetResources.modifiedProperties)
// Little hack to only get modified creds & properly access the array
| extend FederatedCredentials = set_difference(parse_json(tostring(_MP.newValue)), parse_json(tostring(_MP.oldValue)))
| where _MP.displayName == 'FederatedIdentityCredentials'
| mv-expand FederatedCredentials
// Enrich GitHub Federation Details
| parse FederatedCredentials.Subject with * "repo:" _GitHubOrganization: string "@" _GitHubOrganizationImmutableId: int "/" _GitHubRepository: string "@" _GitHubRepositoryImmutableId: int ":ref:" _GitHubRefs: string
| extend GitHubConfig = todynamic(
                            iif(
                                FederatedCredentials.Issuer == "https://token.actions.githubusercontent.com",
                                bag_pack("Organization", _GitHubOrganization, "OrganizationId", _GitHubOrganizationImmutableId, "Repository", _GitHubRepository, "RepositoryId", _GitHubRepositoryImmutableId),
                                "[]"
                            )
                        )
| evaluate bag_unpack(FederatedCredentials, "FederatedCredential")
//| evaluate bag_unpack(GitHubConfig)
| project-away
    _*,
    FederatedCredentialClaimsMatchingExpressionLanguageVersion,
    FederatedCredentialEncodingVersion
| project-reorder
    TimeGenerated,
    ServicePrincipalName,
    ServicePrincipalId,
    FederatedCredential*,
    GitHubConfig,
    Actor,
    ActorId,
    IpAddress
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-github-immutable-subjects>

### MITRE ATT&CK Tags

* **Tactic:** Persistence (TA0003) & Privilege Escalation (TA0004)
* **Technique:**
    * Account Manipulation: Additional Cloud Credentials (T1098.001 )
