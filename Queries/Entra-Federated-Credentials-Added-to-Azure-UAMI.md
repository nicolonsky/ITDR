# Federated Credentials Added to Azure Managed Identity


### Entra Audit Logs

Tracking additions of federated credentials to Azure User Assigned Managed Identities via Entra `AuditLog`.

```kusto
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Update service principal"
| extend Actor = tostring(coalesce(InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName ))
| extend ActorId = tostring(coalesce(InitiatedBy.user.id, InitiatedBy.app.servicePrincipalId ))
| mv-expand TargetResources
| extend ServicePrincipalName = tostring(TargetResources.displayName)
| extend ServicePrincipalId = tostring(TargetResources.id)
| mv-expand _MP = todynamic(TargetResources.modifiedProperties)
// Little hack to only get modified creds & properly access the array
| extend FederatedCredentials = set_difference(parse_json(tostring(_MP.newValue)), parse_json(tostring(_MP.oldValue)))
| where _MP.displayName == 'FederatedIdentityCredentials'
| mv-expand FederatedCredentials
| evaluate bag_unpack(FederatedCredentials, "FederatedCredential")
| project-away _*
```

### Azure Activity Logs

Tracking modifications of federated credentials to Azure User Assigned Managed Identities via `AzureActivity`.

```kusto
AzureActivity
| where TimeGenerated > ago(90d)
| where OperationNameValue =~ "MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS/WRITE"
| extend IdentityName = tostring(split(Properties_d.resource, "/")[0])
| extend FederatedCredentialName = tostring(split(Properties_d.resource, "/")[1])
| summarize Status = make_set(ActivityStatusValue, 100), arg_min(TimeGenerated, *)
    by
    CorrelationId
| project-reorder
    TimeGenerated,
    IdentityName,
    FederatedCredentialName,
    Caller,
    CallerIpAddress
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust-user-assigned-managed-identity>

### MITRE ATT&CK Tags

* **Tactic:** Persistence (TA0003) & Privilege Escalation (TA0004)
* **Technique:**
    * Account Manipulation: Additional Cloud Credentials (T1098.001 )
