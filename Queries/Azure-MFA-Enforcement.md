# Azure-MFA-Enforcement

KQL queries regarding the mandatory multifactor authentication for Azure and other admin portals by Microsoft.

## Check the current MFA requirement provider for Portals

```kusto
let AffectedApps = dynamic([
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', // Azure portal
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', // Microsoft Entra admin center
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' // Microsoft Intune admin center
    // Early 2025 '04b07795-8ddb-461a-bbee-02f9e1bf7b46', // Azure command-line interface (Azure CLI)
    // Early 2025 '1950a258-227b-4e31-a9cf-717495945fc2', // Azure PowerShell
    // Early 2025 '0c1307d4-29d6-4389-a11c-5cbe7f65d7fa' // Azure mobile app 
    ]);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where AppId in (AffectedApps)
| mv-expand parse_json(AuthenticationRequirementPolicies)
| extend RequirementProvider = tostring(AuthenticationRequirementPolicies.requirementProvider)
| extend RequirementDetail = tostring(AuthenticationRequirementPolicies.detail)
// Requirement providers: [multiConditionalAccess, authenticationStrengths, riskBasedPolicy, request, mfaRegistrationRequiredByIdentityProtectionPolicy, user, proofUpCodeRequest]
//| where RequirementProvider =~ 'request'
| summarize count() by AppDisplayName, AppId, RequirementProvider, RequirementDetail
```

## Query user or apps without existing MFA Authentication Requirements

```kusto
let AffectedApps = dynamic([
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', // Azure portal
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c', // Microsoft Entra admin center
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' // Microsoft Intune admin center
    // Early 2025 '04b07795-8ddb-461a-bbee-02f9e1bf7b46', // Azure command-line interface (Azure CLI)
    // Early 2025 '1950a258-227b-4e31-a9cf-717495945fc2', // Azure PowerShell
    // Early 2025 '0c1307d4-29d6-4389-a11c-5cbe7f65d7fa' // Azure mobile app 
    ]);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(90d)
| where AppId in (AffectedApps)
| where AuthenticationRequirement !~ 'multiFactorAuthentication'
| summarize
    UserCount = dcount(UserPrincipalName),
    AffectedUsers = make_set(UserPrincipalName)
    by AppDisplayName, AppId, AuthenticationRequirement
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
