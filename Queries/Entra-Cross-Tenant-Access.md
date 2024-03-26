# Entra-Cross-Tenant-Access

Review cross tenant access from your users to other tenants where they reside as guests (outbound access).

## Query

```kusto
let LookBack = 90d;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(LookBack)
| where CrossTenantAccessType != 'none'
| where ResourceTenantId !in~ (
    '<TID>', // Enter your Tenant ID
    '72f988bf-86f1-41af-91ab-2d7cd011db47' // Microsoft
    )
| summarize dcount(UserPrincipalName) by ResourceTenantId
```
Export the query results as CSV. To parse the tenant IDs to Display Name and Domain Name, you can use the Microsoft Graph API and the following PowerShell snippet:

```powershell
# sentinel export
$reportPath = '~/Downloads/query_data.csv' 

$translatedDomains = @{}

Import-Csv -Path $reportPath -ErrorAction Stop -Encoding UTF8 | ForEach-Object {
    $params = @{
        'Uri'         = "https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByDomainName(domainName='{0}')" -f $_.ResourceTenantId
        'ContentType' = 'application/json'
        'Method'      = 'GET'
        'Headers'     = @{
            'authorization' = (Get-Clipboard) # copy bearer JWT to your clipboard
        }
    }
    
    $response = Invoke-RestMethod @params
    $translatedDomains.Add($_.ResourceTenantId, [PSCustomObject]@{
            displayName       = $response.displayName
            defaultDomainName = $response.defaultDomainName
        })
}

$translatedDomains.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
        TenantId          = $_.Key
        DisplayName       = $_.Value.displayName
        DefaultDomainName = $_.Value.defaultDomainName
    }
} | Export-Csv '~/Downloads/parsed_tenant_ids.csv'
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview>


### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
