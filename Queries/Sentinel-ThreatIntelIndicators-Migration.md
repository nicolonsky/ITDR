# Sentinel-ThreatIntelIndicators-Migration

Microsoft is introducing an improved data schema for Threat Intelligence across Log Analytics (Azure experience) and Advanced Hunting (Unified Security Operations Platform experience), with the launch of two new tables:
* ThreatIntelIndicators
* ThreatIntelObjects 

From 31. July 2025 data ingestion will transition exclusively to the new ThreatIntelIndicators and ThreatIntelObjects tables.
The legacy ThreatIntelligenceIndicator table (and its data) will remain accessible, but no new data will be ingested there. 
**Any custom content, such as workbooks, queries, or analytic rules, must be updated to target the new tables to remain effective.**

The below kusto query helps to identify Sentinel Anyltic Rules that reference the old `ThreatIntelligenceIndicator` table based on the Sentinel Audit Logs (not enabled by default) and historical alerts.

## Sentinel or Unified SecOps Portal

```kusto
let LookBack = 90d;
union
    (SecurityAlert
    | where TimeGenerated > ago(LookBack)
    | extend EP = parse_json(ExtendedProperties)
    | where EP.Query has 'ThreatIntelligenceIndicator'
    | extend AnalyticRule = tostring(EP.['Analytic Rule Name'])
    ),
    (
    SentinelAudit
    | where TimeGenerated > ago(LookBack)
    | where Description =~ "Create or update analytics rule."
    | extend Query = extract_json("$.properties.query", tostring(ExtendedProperties.UpdatedResourceState))
    | where Query has 'ThreatIntelligenceIndicator'
    | project-rename AnalyticRule = SentinelResourceName
    )
| distinct AnalyticRule
```

## PowerShell (Azure REST API)

Charbel Nemnom published a nice snippet leveraging the REST API to identify matches: <https://charbelnemnom.com/sentinel-threat-intelligence-advanced-modeling/#Method_2_Using_Sentinel_REST_API>. This has the advantage that also rules not modified or firing incidents recently will be checked against references to the `ThreatIntelligenceIndicator` table.

```powershell
Connect-AzAccount #-Tenant dev.nicolasuter.ch

$params = @{
	'ResourceGroupName' = '<rg>'
	'WorkspaceName' = '<workspace>
}

Get-AzSentinelAlertRule @params | Where-Object {$_.Query -match 'ThreatIntelligenceIndicator'} `
	| Select-Object -Property DisplayName, Enabled
```
![image](https://github.com/user-attachments/assets/1a9e1132-3a51-467e-8f14-a979933d1cb7)

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://techcommunity.microsoft.com/blog/microsoftsentinelblog/announcing-public-preview-new-stix-objects-in-microsoft-sentinel/4369164>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
