# Entra-Stale-App-Registrations

Find stale app registrations in your Entra ID tenant by reviewing the sign-in logs.
Export a CSV of all your app registrations via Entra portal and add them to the datatable below.

## Query

```kusto
let AppRegistrations =  datatable (AppId: string, AppDisplayName: string)[
    "ab063be5-fa73-4886-ba5a-e53b903011a7", "Blabla"
];
// Get last activity per App Registration
AppRegistrations
| join kind=leftouter (AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(90d)
    | summarize arg_max(TimeGenerated, *) by ServicePrincipalId)
    on AppId
| project
    AppDisplayName,
    ResourceDisplayName,
    LastActivity = TimeGenerated

```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A