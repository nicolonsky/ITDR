# MDE-Entra-Connect-Version

KQL Query to find servers running Entra Connect Sync (aka the good old Azure AD Connect) and the corresponding version. You can use this to find [Retiring or Deprecated Microsoft Entra Connect versions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history#retiring-microsoft-entra-connect-2x-versions).

## Query

### Defender XDR
```kusto
DeviceTvmSoftwareInventory
| where SoftwareName in (@"microsoft_entra_connect_sync", @"microsoft_azure_ad_connect")
| project DeviceName, SoftwareName, SoftwareVersion
```

Advanced query including support information (might wanna double check this one /w Microsoft docs):
```kusto
// https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history#retiring-microsoft-entra-connect-2x-versions
let EntraConnectVersions = datatable (SoftwareVersion: string, SupportEndDate: datetime) [ 
    "2.1.20.0", datetime("2024-06-19"), 
    "2.2.1.0", datetime("2024-10-11"),
    "2.2.8.0", datetime("2024-12-12"),
    "2.3.2.0", datetime("2025-02-21"),
    "2.3.6.0", datetime("2025-04-01"),
    "2.3.8.0", datetime("2025-04-30"),
    "2.3.20.0", datetime("2025-04-30"),
    "2.4.18.0", datetime("2025-10-09"),
    "2.4.21.0", datetime("2025-11-15"),
    "2.4.27.0", datetime("2026-01-15"),
    "2.4.129.0", datetime("2026-03-27"),
    "2.4.131.0", datetime("2026-05-26"),
    "2.5.3.0", datetime("2026-07-31"),
    "2.5.76.0", datetime("2026-09-01")
];
let LatestVersion = toscalar(EntraConnectVersions
    | summarize arg_max(SoftwareVersion, *)
    | project SoftwareVersion);
DeviceTvmSoftwareInventory
| where SoftwareName in (@"microsoft_entra_connect_sync", @"microsoft_azure_ad_connect")
| lookup EntraConnectVersions on SoftwareVersion
| extend isSupported = tostring(toboolean(isnotempty(SupportEndDate) and datetime_diff('day', SupportEndDate, now()) > 0) or (parse_version(SoftwareVersion) > parse_version(LatestVersion)))
| project DeviceName, SoftwareName, SoftwareVersion, SupportEndDate, isSupported
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* [Retiring Microsoft Entra Connect 2.x versions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history#retiring-microsoft-entra-connect-2x-versions)

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
