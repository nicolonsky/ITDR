# MDE-Entra-Connect-Version

KQL Query to find servers running Entra Connect Sync (aka the good old Azure AD Connect) and the corresponding version. You can use this to find [Retiring or Deprecated Microsoft Entra Connect versions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history#retiring-microsoft-entra-connect-2x-versions).

## Query

### Defender XDR
```kusto
DeviceTvmSoftwareInventory
| where SoftwareName == @"microsoft_azure_ad_connect"
| project DeviceName, SoftwareName, SoftwareVersion
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
