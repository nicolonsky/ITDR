# XDR-Contain-User-Sense

Microsoft Defender XDR attack disruption can initiate the 'contain user' automated response action. This is based on Microsoft Defender for Endpoint's capability, this response action automatically contains suspicious identities temporarily to help block any lateral movement and remote encryption related to incoming communication with Defender for Endpoint's onboarded devices.
The Minimum Sense Agent version required for the Contain User action to work is v10.8470. This can be checked with the below KQL query.

## Check the Minimum Sense Agent version

```kusto
let MinimumVersion = parse_version("10.8470");
DeviceTvmSoftwareInventory
| where SoftwareName == @"defender_for_endpoint"
| where parse_version(SoftwareVersion) < MinimumVersion
| project DeviceName, OSPlatform, SoftwareName, SoftwareVersion
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption?source=recommendations#minimum-sense-client-version-mde-client>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
