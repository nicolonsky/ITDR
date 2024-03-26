# Exposure-Management-Privileged-Account-Exposure

⚠️ Draft

Microsoft Security Exposure Management correlates insights from various Microsoft security solutions in the Defender XDR portal.
The following query hunts for privileged cloud account credential exposure on assets and correlates additional accounts that sign-in to the same devices.
This shows potential attack scenarios for credential theft or cached tokens.

## Query

```kusto
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId 
| graph-match (standardUser)-[obtains]-(exposedAsset)-[attacks]->(target)
  where standardUser.NodeLabel  =~ 'user' and exposedAsset.NodeLabel  =~ "device"  and array_length( target.NodeProperties.rawData.assignedRoles) > 0
  project ExposedDevice = exposedAsset.NodeName, ExposedAdminAccount = target.NodeName, ExposedDirectoryRole = target.NodeProperties.rawData.assignedRoles, ExposedStandardAccount = standardUser.NodeName
  | summarize make_set(ExposedStandardAccount), make_set(ExposedDevice) by ExposedAdminAccount, tostring(ExposedDirectoryRole)
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://techcommunity.microsoft.com/t5/security-compliance-and-identity/introducing-microsoft-security-exposure-management/ba-p/4080907>


### MITRE ATT&CK Tags

* **Tactic:** Credential Access (TA0006)
* **Technique:**
    * Credentials from Password Stores (T1555)
    * Compromise Accounts (T1586)
