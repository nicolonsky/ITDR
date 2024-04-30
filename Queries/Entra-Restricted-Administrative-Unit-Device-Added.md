# Entra-Restricted-Administrative-Unit-Device-Added

KQL Query to detect device provisioning / enrollment of a new Admin Workstation into a restricted administrative unit.

## Query

```kusto
// 
// Add the ID of the created administrative unit to the below datatable for filtering
let RestrictedAdministrativeUnits = datatable (AdministrativeUnitDisplayName:string,AdministrativeUnitObjectID:string )[
    "Tier0-PrivilegedAccessWorkstations", "e8907152-8af4-4844-b372-56ada19a33ba" // adjust this
];
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName == "Add member to restricted management administrative unit"
| mv-expand TargetResources
| mv-apply mp = parse_json(TargetResources.modifiedProperties) on ( 
    where mp.displayName =~ "AdministrativeUnit.DisplayName"
    | extend AdministrativeUnitDisplayName = replace_string(tostring(mp.newValue), '"', '')
    )
| mv-apply mp = TargetResources.modifiedProperties on ( 
    where mp.displayName =~ "AdministrativeUnit.ObjectID"
    | extend AdministrativeUnitObjectID = replace_string(tostring(mp.newValue), '"', '')
    )
| where TargetResources.type == "Device"
| join kind=inner RestrictedAdministrativeUnits on AdministrativeUnitObjectID
| extend DeviceName = TargetResources.displayName
| extend DeviceId = TargetResources.id
| project
    TimeGenerated,
    AdministrativeUnitDisplayName,
    AdministrativeUnitObjectID,
    DeviceName,
    DeviceId,
    OperationName
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A