# Entra-Password-Protection

Microsoft Entra Password Protection for Active Directory Domain Services protects on-premises and hybrid Accounts from using known weak, breached or custom banned passwords.
Having coverage around AD domains and domain controllers is important and can be tracked with the following KQL queries in Defender XDR, if you have Defender for Endpoint deployed.

## Entra Password Protection Proxy Servers (Defender XDR)

You can identify Entra Password Protection Proxies with the following KQL query:

```kusto
DeviceTvmSoftwareInventory
| where SoftwareName == @"azure_ad_password_protection_proxy_bundle"
```

## Entra Password Protection DCAgent (Defender XDR)

You can identify Entra Password Protection DC Agent on Domain Controllers based on the following KQL query:

```kusto
// Determine Azure AD PasswordProtection DC Agent based on DeviceRegistryEvents which contains heartbeat info
DeviceRegistryEvents
| where RegistryKey has "AzureADPasswordProtectionDCAgent"
| where RegistryValueName == @"HeartbeatCookie"
| extend RegistryValueData = parse_json(RegistryValueData)
| extend Version = tostring(RegistryValueData.Version)
| extend HeartbeatTimeUTC = todatetime(RegistryValueData.HeartbeatTimeUTC)
| summarize arg_max(HeartbeatTimeUTC, *) by DeviceName
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises>
* <https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-agent-versions>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
