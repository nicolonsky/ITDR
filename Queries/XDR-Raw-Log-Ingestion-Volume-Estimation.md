# XDR-Raw-Log-Ingestion-Volume-Estimation

The Microsoft Defender XDR connector for Microsoft Sentinel allows streaming of Microsoft Defender XDR advanced hunting events into Microsoft Sentinel. To estimate the ingestion volume (and costs) for the individual advanced hunting tables you can use the following KQL query which provides the amount of data ingested per table on a daily average.

![image](https://github.com/user-attachments/assets/5d536f97-67e6-449a-98b2-9a32290af829)


## Defender XDR

```kusto
union withsource=_TableName
    // Defender for Identity (MDI)
    IdentityDirectoryEvents,
    IdentityInfo,
    IdentityLogonEvents,
    IdentityQueryEvents,
    // Defender for Endpoint (MDE)
    DeviceEvents,
    DeviceFileCertificateInfo,
    DeviceFileEvents,
    DeviceImageLoadEvents,
    DeviceInfo,
    DeviceLogonEvents,
    DeviceNetworkEvents,
    DeviceNetworkInfo,
    DeviceProcessEvents,
    DeviceRegistryEvents,
    // Defender for Office (MDO)
    EmailAttachmentInfo,
    EmailEvents,
    EmailPostDeliveryEvents,
    EmailUrlInfo,
    UrlClickEvents,
    // Defender for Cloud Apps (MDCA)
    CloudAppEvents
| where Timestamp between (ago(30d) .. ago(1d)) // lookback only over full days to get meaningful avg
| summarize BilledSize = sum(estimate_data_size(*)) by bin(Timestamp, 1d), _TableName
| summarize
    AvgBilledSizeDaily = format_bytes(avg(BilledSize), 3, "gb")
    by _TableName
| sort by AvgBilledSizeDaily desc
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender?tabs=MDE>

### MITRE ATT&CK Tags

* **Tactic:** N/A
* **Technique:**
    * N/A
