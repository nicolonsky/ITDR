# Entra-SigninLogs-SessionId-Investigation


Microsoft started surfacing the SessionId within Entra ID which helps to link all authentication artifacts issued from a single root authentication with the same identifier, which can be used to link or connect tokens in a single chain together.
The following query provides an example on how to investigate user activity within Defender for Cloud Apps (which again includes Exchange, SharePoint...) and Microsoft Graph Activity Logs based on the Entra Session ID.

## Sentinel or Unified SecOps Portal

```kusto
let InvestigtionSessionId = '00406c49-6e50-4d97-3a65-780c9c0d8642';
let LookBack = 190d;
union
    (
    CloudAppEvents
    | where TimeGenerated > ago(LookBack)
    | extend SessionId = tostring(RawEventData.AppAccessContext.AADSessionId)
    | where SessionId =~ InvestigtionSessionId
    | extend UniqueTokenIdentifier = tostring(RawEventData.AppAccessContext.UniqueTokenId)
    | extend CorrelationId = tostring(RawEventData.AppAccessContext.CorrelationId)
    | where isnotempty(SessionId)
    | join kind=inner (
        union SigninLogs, AADNonInteractiveUserSignInLogs
        )
        on SessionId
    | extend ActivityIP = coalesce(RawEventData.DeviceDisplayName, RawEventData.ClientIP)
    ),
    (
    MicrosoftGraphActivityLogs
    | where TimeGenerated > ago(LookBack)
    | project-rename UniqueTokenIdentifier= SignInActivityId
    | join kind=inner (
        union SigninLogs, AADNonInteractiveUserSignInLogs
        | where SessionId =~ InvestigtionSessionId
        )
        on UniqueTokenIdentifier
    )
```

## Hunt Tags

* **Author:** [Nicola Suter](https://nicolasuter.ch)
* **License:** [MIT License](https://github.com/nicolonsky/ITDR/blob/main/LICENSE)

### Additional information

* <https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-track-linkable-identifiers>

### MITRE ATT&CK Tags

* **Tactic:**
  * T1078 (Valid Accounts)
  * T1606 (Forge Web Credentials)
* **Technique:**
    * T1078.004 (Cloud Accounts)
    * T1606.001 (Web Cookies)


