# Connect via GitHub codespaces to dev environment

# Azure
Disable-AzContextAutosave
$clientSecret = ConvertTo-SecureString $env:CLIENT_SECRET -AsPlainText -Force
$credentials = [System.Management.Automation.PSCredential]::new($env:APPLICATION_ID, $clientSecret)
Connect-AzAccount -Tenant $env:TENANT_ID -Subscription $env:SUBSCRIPTION_ID -Credential $credentials -ServicePrincipal

# Micrososft Graph
Connect-MgGraph -TenantId $env:TENANT_ID -ClientSecretCredential $credentials