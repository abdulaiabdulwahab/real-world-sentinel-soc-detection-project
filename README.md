# real-world-sentinel-soc-detection-project

# Real-World Microsoft Sentinel SOC Detection Project

## Project Overview

This project demonstrates how Microsoft Sentinel can be used to detect, investigate, and respond to potentially unauthorized Azure Network Security Group changes.

The project is fully self-contained and uses its own:

- Resource group
- Log Analytics workspace
- Microsoft Sentinel workspace
- Azure Activity diagnostic setting
- Virtual Network
- Network Security Group
- KQL detection queries
- Analytics rule
- Workbook
- Automation rule

The main objective was to simulate a SOC workflow where a suspicious NSG security rule modification is detected and investigated using Microsoft Sentinel.

## Architecture

```text
Azure Subscription
        |
        v
Azure Activity Log
        |
        v
Diagnostic Setting
        |
        v
Log Analytics Workspace
        |
        v
Microsoft Sentinel
        |
        +--> KQL Queries
        |
        +--> Analytics Rule
        |
        +--> Alert
        |
        +--> Incident
        |
        +--> Investigation
        |
        +--> Workbook
        |
        +--> Automation
```

## Resources Created

```text
Resource Group:
rg-sentinel-soc-project

Log Analytics Workspace:
law-sentinel-soc-xxxxx

Virtual Network:
vnet-sentinel-soc

Subnet:
snet-web

Network Security Group:
nsg-production-web

Diagnostic Setting:
diag-sentinel-soc-activity
```

## Main Technologies Used

- Microsoft Sentinel
- Azure Monitor
- Log Analytics
- Kusto Query Language (KQL)
- Azure Activity Logs
- Azure CLI
- Network Security Groups
- Microsoft Defender portal
- Sentinel Analytics Rules
- Sentinel Workbooks
- Sentinel Automation Rules

## Project Setup

### Create the resource group

```bash
az group create \
  --name rg-sentinel-soc-project \
  --location canadacentral
```

### Create the Log Analytics workspace

```bash
az monitor log-analytics workspace create \
  --resource-group rg-sentinel-soc-project \
  --workspace-name law-sentinel-soc-xxxxx \
  --location canadacentral
```

### Get the workspace resource ID

```bash
export LAW2_ID="$(az monitor log-analytics workspace show \
  --resource-group rg-sentinel-soc-project \
  --workspace-name law-sentinel-soc-xxxxx \
  --query id \
  --output tsv)"

echo "$LAW2_ID"
```

## Enable Microsoft Sentinel

Microsoft Sentinel was enabled on the dedicated Log Analytics workspace.

```text
Azure Portal
→ Microsoft Sentinel
→ Create
→ Select law-sentinel-soc-xxxxx
→ Add
```

## Configure Azure Activity Log Ingestion

A subscription-level diagnostic setting was created to send Azure Activity Logs to the Sentinel workspace.

```bash
az monitor diagnostic-settings subscription create \
  --name "diag-sentinel-soc-activity" \
  --workspace "$LAW2_ID" \
  --logs '[
    {
      "category": "Administrative",
      "enabled": true
    }
  ]'
```

Verify the setting:

```bash
az monitor diagnostic-settings subscription show \
  --name "diag-sentinel-soc-activity" \
  --output jsonc
```

## Create the Network Lab

### Create the VNet

```bash
az network vnet create \
  --resource-group rg-sentinel-soc-project \
  --name vnet-sentinel-soc \
  --location canadacentral \
  --address-prefixes 10.50.0.0/16 \
  --subnet-name snet-web \
  --subnet-prefixes 10.50.1.0/24
```

### Create the NSG

```bash
az network nsg create \
  --resource-group rg-sentinel-soc-project \
  --name nsg-production-web \
  --location canadacentral
```

## KQL Investigation

### View recent activity

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    ResourceGroup,
    _ResourceId
| order by TimeGenerated desc
```

### View NSG-related operations

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "NETWORKSECURITYGROUPS"
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    ResourceGroup,
    _ResourceId
| order by TimeGenerated desc
```

## Detection Query

The main detection looks for successful NSG security-rule modifications.

```kusto
AzureActivity
| where CategoryValue =~ "Administrative"
| where ActivityStatusValue =~ "Success"
| where OperationNameValue contains "NETWORKSECURITYGROUPS"
| where OperationNameValue contains "SECURITYRULES"
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ResourceGroup,
    _ResourceId,
    SubscriptionId,
    CorrelationId
```

This query was used to create a scheduled Sentinel analytics rule named:

```text
Unexpected NSG Security Rule Modification
```

## Simulating Suspicious Activity

A permissive SSH rule was created to generate a realistic security event.

```bash
az network nsg rule create \
  --resource-group rg-sentinel-soc-project \
  --nsg-name nsg-production-web \
  --name AllowInternetSSH \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges 22
```

This generated Azure Activity telemetry that Sentinel could detect.

## Incident Investigation

The Sentinel incident was investigated using:

```text
Caller
CallerIpAddress
OperationNameValue
ResourceGroup
_ResourceId
SubscriptionId
CorrelationId
```

The caller's wider activity could be investigated using:

```kusto
let SuspiciousCaller = "<CALLER>";

AzureActivity
| where TimeGenerated > ago(24h)
| where Caller =~ SuspiciousCaller
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    ResourceGroup,
    _ResourceId
| order by TimeGenerated desc
```

## Correlation ID Investigation

The `CorrelationId` may not automatically appear in the Sentinel incident screen, so it can be retrieved directly from `AzureActivity`.

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ResourceGroup =~ "rg-sentinel-soc-project"
| where isnotempty(CorrelationId)
| project
    TimeGenerated,
    CorrelationId,
    Caller,
    OperationNameValue,
    _ResourceId
| order by TimeGenerated desc
```

Related operations can then be investigated with:

```kusto
let InvestigationCorrelationId = "<CORRELATION-ID>";

AzureActivity
| where CorrelationId == InvestigationCorrelationId
| order by TimeGenerated asc
```

## Workbook

A basic Sentinel workbook was created to visualize:

- Network changes over time
- Most active identities
- Changes by resource group
- NSG security-rule modifications

Example query:

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "MICROSOFT.NETWORK"
| summarize Changes=count()
    by bin(TimeGenerated, 1h)
```

## Automation

A Sentinel automation rule was configured to handle incidents created by the NSG detection.

Example actions:

```text
Set severity to High
Add NetworkSecurity tag
Add NSGChange tag
Create investigation tasks
```

## Troubleshooting

### AzureActivity returns no results

Check the subscription diagnostic setting:

```bash
az monitor diagnostic-settings subscription list \
  --query "value[].{Name:name,Workspace:workspaceId}" \
  --output table
```

Make sure:

```text
diag-sentinel-soc-activity
```

points to the Project 2 workspace.

Also verify Azure itself has Activity Log events:

```bash
az monitor activity-log list \
  --resource-group rg-sentinel-soc-project \
  --offset 1h \
  --output table
```

### AzureActivity table is not found

Confirm that Azure Activity Logs are being exported to the Log Analytics workspace and that you are querying the correct Project 2 workspace.

### Git Bash modifies Azure resource IDs

Use:

```bash
export MSYS_NO_PATHCONV=1
```

before working with Azure ARM resource IDs.

### Defender portal opens the wrong tenant

Use:

```text
https://security.microsoft.com/?tid=<TENANT-ID>
```

Get the tenant ID with:

```bash
az account show \
  --query tenantId \
  --output tsv
```

## Skills Practiced

This project provided hands-on experience with:

- Microsoft Sentinel
- SIEM concepts
- Security monitoring
- KQL
- Azure Activity Logs
- Log Analytics
- Diagnostic Settings
- Azure Networking
- NSG security monitoring
- Detection engineering
- Analytics rules
- Incident investigation
- Threat hunting
- Workbooks
- Automation rules
- Azure CLI
- SOC workflows

## Cleanup

Remove the subscription diagnostic setting first:

```bash
az monitor diagnostic-settings subscription delete \
  --name "diag-sentinel-soc-activity"
```

Then delete the Project 2 resource group:

```bash
az group delete \
  --name rg-sentinel-soc-project \
  --yes \
  --no-wait
```

## Key Learning

This project demonstrated the full Microsoft Sentinel security-monitoring lifecycle:

```text
Collect
  ↓
Ingest
  ↓
Query
  ↓
Detect
  ↓
Alert
  ↓
Investigate
  ↓
Hunt
  ↓
Visualize
  ↓
Automate
```

The project also demonstrated how Microsoft Sentinel can monitor Azure infrastructure changes and help a SOC identify potentially unauthorized network-security modifications.

## Conclusion

This project provided a practical example of using Microsoft Sentinel as a cloud-native SIEM platform.

By combining Azure Activity Logs, Log Analytics, KQL, analytics rules, incidents, threat hunting, workbooks, and automation, the project demonstrated how Azure security events can be detected and investigated through a centralized SOC workflow.