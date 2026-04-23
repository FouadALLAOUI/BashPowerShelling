# Storage CMK Compliance Scripts

This repository contains two PowerShell scripts:

- `Get-NonCompliantStorageAccounts.ps1`: audits storage accounts and exports accounts not using CMK.
- `Set-CMKEncryptionOnStorageAccounts.ps1`: remediates non-compliant accounts by enabling CMK encryption.

## What You Need

- Windows PowerShell 5.1+ or PowerShell 7+
- Azure permissions:
  - Read subscriptions/storage accounts for audit
  - Update storage accounts (identity + encryption settings) for remediation
  - Key Vault permissions management (RBAC assignment or access policy update)
- Azure PowerShell modules:
  - `Az.Accounts`
  - `Az.Storage`
  - `Az.KeyVault`
  - `Az.Resources` (used for role assignment cmdlets)

Install modules (current user):

```powershell
Install-Module Az.Accounts,Az.Storage,Az.KeyVault,Az.Resources -Scope CurrentUser -Force
```

## 1) Run the Audit Script

From this folder:

```powershell
cd "c:\Users\Fouad\Desktop\Projects\BashPowerShelling"
```

Scan all enabled subscriptions:

```powershell
.\Get-NonCompliantStorageAccounts.ps1
```

Scan specific subscriptions only:

```powershell
.\Get-NonCompliantStorageAccounts.ps1 -SubscriptionIds "sub-id-1","sub-id-2"
```

Use a custom output path:

```powershell
.\Get-NonCompliantStorageAccounts.ps1 -OutputCsvPath ".\NonCompliant_Custom.csv"
```

The script generates a CSV report like:

- `.\NonCompliant_StorageAccounts_yyyyMMdd_HHmmss.csv`

## 2) Run Remediation (Enable CMK)

### Dry Run First (Recommended)

This shows what would be changed without applying changes:

```powershell
.\Set-CMKEncryptionOnStorageAccounts.ps1 `
  -KeyVaultName "kv-cmk-prod" `
  -KeyVaultResourceGroup "rg-kv-prod" `
  -KeyVaultSubscriptionId "kv-subscription-id" `
  -KeyName "storage-cmk-key" `
  -AuditCsvPath ".\NonCompliant_StorageAccounts_yyyyMMdd_HHmmss.csv" `
  -WhatIf
```

### Apply Changes Using Audit CSV

```powershell
.\Set-CMKEncryptionOnStorageAccounts.ps1 `
  -KeyVaultName "kv-cmk-prod" `
  -KeyVaultResourceGroup "rg-kv-prod" `
  -KeyVaultSubscriptionId "kv-subscription-id" `
  -KeyName "storage-cmk-key" `
  -AuditCsvPath ".\NonCompliant_StorageAccounts_yyyyMMdd_HHmmss.csv"
```

### Apply Changes by Live Scan (No CSV)

If `-AuditCsvPath` is not provided, the script scans target subscriptions and remediates live:

```powershell
.\Set-CMKEncryptionOnStorageAccounts.ps1 `
  -KeyVaultName "kv-cmk-prod" `
  -KeyVaultResourceGroup "rg-kv-prod" `
  -KeyVaultSubscriptionId "kv-subscription-id" `
  -KeyName "storage-cmk-key" `
  -SubscriptionIds "sub-id-1","sub-id-2"
```

### Skip Confirmation Prompt

```powershell
.\Set-CMKEncryptionOnStorageAccounts.ps1 `
  -KeyVaultName "kv-cmk-prod" `
  -KeyVaultResourceGroup "rg-kv-prod" `
  -KeyVaultSubscriptionId "kv-subscription-id" `
  -KeyName "storage-cmk-key" `
  -AuditCsvPath ".\NonCompliant_StorageAccounts_yyyyMMdd_HHmmss.csv" `
  -Force
```

Remediation outputs a report:

- `.\RemediationReport_yyyyMMdd_HHmmss.csv`

## 3) Rollback Plan

Use this plan if remediation causes unexpected impact (application errors, key permission issues, or broad failures).

### A. Immediate containment

1. Stop new executions:
   - Disable the Azure DevOps pipeline trigger or pause manual runs.
2. Keep evidence:
   - Preserve the latest audit CSV and remediation report artifact.
3. Scope impact:
   - Filter `Status = Success` in remediation report to identify accounts that changed.

### B. Per-account rollback options

#### Option 1 (preferred): move back to previous CMK version

Use this when the account should remain CMK-encrypted, but the latest key/version caused issues.

```powershell
Set-AzStorageAccount -ResourceGroupName "<rg>" -Name "<storage-account>" `
  -KeyvaultEncryption `
  -KeyVaultUri "<kv-uri>" `
  -KeyName "<key-name>" `
  -KeyVersion "<previous-working-version>"
```

#### Option 2 (emergency): switch to Microsoft-managed keys (MMK)

Use this only as a temporary emergency measure, if your policy allows MMK fallback.

```powershell
az storage account update `
  --resource-group "<rg>" `
  --name "<storage-account>" `
  --encryption-key-source Microsoft.Storage
```

### C. Validate rollback

```powershell
Get-AzStorageAccount -ResourceGroupName "<rg>" -Name "<storage-account>" |
  Select-Object StorageAccountName,@{N='KeySource';E={$_.Encryption.KeySource}}
```

- `Microsoft.Keyvault` means CMK is active.
- `Microsoft.Storage` means MMK is active.

### D. Recover safely

1. Fix root cause (permissions, key state, wrong key version, etc.).
2. Re-run remediation in `-WhatIf` mode first.
3. Re-apply remediation for a small subset before full rollout.

## 4) Automated Rollback Script

Use `Rollback-CMKEncryption.ps1` to rollback from a CSV list.

### Rollback to previous CMK version

CSV must include these columns (or equivalent configured by parameters):

- `SubscriptionId` (or pass `-DefaultSubscriptionId`)
- `ResourceGroup`
- `StorageAccountName`
- `PreviousKeyVaultUri` (or `KeyVaultUri`)
- `PreviousKeyName` (or `KeyName`)
- `PreviousKeyVersion` (or `KeyVersion`)

Dry run:

```powershell
.\Rollback-CMKEncryption.ps1 `
  -CsvPath ".\RollbackTargets.csv" `
  -Mode PreviousCmk `
  -WhatIf
```

Apply:

```powershell
.\Rollback-CMKEncryption.ps1 `
  -CsvPath ".\RollbackTargets.csv" `
  -Mode PreviousCmk `
  -Force
```

### Emergency rollback to MMK

Dry run:

```powershell
.\Rollback-CMKEncryption.ps1 `
  -CsvPath ".\RollbackTargets.csv" `
  -Mode Mmk `
  -WhatIf
```

Apply:

```powershell
.\Rollback-CMKEncryption.ps1 `
  -CsvPath ".\RollbackTargets.csv" `
  -Mode Mmk `
  -Force
```

The script writes:

- `.\RollbackReport_yyyyMMdd_HHmmss.csv`

## Notes

- `WhatIf` mode does not modify Azure resources.
- If your Key Vault uses RBAC authorization, the script assigns the required crypto role to each storage account managed identity.
- If your Key Vault uses access policies, the script sets key permissions (`get`, `wrapKey`, `unwrapKey`) for each identity.
- For new identity assignments, principal propagation can take a short time; the remediation script includes retry logic.

## Troubleshooting

- **No subscriptions found**: confirm account access and provided subscription IDs.
- **Key Vault/key not found**: verify `-KeyVaultName`, `-KeyVaultResourceGroup`, `-KeyVaultSubscriptionId`, and `-KeyName`.
- **Permission errors**: verify your operator account has rights on target subscriptions and Key Vault.
- **CSV path error**: confirm the file path passed to `-AuditCsvPath` exists.
