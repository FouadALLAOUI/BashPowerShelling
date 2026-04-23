# =============================================================================
# AUDIT: List All Storage Accounts NOT Encrypted with CMK (Customer-Managed Key)
# Scans all accessible subscriptions and exports a CSV report
# =============================================================================

#Requires -Modules Az.Accounts, Az.Storage

param(
    # Output report path. A timestamped filename is used by default.
    [string]$OutputCsvPath = ".\NonCompliant_StorageAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    # Optional: specific subscriptions to scan. If omitted, all enabled subscriptions are scanned.
    [string[]]$SubscriptionIds = @()   # Leave empty to scan ALL subscriptions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 1. Connect ────────────────────────────────────────────────────────────────
Write-Host "`n[*] Connecting to Azure..." -ForegroundColor Cyan
if (-not (Get-AzContext)) {
    Connect-AzAccount -ErrorAction Stop
}

# ── 2. Resolve subscriptions ──────────────────────────────────────────────────
if ($SubscriptionIds.Count -gt 0) {
    # Resolve only user-provided subscription IDs.
    $subscriptions = $SubscriptionIds | ForEach-Object {
        Get-AzSubscription -SubscriptionId $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_ -and $_.State -eq "Enabled" }
} else {
    # Default behavior: include every subscription where state is Enabled.
    $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
}

if ($subscriptions.Count -eq 0) {
    throw "No enabled subscriptions were resolved. Check your account access and any provided -SubscriptionIds."
}

Write-Host "[*] Subscriptions to scan : $($subscriptions.Count)" -ForegroundColor Cyan

# ── 3. Scan ───────────────────────────────────────────────────────────────────
$nonCompliant = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalScanned = 0

foreach ($sub in $subscriptions) {
    Write-Host "`n  -> Subscription : $($sub.Name)  [$($sub.Id)]" -ForegroundColor Yellow

    try {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "     Could not switch to subscription $($sub.Id): $_"
        continue
    }

    # Retrieve all storage accounts visible in the current subscription context.
    $storageAccounts = Get-AzStorageAccount -ErrorAction Stop

    foreach ($sa in $storageAccounts) {
        $totalScanned++

        # KeySource tells whether account encryption uses Microsoft-managed keys (MMK)
        # or customer-managed keys (CMK in Key Vault).
        $encryptionSource = $sa.Encryption.KeySource

        # CMK = "Microsoft.Keyvault" ; MMK (default) = "Microsoft.Storage"
        if ($encryptionSource -ne "Microsoft.Keyvault") {

            # KeyVaultProperties can be null for non-CMK accounts, so keep access null-safe.
            $keyVaultProp = $sa.Encryption.KeyVaultProperties

            $nonCompliant.Add([PSCustomObject]@{
                SubscriptionId      = $sub.Id
                SubscriptionName    = $sub.Name
                ResourceGroup       = $sa.ResourceGroupName
                StorageAccountName  = $sa.StorageAccountName
                Location            = $sa.Location
                SkuName             = $sa.Sku.Name
                Kind                = $sa.Kind
                EncryptionKeySource = $encryptionSource    # Microsoft.Storage = MMK
                KeyVaultUri         = $keyVaultProp.KeyVaultUri
                KeyName             = $keyVaultProp.KeyName
                KeyVersion          = $keyVaultProp.KeyVersion
                IdentityType        = $sa.Identity.Type
                ResourceId          = $sa.Id
            })

            Write-Host "     [NON-COMPLIANT] $($sa.StorageAccountName)" -ForegroundColor Red
        } else {
            Write-Host "     [OK]            $($sa.StorageAccountName)" -ForegroundColor Green
        }
    }
}

# ── 4. Report ─────────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Total storage accounts scanned : $totalScanned"
Write-Host "  Non-compliant (no CMK)         : $($nonCompliant.Count)" -ForegroundColor Red
Write-Host "============================================================`n" -ForegroundColor Cyan

if ($nonCompliant.Count -gt 0) {
    # Persist full remediation input data to CSV for downstream remediation script usage.
    $nonCompliant | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Report saved to : $OutputCsvPath" -ForegroundColor Green
    $nonCompliant | Format-Table SubscriptionName, ResourceGroup, StorageAccountName, Location, EncryptionKeySource -AutoSize
} else {
    Write-Host "[+] All storage accounts are already encrypted with CMK. Nothing to remediate." -ForegroundColor Green
}
