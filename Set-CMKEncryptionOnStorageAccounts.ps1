# =============================================================================
# REMEDIATION: Enable CMK Encryption on Non-Compliant Storage Accounts
# Works across all subscriptions. Requires a pre-existing Azure Key Vault + Key.
# =============================================================================

#Requires -Modules Az.Accounts, Az.Storage, Az.KeyVault, Az.ManagedServiceIdentity

param(
    # ── Key Vault settings (one KV per region or a global one) ────────────────
    [Parameter(Mandatory)]
    [string]$KeyVaultName,           # e.g. "kv-cmk-prod"

    [Parameter(Mandatory)]
    [string]$KeyVaultResourceGroup,  # RG that hosts the Key Vault

    [Parameter(Mandatory)]
    [string]$KeyVaultSubscriptionId, # Subscription that hosts the Key Vault

    [Parameter(Mandatory)]
    [string]$KeyName,                # Key name inside the KV, e.g. "storage-cmk-key"

    # ── Scope ─────────────────────────────────────────────────────────────────
    [string[]]$SubscriptionIds = @(), # Leave empty to target ALL subscriptions

    # ── Optional: path to the CSV produced by the audit script ────────────────
    [string]$AuditCsvPath = "",       # If provided, only remediates accounts in the CSV

    # ── Safety ────────────────────────────────────────────────────────────────
    [switch]$WhatIf,                  # Dry-run: show what would change, make no changes
    [switch]$Force                    # Skip confirmation prompts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "`n[STEP] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Fail  { param($msg) Write-Host " [FAIL] $msg" -ForegroundColor Red }
function Write-Info  { param($msg) Write-Host "  [..] $msg" -ForegroundColor Gray }

function Set-ContextSafe {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId
    )
    # Centralized context switching with explicit failures.
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}

function Get-StoragePrincipalIdWithRetry {
    param(
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$StorageAccountName,
        [int]$MaxAttempts = 6,
        [int]$DelaySeconds = 5
    )

    # Identity principal propagation can be eventually consistent.
    # Retry for a short period before failing.
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $saCurrent = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
        if ($saCurrent.Identity -and $saCurrent.Identity.PrincipalId) {
            return @{
                StorageAccount = $saCurrent
                PrincipalId    = $saCurrent.Identity.PrincipalId
            }
        }

        if ($attempt -lt $MaxAttempts) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    throw "Managed identity principal ID was not available after waiting. Try rerunning in a few minutes."
}

# ── 1. Connect ────────────────────────────────────────────────────────────────
Write-Step "Connecting to Azure"
if (-not (Get-AzContext)) { Connect-AzAccount -ErrorAction Stop }

# ── 2. Resolve Key Vault & Key ────────────────────────────────────────────────
Write-Step "Resolving Key Vault"
Set-ContextSafe -SubscriptionId $KeyVaultSubscriptionId

$kv = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultResourceGroup
if (-not $kv) { throw "Key Vault '$KeyVaultName' not found." }

# Get the latest key version
$kvKey = Get-AzKeyVaultKey -VaultName $KeyVaultName -Name $KeyName
if (-not $kvKey) { throw "Key '$KeyName' not found in Key Vault '$KeyVaultName'." }

$keyVaultUri  = $kv.VaultUri
$keyVersion   = $kvKey.Version
Write-OK "Key Vault URI : $keyVaultUri"
Write-OK "Key           : $KeyName  (version: $keyVersion)"

# ── 3. Resolve subscriptions ──────────────────────────────────────────────────
Write-Step "Resolving target subscriptions"
if ($SubscriptionIds.Count -gt 0) {
    # Resolve only provided subscriptions and keep enabled ones.
    $subscriptions = $SubscriptionIds | ForEach-Object {
        Get-AzSubscription -SubscriptionId $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_ -and $_.State -eq "Enabled" }
} else {
    # Default: resolve all enabled subscriptions available to current identity.
    $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
}
if ($subscriptions.Count -eq 0) {
    throw "No enabled target subscriptions were resolved. Check your account access and any provided -SubscriptionIds."
}
Write-OK "Subscriptions : $($subscriptions.Count)"

# ── 4. Build target list ──────────────────────────────────────────────────────
Write-Step "Building target storage account list"

$targets = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($AuditCsvPath) {
    if (-not (Test-Path $AuditCsvPath)) {
        throw "Audit CSV path was provided but file does not exist: $AuditCsvPath"
    }

    Write-Info "Loading targets from audit CSV: $AuditCsvPath"
    Import-Csv $AuditCsvPath | ForEach-Object {
        $targets.Add($_)
    }
    Write-OK "$($targets.Count) accounts loaded from CSV"
} else {
    Write-Info "No CSV provided — scanning subscriptions live..."
    foreach ($sub in $subscriptions) {
        Write-Info "Scanning: $($sub.Name) [$($sub.Id)]"
        Set-ContextSafe -SubscriptionId $sub.Id

        Get-AzStorageAccount | Where-Object {
            $_.Encryption.KeySource -ne "Microsoft.Keyvault"
        } | ForEach-Object {
            $targets.Add([PSCustomObject]@{
                SubscriptionId     = $sub.Id
                SubscriptionName   = $sub.Name
                ResourceGroup      = $_.ResourceGroupName
                StorageAccountName = $_.StorageAccountName
                Location           = $_.Location
                IdentityType       = $_.Identity.Type
                ResourceId         = $_.Id
            })
        }
    }
    Write-OK "$($targets.Count) non-compliant accounts found"
}

if ($targets.Count -eq 0) {
    Write-Host "`n[+] Nothing to remediate. All storage accounts are already CMK-encrypted." -ForegroundColor Green
    exit 0
}

# ── 5. Confirm ────────────────────────────────────────────────────────────────
if (-not $Force -and -not $WhatIf) {
    $targets | Format-Table SubscriptionName, ResourceGroup, StorageAccountName, Location -AutoSize
    $answer = Read-Host "`nAbout to enable CMK on $($targets.Count) storage accounts. Continue? [y/N]"
    if ($answer -notmatch '^[Yy]') { Write-Host "Aborted."; exit 0 }
}

# ── 6. Remediate ──────────────────────────────────────────────────────────────
Write-Step "Starting remediation $(if ($WhatIf) { '[WHATIF - DRY RUN]' })"

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$currentSubId = ""

foreach ($target in $targets) {

    $saName = $target.StorageAccountName
    $rg     = $target.ResourceGroup
    $subId  = $target.SubscriptionId

    Write-Host "`n  Storage Account : $saName  (RG: $rg, Sub: $($target.SubscriptionName))" -ForegroundColor Yellow

    $status = "Success"
    $notes  = ""

    try {
        # Switch subscription context only when needed
        if ($subId -ne $currentSubId) {
            Set-ContextSafe -SubscriptionId $subId
            $currentSubId = $subId
        }

        $sa = Get-AzStorageAccount -ResourceGroupName $rg -Name $saName

        # ── 6a. Ensure System-Assigned Managed Identity ───────────────────────
        if ($sa.Identity.Type -notmatch "SystemAssigned") {
            Write-Info "Assigning System-Assigned Managed Identity..."
            if (-not $WhatIf) {
                $sa = Set-AzStorageAccount -ResourceGroupName $rg -Name $saName `
                          -AssignIdentity
            }
            Write-OK "Identity assigned"
        } else {
            Write-OK "Identity already present: $($sa.Identity.Type)"
        }

        $principalId = $sa.Identity.PrincipalId
        if (-not $WhatIf -and -not $principalId) {
            $identityState = Get-StoragePrincipalIdWithRetry -ResourceGroupName $rg -StorageAccountName $saName
            $sa = $identityState.StorageAccount
            $principalId = $identityState.PrincipalId
        }

        # ── 6b. Grant Key Vault access to the storage account identity ────────
        Write-Info "Granting Key Vault permissions to managed identity ($principalId)..."
        if (-not $WhatIf) {
            # Switch to KV subscription to set policy, then switch back
            Set-ContextSafe -SubscriptionId $KeyVaultSubscriptionId

            # Use RBAC role assignment if KV is RBAC-enabled, otherwise access policy
            $kvFresh = Get-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $KeyVaultResourceGroup

            if ($kvFresh.EnableRbacAuthorization) {
                # Assign "Key Vault Crypto Service Encryption User" role
                $roleDefId = "e147488a-f6f5-4113-8e2d-b22465e65bf6"
                $scope = $kvFresh.ResourceId

                $existingAssignment = Get-AzRoleAssignment -ObjectId $principalId `
                    -RoleDefinitionId $roleDefId -Scope $scope -ErrorAction SilentlyContinue

                if (-not $existingAssignment) {
                    New-AzRoleAssignment -ObjectId $principalId `
                        -RoleDefinitionId $roleDefId -Scope $scope | Out-Null
                    Write-OK "RBAC role assigned on Key Vault"
                } else {
                    Write-OK "RBAC role already exists"
                }
            } else {
                # Classic access policy
                Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName `
                    -ResourceGroupName $KeyVaultResourceGroup `
                    -ObjectId $principalId `
                    -PermissionsToKeys @("get","wrapKey","unwrapKey") | Out-Null
                Write-OK "Access policy set on Key Vault"
            }

            # Switch back to storage account subscription
            Set-ContextSafe -SubscriptionId $subId
            $currentSubId = $subId
        }

        # ── 6c. Enable CMK encryption on the storage account ─────────────────
        Write-Info "Enabling CMK encryption..."
        if (-not $WhatIf) {
            Set-AzStorageAccount -ResourceGroupName $rg -Name $saName `
                -KeyvaultEncryption `
                -KeyVaultUri      $keyVaultUri `
                -KeyName          $KeyName `
                -KeyVersion       $keyVersion | Out-Null

            # Verify
            $saVerify = Get-AzStorageAccount -ResourceGroupName $rg -Name $saName
            if ($saVerify.Encryption.KeySource -eq "Microsoft.Keyvault") {
                Write-OK "CMK encryption ENABLED successfully"
            } else {
                throw "Encryption source is still '$($saVerify.Encryption.KeySource)' after update."
            }
        } else {
            Write-Host "  [WHATIF] Would enable CMK with Key '$KeyName' from '$keyVaultUri'" -ForegroundColor Magenta
        }

    } catch {
        $status = "Failed"
        $notes  = $_.Exception.Message
        Write-Fail "Error on $saName : $notes"
    } finally {
        # Prevent context drift after each target, regardless of success/failure.
        if ($subId) {
            try {
                Set-ContextSafe -SubscriptionId $subId
                $currentSubId = $subId
            } catch {
                # Keep original failure details in result; context recovery best effort.
            }
        }
    }

    $results.Add([PSCustomObject]@{
        SubscriptionName   = $target.SubscriptionName
        ResourceGroup      = $rg
        StorageAccountName = $saName
        Location           = $target.Location
        Status             = $status
        Notes              = $notes
        Timestamp          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    })
}

# ── 7. Summary ────────────────────────────────────────────────────────────────
$successCount = ($results | Where-Object Status -eq "Success").Count
$failCount    = ($results | Where-Object Status -eq "Failed").Count

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Remediation complete $(if ($WhatIf) { '[DRY RUN]' })"
Write-Host "  Success : $successCount" -ForegroundColor Green
Write-Host "  Failed  : $failCount"   -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Gray" })
Write-Host "============================================================`n" -ForegroundColor Cyan

$reportPath = ".\RemediationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] Remediation report saved to : $reportPath" -ForegroundColor Green
$results | Format-Table SubscriptionName, ResourceGroup, StorageAccountName, Status, Notes -AutoSize
