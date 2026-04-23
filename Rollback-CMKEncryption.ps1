# =============================================================================
# ROLLBACK: Revert storage account encryption state from a CSV target list
# Supports:
#   1) PreviousCmk: re-point to a previous known-good CMK version
#   2) Mmk:         emergency fallback to Microsoft-managed keys
# =============================================================================

#Requires -Modules Az.Accounts, Az.Storage

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # CSV file containing rollback targets.
    [Parameter(Mandatory)]
    [string]$CsvPath,

    # Rollback mode:
    # - PreviousCmk: uses CMK metadata columns from CSV
    # - Mmk: switches encryption key source to Microsoft.Storage
    [Parameter(Mandatory)]
    [ValidateSet("PreviousCmk", "Mmk")]
    [string]$Mode,

    # Optional: restrict to specific subscriptions.
    [string[]]$SubscriptionIds = @(),

    # Optional fallback subscription if CSV does not contain SubscriptionId.
    [string]$DefaultSubscriptionId = "",

    # Optional override column names if your CSV uses custom headers.
    [string]$SubscriptionIdColumn = "SubscriptionId",
    [string]$SubscriptionNameColumn = "SubscriptionName",
    [string]$ResourceGroupColumn = "ResourceGroup",
    [string]$StorageAccountNameColumn = "StorageAccountName",
    [string]$PrevKeyVaultUriColumn = "PreviousKeyVaultUri",
    [string]$PrevKeyNameColumn = "PreviousKeyName",
    [string]$PrevKeyVersionColumn = "PreviousKeyVersion",

    # Skip interactive confirmation.
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step  { param($msg) Write-Host "`n[STEP] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "  [OK]  $msg" -ForegroundColor Green }
function Write-Fail  { param($msg) Write-Host " [FAIL] $msg" -ForegroundColor Red }
function Write-Info  { param($msg) Write-Host "  [..] $msg" -ForegroundColor Gray }

function Set-ContextSafe {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId
    )
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}

function Get-ValueByCandidates {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string[]]$CandidateColumns
    )

    foreach ($col in $CandidateColumns) {
        if ($null -ne $Row.PSObject.Properties[$col]) {
            $value = [string]$Row.$col
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $value.Trim()
            }
        }
    }
    return ""
}

function Resolve-TargetSubscriptionId {
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)]$SubscriptionNameLookup
    )

    $subIdFromCsv = Get-ValueByCandidates -Row $Row -CandidateColumns @($SubscriptionIdColumn)
    if (-not [string]::IsNullOrWhiteSpace($subIdFromCsv)) {
        return $subIdFromCsv
    }

    if (-not [string]::IsNullOrWhiteSpace($DefaultSubscriptionId)) {
        return $DefaultSubscriptionId
    }

    $subName = Get-ValueByCandidates -Row $Row -CandidateColumns @($SubscriptionNameColumn)
    if (-not [string]::IsNullOrWhiteSpace($subName)) {
        $resolved = $SubscriptionNameLookup[$subName]
        if ($resolved) {
            return $resolved
        }
    }

    throw "Unable to resolve SubscriptionId. Provide '$SubscriptionIdColumn' in CSV or use -DefaultSubscriptionId."
}

function Set-StorageToMmk {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$StorageAccountName
    )

    # Storage account MMK fallback via ARM PATCH.
    $resourcePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName?api-version=2023-01-01"
    $payload = @{
        properties = @{
            encryption = @{
                keySource = "Microsoft.Storage"
            }
        }
    } | ConvertTo-Json -Depth 8

    Invoke-AzRestMethod -Method PATCH -Path $resourcePath -Payload $payload -ErrorAction Stop | Out-Null
}

Write-Step "Connecting to Azure"
if (-not (Get-AzContext)) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
}

Write-Step "Loading CSV targets"
if (-not (Test-Path $CsvPath)) {
    throw "CSV file not found: $CsvPath"
}

$rows = Import-Csv -Path $CsvPath
if (-not $rows -or $rows.Count -eq 0) {
    throw "CSV contains no rows: $CsvPath"
}
Write-OK "Rows loaded: $($rows.Count)"

Write-Step "Resolving enabled subscriptions"
$enabledSubscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
if (-not $enabledSubscriptions -or $enabledSubscriptions.Count -eq 0) {
    throw "No enabled subscriptions are available for current identity."
}

$enabledSubIds = @($enabledSubscriptions | ForEach-Object { $_.Id })
$subscriptionNameLookup = @{}
foreach ($sub in $enabledSubscriptions) {
    if (-not $subscriptionNameLookup.ContainsKey($sub.Name)) {
        $subscriptionNameLookup[$sub.Name] = $sub.Id
    }
}

if ($SubscriptionIds.Count -gt 0) {
    $invalid = @($SubscriptionIds | Where-Object { $_ -notin $enabledSubIds })
    if ($invalid.Count -gt 0) {
        throw "Provided -SubscriptionIds contain inaccessible/disabled items: $($invalid -join ', ')"
    }
}

if (-not $Force) {
    Write-Host ""
    Write-Host "Rollback mode : $Mode" -ForegroundColor Yellow
    Write-Host "CSV path      : $CsvPath" -ForegroundColor Yellow
    Write-Host "Rows          : $($rows.Count)" -ForegroundColor Yellow
    $answer = Read-Host "Continue rollback? [y/N]"
    if ($answer -notmatch '^[Yy]') {
        Write-Host "Aborted."
        exit 0
    }
}

Write-Step "Starting rollback"
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$currentSubId = ""

foreach ($row in $rows) {
    $status = "Success"
    $notes  = ""

    $subId = ""
    $rg    = ""
    $sa    = ""
    $targetKeySource = ""

    try {
        $subId = Resolve-TargetSubscriptionId -Row $row -SubscriptionNameLookup $subscriptionNameLookup

        if ($SubscriptionIds.Count -gt 0 -and $subId -notin $SubscriptionIds) {
            $results.Add([PSCustomObject]@{
                SubscriptionId     = $subId
                SubscriptionName   = (Get-ValueByCandidates -Row $row -CandidateColumns @($SubscriptionNameColumn))
                ResourceGroup      = (Get-ValueByCandidates -Row $row -CandidateColumns @($ResourceGroupColumn, "ResourceGroupName"))
                StorageAccountName = (Get-ValueByCandidates -Row $row -CandidateColumns @($StorageAccountNameColumn, "Name"))
                Mode               = $Mode
                Status             = "Skipped"
                Notes              = "Filtered out by -SubscriptionIds."
                Timestamp          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            })
            continue
        }

        if ($subId -notin $enabledSubIds) {
            throw "Resolved subscription '$subId' is not enabled/accessible."
        }

        $rg = Get-ValueByCandidates -Row $row -CandidateColumns @($ResourceGroupColumn, "ResourceGroupName")
        $sa = Get-ValueByCandidates -Row $row -CandidateColumns @($StorageAccountNameColumn, "Name")
        if ([string]::IsNullOrWhiteSpace($rg) -or [string]::IsNullOrWhiteSpace($sa)) {
            throw "Resource group or storage account name is missing in CSV row."
        }

        Write-Host "`n  Storage Account : $sa  (RG: $rg, SubId: $subId)" -ForegroundColor Yellow

        if ($subId -ne $currentSubId) {
            Set-ContextSafe -SubscriptionId $subId
            $currentSubId = $subId
        }

        if ($Mode -eq "PreviousCmk") {
            # Accept both "Previous*" and standard CMK columns.
            $kvUri = Get-ValueByCandidates -Row $row -CandidateColumns @($PrevKeyVaultUriColumn, "KeyVaultUri")
            $keyName = Get-ValueByCandidates -Row $row -CandidateColumns @($PrevKeyNameColumn, "KeyName")
            $keyVersion = Get-ValueByCandidates -Row $row -CandidateColumns @($PrevKeyVersionColumn, "KeyVersion")

            if ([string]::IsNullOrWhiteSpace($kvUri) -or
                [string]::IsNullOrWhiteSpace($keyName) -or
                [string]::IsNullOrWhiteSpace($keyVersion)) {
                throw "Previous CMK details are missing. Required columns: $PrevKeyVaultUriColumn, $PrevKeyNameColumn, $PrevKeyVersionColumn (or KeyVaultUri/KeyName/KeyVersion)."
            }

            $targetKeySource = "Microsoft.Keyvault"
            if ($PSCmdlet.ShouldProcess("$sa in $rg", "Rollback to previous CMK version")) {
                Set-AzStorageAccount -ResourceGroupName $rg -Name $sa `
                    -KeyvaultEncryption `
                    -KeyVaultUri $kvUri `
                    -KeyName $keyName `
                    -KeyVersion $keyVersion | Out-Null
                Write-OK "Set to CMK key '$keyName' version '$keyVersion'"
            }
        } else {
            $targetKeySource = "Microsoft.Storage"
            if ($PSCmdlet.ShouldProcess("$sa in $rg", "Rollback to MMK (Microsoft.Storage)")) {
                Set-StorageToMmk -SubscriptionId $subId -ResourceGroupName $rg -StorageAccountName $sa
                Write-OK "Set to MMK (Microsoft.Storage)"
            }
        }

        # Validate resulting key source when action executed.
        if ($PSCmdlet.ShouldProcess("verification", "Read storage account state")) {
            $verify = Get-AzStorageAccount -ResourceGroupName $rg -Name $sa -ErrorAction Stop
            $actualKeySource = [string]$verify.Encryption.KeySource
            if ($actualKeySource -ne $targetKeySource) {
                throw "Verification failed. Expected '$targetKeySource', actual '$actualKeySource'."
            }
            Write-OK "Verified key source: $actualKeySource"
        }

    } catch {
        $status = "Failed"
        $notes = $_.Exception.Message
        Write-Fail "Error on $sa : $notes"
    } finally {
        $results.Add([PSCustomObject]@{
            SubscriptionId     = $subId
            SubscriptionName   = (Get-ValueByCandidates -Row $row -CandidateColumns @($SubscriptionNameColumn))
            ResourceGroup      = $rg
            StorageAccountName = $sa
            Mode               = $Mode
            Status             = $status
            Notes              = $notes
            Timestamp          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
    }
}

Write-Step "Rollback summary"
$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$failedCount  = ($results | Where-Object { $_.Status -eq "Failed" }).Count
$skippedCount = ($results | Where-Object { $_.Status -eq "Skipped" }).Count

Write-Host "  Success : $successCount" -ForegroundColor Green
Write-Host "  Failed  : $failedCount" -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Gray" })
Write-Host "  Skipped : $skippedCount" -ForegroundColor Gray

$reportPath = ".\RollbackReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
Write-Host "`n[+] Rollback report saved to: $reportPath" -ForegroundColor Green
$results | Format-Table SubscriptionId, ResourceGroup, StorageAccountName, Mode, Status, Notes -AutoSize
