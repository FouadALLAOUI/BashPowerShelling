<#
.SYNOPSIS
    Lists Azure Cosmos DB accounts across one or more subscriptions.

.DESCRIPTION
    This script connects to Azure (if needed), loops through selected subscriptions,
    retrieves Cosmos DB accounts, and displays the result in a colored table.
    DisableLocalAuth = True  → Green  (local auth is disabled — more secure)
    DisableLocalAuth = False → Red    (local auth is enabled  — less secure)
    DisableLocalAuth = $null → Yellow (property not returned  — treat as unknown)

.PARAMETER SubscriptionIds
    Optional list of subscription IDs. If not provided, all accessible subscriptions
    for the signed-in account are scanned.

.EXAMPLE
    .\CosmosDB_LocalAuthDisabled.ps1

.EXAMPLE
    .\CosmosDB_LocalAuthDisabled.ps1 -SubscriptionIds "sub-id-1","sub-id-2"
#>

param(
    [string[]]$SubscriptionIds
)

# ── Step 1: Ensure authenticated ────────────────────────────────────────────
if (-not (Get-AzContext)) {
    Write-Host "[Step 1/5] No Azure context found. Signing in..." -ForegroundColor Cyan
    Connect-AzAccount | Out-Null
    Write-Host "[Step 1/5] Azure sign-in completed." -ForegroundColor Green
}
else {
    Write-Host "[Step 1/5] Azure context already available." -ForegroundColor Green
}

# ── Step 2: Resolve subscriptions ───────────────────────────────────────────
Write-Host "[Step 2/5] Resolving subscriptions..." -ForegroundColor Cyan
if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "Using user-provided subscription IDs." -ForegroundColor DarkCyan
    $subscriptions = foreach ($id in $SubscriptionIds) {
        Get-AzSubscription -SubscriptionId $id -ErrorAction SilentlyContinue
    }
}
else {
    Write-Host "No subscription IDs provided. Loading all accessible subscriptions." -ForegroundColor DarkCyan
    $subscriptions = Get-AzSubscription
}

if (-not $subscriptions) {
    Write-Host "No subscriptions found." -ForegroundColor Yellow
    return
}

Write-Host "[Step 2/5] Found $($subscriptions.Count) subscription(s) to scan." -ForegroundColor Green
Write-Host "[Step 3/5] Starting Cosmos DB discovery per subscription..." -ForegroundColor Cyan

# ── Step 3: Collect results ──────────────────────────────────────────────────
$results = foreach ($subscription in $subscriptions) {
    try {
        Write-Host "  Switching to: $($subscription.Name) [$($subscription.Id)]" -ForegroundColor DarkGray
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null

        $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
        Write-Host "  Found $($resourceGroups.Count) resource group(s) in $($subscription.Name)." -ForegroundColor Gray

        foreach ($rg in $resourceGroups) {
            try {
                $cosmosAccounts = Get-AzCosmosDBAccount -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop

                if ($cosmosAccounts.Count -gt 0) {
                    Write-Host "  [$($rg.ResourceGroupName)] Found $($cosmosAccounts.Count) Cosmos DB account(s)." -ForegroundColor Gray
                }

                foreach ($account in $cosmosAccounts) {
                    [PSCustomObject]@{
                        SubscriptionName = $subscription.Name
                        SubscriptionId   = $subscription.Id
                        ResourceGroup    = $rg.ResourceGroupName
                        CosmosAccount    = $account.Name
                        Location         = $account.Location
                        Kind             = $account.Kind
                        DisableLocalAuth = $account.DisableLocalAuth
                    }
                }
            }
            catch {
                Write-Warning "  Skipping RG [$($rg.ResourceGroupName)]: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warning "Failed in [$($subscription.Name)] ($($subscription.Id)): $($_.Exception.Message)"
    }
}

if (-not $results) {
    Write-Host "No Cosmos DB accounts found in the selected subscriptions." -ForegroundColor Yellow
    return
}

# ── Step 4: Colored table output ─────────────────────────────────────────────
Write-Host "`n[Step 4/5] Discovery completed. Displaying results...`n" -ForegroundColor Cyan

# Calculate column widths dynamically from the data (with minimums matching headers).
$colWidths = @{
    SubscriptionName = [Math]::Max(16, ($results | ForEach-Object { $_.SubscriptionName.Length } | Measure-Object -Maximum).Maximum)
    ResourceGroup    = [Math]::Max(13, ($results | ForEach-Object { $_.ResourceGroup.Length    } | Measure-Object -Maximum).Maximum)
    CosmosAccount    = [Math]::Max(12, ($results | ForEach-Object { $_.CosmosAccount.Length    } | Measure-Object -Maximum).Maximum)
    Location         = [Math]::Max(8,  ($results | ForEach-Object { $_.Location.Length         } | Measure-Object -Maximum).Maximum)
    Kind             = [Math]::Max(4,  ($results | ForEach-Object { $_.Kind.Length             } | Measure-Object -Maximum).Maximum)
    DisableLocalAuth = 15  # fixed — value is always True/False/Unknown
}

# Header
$header = "{0,-$($colWidths.SubscriptionName)}  {1,-$($colWidths.ResourceGroup)}  {2,-$($colWidths.CosmosAccount)}  {3,-$($colWidths.Location)}  {4,-$($colWidths.Kind)}  {5,-$($colWidths.DisableLocalAuth)}" `
    -f "SubscriptionName", "ResourceGroup", "CosmosAccount", "Location", "Kind", "DisableLocalAuth"

$separator = "-" * $header.Length

Write-Host $header   -ForegroundColor White
Write-Host $separator -ForegroundColor DarkGray

# Rows — color the entire row based on DisableLocalAuth
$sorted = $results | Sort-Object SubscriptionName, ResourceGroup, CosmosAccount

foreach ($row in $sorted) {

    # Determine display value and row color
    if ($null -eq $row.DisableLocalAuth) {
        $authDisplay = "Unknown"
        $rowColor    = "Yellow"   # unknown / not returned by API
    }
    elseif ($row.DisableLocalAuth -eq $true) {
        $authDisplay = "True"
        $rowColor    = "Green"    # local auth disabled → secure ✓
    }
    else {
        $authDisplay = "False"
        $rowColor    = "Red"      # local auth enabled  → insecure ✗
    }

    $line = "{0,-$($colWidths.SubscriptionName)}  {1,-$($colWidths.ResourceGroup)}  {2,-$($colWidths.CosmosAccount)}  {3,-$($colWidths.Location)}  {4,-$($colWidths.Kind)}  {5,-$($colWidths.DisableLocalAuth)}" `
        -f $row.SubscriptionName, $row.ResourceGroup, $row.CosmosAccount,
           $row.Location, $row.Kind, $authDisplay

    Write-Host $line -ForegroundColor $rowColor
}

Write-Host $separator -ForegroundColor DarkGray

# ── Step 5: Summary ──────────────────────────────────────────────────────────
$secureCount   = ($results | Where-Object { $_.DisableLocalAuth -eq $true  }).Count
$insecureCount = ($results | Where-Object { $_.DisableLocalAuth -eq $false }).Count
$unknownCount  = ($results | Where-Object { $null -eq $_.DisableLocalAuth  }).Count

Write-Host "`n[Step 5/5] Done. Total accounts: $($results.Count)" -ForegroundColor Cyan
Write-Host "  Secure   (DisableLocalAuth = True) : $secureCount"   -ForegroundColor Green
Write-Host "  Insecure (DisableLocalAuth = False): $insecureCount"  -ForegroundColor Red
Write-Host "  Unknown  (property not returned)   : $unknownCount"   -ForegroundColor Yellow