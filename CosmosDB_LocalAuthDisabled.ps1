<#
.SYNOPSIS
    Lists Azure Cosmos DB accounts across one or more subscriptions.

.DESCRIPTION
    This script connects to Azure (if needed), loops through selected subscriptions,
    retrieves Cosmos DB accounts, and displays the result in a table.
    It includes the DisableLocalAuth property to help identify local-auth status.

.PARAMETER SubscriptionIds
    Optional list of subscription IDs. If not provided, all accessible subscriptions
    for the signed-in account are scanned.

.EXAMPLE
    .\CosmosDB_LocalAuthDisabled.ps1

    Scans all subscriptions available to the current user context.

.EXAMPLE
    .\CosmosDB_LocalAuthDisabled.ps1 -SubscriptionIds "sub-id-1","sub-id-2"

    Scans only the specified subscriptions.
#>

param(
    [string[]]$SubscriptionIds
)

# Ensure user is authenticated before querying subscriptions/resources.
if (-not (Get-AzContext)) {
    Write-Host "[Step 1/5] No Azure context found. Signing in..." -ForegroundColor Cyan
    Connect-AzAccount | Out-Null
    Write-Host "[Step 1/5] Azure sign-in completed." -ForegroundColor Green
}
else {
    Write-Host "[Step 1/5] Azure context already available." -ForegroundColor Green
}

# Determine which subscriptions to process.
Write-Host "[Step 2/5] Resolving subscriptions..." -ForegroundColor Cyan
if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "Using user-provided subscription IDs." -ForegroundColor DarkCyan
    $subscriptions = foreach ($subscriptionId in $SubscriptionIds) {
        Get-AzSubscription -SubscriptionId $subscriptionId -ErrorAction SilentlyContinue
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

# Collect Cosmos DB account details from each subscription.
$results = foreach ($subscription in $subscriptions) {
    try {
        Write-Host "Switching context to: $($subscription.Name) [$($subscription.Id)]" -ForegroundColor DarkGray
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null

        Write-Host "Querying Cosmos DB accounts in subscription: $($subscription.Name)" -ForegroundColor DarkGray
        $cosmosAccounts = Get-AzCosmosDBAccount -ErrorAction Stop
        Write-Host "Found $($cosmosAccounts.Count) Cosmos DB account(s) in $($subscription.Name)." -ForegroundColor Gray

        foreach ($account in $cosmosAccounts) {
            [PSCustomObject]@{
                SubscriptionName = $subscription.Name
                SubscriptionId   = $subscription.Id
                ResourceGroup    = $account.ResourceGroupName
                CosmosAccount    = $account.Name
                Location         = $account.Location
                Kind             = $account.Kind
                DisableLocalAuth = $account.DisableLocalAuth
            }
        }
    }
    catch {
        Write-Warning "Failed in subscription [$($subscription.Name)] ($($subscription.Id)): $($_.Exception.Message)"
    }
}

if (-not $results) {
    Write-Host "No Cosmos DB accounts found in the selected subscriptions." -ForegroundColor Yellow
    return
}

Write-Host "[Step 4/5] Discovery completed. Preparing output table..." -ForegroundColor Cyan
$results |
    Sort-Object SubscriptionName, ResourceGroup, CosmosAccount |
    Format-Table -AutoSize

Write-Host "[Step 5/5] Done. Total Cosmos DB accounts listed: $($results.Count)" -ForegroundColor Green























