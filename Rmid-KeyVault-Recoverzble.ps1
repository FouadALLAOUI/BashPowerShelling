<#
.SYNOPSIS
    Remediates Azure Key Vaults by enabling Soft Delete and Purge Protection
    across all enabled subscriptions.

.DESCRIPTION
    This script iterates through all enabled Azure subscriptions and identifies
    Key Vaults where Soft Delete is disabled. It then enables both Soft Delete
    and Purge Protection on each non-compliant Key Vault to ensure recoverability.

.NOTES
    Author      : Fouad Allaoui
    Branch      : feat/ensure-keyvault-recoverable
    Requires    : Az PowerShell module (Connect-AzAccount must be called before this script
                  or handled by the pipeline's "Logging and Setting Azure Context" step)
    Permissions : Contributor or Key Vault Contributor on each target subscription
#>



Get-AzKeyVault | ForEach-Object {
    Get-AzKeyVault -VaultName $_.VaultName
} | Where-Object {
    $_.EnablePurgeProtection -ne $true
} | Select-Object VaultName, ResourceGroupName, Location, EnableSoftDelete, EnablePurgeProtection
           
[CmdletBinding(SupportsShouldProcess = $true)]
param()

#region --- Helper Functions ---

function Write-StepHeader {
    <#
    .SYNOPSIS Prints a formatted step header to the console. #>
    param(
        [Parameter(Mandatory)][int]    $StepNumber,
        [Parameter(Mandatory)][string] $Message
    )
    Write-Host "`n========================================" -ForegroundColor DarkCyan
    Write-Host "  STEP $StepNumber : $Message"             -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor DarkCyan
}

function Write-Success { param([string]$Message) Write-Host "[OK]  $Message" -ForegroundColor Green  }
function Write-Info    { param([string]$Message) Write-Host "[..] $Message"  -ForegroundColor Yellow }
function Write-Skip    { param([string]$Message) Write-Host "[--] $Message"  -ForegroundColor Gray   }
function Write-Fail    { param([string]$Message) Write-Host "[!!] $Message"  -ForegroundColor Red    }

#endregion

#region --- Main Script ---

Write-Host "`n##############################################" -ForegroundColor Green
Write-Host "  Key Vault Recoverability Remediation Script  " -ForegroundColor Green
Write-Host "##############################################`n" -ForegroundColor Green

try {

    # ------------------------------------------------------------------ #
    # STEP 1 – Discover all enabled subscriptions                         #
    # ------------------------------------------------------------------ #
    Write-StepHeader -StepNumber 1 -Message "Fetching all enabled Azure subscriptions"

    [array]$subscriptions = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }

    if (-not $subscriptions) {
        Write-Fail "No enabled subscriptions found for the provided credentials. Exiting."
        exit 1
    }

    Write-Success "Found $($subscriptions.Count) enabled subscription(s) to process."

    # Counters for final summary
    $totalVaultsScanned   = 0
    $totalVaultsRemediated = 0
    $totalVaultsFailed    = 0

    # ------------------------------------------------------------------ #
    # STEP 2 – Loop through each subscription                             #
    # ------------------------------------------------------------------ #
    Write-StepHeader -StepNumber 2 -Message "Looping through subscriptions to find and update Key Vaults"

    foreach ($sub in $subscriptions) {

        Write-Info "Processing subscription: '$($sub.Name)' [$($sub.Id)]"

        # Switch Azure context to the current subscription
        $null = Set-AzContext -SubscriptionId $sub.Id -Tenant $sub.TenantId -ErrorAction Stop

        # ------------------------------------------------------------ #
        # Find all Key Vaults with Soft Delete disabled                 #
        # NOTE: Results are kept as objects – no Format-Table           #
        # ------------------------------------------------------------ #
        [array]$kvsToUpdate = Get-AzKeyVault |
            Where-Object { $_.EnableSoftDelete -eq $false }

        $totalVaultsScanned += (Get-AzKeyVault).Count

        if (-not $kvsToUpdate) {
            Write-Skip "  No non-recoverable Key Vaults found in '$($sub.Name)'. Skipping."
            continue
        }

        Write-Info "  Found $($kvsToUpdate.Count) non-recoverable Key Vault(s) in '$($sub.Name)'."

        # ------------------------------------------------------------ #
        # Remediate each non-compliant Key Vault                        #
        # ------------------------------------------------------------ #
        foreach ($kv in $kvsToUpdate) {

            $vaultLabel = "'$($kv.VaultName)' (RG: $($kv.ResourceGroupName))"
            Write-Info "  --> Remediating Key Vault: $vaultLabel"

            try {
                if ($PSCmdlet.ShouldProcess($vaultLabel, "Enable SoftDelete + PurgeProtection")) {

                    # Use the Az PowerShell cmdlet directly (preferred over az CLI)
                    # to enable both Soft Delete and Purge Protection atomically.
                    Update-AzKeyVault `
                        -ResourceGroupName $kv.ResourceGroupName `
                        -VaultName         $kv.VaultName `
                        -EnableSoftDelete  $true `
                        -EnablePurgeProtection $true `
                        -ErrorAction Stop

                    Write-Success "  [+] Remediated: $vaultLabel"
                    $totalVaultsRemediated++
                }
            }
            catch {
                Write-Fail "  Failed to remediate $vaultLabel : $_"
                $totalVaultsFailed++
                # Continue with next vault instead of aborting the whole run
            }
        }
    }

    # ------------------------------------------------------------------ #
    # STEP 3 – Print final summary                                        #
    # ------------------------------------------------------------------ #
    Write-StepHeader -StepNumber 3 -Message "Remediation Complete – Summary"

    Write-Host "  Subscriptions processed : $($subscriptions.Count)" -ForegroundColor White
    Write-Host "  Key Vaults scanned      : $totalVaultsScanned"      -ForegroundColor White
    Write-Host "  Key Vaults remediated   : $totalVaultsRemediated"   -ForegroundColor Green
    if ($totalVaultsFailed -gt 0) {
        Write-Host "  Key Vaults FAILED       : $totalVaultsFailed"   -ForegroundColor Red
    }
    Write-Host ""
    Write-Success "Script finished successfully. All subscriptions have been processed."

}
catch {
    Write-Fail "A fatal error occurred during script execution: $_"
    exit 1
}

#endregion




