#************************************************
# Automated_Changes_EntraID.ps1
# Version 1.0
# Date: 06-12-2026
# Author: Tim Springston
# Initial testing script for adding relational complexity to test objects in an Entra tenant.
# This script should not be run in a production environment.
#************************************************
Import-Module Microsoft.Entra
   

function Update-EntraAppAndSpDescription {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $true)]
        [string]$NewDescription
    )

    process {
        Write-Verbose "Retrieving up to $Count Entra ID applications..."

        # Get the first N applications (adjust filters/sorting as needed)
        $apps = Get-EntraApplication -Top $Count

        if (-not $apps) {
            Write-Warning "No applications found."
            return
        }

        foreach ($app in $apps) {
            Write-Verbose "Processing application: $($app.DisplayName) (AppId: $($app.AppId))"

            # Find the corresponding service principal(s), if any
            $sps = Get-EntraServicePrincipal -Filter "appId eq '$($app.AppId)'"

            if ($sps) {
                foreach ($sp in $sps) {
                    if ($PSCmdlet.ShouldProcess("Service principal $($sp.DisplayName) ($($sp.Id))", "Update Description")) {
                        Set-EntraServicePrincipal -ServicePrincipalId $sp.Id -AlternativeNames $NewDescription
                    }
                }
            }
            else {
                Write-Verbose "No service principal found for AppId $($app.AppId)."
            }

            # Update the application object itself
            if ($PSCmdlet.ShouldProcess("Application $($app.DisplayName) ($($app.Id))", "Update Description")) {
                Set-EntraApplication -ApplicationId $app.Id -Tags $NewDescription
            }
        }
    }
}

#Change description and job titles for users
function EditUserProps {
    param (
        [int]$numberofusers
    )  
    $EntraUsers = Get-EntraUser -Filter "startsWith(displayName, 'Test')" -Select Id, UserPrincipalName, DisplayName -Top $numberofusers
    #https://learn.microsoft.com/en-us/powershell/module/microsoft.entra/set-entrauser?view=entra-powershell
    foreach ($EntraUser in $EntraUsers) {
        if ($EntraUser.department -eq $null) {
            $objectId = $EntraUser.id.ToString()
            $displayName = $EntraUser.displayName.ToString()
            #Add properties
            Set-EntraUser -UserId $objectId -city "New York" -State "NY" -department "Sales"
        }
    }
}

cls
#Context
$TenantId     = "<GUID>"
$ClientId     = "<GUID>"
$ClientSecret = "<value>"   

# ── Convert secret to secure credential ─────────────────────────────
$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$Credential   = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)

# ── Import & Connect ─────────────────────────────────────────────────
#Install-Module Microsoft.Graph.Entra.Beta -Scope CurrentUser
Connect-Entra -TenantId $TenantId -ClientSecretCredential $Credential 

$Date = Get-Date
[int]$NumberofEdits = Read-Host "Enter the number of items to edit"
$Date = Get-Date

Update-EntraAppAndSpDescription $NumberofEdits $Date
EditUserProps $NumberofEdits
