#************************************************
# EntraSpeedBulk.ps1
# Version 1.0
# Date: 7-11-2025
# Author: Tim Springston
# Description: This script can be used to add a large number of Entra ID objects to a tenant quickly. 
#  The use case for this script is to simply add a large number of objects for operational and recovery scenario testing. 
#  This script will create an admin-specified number applications, service principals, users, and groups. 
#  Conditional Access policies have a default max of 200 per tenant. The script will add as many as possible while leaving room for 10 additional new policies to be created.
#
#  This script relies on Windows 11 cloud integration for authentication and the Microsoft.Entra PowerShell modules.
#   Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber ##
#  The CA policy function utilizes the Microsoft.Graph.Identity.SignIns Module.
#   https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/new-mgidentityconditionalaccesspolicy?view=graph-powershell-1.0
#************************************************

#Function definitions#######
#####################################################################################
function CreateManyAppsandSPs {
param (
     [int]$NumberofAppsandSPs
     )
$Tenant = Get-EntraTenantDetail
$A = 1
For ($A; $A -le $NumberofAppsandSPs; $A++)
{
$Appname = "Test_App_" + (new-guid)
$URI = "https://" + $Appname + "." + $Tenant.VerifiedDomains[0].name
Try {
    New-EntraApplication -DisplayName $Appname  -IdentifierUris $URI -ErrorAction SilentlyContinue
    $MyApp = Get-EntraApplication -Filter "DisplayName eq '$Appname'"
    New-EntraServicePrincipal -AccountEnabled $true -AppId $MyApp.AppId -AppRoleAssignmentRequired $true -DisplayName $AppName -Tags {WindowsAzureActiveDirectoryIntegratedApp} -ServicePrincipalType "Application" -ErrorAction SilentlyContinue
    }
    Catch {Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Yellow }
    $Appname = $null
    $URI = $nul
    $ServicePrincipalname = $null
    $MyApp = $null
    }
}

function CreateManyCAPolicies {
$Policies = Get-EntraConditionalAccessPolicy
$PolicyCount = $Policies.Count
If ($PolicyCount -lt 190)
    {$NumberToAdd = 190 - $PolicyCount}
    else {Return "The tenant has $PolicyCount CA policies. Adding more using automation is not recommended."}
$P= 1
For ($P; $P -le $NumberToAdd; $P++)
{
$GUID = New-GUID
$CAPName = $GUID.Guid.Split('-')[0]
$PolicyName = "Test_Policy_" + $CAPName
$body = @{
          displayName = $PolicyName
          state = "enabledForReportingButNotEnforced"
          conditions = @{
            applications = @{
              includeApplications = @(
                "All"
              )
            }
            users = @{
              includeUsers = @(
                "All"
              )
            }
            clientAppTypes = @(
              "all"
            )
          }
            grantControls = @{
            operator = "AND"
            builtInControls = @(
              "mfa"
            )
          }
        }
        New-MgIdentityConditionalAccessPolicy -BodyParameter $body
        Write-Host $PolicyName
        $PolicyName = $null
    }
}

function CreateManyUsers {
param (
        [int]$NumberofUsers
       )
$Tenant = Get-EntraTenantDetail
For ($U; $U -le $NumberofUsers; $U++)
{
$GUID = New-GUID
$Username = $GUID.Guid.Split('-')[0]
$UPN =  "Test_User_" + $Username + "@" + $Tenant.VerifiedDomains[0].name
$PasswordProfile = @{Password = new-guid }
New-EntraUser -AccountEnabled $true -DisplayName $Username -UserPrincipalName $UPN `
-PasswordProfile $PasswordProfile -MailNickName $Username -InformationAction SilentlyContinue
Write-Host $UPN
$Username = $null}
}

function CreateManyGroups {
param (
    [int]$NumberofGroups
    )
For ($G; $G -le $NumberofGroups; $G++)
{
$GUID = New-GUID
$Groupname =  "Test_Group_" + $GUID.Guid.Split('-')[0]
New-EntraGroup -Description "Bulk Added Group" -DisplayName $Groupname -SecurityEnabled $True `
-MailEnabled $false -MailNickName $Groupname -InformationAction SilentlyContinue
Write-Host $Groupname
$Groupname = $null}

}

########################################################################################################
#Script logic
########################################################################################################

cls
Import-Module Microsoft.Entra

Write-host "Welcome to the Entra Speed Bulk PowerShell script. The script uses the Microsoft.Entra and Microsoft Graph CA policy modules."
Write-host " This script provides automation to quickly add objects to an Entra ID test tenant. You will be prompted for how many of each object to create. The added objects are simply filler-they will not be usable for login or other scenarios outside of recovery testing."
$Domain = Read-Host "Enter the domain name of your tenant"

Connect-Entra -TenantId $Domain -NoWelcome

[int]$NumberofAppsandSPs = Read-Host "Enter the number of Application and Service Principal objects to create."
CreateManyAppsandSPs $NumberofAppsandSPs

$CreatePolicies = Read-Host "Create CA policies? Enter Yes or No."
If ($CreatePolicies -match "Yes")
    {
    Write-Host "Creating Conditional Access policy objects. All policies are created in Report-only mode."
    CreateManyCAPolicies
    }

[int]$NumberofUsers = Read-Host "Enter the number of user objects to create."
CreateManyUsers $NumberofUsers

[int]$NumberofGroups = Read-Host "Enter the number of group objects to create."
CreateManyGroups $NumberofGroups
 