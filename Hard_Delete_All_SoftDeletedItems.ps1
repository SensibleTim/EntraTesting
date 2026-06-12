#************************************************
# Hard_Delete_All_SoftDeletedItems.ps1
# Version 1.0
# Date: 06-12-2026
# Author: Tim Springston
# This script can be used to permanently delete any currently soft deleted items. This requires an application in the tenant which has sufficient access to perform deletion actions.
# The script requires a clientID and secret.
# NOTE: THIS SCRIPT IS FOR TESTING PURPOSES ONLY. It uses documented public Microsoft APIs.
#************************************************

cls
Import-Module Microsoft.Entra

#Context
$TenantId     = "<GUID>"
$ClientId     = "<GUID>"
$ClientSecret = "<value>"   # or use a certificate (see below)

# ── Convert secret to secure credential ─────────────────────────────
$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$Credential   = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)

# ── Import & Connect ─────────────────────────────────────────────────
#Install-Module Microsoft.Graph.Entra.Beta -Scope CurrentUser
Connect-Entra -TenantId $TenantId -ClientSecretCredential $Credential 

Write-host "This script will automatically hard delete all soft deleted objects. If you do not want to permanently delete the soft deleted items then press CTR+C to exit the script."

Write-host "Hard deleting applications..."
$SoftDeletedItems = Invoke-MgGraphRequest -Method GET  -Uri https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.application
foreach ($object in $SoftDeletedItems.Value)
    {
    $objectId = $object.id.ToString()
    $displayName = $object.displayName.ToString()
    Write-host "Deleted object $displayname with objectId of $objectId." 
    Invoke-MgGraphRequest -Method DELETE  -Uri "https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.application/$objectId" 
    }


Write-host "Hard deleting service principals..."
$SoftDeletedItems = Invoke-MgGraphRequest -Method GET  -Uri https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.servicePrincipal
foreach ($object in $SoftDeletedItems.Value)
    {
    $objectId = $object.id.ToString()
    $displayName = $object.displayName.ToString()
    Write-host "Deleted object $displayname with objectId of $objectId."
    Invoke-MgGraphRequest -Method DELETE  -Uri "https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.servicePrincipal/$objectId"
    }

Write-host "Hard deleting users..."
$SoftDeletedItems = Invoke-MgGraphRequest -Method GET  -Uri https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.user
foreach ($object in $SoftDeletedItems.Value)
    {
    $objectId = $object.id.ToString()
    $displayName = $object.displayName.ToString()
    Write-host "Deleted object $displayname with objectId of $objectId." 
    Invoke-MgGraphRequest -Method DELETE  -Uri "https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.user/$objectId"
    }

Write-host "Hard deleting groups..."
$SoftDeletedItems = Invoke-MgGraphRequest -Method GET  -Uri https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.group
foreach ($object in $SoftDeletedItems.Value)
    {
    $objectId = $object.id.ToString()
    $displayName = $object.displayName.ToString()
    Write-host "Deleted object $displayname with objectId of $objectId." 
    Invoke-MgGraphRequest -Method DELETE  -Uri "https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.group/$objectId"
    }