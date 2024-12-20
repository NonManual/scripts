# Output spreadsheet
$SpreadsheetPath = "$HOME/Log4Shell_Vulnerability_Report.xlsx"

# Linux and Windows mitigation commands
$LinuxMitigationCommand = "find / -type f -name 'log4j-core-*.jar' 2>/dev/null | while read jar; do zip -q -d \$jar org/apache/logging/log4j/core/lookup/JndiLookup.class; done"
$WindowsMitigationCommand = "powershell.exe -Command \"Get-ChildItem -Path C:\\ -Recurse -Include log4j-core-*.jar | ForEach-Object { & 'C:\\Program Files\\7-Zip\\7z.exe' d $_.FullName 'org/apache/logging/log4j/core/lookup/JndiLookup.class' -y }\""

# Function to retrieve secrets from Azure Key Vault
function Get-KeyVaultSecret {
    param (
        [string]$VaultName,
        [string]$SecretName
    )
    try {
        $secret = az keyvault secret show --vault-name $VaultName --name $SecretName --query "value" -o tsv
        return $secret
    } catch {
        Write-Output "Failed to retrieve secret $SecretName from Key Vault $VaultName: $_"
        return $null
    }
}

# Retrieve credentials from Azure Key Vault
$VaultName = "YourKeyVaultName"
$LinuxUsername = Get-KeyVaultSecret -VaultName $VaultName -SecretName "LinuxUsername"
$PrivateKeyPath = Get-KeyVaultSecret -VaultName $VaultName -SecretName "LinuxPrivateKeyPath"
$WindowsUsername = Get-KeyVaultSecret -VaultName $VaultName -SecretName "WindowsUsername"
$WindowsPassword = Get-KeyVaultSecret -VaultName $VaultName -SecretName "WindowsPassword"

# Function to log results to a spreadsheet
function Update-Spreadsheet {
    param (
        [string]$ResourceGroup,
        [string]$VMName,
        [string]$OSType,
        [string]$PublicIP,
        [string]$Status,
        [string]$Message
    )

    if (-Not (Test-Path $SpreadsheetPath)) {
        @(
            [PSCustomObject]@{
                ResourceGroup = $ResourceGroup
                VMName        = $VMName
                OSType        = $OSType
                PublicIP      = $PublicIP
                Status        = $Status
                Message       = $Message
            }
        ) | Export-Excel -Path $SpreadsheetPath -AutoSize -WorksheetName "Vulnerability Report"
    } else {
        [PSCustomObject]@{
            ResourceGroup = $ResourceGroup
            VMName        = $VMName
            OSType        = $OSType
            PublicIP      = $PublicIP
            Status        = $Status
            Message       = $Message
        } | Export-Excel -Path $SpreadsheetPath -WorksheetName "Vulnerability Report" -Append
    }
}

# Function to mitigate Linux VMs
function Mitigate-LinuxVM {
    param (
        [string]$VMName,
        [string]$PublicIP
    )
    try {
        ssh -i $PrivateKeyPath $LinuxUsername@$PublicIP $LinuxMitigationCommand
        Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "Linux" -PublicIP $PublicIP -Status "Patched" -Message "Log4Shell mitigated successfully."
    } catch {
        Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "Linux" -PublicIP $PublicIP -Status "Error" -Message $_.Exception.Message
    }
}

# Function to mitigate Windows VMs
function Mitigate-WindowsVM {
    param (
        [string]$VMName,
        [string]$PublicIP
    )
    try {
        $Session = New-PSSession -ComputerName $PublicIP -Credential (New-Object PSCredential($WindowsUsername, (ConvertTo-SecureString $WindowsPassword -AsPlainText -Force)))
        Invoke-Command -Session $Session -ScriptBlock {
            Invoke-Expression $using:WindowsMitigationCommand
        }
        Remove-PSSession $Session
        Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "Windows" -PublicIP $PublicIP -Status "Patched" -Message "Log4Shell mitigated successfully."
    } catch {
        Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "Windows" -PublicIP $PublicIP -Status "Error" -Message $_.Exception.Message
    }
}

# Fetch Resource Groups and VMs
$ResourceGroups = az group list --query "[].{name:name}" -o json | ConvertFrom-Json
foreach ($ResourceGroup in $ResourceGroups) {
    $VMs = az vm list -g $ResourceGroup.name --query "[].{name:name, os:storageProfile.osDisk.osType, ip:publicIps}" -o json | ConvertFrom-Json
    foreach ($VM in $VMs) {
        $VMName = $VM.name
        $OSType = $VM.os
        $PublicIP = $VM.ip
        if ($OSType -eq "Linux") {
            Mitigate-LinuxVM -VMName $VMName -PublicIP $PublicIP
        } elseif ($OSType -eq "Windows") {
            Mitigate-WindowsVM -VMName $VMName -PublicIP $PublicIP
        } else {
            Update-Spreadsheet -ResourceGroup $ResourceGroup.name -VMName $VMName -OSType $OSType -PublicIP $PublicIP -Status "Skipped" -Message "Unknown OS type."
        }
    }
}

Write-Output "Vulnerability scan and mitigation completed. Report saved at: $SpreadsheetPath"
