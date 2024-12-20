# Import required modules
if (-Not (Get-Module -ListAvailable -Name ImportExcel)) {
    Install-Module -Name ImportExcel -Force
}

# Output spreadsheet
$SpreadsheetPath = "./Log4Shell_Vulnerability_Report.xlsx"

# Linux and Windows mitigation commands
$LinuxMitigationCommand = "sudo find / -type f -name 'log4j-core-*.jar' 2>/dev/null | while read jar; do sudo zip -q -d \$jar org/apache/logging/log4j/core/lookup/JndiLookup.class; done"
$WindowsMitigationCommand = "powershell.exe -Command \"Get-ChildItem -Path C:\\ -Recurse -Include log4j-core-*.jar | ForEach-Object { & 'C:\\Program Files\\7-Zip\\7z.exe' d $_.FullName 'org/apache/logging/log4j/core/lookup/JndiLookup.class' -y }\""

# Ensure Azure CLI is authenticated
if (-not (az account show)) {
    Write-Error "Azure CLI is not authenticated. Please log in using 'az login'."
    exit
}

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

# Function to log errors
function Log-Error {
    param (
        [string]$ResourceGroup,
        [string]$VMName,
        [string]$Message
    )
    Write-Output "Error in $ResourceGroup/$VMName: $Message"
    Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "N/A" -PublicIP "N/A" -Status "Error" -Message $Message
}

# Function to retrieve public IP
function Get-PublicIP {
    param (
        [string]$ResourceGroup,
        [string]$VMName
    )
    try {
        $ip = az network public-ip list --resource-group $ResourceGroup --query "[?tags.vmName=='$VMName'].ipAddress" -o tsv
        return $ip
    } catch {
        Log-Error -ResourceGroup $ResourceGroup -VMName $VMName -Message "Failed to retrieve public IP."
        return $null
    }
}


function Get-PrivateIP {
    param (
        [string]$ResourceGroup,
        [string]$VMName
    )
    try {
        $ip = az vm list-ip-addresses --resource-group $ResourceGroup --name $VMName --query "[0].virtualMachine.network.privateIpAddresses[0]" -o tsv
        return $ip
    } catch {
        Log-Error -ResourceGroup $ResourceGroup -VMName $VMName -Message "Failed to retrieve private IP."
        return $null
    }
}

# Function to mitigate Linux VMs
function Mitigate-LinuxVM {
    param (
        [string]$ResourceGroup,
        [string]$VMName,
        [string]$PublicIP,
        [string]$Username,
        [string]$PrivateKeyPath
    )
    try {
        ssh -i $PrivateKeyPath $Username@$PublicIP $LinuxMitigationCommand
        Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "Linux" -PublicIP $PublicIP -Status "Patched" -Message "Log4Shell mitigated successfully."
    } catch {
        Log-Error -ResourceGroup $ResourceGroup -VMName $VMName -Message $_.Exception.Message
    }
}

# Function to mitigate Windows VMs
function Mitigate-WindowsVM {
    param (
        [string]$ResourceGroup,
        [string]$VMName,
        [string]$PublicIP,
        [string]$Username,
        [string]$Password
    )
    try {
        $Session = New-PSSession -ComputerName $PublicIP -Credential (New-Object PSCredential($Username, (ConvertTo-SecureString $Password -AsPlainText -Force)))
        Invoke-Command -Session $Session -ScriptBlock {
            Invoke-Expression $using:WindowsMitigationCommand
        }
        Remove-PSSession $Session
        Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType "Windows" -PublicIP $PublicIP -Status "Patched" -Message "Log4Shell mitigated successfully."
    } catch {
        Log-Error -ResourceGroup $ResourceGroup -VMName $VMName -Message $_.Exception.Message
    }
}

# Function to check if a VMSS node is part of AKS
function Is-AKSNode {
    param (
        [string]$ResourceGroup,
        [string]$VMSSName
    )
    try {
        $aksClusters = az aks list --query "[].{name:name, resourceGroup:resourceGroup}" -o json | ConvertFrom-Json
        foreach ($cluster in $aksClusters) {
            $nodePools = az aks nodepool list -g $cluster.resourceGroup --cluster-name $cluster.name --query "[].{vmssName:scaleSetName}" -o json | ConvertFrom-Json
            if ($nodePools.vmssName -contains $VMSSName) {
                return $true
            }
        }
        return $false
    } catch {
        Write-Output "Error checking AKS node status: $_"
        return $false
    }
}

# Function to process VM Scale Sets (VMSS)
function Process-VMSS {
    param (
        [string]$ResourceGroup
    )

    $VMSSInstances = az vmss list-instances -g $ResourceGroup --query "[].{name:osProfile.computerName, id:instanceId, os:osProfile.linuxConfiguration | osProfile.windowsConfiguration}" -o json | ConvertFrom-Json

    foreach ($instance in $VMSSInstances) {
        $InstanceID = $instance.id
        $VMSSName = (az vmss show -g $ResourceGroup --name $InstanceID --query "name" -o tsv)

        if (Is-AKSNode -ResourceGroup $ResourceGroup -VMSSName $VMSSName) {
            Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $InstanceID -OSType "AKS" -PublicIP "N/A" -Status "Skipped" -Message "Node belongs to AKS. Managed by Azure."
            continue
        }

        $VMName = $instance.name
        $OSType = $instance.os.osType

        if ($OSType -eq "Linux") {
            Mitigate-LinuxVM -ResourceGroup $ResourceGroup -VMName $VMName -PublicIP "<PUBLIC_IP>" -Username "<LINUX_USERNAME>" -PrivateKeyPath "<PRIVATE_KEY_PATH>"
        } elseif ($OSType -eq "Windows") {
            Mitigate-WindowsVM -ResourceGroup $ResourceGroup -VMName $VMName -PublicIP "<PUBLIC_IP>" -Username "<WINDOWS_USERNAME>" -Password "<WINDOWS_PASSWORD>"
        } else {
            Update-Spreadsheet -ResourceGroup $ResourceGroup -VMName $VMName -OSType $OSType -PublicIP "N/A" -Status "Skipped" -Message "Unknown OS type."
        }
    }
}

# Main execution
Write-Output "Fetching all Azure Resource Groups and VMs..."
$ResourceGroups = az group list --query "[].{name:name}" -o json | ConvertFrom-Json

foreach ($ResourceGroup in $ResourceGroups) {
    $VMs = az vm list -g $ResourceGroup.name --query "[].{name:name, os:storageProfile.osDisk.osType, ip:publicIps}" -o json | ConvertFrom-Json

    foreach ($VM in $VMs) {
        $VMName = $VM.name
        $OSType = $VM.os
        $PublicIP = Get-PublicIP -ResourceGroup $ResourceGroup.name -VMName $VMName
        if ($PublicIP -eq $null) {
            continue
        }

        if ($OSType -eq "Linux") {
            Mitigate-LinuxVM -ResourceGroup $ResourceGroup.name -VMName $VMName -PublicIP $PublicIP -Username "<LINUX_USERNAME>" -PrivateKeyPath "<PRIVATE_KEY_PATH>"
        } elseif ($OSType -eq "Windows") {
            Mitigate-WindowsVM -ResourceGroup $ResourceGroup.name -VMName $VMName -PublicIP $PublicIP -Username "<WINDOWS_USERNAME>" -Password "<WINDOWS_PASSWORD>"
        } else {
            Update-Spreadsheet -ResourceGroup $ResourceGroup.name -VMName $VMName -OSType $OSType -PublicIP $PublicIP -Status "Skipped" -Message "Unknown OS type."
        }
    }

    Process-VMSS -ResourceGroup $ResourceGroup.name
}

Write-Output "Vulnerability scan and mitigation completed. Report saved at: $SpreadsheetPath"
