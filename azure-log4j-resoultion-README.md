# Log4j Vulnerability Scanner and Mitigation Script

This PowerShell script scans Azure Virtual Machines (VMs) and Virtual Machine Scale Sets (VMSS) for the Log4Shell vulnerability and mitigates it by removing the affected class from `log4j-core` JAR files. It updates a master Excel spreadsheet with details of each scanned VM/VMSS and their mitigation status.

---

## Features

1. **Scan and Mitigate**
   - Identifies VMs (Windows/Linux) and VMSS instances.
   - Automatically detects and skips AKS nodes.
   - Executes mitigation commands for both Linux and Windows.
2. **Report Generation**
   - Logs mitigation results in an Excel spreadsheet (`Log4Shell_Vulnerability_Report.xlsx`).
3. **Error Handling**
   - Logs errors during scanning and mitigation.
4. **Dynamic Public IP Retrieval**
   - Automatically fetches public IPs for VMs.
5. **Secure Credential Management**
   - Supports integration with Azure Key Vault for securely storing sensitive information.

---

## Prerequisites

1. **Azure CLI**
   - Ensure Azure CLI is installed and authenticated: `az login`.
2. **PowerShell Modules**
   - Install `ImportExcel` for Excel report generation:
     ```powershell
     Install-Module -Name ImportExcel -Force
     ```
3. **Dependencies**
   - Ensure `ssh` is available for Linux VMs.
   - Ensure `7-Zip` is installed for Windows VMs.
4. **Azure Key Vault**
   - Set up a Key Vault to securely store:
     - Linux username and private key.
     - Windows username and password.

---

## Usage

### Running the Script
1. Clone or download the script to your local machine.
2. Replace placeholder values (`<LINUX_USERNAME>`, `<PRIVATE_KEY_PATH>`, `<WINDOWS_USERNAME>`, `<WINDOWS_PASSWORD>`) with values retrieved securely from Azure Key Vault.
3. Execute the script:
   ```powershell
   .\Log4Shell_Scanner.ps1
   ```
4. Upon completion, check the generated `Log4Shell_Vulnerability_Report.xlsx` for results.

---

## Using Azure Key Vault for Secure Storage

To securely store and retrieve sensitive information like credentials, use Azure Key Vault.

### Step 1: Create a Key Vault
1. Log in to Azure CLI:
   ```bash
   az login
   ```
2. Create a Key Vault:
   ```bash
   az keyvault create --name <YourKeyVaultName> --resource-group <YourResourceGroup> --location <YourLocation>
   ```

### Step 2: Add Secrets to Key Vault
Store sensitive values as secrets in the Key Vault:
```bash
az keyvault secret set --vault-name <YourKeyVaultName> --name "LinuxUsername" --value "your-linux-username"
az keyvault secret set --vault-name <YourKeyVaultName> --name "LinuxPrivateKeyPath" --value "path-to-your-private-key"
az keyvault secret set --vault-name <YourKeyVaultName> --name "WindowsUsername" --value "your-windows-username"
az keyvault secret set --vault-name <YourKeyVaultName> --name "WindowsPassword" --value "your-windows-password"
```

### Step 3: Update the Script for Key Vault Integration
Add the following function to the script to retrieve secrets dynamically:

```powershell
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
```

Replace placeholders in the script with calls to this function:

```powershell
$LinuxUsername = Get-KeyVaultSecret -VaultName "<YourKeyVaultName>" -SecretName "LinuxUsername"
$PrivateKeyPath = Get-KeyVaultSecret -VaultName "<YourKeyVaultName>" -SecretName "LinuxPrivateKeyPath"
$WindowsUsername = Get-KeyVaultSecret -VaultName "<YourKeyVaultName>" -SecretName "WindowsUsername"
$WindowsPassword = Get-KeyVaultSecret -VaultName "<YourKeyVaultName>" -SecretName "WindowsPassword"
```

### Step 4: Verify Key Vault Access
Ensure the Azure CLI account has access to the Key Vault. Assign access policies if necessary:
```bash
az keyvault set-policy --name <YourKeyVaultName> --upn <YourAzureADUserPrincipalName> --secret-permissions get
```

---

## Troubleshooting

### Common Errors
1. **Authentication Error:**
   Ensure Azure CLI is authenticated (`az login`).
2. **Public IP Retrieval Fails:**
   Verify that the VM has a public IP.
3. **Key Vault Access Denied:**
   Check Key Vault permissions and ensure the CLI account has `get` permissions on secrets.

---

## Disclaimer
This script is provided "as is" without any guarantees. Use in a testing environment before applying it in production.


