# Log4Shell Vulnerability Mitigation Script (Cloud Shell Optimized)

This script scans Azure VMs and VMSS instances for the Log4j vulnerability and mitigates it by removing the vulnerable `JndiLookup.class` from affected `log4j-core` JAR files. It is optimized for execution within the Azure Cloud Shell.

## Features
- Dynamic public IP retrieval for VMs.
- Integration with Azure Key Vault for secure credential management.
- Mitigation support for Linux and Windows VMs.
- Automatically generates an Excel report with the mitigation status of each VM/VMSS instance.

## Prerequisites
1. **Azure Subscription**: Ensure you have access to the subscription containing the target resources.
2. **Azure Key Vault**:
   - Store sensitive credentials such as usernames, passwords, and private key paths in Azure Key Vault.
   - Example secrets:
     - `LinuxUsername`
     - `LinuxPrivateKeyPath`
     - `WindowsUsername`
     - `WindowsPassword`

3. **Azure Cloud Shell**: Use this script directly in Azure Cloud Shell. No additional setup is required.

## Usage

### Step 1: Set Up Azure Key Vault
1. Create a Key Vault:
   ```bash
   az keyvault create --name <YourKeyVaultName> --resource-group <ResourceGroupName> --location <Location>
   ```

2. Add secrets to the Key Vault:
   ```bash
   az keyvault secret set --vault-name <YourKeyVaultName> --name "LinuxUsername" --value "<LINUX_USERNAME>"
   az keyvault secret set --vault-name <YourKeyVaultName> --name "LinuxPrivateKeyPath" --value "<PRIVATE_KEY_PATH>"
   az keyvault secret set --vault-name <YourKeyVaultName> --name "WindowsUsername" --value "<WINDOWS_USERNAME>"
   az keyvault secret set --vault-name <YourKeyVaultName> --name "WindowsPassword" --value "<WINDOWS_PASSWORD>"
   ```

### Step 2: Run the Script in Cloud Shell
1. Upload the script to Azure Cloud Shell.
2. Execute the script:
   ```bash
   pwsh Log4Shell_CloudShell.ps1
   ```

3. The Excel report will be saved in your Cloud Shell home directory as `Log4Shell_Vulnerability_Report.xlsx`.

## Limitations
- This script assumes all VMs have public IPs. Private IP configurations are not supported.
- Ensure that the Key Vault secrets are set up before running the script.

## Support
For issues or feature requests, please contact the repository maintainer.
