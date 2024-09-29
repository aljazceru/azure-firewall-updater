# Azure Firewall Update Script

This Python script automates the process of updating Azure Network Security Group (NSG) rules to allow SSH access from your current IP address. It's designed to work with Azure VMs and can operate on all VMs in a subscription or target a specific VM.

## Features

- Update NSG rules to allow SSH access from your current IP address
- List all available VMs in your Azure subscription
- Dump existing firewall rules for all VMs or a specific VM
- Perform a dry run to see potential changes without applying them
- Create backups of NSGs before making changes
- Log IP addresses used for updates

## Prerequisites

- Python 3.6 or higher
- Azure CLI installed and configured with your Azure account
- Azure subscription with permission to modify NSGs

## Installation

1. Clone this repository or download the script file.

2. Install the required Python packages:

   ```
   pip install azure-identity azure-mgmt-network azure-mgmt-compute azure-mgmt-subscription requests
   ```

3. Ensure you're logged in to Azure CLI:

   ```
   az login
   ```

## Usage

The script provides several options for different operations:

### List all VMs

To list all available VMs in your subscription:

```
python az-fw.py --list
```

### Update firewall rules

To update firewall rules for all VMs:

```
python az-fw.py
```

To update firewall rules for a specific VM:

```
python az-fw.py --vm <vm_name>
```

### Dry run

To perform a dry run (see potential changes without applying them):

```
python az-fw.py --dry-run
```

or for a specific VM:

```
python az-fw.py --dry-run --vm <vm_name>
```

### Dump firewall rules

To dump current firewall rules for all VMs:

```
python az-fw.py --dump
```

To dump firewall rules for a specific VM:

```
python az-fw.py --dump --vm <vm_name>
```

## Backups and Logging

- NSG backups are stored in the `nsg_backups` directory.
- IP addresses used for updates are logged in the `ip_log.csv` file.

## Notes

- The script uses your current public IP address for updating the NSG rules.
- It only modifies rules for SSH access (port 22).
- If the script encounters any errors, it will display relevant error messages.



## Disclaimer

This script modifies Azure NSG rules. Use it carefully and at your own risk. Always review the changes, especially in production environments.
