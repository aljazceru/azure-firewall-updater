import os
import json
from datetime import datetime
from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.subscription import SubscriptionClient
import requests

def get_azure_clients():
    """Create and return Azure clients using Azure CLI credentials."""
    try:
        credential = AzureCliCredential()
        
        # Get the subscription ID
        subscription_client = SubscriptionClient(credential)
        subscriptions = list(subscription_client.subscriptions.list())
        if not subscriptions:
            raise ValueError("No subscriptions found. Please check your Azure CLI login.")
        subscription_id = subscriptions[0].subscription_id

        network_client = NetworkManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        return network_client, compute_client
    except Exception as e:
        print(f"Error setting up Azure clients: {str(e)}")
        print("Please ensure you're logged in with Azure CLI (run 'az login')")
        exit(1)

def get_resource_group_from_id(resource_id):
    """Extract resource group name from a resource ID."""
    parts = resource_id.split('/')
    return parts[parts.index('resourceGroups') + 1]

def get_current_ip():
    """Get the current outgoing IP address."""
    return requests.get('https://api.ipify.org').text

def backup_nsg(nsg, backup_dir):
    """Create a backup of the network security group."""
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    backup_file = os.path.join(backup_dir, f"{nsg.name}_{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
    with open(backup_file, 'w') as f:
        json.dump(nsg.as_dict(), f)
    return backup_file

def update_nsg_rule(network_client, nsg, ip_address, dry_run=False):
    """Update the NSG rule to allow SSH access from the specified IP."""
    ssh_rule = next((rule for rule in nsg.security_rules if rule.destination_port_range == '22'), None)
    
    if ssh_rule:
        if ip_address not in ssh_rule.source_address_prefixes:
            ssh_rule.source_address_prefixes.append(ip_address)
    else:
        ssh_rule = {
            'name': 'AllowSSH',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '22',
            'source_address_prefixes': [ip_address],
            'destination_address_prefix': '*',
            'access': 'Allow',
            'priority': 1000,
            'direction': 'Inbound'
        }
        nsg.security_rules.append(ssh_rule)
    
    if not dry_run:
        return network_client.network_security_groups.begin_create_or_update(
            get_resource_group_from_id(nsg.id), nsg.name, nsg
        )
    return None

def log_ip(ip_address, log_file):
    """Log the IP address with timestamp."""
    with open(log_file, 'a') as f:
        f.write(f"{datetime.now().isoformat()},{ip_address}\n")

def list_vms():
    """List all virtual machines in the subscription."""
    _, compute_client = get_azure_clients()
    vms = compute_client.virtual_machines.list_all()
    print("Available Virtual Machines:")
    for vm in vms:
        print(f"- {vm.name} (Resource Group: {get_resource_group_from_id(vm.id)})")

def firewall_dump(vm_name=None):
    """Iterate through virtual machines and print their firewall rules."""
    network_client, compute_client = get_azure_clients()
    
    if vm_name:
        vms = [vm for vm in compute_client.virtual_machines.list_all() if vm.name == vm_name]
        if not vms:
            print(f"No VM found with name: {vm_name}")
            return
    else:
        vms = compute_client.virtual_machines.list_all()

    for vm in vms:
        print(f"\nFirewall rules for VM: {vm.name}")
        print("=" * 50)

        resource_group_name = get_resource_group_from_id(vm.id)

        for nic_ref in vm.network_profile.network_interfaces:
            nic_name = nic_ref.id.split('/')[-1]
            try:
                nic = network_client.network_interfaces.get(resource_group_name, nic_name)

                if nic.network_security_group:
                    nsg_id = nic.network_security_group.id
                    nsg_name = nsg_id.split('/')[-1]
                    nsg = network_client.network_security_groups.get(resource_group_name, nsg_name)

                    for rule in nsg.security_rules:
                        print(f"Rule: {rule.name}")
                        print(f"  Direction: {rule.direction}")
                        print(f"  Priority: {rule.priority}")
                        print(f"  Protocol: {rule.protocol}")
                        print(f"  Source Port Range: {rule.source_port_range}")
                        print(f"  Destination Port Range: {rule.destination_port_range}")
                        print(f"  Source Address Prefix: {rule.source_address_prefix}")
                        print(f"  Destination Address Prefix: {rule.destination_address_prefix}")
                        print(f"  Access: {rule.access}")
                        print("-" * 40)
                else:
                    print(f"No Network Security Group associated with NIC: {nic_name}")
            except Exception as e:
                print(f"Error processing NIC {nic_name}: {str(e)}")

def main(dry_run=False, vm_name=None):
    network_client, compute_client = get_azure_clients()
    current_ip = get_current_ip()
    backup_dir = 'nsg_backups'
    log_file = 'ip_log.csv'

    log_ip(current_ip, log_file)

    if vm_name:
        vms = [vm for vm in compute_client.virtual_machines.list_all() if vm.name == vm_name]
        if not vms:
            print(f"No VM found with name: {vm_name}")
            return
    else:
        vms = compute_client.virtual_machines.list_all()

    for vm in vms:
        resource_group_name = get_resource_group_from_id(vm.id)
        for nic_ref in vm.network_profile.network_interfaces:
            nic_name = nic_ref.id.split('/')[-1]
            nic = network_client.network_interfaces.get(resource_group_name, nic_name)

            if nic.network_security_group:
                nsg_id = nic.network_security_group.id
                nsg_name = nsg_id.split('/')[-1]
                nsg = network_client.network_security_groups.get(resource_group_name, nsg_name)

                backup_file = backup_nsg(nsg, backup_dir)
                print(f"Backed up NSG {nsg.name} to {backup_file}")

                operation = update_nsg_rule(network_client, nsg, current_ip, dry_run)
                if dry_run:
                    print(f"Dry run: Would update NSG {nsg.name} to allow SSH from {current_ip}")
                else:
                    operation.wait()
                    print(f"Updated NSG {nsg.name} to allow SSH from {current_ip}")
            else:
                print(f"No Network Security Group associated with NIC: {nic_name}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Update Azure VM firewalls for SSH access.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without making changes.")
    parser.add_argument("--dump", action="store_true", help="Dump firewall rules for all VMs.")
    parser.add_argument("--list", action="store_true", help="List all available VMs.")
    parser.add_argument("--vm", help="Specify a VM name to update or dump firewall rules for.")
    args = parser.parse_args()

    if args.list:
        list_vms()
    elif args.dump:
        firewall_dump(args.vm)
    else:
        main(dry_run=args.dry_run, vm_name=args.vm)