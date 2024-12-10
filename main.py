import sys
from scanner_gui import main as gui_main
from malware_scanner import MalwareScanner
import logging
import wmi
import platform
from datetime import datetime

def setup_logging():
    logging.basicConfig(
        filename='malware_scanner.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def get_system_info():
    try:
        c = wmi.WMI()
        system_info = {}
        
        # System/Machine HWID Information
        for system in c.Win32_ComputerSystemProduct():
            system_info['System'] = {
                'Name': system.Name,
                'Vendor': system.Vendor,
                'Version': system.Version,
                'UUID': system.UUID,
                'SKU': system.SKUNumber,
                'Identifier': system.IdentifyingNumber
            }
        
        # CPU Information with HWID
        for processor in c.Win32_Processor():
            system_info['CPU'] = {
                'Name': processor.Name,
                'Manufacturer': processor.Manufacturer,
                'Cores': processor.NumberOfCores,
                'Threads': processor.NumberOfLogicalProcessors,
                'ProcessorId': processor.ProcessorId,  # CPU HWID
                'DeviceID': processor.DeviceID,
                'Serial': processor.SerialNumber if hasattr(processor, 'SerialNumber') else 'N/A',
                'Architecture': processor.Architecture
            }
        
        # Motherboard Information
        for board in c.Win32_BaseBoard():
            system_info['Motherboard'] = {
                'Manufacturer': board.Manufacturer,
                'Product': board.Product,
                'Serial': board.SerialNumber,
                'Version': board.Version,
                'Tag': board.Tag
            }
        
        # BIOS Information
        for bios in c.Win32_BIOS():
            system_info['BIOS'] = {
                'Manufacturer': bios.Manufacturer,
                'Version': bios.Version,
                'Serial': bios.SerialNumber,
                'ReleaseDate': bios.ReleaseDate
            }
        
        # RAM Information with detailed IDs
        total_ram = 0
        ram_info = []
        for ram in c.Win32_PhysicalMemory():
            ram_data = {
                'Manufacturer': ram.Manufacturer,
                'PartNumber': ram.PartNumber,
                'Capacity': f"{round(int(ram.Capacity) / (1024**3), 2)} GB",
                'Speed': f"{ram.Speed} MHz",
                'Serial': ram.SerialNumber,
                'DeviceLocator': ram.DeviceLocator,
                'BankLabel': ram.BankLabel,
                'Tag': ram.Tag
            }
            ram_info.append(ram_data)
            total_ram += int(ram.Capacity)
        system_info['RAM'] = {
            'Modules': ram_info,
            'Total': f"{round(total_ram / (1024**3), 2)} GB"
        }
        
        # Storage Information with detailed IDs
        storage_info = []
        for disk in c.Win32_DiskDrive():
            storage_data = {
                'Model': disk.Model,
                'Size': f"{round(int(disk.Size) / (1024**3), 2)} GB",
                'Serial': disk.SerialNumber,
                'InterfaceType': disk.InterfaceType,
                'DeviceID': disk.DeviceID,
                'PNPDeviceID': disk.PNPDeviceID,
                'Signature': disk.Signature
            }
            storage_info.append(storage_data)
        system_info['Storage'] = storage_info
        
        # GPU Information with detailed IDs
        gpu_info = []
        for gpu in c.Win32_VideoController():
            gpu_data = {
                'Name': gpu.Name,
                'Manufacturer': gpu.VideoProcessor,
                'Memory': f"{round(int(gpu.AdapterRAM if gpu.AdapterRAM else 0) / (1024**3), 2)} GB",
                'Driver Version': gpu.DriverVersion,
                'DeviceID': gpu.DeviceID,
                'PNPDeviceID': gpu.PNPDeviceID,
                'VideoProcessor': gpu.VideoProcessor,
                'VideoArchitecture': gpu.VideoArchitecture
            }
            gpu_info.append(gpu_data)
        system_info['GPU'] = gpu_info
        
        # Network Adapters Information
        network_info = []
        for nic in c.Win32_NetworkAdapter(PhysicalAdapter=True):
            network_data = {
                'Name': nic.Name,
                'Manufacturer': nic.Manufacturer,
                'MACAddress': nic.MACAddress,
                'DeviceID': nic.DeviceID,
                'PNPDeviceID': nic.PNPDeviceID,
                'GUID': nic.GUID if hasattr(nic, 'GUID') else 'N/A',
                'AdapterType': nic.AdapterType
            }
            network_info.append(network_data)
        system_info['Network'] = network_info
        
        # Operating System Information
        for os in c.Win32_OperatingSystem():
            system_info['OS'] = {
                'Name': os.Caption,
                'Version': os.Version,
                'Architecture': os.OSArchitecture,
                'Serial': os.SerialNumber,
                'Install Date': os.InstallDate,
                'SystemDrive': os.SystemDrive,
                'WindowsDirectory': os.WindowsDirectory,
                'BuildNumber': os.BuildNumber,
                'ProductID': os.SerialNumber
            }
        
        logging.info("System information collected successfully")
        logging.info(f"System Info: {system_info}")
        
        return system_info
        
    except Exception as e:
        logging.error(f"Error collecting system information: {str(e)}")
        return None

def format_system_info(system_info):
    """Format system information into a readable string"""
    if not system_info:
        return "Could not collect system information"
        
    formatted = "=== SYSTEM INFORMATION ===\n\n"
    
    # System/Machine Info
    if 'System' in system_info:
        formatted += "System:\n"
        sys = system_info['System']
        formatted += f"  Name: {sys['Name']}\n"
        formatted += f"  Vendor: {sys['Vendor']}\n"
        formatted += f"  UUID: {sys['UUID']}\n"
        formatted += f"  SKU: {sys['SKU']}\n"
        formatted += f"  Identifier: {sys['Identifier']}\n\n"
    
    # CPU
    if 'CPU' in system_info:
        formatted += "CPU:\n"
        cpu = system_info['CPU']
        formatted += f"  Name: {cpu['Name']}\n"
        formatted += f"  Manufacturer: {cpu['Manufacturer']}\n"
        formatted += f"  Cores/Threads: {cpu['Cores']}/{cpu['Threads']}\n"
        formatted += f"  Processor ID: {cpu['ProcessorId']}\n"
        formatted += f"  Device ID: {cpu['DeviceID']}\n"
        formatted += f"  Serial: {cpu['Serial']}\n"
        formatted += f"  Architecture: {cpu['Architecture']}\n\n"
    
    # Motherboard
    if 'Motherboard' in system_info:
        formatted += "Motherboard:\n"
        mb = system_info['Motherboard']
        formatted += f"  Manufacturer: {mb['Manufacturer']}\n"
        formatted += f"  Product: {mb['Product']}\n"
        formatted += f"  Serial: {mb['Serial']}\n"
        formatted += f"  Version: {mb['Version']}\n"
        formatted += f"  Tag: {mb['Tag']}\n\n"
    
    # RAM
    if 'RAM' in system_info:
        formatted += "RAM:\n"
        formatted += f"  Total: {system_info['RAM']['Total']}\n"
        for i, module in enumerate(system_info['RAM']['Modules'], 1):
            formatted += f"  Module {i}:\n"
            formatted += f"    Manufacturer: {module['Manufacturer']}\n"
            formatted += f"    Part Number: {module['PartNumber']}\n"
            formatted += f"    Capacity: {module['Capacity']}\n"
            formatted += f"    Speed: {module['Speed']}\n"
            formatted += f"    Serial: {module['Serial']}\n"
            formatted += f"    Location: {module['DeviceLocator']}\n"
            formatted += f"    Bank: {module['BankLabel']}\n\n"
    
    # Storage
    if 'Storage' in system_info:
        formatted += "Storage:\n"
        for i, disk in enumerate(system_info['Storage'], 1):
            formatted += f"  Disk {i}:\n"
            formatted += f"    Model: {disk['Model']}\n"
            formatted += f"    Size: {disk['Size']}\n"
            formatted += f"    Serial: {disk['Serial']}\n"
            formatted += f"    Interface: {disk['InterfaceType']}\n"
            formatted += f"    Device ID: {disk['DeviceID']}\n"
            formatted += f"    PNP Device ID: {disk['PNPDeviceID']}\n\n"
    
    # GPU
    if 'GPU' in system_info:
        formatted += "GPU:\n"
        for i, gpu in enumerate(system_info['GPU'], 1):
            formatted += f"  GPU {i}:\n"
            formatted += f"    Name: {gpu['Name']}\n"
            formatted += f"    Manufacturer: {gpu['Manufacturer']}\n"
            formatted += f"    Memory: {gpu['Memory']}\n"
            formatted += f"    Driver: {gpu['Driver Version']}\n"
            formatted += f"    Device ID: {gpu['DeviceID']}\n"
            formatted += f"    PNP Device ID: {gpu['PNPDeviceID']}\n\n"
    
    # Network
    if 'Network' in system_info:
        formatted += "Network Adapters:\n"
        for i, nic in enumerate(system_info['Network'], 1):
            formatted += f"  Adapter {i}:\n"
            formatted += f"    Name: {nic['Name']}\n"
            formatted += f"    MAC Address: {nic['MACAddress']}\n"
            formatted += f"    Device ID: {nic['DeviceID']}\n"
            formatted += f"    GUID: {nic['GUID']}\n"
            formatted += f"    Type: {nic['AdapterType']}\n\n"
    
    # OS
    if 'OS' in system_info:
        formatted += "Operating System:\n"
        os = system_info['OS']
        formatted += f"  Name: {os['Name']}\n"
        formatted += f"  Version: {os['Version']}\n"
        formatted += f"  Architecture: {os['Architecture']}\n"
        formatted += f"  Serial: {os['Serial']}\n"
        formatted += f"  Build: {os['BuildNumber']}\n"
        formatted += f"  Product ID: {os['ProductID']}\n"
        formatted += f"  Install Date: {os['Install Date']}\n"
    
    return formatted

def main():
    setup_logging()
    try:
        # Collect system information
        system_info = get_system_info()
        formatted_info = format_system_info(system_info)
        
        if system_info:
            logging.info("Successfully collected hardware information")
        else:
            logging.warning("Failed to collect complete hardware information")
            
        # Start GUI with system info
        gui_main(formatted_info)  # Make sure this line is passing the formatted_info
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 