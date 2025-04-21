from scapy.all import sniff, DNS, DNSRR, TCP, UDP
import requests
import socket
import os
import psutil
import time
import pywifi
import threading 


BACKEND_SERVER_URL = "localhost:4141"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error as e:
        print(f"Error getting local IP address: {e}")
        return None

def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    else:
        return "Unknown"

def send_data_to_backend(data):
    try:
        response = requests.post(
            f"http://{BACKEND_SERVER_URL}/network_details", json=data)
        response.raise_for_status()
        print("Data sent successfully to the backend server.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending data to the backend server: {e}")

def packet_callback(packet):
    local_ip = get_local_ip()
    print(local_ip)
    # print(packet)
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = get_protocol(packet)

        if src_ip == local_ip:
            if packet.haslayer("TCP"):
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                src_port = packet["UDP"].sport
                dst_port = packet["UDP"].dport
            else:
                src_port = "N/A"
                dst_port = "N/A"

            if packet.haslayer(DNS) and packet[DNS].qd:
                src_domain = packet[DNS].qd.qname.decode("utf-8", errors="replace")
                dst_ip = get_destination_ip(src_domain)
                print("domain " + src_domain)
            else:
                src_domain = "N/A"

            if DNSRR in packet:
                dst_domain = packet[DNSRR].rrname.decode("utf-8", errors="replace")
            else:
                dst_domain = "N/A"

            data = {
                "source_ip": src_ip,
                "source_port": src_port,
                "source_domain": src_domain,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "destination_domain": dst_domain,
                "protocol": protocol
            }

            if (data['destination_ip'] != "localhost" and data['source_domain'] != "N/A"):
                print(data)
                send_data_to_backend(data)

def get_destination_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        return "N/A"

def get_process_details():
    process_details = []

    # Get a list of all running processes
    processes = psutil.process_iter(
        ['pid', 'name', 'username', 'cpu_percent', 'memory_info'])

    for process in processes:
        try:
            # Convert memory usage from bytes to megabytes
            memory_mb = process.info['memory_info'].rss / (1024 ** 2)

            # Append process details to the list
            process_details.append({
                'PID': process.info['pid'],
                'Name': process.info['name'],
                'Username': process.info['username'],
                'CPU Percent': process.info['cpu_percent'],
                'Memory Usage (MB)': memory_mb
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Ignore processes that cannot be accessed

    return process_details

def get_connected_devices():
    connected_devices = []

    # Get Wi-Fi connected devices
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        scan_results = iface.scan_results()
        for device in scan_results:
            # Clean up device name and MAC address
            cleaned_device_name = device.ssid.strip()
            cleaned_mac_address = device.bssid.replace(':', '').upper()

            connected_devices.append({
                'Device Type': 'Wi-Fi',
                'Device Name': cleaned_device_name,
                'MAC Address': cleaned_mac_address,
                'Signal Strength': device.signal
            })
    except Exception as e:
        print(f"Error in Wi-Fi scanning: {e}")

    # Get information about secondary storage devices (pendrive, etc.)
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts or 'cdrom' in partition.opts:
            device_name = os.path.basename(partition.device)
            connected_devices.append({
                'Device Type': 'Secondary Storage',
                'Device Name': device_name,
                'Mount Point': partition.mountpoint
            })

    return connected_devices

def write_to_text_file(data, file_path='output.txt'):
    with open(file_path, 'w') as file:
        # Write header
        if (data):
            file.write("\t".join(data[0].keys()) + "\n")

        # Write details
        for entry in data:
            file.write("\t".join(map(str, entry.values())) + "\n")

def send_to_server(file_paths, server_ip='localhost', server_port=4141):
    try:
        for file_path in file_paths:
            # Extract the file name from the file path
            file_name = os.path.basename(file_path)
            print(f"Uploading file: {file_name}")  # Add this line for logging
            with open(file_path, 'rb') as file:
                file_content = file.read()  # Read the content before closing
                # Use the same API endpoint for both types of files
                if 'connected_devices' in file_name.lower():
                    endpoint = f'http://{server_ip}:{server_port}/connected_devices'
                else:
                    endpoint = f'http://{server_ip}:{server_port}/process_details'
                # Ensure that the field name is 'file'
                files = {'file': (file_name, file_content)}

                response = requests.post(endpoint, files=files)

                if response.status_code == 200:
                    print(f"File '{file_name}' successfully sent to the server.")
                else:
                    print(f"Failed to send file '{file_name}'. Server returned status code: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def network_sniffing():
    # Sniff network packets
    sniff(prn=packet_callback, store=0)

def process_and_devices():
    while True:
        # Get and write process details
        processes = get_process_details()
        write_to_text_file(processes, 'process_details.txt')
        print("Process details updated in process_details.txt")

        # Get and write connected devices details
        connected_devices = get_connected_devices()
        write_to_text_file(connected_devices, 'connected_devices.txt')
        print("Connected devices details updated in connected_devices.txt")

        # Send the files to the server
        send_to_server(
            ['process_details.txt', 'connected_devices.txt'], server_port=4141)

        # Add a delay (e.g., 60 seconds) before the next iteration
        time.sleep(10)

if __name__ == "__main__":
    # Run the network sniffing in a separate thread
    network_thread = threading.Thread(target=network_sniffing)
    network_thread.start()

    # Run the process and devices script in the main thread
    process_and_devices()