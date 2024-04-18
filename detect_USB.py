import os
import psutil


def detect_usb():
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            removable_disk = partition.mountpoint
            print(f"Found USB drive at {removable_disk} (Name: {partition.device})")
            key_file_path = os.path.join(removable_disk, 'key.pem')
            if os.path.exists(key_file_path):
                print("Found key.pem file on the removable disk.")
                return key_file_path
            else:
                print("key.pem file not found on the removable disk.")
    print("No USB drive found.")
    return "False"
