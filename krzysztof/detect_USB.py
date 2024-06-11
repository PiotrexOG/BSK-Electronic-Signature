import os
import psutil
import globals
import time
import threading
from GUI_interface import update_sign_document_sidebar
def start_usb_detection_thread():
    detection_thread = threading.Thread(target=usb_detection_loop, daemon=True)
    detection_thread.start()
def usb_detection_loop():
    while True:
        usb_path = detect_usb()
        if usb_path and usb_path != "False":
            globals.usb_path_queue.put(usb_path)
            globals.usb_detected_event.set()
        time.sleep(5)  # Check every 5 seconds

def refresh_sidebar_if_usb_detected(root, sidebar, pendrive_label):

    if globals.usb_detected_event.is_set():
        globals.usb_detected_event.clear()
        private_key_path = globals.usb_path_queue.get()
        update_sign_document_sidebar(sidebar, private_key_path, pendrive_label)
    root.after(1000, refresh_sidebar_if_usb_detected, root, sidebar, pendrive_label)

def detect_usb():
    for partition in psutil.disk_partitions():
        if 'removable' in partition.opts:
            removable_disk = partition.mountpoint
            if not globals.foundUSB:
                print(f"Found USB drive at {removable_disk} (Name: {partition.device})")
            key_file_path = os.path.join(removable_disk, 'encrypted_private_key.bin')
            if os.path.exists(key_file_path):
                if not globals.foundUSB:
                    print("Found key.pem file on the removable disk.")
                globals.foundUSB = True
                return key_file_path
            else:
                globals.foundUSB = False
                print("key.pem file not found on the removable disk.")
        else:
            globals.foundUSB = False
    #print("No USB drive found.")
    return "False"