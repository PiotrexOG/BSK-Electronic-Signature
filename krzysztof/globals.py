from queue import Queue
import threading

usb_path_queue = Queue()
usb_detected_event = threading.Event()
correctPassword = False
key_password = None
path_public_key = None
path_private_key = None
public_key = None
foundUSB = False