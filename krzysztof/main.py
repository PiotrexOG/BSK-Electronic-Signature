from krzysztof.GUI_interface import create_sidebar, create_encryption_sidebar, create_sign_document_sidebar
from krzysztof.detect_USB import start_usb_detection_thread
from krzysztof.frontend import create_root_window


def main():
    root = create_root_window()
    start_usb_detection_thread()
    create_sidebar(root, 0, 0, 3)
    create_encryption_sidebar(root, 0, 2, 8)
    create_sign_document_sidebar(root, 0, 3, 8)
    root.mainloop()


if __name__ == "__main__":
    main()