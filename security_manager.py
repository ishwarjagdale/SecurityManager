import os
import winreg


class SecurityManager:
    def __init__(self):
        print("Initializing system...")

    @staticmethod
    def write_to_value(hkey, sub_key, value_name, value_type, value):
        """
        opens a key (including subkey) having access to write
        Then adds a property (value_name) to the key and value (value) to it.

        :param hkey: int
        :param sub_key: str
        :param value_name:
        :param value_type: int
        :param value:  | str
        :return None
        """
        handle = winreg.OpenKey(hkey, sub_key, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(handle, value_name, 0, value_type, value)  # creates value_name if it doesn't exist
        winreg.CloseKey(handle)

    @staticmethod
    def toggle_bluetooth(enable=False):
        """
        enables or disables bluetooth according to passed parameter 'enable'.

        :param enable: bool
        :return None
        """
        print("Enabling" if enable else "Disabling", "Bluetooth service...")

        # following keys represents the bluetooth services provided in Windows 10-11
        bluetooth_service_keys = (r"SYSTEM\CurrentControlSet\Services\BthA2dp",
                                  r"SYSTEM\CurrentControlSet\Services\BthAvctpSvc",
                                  r"SYSTEM\CurrentControlSet\Services\BthEnum",
                                  r"SYSTEM\CurrentControlSet\Services\BthHFAud",
                                  r"SYSTEM\CurrentControlSet\Services\BthHFEnum",
                                  r"SYSTEM\CurrentControlSet\Services\BthLEEnum",
                                  r"SYSTEM\CurrentControlSet\Services\BthMini",
                                  r"SYSTEM\CurrentControlSet\Services\BthMODEM",
                                  r"SYSTEM\CurrentControlSet\Services\BthPan",
                                  r"SYSTEM\CurrentControlSet\Services\BTHPORT",
                                  r"SYSTEM\CurrentControlSet\Services\bthserv",
                                  r"SYSTEM\CurrentControlSet\Services\BTHUSB",)

        any_issues = False  # flag variable, True if an exception occurs
        for key in bluetooth_service_keys:
            try:
                # writing value '3' to enable or '4' to disable, to a property name 'Start' for every service key
                SecurityManager.write_to_value(winreg.HKEY_LOCAL_MACHINE, key, 'Start', winreg.REG_DWORD,
                                               3 if enable else 4)
            except OSError as e:
                any_issues = True
                print(f"{key} :: {e}")

        print("Finished", "with some issues\n" if any_issues else "\n")

    @staticmethod
    def toggle_usb_hubs(enable=False):
        """
        enables or disables usb hubs according to passed parameter 'enable'.
        !! may disable inbuilt fingerprint (biometric) devices

        :param enable: bool
        :return: None
        """
        print("Enabling" if enable else "Disabling", "USB ports...")

        # the following keys represent the USB Hubs of versions 2.0 and 3.0
        usb_hub_keys = (r"SYSTEM\CurrentControlSet\Services\usbhub",
                        r"SYSTEM\CurrentControlSet\Services\USBHUB3",)

        any_issues = False
        for key in usb_hub_keys:
            try:
                SecurityManager.write_to_value(winreg.HKEY_LOCAL_MACHINE, key, 'Start', winreg.REG_DWORD,
                                               3 if enable else 4)
            except OSError as e:
                any_issues = True
                print(f"{key} :: {e}")

        print("Finished", "with some issues\n" if any_issues else "\n")

    @staticmethod
    def toggle_cmd(enable=False):
        """
        enables or disables command prompt according to passed parameter 'enable'.

        :param enable: bool
        :return: None
        """
        print("Enabling" if enable else "Disabling", "CMD...")
        try:

            # Creates key named 'System' and sets property DisableCMD to 0 or 2
            handle = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r'Software\Policies\Microsoft\Windows\System', 0,
                                        winreg.KEY_WRITE)

            # value 0 or 1 enables the service and 2 disables the service
            winreg.SetValueEx(handle, 'DisableCMD', 0, winreg.REG_DWORD, 0 if enable else 2)
        except OSError as e:
            print(e, f"while {'enabling' if enable else 'disabling'} CMD")

        print("Finished\n")

    @staticmethod
    def toggle_website_access(urls, enable=False):
        """
        enables or disable access to a given website or list of websites
        by changing the IP address of the domain

        this method manipulates the file C:/Windows/System32/drivers/etc/hosts
        to disable the following line is added to the file

                "127.0.0.1 <tab character> domain-name"

        and to enable, the above line is removed from the hosts

        :param urls: list | str
        :param enable: bool
        :return: None
        """
        print("Allowing" if enable else "Blocking", f"access to {urls}...")

        if type(urls) == str:
            urls = [urls, ]  # if parameter urls is a string, then it is converted into a list

        try:
            if enable:
                with(open(os.path.join(os.environ.get("WINDIR"), "System32\\drivers\\etc\\hosts"), "r")) as hosts:
                    lines = hosts.readlines()  # a list of lines from the file is gathered
                for url in urls:
                    # removes lines containing a line such as "127.0.0.1 <tab character> url"
                    lines = list(filter(
                        lambda line: len(line.strip()) and url not in line and line.strip().split()[0] != "127.0.0.1",
                        lines))

                # the list of lines are again written to the file
                with(open(os.path.join(os.environ.get("WINDIR"), "System32\\drivers\\etc\\hosts"), "w")) as hosts:
                    hosts.writelines(lines)

            else:

                # while disabling, the following string is appended at the end of the file
                with(open(os.path.join(os.environ.get("WINDIR"), "System32\\drivers\\etc\\hosts"), "a+")) as hosts:
                    for url in urls:
                        hosts.write(f"\n127.0.0.1\t{url}\n")

        except OSError as e:
            print(e)
        except Exception as e:
            print(e)


if __name__ == '__main__':

    secure_u = SecurityManager()

    print("""
Choose one of the following service:
[1] Bluetooth
[2] USB Hubs
[3] Command Prompt
[4] Block a domain

[0] To quit
            """)

    while True:

        option = input(">> ").strip()

        def get_mode():
            """
            returns True if entered 1 else False if entered 0 else choose again
            :return: bool
            """
            while True:
                en_or_di = input("Enter 0 to disable or 1 to enable: ").strip()

                if en_or_di == '0':
                    return False
                elif en_or_di == '1':
                    return True
                else:
                    print("Invalid mode, choose again")

        match option:
            case '0':
                exit(0)
            case '1':
                secure_u.toggle_bluetooth(get_mode())
            case '2':
                secure_u.toggle_usb_hubs(get_mode())
            case '3':
                secure_u.toggle_cmd(get_mode())
            case '4':
                urls = input("Enter comma separated domain names: ").strip().split(",")
                secure_u.toggle_website_access(urls, get_mode())
            case _:
                print("Invalid service")
