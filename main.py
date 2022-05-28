# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
import ipaddress


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    ip = '192.168.1.1'

    print(ipaddress.ip_address(ip)+255)  # Press ⌘F8 to toggle the breakpoint.

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
