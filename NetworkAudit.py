import platform
import nmap
import subprocess
import re
import os
import sys

nm = nmap.PortScanner()


def macBook(dataa):
    finalOne = []       # final output: list of tuples, each tuple is one active interface and all its data
    interface_name = []
    interface_status = False

    for everyData in dataa.stdout.splitlines():
        if everyData.startswith((" ", "\t")) == False:  # if it is a header line (en0, en11, etc.)
            if interface_status == False:               # and the previous interface was not active
                interface_name.clear()                  # clear the temp list
            interface_name.append(everyData.strip())    # add the interface header to the temp list
        else:
            interface_name.append(everyData.strip())    # add each indented data line to the temp list
            if everyData.strip() == "status: active":   # found an active interface
                interface_status = True
                finalOne.append(tuple(interface_name))  # save it to the final list as a tuple
                interface_status = False
                interface_name.clear()
            elif everyData.strip() == "status: inactive":
                interface_status = False
            else:
                interface_status = False

    return finalOne


def windows(dataa):
    finalOne = []
    tempList = []
    interface_status = False

    for everyData in dataa.stdout.splitlines():
        if everyData.startswith((" ", "\t")) == False and len(everyData) > 1:
            if interface_status == False:
                tempList.clear()
            tempList.append(everyData.strip())
        else:
            clean_Str = re.sub(r"[\s.]+:", ":", everyData.strip())  # remove dots/spaces before colons
            tempList.append(clean_Str)
            if "NetBIOS over Tcpip" in clean_Str:   # last line of a fully connected Windows interface
                interface_status = True
                finalOne.append(tuple(tempList))
                interface_status = False
                tempList.clear()
            else:
                interface_status = False

    return finalOne


def buildInterfaceDict(interfaces, deviceOS):
    # Takes the list of active interface tuples and builds a dictionary
    # Key: interface name (en0, Ethernet, etc.)
    # Value: dictionary of all key-value pairs for that interface
    interfaceDict = {}

    for index, tupl in enumerate(interfaces):
        interfaceHeader = tupl[0].split(":")[0]
        newDict = {}

        for everyLine in tupl[1:]:
            if deviceOS == "Windows":
                if ":" not in everyLine:
                    continue
                key, val = everyLine.split(":", 1)
                newDict[key] = val.strip()
            elif deviceOS == "Darwin":
                if " " not in everyLine:
                    continue
                key, val = everyLine.split(" ", 1)
                if key == "inet":
                    parts = val.split()
                    newDict["inet"]      = parts[0]
                    newDict["netmask"]   = parts[parts.index("netmask") + 1]
                    newDict["broadcast"] = parts[parts.index("broadcast") + 1]
                else:
                    newDict[key] = val

        interfaceDict[interfaceHeader] = newDict

    return interfaceDict


def getSubnets(interfaceDict, deviceOS):
    # Converts each active interface's subnet mask to CIDR notation
    # Returns a list of strings in the format "IP/prefix" e.g. "192.168.1.5/24"
    subnets = []

    for primary, product in interfaceDict.items():

        if deviceOS == "Darwin":
            if "inet" not in product:
                continue
            hexNumb = product["netmask"]
            ip = product["inet"]

            final = int(hexNumb, 16)        # convert hex mask to integer
            mask_bytes = final.to_bytes(4, "big")
            '''
            .to_bytes(4, "big") chops the integer into 4 separate 8-bit chunks (octets)
            e.g. 0xffffff00 becomes b'\xff\xff\xff\x00' which is [255, 255, 255, 0]
            '''
            prefix_len = bin(final).count("1")  # count the 1 bits to get CIDR prefix length
            subnets.append(f"{ip}/{prefix_len}")

        elif deviceOS == "Windows":
            dotted_mask = product["Subnet Mask"]
            ip = product["IPv4 Address"].strip().replace("(Preferred)", "").strip()

            # Step 1: split dotted decimal mask into list of integers [255, 255, 255, 0]
            mask_bytes = list(map(int, dotted_mask.split(".")))

            # Step 2: convert the 4 bytes into a single 32-bit integer using big-endian base-256 math
            '''
            255 * (256**3) = 4,278,190,080
            255 * (256**2) =    16,711,680
            255 * (256**1) =        65,280
              0 * (256**0) =             0
            Total          = 4,294,967,040
            '''
            final = int.from_bytes(mask_bytes, "big")

            # Step 3: count the 1 bits for CIDR prefix length
            prefix_len = bin(final).count("1")

            # Step 4: failsafe - rebuild the mask from prefix_len and compare to original input
            '''
            "1" * prefix_len builds a string of 1s e.g. "111111111111111111111111" for /24
            .ljust(32, "0") pads right side with zeros to reach 32 characters total
            then we convert back to dotted decimal and compare to the original mask
            if they do not match the input mask had non-contiguous bits and is invalid
            '''
            valid_binary = ("1" * prefix_len).ljust(32, "0")
            valid_mask = ".".join(map(str, int(valid_binary, 2).to_bytes(4, "big")))

            if dotted_mask != valid_mask:
                raise ValueError(f"Invalid subnet mask: {dotted_mask}")

            subnets.append(f"{ip}/{prefix_len}")

    return subnets


def nmapScan(subnets):
    # Runs a quiet ping scan (-sn) on each subnet and prints discovered devices
    for subnet in subnets:
        result = nm.scan(subnet, arguments="-sn")
        for ip, data in result["scan"].items():
            hostname = data["hostnames"][0]["name"] if data["hostnames"][0]["name"] else "No hostname"
            mac      = data["addresses"].get("mac", "No MAC")
            vendor   = list(data["vendor"].values())[0] if data["vendor"] else "Unknown vendor"
            state    = data["status"]["state"]
            reason   = data["status"]["reason"]

            print(f"{ip:<20} {mac:<20} {vendor:<40} {hostname:<30} ({state} / {reason})")


if __name__ == "__main__":
    deviceOS = platform.system()

    # On Mac, nmap needs root for ARP scanning
    # If not root, relaunch this exact script with sudo automatically
    if deviceOS == "Darwin" and os.geteuid() != 0:
        print("Relaunching with sudo for full ARP scan...")
        subprocess.run(["sudo", sys.executable] + sys.argv)
        sys.exit()

    if deviceOS == "Darwin":
        data = subprocess.run("ifconfig", capture_output=True, text=True)
        interfaces = macBook(data)
    elif deviceOS == "Windows":
        data = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
        interfaces = windows(data)
    else:
        raise SystemExit(f"Unsupported OS: {deviceOS}")

    interfaceDict = buildInterfaceDict(interfaces, deviceOS)
    subnets       = getSubnets(interfaceDict, deviceOS)
    nmapScan(subnets)