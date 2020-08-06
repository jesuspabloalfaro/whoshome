import pyshark
import re

#Authorized Macs
auth_macs = ['48:b8:a3:eb:39:83', '64:76:ba:97:80:08']

def scan(network_interface):
    #Capture From Source
    cap = pyshark.LiveCapture(interface=network_interface, display_filter='dhcp')

    #Loop through each incoming packet
    for packet in cap.sniff_continuously():
        #Filter out to lowest layer (ETH)
        text = str(packet.layers[3])
        pattern = r'(Client MAC address: (\w{2}):(\w{2}):(\w{2}):(\w{2}):(\w{2}):(\w{2}))'
        result = re.search(pattern, text)

        #Filter out existing text to get plain mac addr
        text = result.group()
        pattern = r'((\w{2}):(\w{2}):(\w{2}):(\w{2}):(\w{2}):(\w{2}))'
        result = re.search(pattern, text)

        #Create mac variable for ease of use
        mac = str(result.group())

        #Filter out hostname
        text = str(packet.layers[3])
        pattern = r'(Host Name: (.*))'
        result = re.search(pattern, text)

        text = result.group()
        pattern = r'((?<=\:\s).*)'
        result = re.search(pattern, text)

        host = str(result.group()).rstrip()

        #Process mac addr if host is known or not
        if result is not None:
            #Parse through authorized macs
            for a_mac in auth_macs:
                #CHANGE THIS FOR TESTING NEW MAC ADDR
                if(str(mac) == a_mac):
                    pass
                else:
                    #Print to screen
                    a = "UNAUTHORIZED MAC:"
                    print(a + ' ' + host + ' ' + mac)

                    #Write to log file
                    f = open("maclogs.txt", "a")
                    f.write("{} {} {}\n".format(a, host, mac))
                    f.close()

#START
if __name__ == "__main__":
    #CHANGE THIS FOR DIFFERENT INTERFACES
    scan('Ethernet')        