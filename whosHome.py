import pyshark
import re
import csv
import os

def scan(network_interface):
    #Capture From Source
    cap = pyshark.LiveCapture(interface=network_interface, display_filter='dhcp')

    #Loop through each incoming packet
    for packet in cap.sniff_continuously():
        isKnown = False
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
       
        date = os.popen('date').read()

        try: 
            text = result.group()
            pattern = r'((?<=\:\s).*)'
            result = re.search(pattern, text)

            host = str(result.group()).rstrip()
        except:
            host = "NULL"

        try:
            with open('macs.csv', mode='r') as csv_file:
                csv_reader = csv.DictReader(csv_file)
        except:
                print("No macs.csv File")


            #Process mac addr if host is known or not
            if result is not None:
                #Parse through authorized macs
                for row in csv_reader:
                    #CHANGE THIS FOR TESTING NEW MAC ADDR
                    if(str(mac) == row["macs"]):
                        isKnown = True
                    else:
                        pass

                if(isKnown == True):
                    pass
                else:
                    #Print to screen
                    a = "UNAUTHORIZED MAC:"
                    print(date + ' ' + a + ' ' + host + ' ' + mac)

                    #Write to log file
                    f = open("/var/log/whoshome/maclogs.txt", "a")
                    f.write("{} {} {} {}\n".format(date, a, host, mac))
                    f.close()

#START
if __name__ == "__main__":
    #CHANGE THIS FOR DIFFERENT INTERFACES
    scan('eth0')
