#!/bin/python3
import argparse, pwn, sys, signal, os, json, xml, xmltodict, re

def signal_handler(key,frame):
    pwn.log.failure("Exit...")
    sys.exit(1)

def xml_to_json(name_file):
    file_xml = open(name_file)
    json_content = file_xml.read()
    file_xml.close()
    return json_content

#execute command
def exec_command(command,name_file,p1):
    #try: 
    #    os.popen(command)
    #    try:
    #        json_content = xml_to_json(name_file)
    #        return json_content
    #    except:
    #        p1.status("Corrupt XML.")
    #except:
    #    p1.status("An error has occurred.")    
    os.system(command)

## host alive with ping and arp
def arp_host_discovery(ip_address,p1):
    name_file = "nmap_arp.xml"
    p1.status("ARP Host Discovery scan in progress...")
    command = "nmap -sn -PR {} -oX {}".format(ip_address,name_file)
    json_arp = exec_command(command,name_file,p1)
    return json_arp

def icmp_host_discovery(ip_address,p1):
    name_file = "nmap_icmp.xml"
    p1.status("ICMP Host Discovery scan in progress...")
    command = "nmap -sn -PE --send-ip {} -oX {}".format(ip_address,name_file)
    json_icmp = exec_command(command,name_file,p1)
    return json_icmp

def nmap_allPorts(ip_address,p1):
    name_file = "nmap_output.xml"
    p1.status("nmap scan in progress...")
    command = "nmap -p- --open -T5 -n -oX {} {} 1>/dev/null".format(name_file, ip_address)
    with open("masscan_allports.sh", "w") as f:
        f.write(command )
    json_content_nmap = exec_command(command,name_file,p1)
    return json_content_nmap

def masscan_allPorts(ip_address,p1):
    name_file = "masscan_output.xml"
    p1.status("masscan scan in progress...")
    command = "masscan -p 1-65535 --rate 100000 --wait 0 --open {} -oX {} 1>/dev/null".format(name_file,ip_address)
    json_content_masscan = exec_command(command,name_file,p1)
    return json_content_masscan

def main():
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(description='Automatic scan with nmap and masscan')
    parser.add_argument("-i", dest="ip_address", type=str, action="store", help="enter ip address or subnet with mask in format standar", required=True)
    parser.add_argument("-f", dest="name_folder", type=str, action="store", help="name of folder", required=False)
    args = vars(parser.parse_args())
    
    ipv4 = """^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"""
    cidr = """(10(\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){3}/([8-9]|(1[0-9])|(2[0-9])|(3[0-1])))|(172\.((1[6-9])|(2[0-9])(3[0-1]))(\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){2}/((1[2-9])|(2[0-9])|(3[0-1])))|(192\.168(\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){2}/((1[6-9])|(2[0-9])|(3[0-1])))|(127(\.(([0-9]?[0-9])|(1[0-9]?[0-9])|(2[0-4]?[0-9])|(25[0-5]))){3}/([8-9]|(1[0-9])|(2[0-9])|(3[0-1])))$"""

    if re.search(ipv4,args["ip_address"]):
        p1 = pwn.log.progress("Scan all ports")
        #json_content_nmap = nmap_allPorts(args["ip_address"],p1)
        #json_content_masscan = masscan_allPorts(args["ip_address"],p1)
    elif re.search(cidr,args["ip_address"]):
        p1 = pwn.log.progress("Search host alive")
        #arp_host_discovery(args["ip_address"],p1)
        #icmp_host_discovery(args["ip_address"],p1)
    else:
        print("IP or Subnet invalid!")

if __name__ == "__main__":
    main()