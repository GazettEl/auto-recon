#!/bin/bash

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

function trap_ctrlc(){
        echo -e "\n${redColour}[*]${endColour} Exit."
        exit 2
}

function scan_arp(){
        nmap -sn -PR $ip_address -oG nmap_arp.tmp
        tail -n +2 nmap_arp.tmp | head -n -1 | cut -f2 -d " " >> nmap_all.tmp; rm nmap_arp.tmp
}

function scan_icmp(){
        nmap -sn -PE --send-ip $ip_address -oG nmap_icmp.tmp
        tail -n +2 nmap_icmp.tmp | head -n -1 | cut -f2 -d " " >> nmap_all.tmp; rm nmap_icmp.tmp
}

function scan_allPorts(){
	nmap -p- --open -T5 -n -oG nmap_allPorts.tmp $ip_address
	ports="$(cat nmap_allPorts.tmp | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
	echo -e "$ip_address:$ports" >> ports.tmp; rm nmap_allPorts.tmp
}

function scan_services(){
	nmap -sCV -p$ports $ip_address -oN "services_$ip_address"
}

function scan_ports_range(){
	for ip in $(cat $FILE); do
		nmap -p- --open -T5 -n -oG "nmap_allPorts_$ip.tmp" $ip
	done
	for file in $(ls nmap_allPorts_*); do
		ports="$(cat $file | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
		ip_address="$(cat $file | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
		echo -e "$ip_address:$ports" >> ports-hosts-alive.tmp
	done
}

function scan_services_range(){
	for line in $(cat ports-hosts-alive);do                                                                                                                                        10.10.14.6
		ports="$(echo $line | awk '{print $2}' FS=':')"
		ip="$(echo $line | awk '{print $1}' FS=':')"
		if [ "$ports" != "X" ]; then
			nmap -sCV -p$ports $ip -oN "services_$ip"
		fi
	done

}

function scan_host(){
        if valid_ip $ip; then
                echo -e "\n${blueColour}---------${endColour} ${greenColour}Scan all port${endColour} ${blueColour}---------${endColour}"
                scan_allPorts $ip_address
                ports="$(cat ports.tmp | awk '{print $2}' FS=':')"
                echo -e "\n${blueColour}---------${endColour} ${greenColour}Ports open${endColour} ${blueColour}---------${endColour}"
                echo -e "${blueColour}[*]${endColour} $ip_address - $ports"
                echo -e "\n${blueColour}---------${endColour} ${greenColour}Scan services in $ip_address${endColour} ${blueColour}---------${endColour}"
                rm ports.tmp
                scan_services $ports $ip_address
        else
                echo -e "Invalid ip"
        fi
}

function hosts_alive(){
        if [[ $ip_address == *"/"* ]]; then
                echo -e "\n${blueColour}---------${endColour} ${greenColour}Search host alive${endColour} ${blueColour}---------${endColour}"
                echo -e "\n${blueColour}[*]${endColour} ${greenColour}ARP Host Discovery scan in progress...${endColour}"
                scan_arp $ip_address
                echo -e "\n${blueColour}[*]${endColour} ${greenColour}ICMP Host Discovery scan in progress...${endColour}"
                scan_icmp $ip_address
                cat nmap_all.tmp | sort -u > nmap_alive.tmp; rm nmap_all.tmp
                echo -e "\n${blueColour}---------${endColour} ${greenColour}Hosts alive${endColour} ${blueColour}---------${endColour}"
                for i in $(cat nmap_alive); do echo -e "${blueColour}[*]${endColour} $i"; done
        fi
        FILE=nmap_alive.tmp
        if [ -f "$FILE" ]; then
		echo -e "\n${blueColour}---------${endColour}Scan all ports in hosts alive${greenColour}${endColour} ${blueColour}---------${endColour}"
		scan_ports_range $FILE
		for line in $(cat ports-hosts-alive.tmp); do
			ports="$(echo $line | awk '{print $2}' FS=':')"
			if [[ -z "$ports" ]]; then
				ports="X"
			fi
			ip="$(echo $line | awk '{print $1}' FS=':')"
			echo -e "${blueColour}[*]${endColour} $ip - $ports"
			echo -e "$ip:$ports" >> ports-hosts-alive
		done
		scan_services_range
        else
                echo "$FILE does not exist."
        fi

}

function valid_ip(){
    local  ip=$ip_address
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

function main() {
        trap "trap_ctrlc" 2
        ip_address=$2
	C=$1
	case "$C" in
	"hosts_alive")
		hosts_alive
    		;;
	"scan_host")
		scan_host
    		;;
	*)
	echo "Invalid option"
	    ;;
	esac
}

main "$@"
