'''In this project, i build a very simply firewall simulator so we can start getting a high-level
idea of the logic underpinning a firewall. In this series i will build on this concept to create 
actual functional firewalls, in the process getting a deeper understanding of what these programs actually do.

In this sample project, we will specifically be doing 4 things:
1. Define a set of firewall rules using a Python dictionary.
2. Generate random IP addresses to simulate network traffic.
3. Check each IP address against the firewall rules.
4. Print the result (allowed or blocked) for each IP address based on the rules.
'''


#randomly generate ip_addresss
import random

#fn to generate a random ip address
def generate_ip():
    return f"192.168.1.{random.randint(0,20)}"

#checks the firewall rules if the generated ip is within the rule dictionary
def check_firewall_rules(ip,rules):
    for rule_ip, action in rules.items():
        if ip == rule_ip:
            return action
    return "allow"


#Main fn: 
def main():

    #pre-defined firewall rules
    firewall_rules = {
        "192.168.1.1":"block",
        "192.168.1.4":"block",
        "192.168.1.9":"block",
        "192.168.1.13":"block",
        "192.168.1.16":"block",
        "192.168.1.19":"block",
    }

    #generate 12 random ip_address and checks with the firewall_rules
    #if ip is to be blocked/allowed
    for _ in range(12):
        ip_address = generate_ip()
        action = check_firewall_rules(ip_address,firewall_rules)
        random_no = random.randint(0,9999)
        print(f"IP: {ip_address}, Action: {action}, Random: {random_no}")


#main-guard: ensure when the script is executed the main fn is called
if __name__=="__main__":
    main()