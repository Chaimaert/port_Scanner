import nmap 

nm = nmap.PortScanner()

target = "45.33.32.156" #the IP targeted adress
options = "-sV -sC scan_results" #The -sV version detection, and the -sC the use of default scripts.

nm.scan(target, arguments=options)

for host in nm.all_hosts():
  print("Host: %s (%s)" % (host, nm[host].hostname())) #retrieves the hostname associated with the IP address.
  print("State: %s" %  nm[host].state()) #retrieves the state of the host, which can be up, down, or unknown.
  for protocol in nm[host].all_protocols():
    print("Protocol: %s" %  protocol)
    port_info = nm[host][protocol] #returns a dictionary where the keys are port numbers and the values are information about each port.
    for port, state in port_info.items():
        print("Port: %s\tState: %s" % (port, state))


