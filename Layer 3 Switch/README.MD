Usage:

1. Copy all files to the mininet VM directory.
2. Execute:
   sudo mn --topo single,6 --mac --controller remote --switch ovsk,protocols=OpenFlow13
3. In that instance execute:
   source ifconf **This will automatically configure the hosts**
4. In other terminal, do:
   ryu-manager switch.py

Now you can test the connections between the hosts from mininet.
For a speed testing do:
* h1 iperf -s
* h2 iperf -c h1
* h3 iperf -c h1