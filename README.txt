To run the program, make sure to have the following libraries installed: dpkt

Once that is done, open cmd/terminal and change directory to the folder containing the program.

After that, run the python program using the command below (Windows version):
	>> py analysis_pcap_arp.py <pcap_file_here>.pcap

The second argument can be any pcap file but note that it only handles processing for
arp packets.

Logic:

First, we check for valid command invocation and checking if pcap file is valid. Once
that is done, we open the pcap file and filter for only arp packets. Once we have all
the arp packets, we filter further into two separate lists; request packets and reply
packets. If there exists request and reply packets, we print the first of each list
to the terminal/cmd. 