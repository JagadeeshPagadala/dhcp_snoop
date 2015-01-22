Alogorith to implement DHCP snooping (MAC  tracker) and IP spoof module

Check the packet
	If DHCP ACK packet
		check packet is coming from client directly
			If yes add to mac table
		check if packet is coming from relay agent
			Check, the relay agent is in allowed list or not
				if relay agent is in allowed list
					add to mac table
				if relay agent is not in allowed list
					1. We can add to the router to allowed list
					2. Simply drop
	If non DHCP ack packet
		check the src IP-MAC with table IP-MAC
			if match accep the packet

			if not match give some warning message
