### module to build network profile for scan detection 
### this module builds the 'ground-truth' ie prepares the list 
### legit LBNL servers and ports based on incoming SF.
### premise: if external IP connecting to something not in this list
### is likely a scan if (1) incoming connections meet fanout criteria 

### basically, the script works like this: 
### src: knock .
### src: knock ..	
### src: knock ...
### bro: bye bye 

### Also
### a. need backscatter identification (same src port diff dst port for scanner
### b. address 80/tcp, 443/tcp, 861/tcp, 389/tcp (sticky config)  - high_threshold_ports 
### c. dynamic thresholds 
### todo 
### c. GeoIP integration - different treatment to > 130 miles IP vs US IPs vs Non-US IPs
### d. False +ve suppression and statistics _


@load trw.bro 
@load protocols/conn/known-services.bro

module Scan;

export {

	redef enum Notice::Type += {
                KnockKnockScan, # source flagged as scanner by TRW algorithm
                KnockKnockSummary, # summary of scanning activities reported by TRW
		BackscatterSeen, 
		LikelyScanner, 
		IgnoreLikelyScanner, 
        };

	
	global host_profiles: table [addr] of set[port] &persistent &read_expire=2 days &synchronized; 

	global likely_scanner: table[addr,port] of set[addr] &create_expire=1 day &synchronized ; 

	global known_scanners: table[addr] of count &default=0 &create_expire=1 day &synchronized ; 

	global backscatter: table[addr] of count &default=0 &create_expire=1 day &synchronized; 


	global high_threshold_ports: set[port] = { 861/tcp, 80/tcp, 443/tcp, 8443/tcp, 8080/tcp } &redef ; 

	global medium_threshold_ports: set[port] = { 	
							17500/tcp,  # dropbox-lan-sync
							135/tcp, 139/tcp, 445/tcp, 
							0/tcp, 389/tcp, 88/tcp,
							3268/tcp, 52311/tcp, 
						    } &redef ; 

	redef high_threshold_ports += { 135/tcp, 139/tcp, 17500/tcp, 18457/tcp,
					3268/tcp, 3389/tcp, 3832/tcp, 389/tcp,
					4242/tcp, 443/tcp, 445/tcp, 52311/tcp, 5900/tcp,
					60244/tcp, 60697/tcp, 80/tcp, 8080/tcp, 8192/tcp,
					8194/tcp, 8443/tcp, 88/tcp, 9001/tcp, 
}; 

	global ignore_sources: table[addr] of bool &create_expire=1 day ; 

	###automated_exceptions using input-framework

	global ipportexclude_file  = "../feeds/knockknock.exceptions" &redef ;

        type ipportexclude_Idx: record {
                exclude_ip: addr;
                exclude_port: port &type_column="t";
        };
        type ipportexclude_Val: record {
                exclude_ip: addr;
                exclude_port: port &type_column="t" ;
                comment: string &optional ;
        } ;

	global ipportexclude: table[addr, port] of ipportexclude_Val = table() &redef &synchronized ;
	global port_counter: table[port] of set[addr] &write_expire=6 hrs &synchronized ; 

}

event udp_request(u: connection )
{
}

event udp_reply (u: connection )
{

}

event connection_established(c: connection)
{
	local orig = c$id$orig_h ; 
	local resp = c$id$resp_h ; 
	local d_port = c$id$resp_p ; 

	### if ! incoming traffic, exit 

	if (Site::is_local_addr(orig)) 
		return  ; 

	if (resp !in host_profiles)
		host_profiles[resp]=set();
	
	if (d_port !in host_profiles[resp])
	{ 
		add host_profiles[resp][d_port] ;
		
		local _services="" ;
		for (s in host_profiles[resp])
			_services += fmt (" %s ", s); 
		#print fmt ("%s has services on %s", resp, _services) ; 
	
	}

	#print fmt ("added %s : %s", d_port, host_profiles[resp]); 

	if ([orig,d_port] in likely_scanner ) 
	{
		#print fmt ("scanner saw a full SF: %s - %s - %s", orig, resp, d_port); 
		#print fmt ("likely_scanner: %s, known_scanner: %s", likely_scanner[orig, d_port], known_scanners[orig]);
		#NOTICE([$note=IgnoreLikelyScanner, $src=orig, $msg=fmt("%s potential scanner hitting total of %d hosts: [%s]", 
		#		orig, |likely_scanner[orig,d_port]|,d_port), $identifier=cat(orig),$suppress_for=1 hrs]);
	
		delete likely_scanner[orig,d_port][resp]; 
		known_scanners[orig]=0 ; 
	} 
		
	### reset the scan thresholds  - since we saw a SF from this IP to a LBL port 

}



event bro_done()
{

	local msg=""; 

#	for (a in host_profiles)
#	{
#		msg = fmt ("%s : has ports: ", a);
#			for (p in host_profiles[a])
#				msg += fmt ("%s ", p); 
#		print fmt ("%s", msg); 
#		msg = "" ;
#	}

} 
	
event connection_state_remove(c: connection) 
#event new_connection(c: connection) 
{

	print fmt ("CONN: %s", c); 


        local orig = c$id$orig_h ;
        local resp = c$id$resp_h ;
        local d_port = c$id$resp_p ;
	local s_port = c$id$orig_p ; 

        if (Site::is_local_addr(c$id$orig_h))
                return ;

	
	if (c$resp$state == TCP_ESTABLISHED) 
	{ return ; } 

	### firewalled hosts 



	if (orig in ignore_sources)
		return  ; 

	### if ever an SF seem to a LBL host on a port - ignore the orig 
	###if (resp in Scan::host_profiles && d_port in Scan::host_profiles[resp])

	if (resp in host_profiles && d_port in Scan::host_profiles[resp])
		return ; 


	if (c$conn$proto == udp || c$conn$proto == icmp )
		return ; 

	if (orig in known_scanners)
		return ; 
	
	local state = c$conn$conn_state ; 

	local resp_bytes =c$resp$size ; 


	
	if (state == "OTH" &&  resp_bytes >0 )
	{	return ; } 

	if ([resp,d_port] in ipportexclude && /SF/ in c$conn$conn_state) 
	{	return ;  } 
	
	if ([orig,d_port] !in likely_scanner)
	{ 
		likely_scanner[orig,d_port]=set(); 
	} 

	 add likely_scanner[orig,d_port][resp] ;

	
	local orig_loc = lookup_location(orig);
       	local resp_loc = lookup_location(resp);

	local distance = 0.0 ;

#        if (orig_loc?$latitude &&  orig_loc?$longitude &&  resp_loc?$latitude && resp_loc?$longitude)
#                { distance = haversine_distance(orig_loc$latitude, orig_loc$longitude, resp_loc$latitude, resp_loc$longitude);}

#	if (orig !in ignore_sources)
#	{
#		ignore_sources[orig] = T; 
#
#		NOTICE([$note=IgnoreLikelyScanner, $src=orig, $msg=fmt("Ignoring : %s because it tried %s:%s (%s: %.2f)", 
#			orig, resp, d_port, orig_loc$country_code, distance), $identifier=cat(orig), $suppress_for=1 hrs]);
#	}
#	
#		NOTICE([$note=LikelyScanner, $src=orig, $msg=fmt("%s : tried %s:%s (%s: %.2f)", 
#			orig, resp, d_port, orig_loc$country_code, distance), $identifier=cat(orig), $suppress_for=1 hrs]);

	local msg ="" ; 

	for (a in likely_scanner[orig,d_port])
		msg += fmt (" %s ", a); 

	local high_threshold=F ;
	local medium_threshold=F; 
	local usual_threshold=F; 


	if (d_port !in port_counter)
	{
		port_counter[d_port]=set();
	} 

	if (|port_counter[d_port]| <=5)
	{ 
		add port_counter[d_port][orig] ;
	}
	#else
	#	usual_threshold=T ; 


	if (d_port in high_threshold_ports  || |port_counter[d_port]| <=2)
	{	high_threshold = T ; } 
	else if (d_port in medium_threshold_ports  || |port_counter[d_port]| <=5)
	{	medium_threshold = T ;  } 
	

	local _msg="" ; 

	for (a in port_counter[d_port])
		_msg += fmt (" %s ", a); 

	##print fmt ("for %s count is %s and values: %s", d_port, |port_counter[d_port]|, _msg); 

	

	if (orig !in known_scanners) 
	{ 
		#if (|likely_scanner[orig,d_port]| == 5 && d_port in high_threshold_ports)
		if (|likely_scanner[orig,d_port]| == 12 && high_threshold ) 
		{
				known_scanners[orig] += 1 ; 
		} 
		else if (|likely_scanner[orig,d_port]| == 9  && medium_threshold ) 
		{
				known_scanners[orig] += 1 ; 
		}
		else if (|likely_scanner[orig,d_port]| >= 3 && !high_threshold && !medium_threshold) 
		{
				known_scanners[orig] += 1 ; 
		}

		if (known_scanners[orig] >= 1)
		{
			NOTICE([$note=KnockKnockScan, $src=orig, $msg=fmt("%s scanned a total of %d hosts: [%s] (%s : %.2f miles) on %s", orig, |likely_scanner[orig,d_port]|,d_port, orig_loc$country_code, distance, msg), $identifier=cat(orig), $suppress_for=1 hrs]);


		} 
	} 
}


event bro_init()
{

Input::add_table([$source=ipportexclude_file, $name="ipportexclude", $idx=ipportexclude_Idx, $val=ipportexclude_Val,  $destination=ipportexclude, $mode=Input::REREAD ]);

} 

event bro_done()
{
#	for ([a,p] in ipportexclude)
#		print fmt ("%s %s", a, p); 
} 




#                ## ==========   ===============================================
#                ## conn_state   Meaning
#                ## ==========   ===============================================
#                ## S0           Connection attempt seen, no reply.
#                ## S1           Connection established, not terminated.
#                ## SF           Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
#                ## REJ          Connection attempt rejected.
#                ## S2           Connection established and close attempt by originator seen (but no reply from responder).
#                ## S3           Connection established and close attempt by responder seen (but no reply from originator).
#                ## RSTO         Connection established, originator aborted (sent a RST).
#                ## RSTR         Established, responder aborted.
#                ## RSTOS0       Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
#                ## RSTRH        Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
#                ## SH           Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was "half" open).
#                ## SHR          Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
#                ## OTH          No SYN seen, just midstream traffic (a "partial connection" that was not later closed).
#                ## ==========   ===============================================
#                conn_state:   string          &log &optional;

#                ## Records the state history of connections as a string of
#                ## letters.  The meaning of those letters is:
#                ##
#                ## ======  ====================================================
#                ## Letter  Meaning
#                ## ======  ====================================================
#                ## s       a SYN w/o the ACK bit set
#                ## h       a SYN+ACK ("handshake")
#                ## a       a pure ACK
#                ## d       packet with payload ("data")
#                ## f       packet with FIN bit set
#                ## r       packet with RST bit set
#                ## c       packet with a bad checksum
#                ## i       inconsistent packet (e.g. SYN+RST bits both set)
#                ## ======  ====================================================
#                ##
#                ## If the event comes from the originator, the letter is in
#                ## upper-case; if it comes from the responder, it's in
#                ## lower-case. Multiple packets of the same type will only be
#                ## noted once (e.g. we only record one "d" in each direction,
#                ## regardless of how many data packets were seen.)
#                history:      string          &log &optional;
