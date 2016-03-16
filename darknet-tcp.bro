module Darknet ; 

@load base/protocols/conn

@load subnets-bldg.bro 

export 
{ 
	global darknet_v6: set [subnet] &redef ; 
	global darknet_scanners: table [addr] of  set[addr] ; 
	global scanners: table[addr] of count &create_expire=1 day &redef ; 

	global ignore_src_ports: set [port] = { 53/tcp, 53/udp};

	redef enum Notice::Type += {
                LandMine,
        } ;

	global active_subnets: set[subnet] &redef ; 
} 


function is_failed_conn(c: connection): bool
        {
        # Sr || ( (hR || ShR) && (data not sent in any direction) )
        if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
		(c$orig$state == TCP_SYN_SENT && c$resp$state ==  TCP_INACTIVE ) || 
             (((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
               (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )
              ) && /[Dd]/ !in c$history )
           )
                return T;
        return F;
        }

function is_reverse_failed_conn(c: connection): bool
        {
        # reverse scan i.e. conn dest is the scanner
        # sR || ( (Hr || sHr) && (data not sent in any direction) )
        if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
             (((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
               (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history )
              ) && /[Dd]/ !in c$history )
           )
                return T;
        return F;
        }


function print_state(s: count, t: transport_proto): string
{
	if (t == tcp ) { 
	switch(s)
	{ 
		case 0: return "TCP_INACTIVE" ;
		case 1: return "TCP_SYN_SENT" ; 
		case 2: return "TCP_SYN_ACK_SENT"; 
		case 3: return "TCP_PARTIAL" ;
		case 4: return "TCP_ESTABLISHED" ; 
		case 5: return "TCP_CLOSED" ;
		case 6: return "TCP_RESET" ; 
	};	
	} 
	
	if ( t == udp )
	{ 
		switch(s)
		{ 
			case 0: return "UDP_INACTIVE" ; 
			case 1: return "UDP_ACTIVE" ; 
		} 
	} 

	return "UNKNOWN" ; 
} 

event connection_state_remove(c: connection)
{

        local src = c$id$orig_h ; 
        local dst = c$id$resp_h ; 
	
	local src_p = c$id$orig_p ;
        local dst_p = c$id$resp_p ;

	if (src_p in ignore_src_ports)
                return;

	if (src in scanners)
		return ; 

	if (c$conn$proto != tcp)
		return ; 

	if (/SF/ in c$conn$conn_state )
		return ;
	
	local iplist = "" ; 

	if (Site::is_local_addr(dst) && dst !in active_subnets)
	{
		if ((is_failed_conn(c) || is_reverse_failed_conn(c) ) ) 
		{ 
			    if ([src] !in darknet_scanners)
				darknet_scanners[src]=set();
	
			    if([dst] !in darknet_scanners[src])
				add darknet_scanners[src][dst]; 

			if (|darknet_scanners[src]| > 5)
			{	
				for (ip in darknet_scanners[src])
				{
				    iplist = fmt ("%s %s", iplist, ip); 
				} 
		
				local cs=c$conn$conn_state ; 

				local msg = fmt ("Scanner Darknet : %s [%s %s (%s - %s [%s - %s ]) HIT: %s]", 
				src, c$id$resp_h, c$id$resp_p, cs, c$history, print_state(c$orig$state, c$conn$proto), 
				print_state(c$resp$state, c$conn$proto), iplist);

			  	NOTICE([$note=LandMine, $conn=c, $msg=msg, $identifier=cat(src)]);
				scanners[src] = 1 ; 
			} 
		} 	
	}
	else if (Site::is_local_addr(dst) && src in darknet_scanners)
	{
	    cs=c$conn$conn_state ; 

	}
}


#const TCP_INACTIVE = 0; ##< Endpoint is still inactive.
#const TCP_SYN_SENT = 1; ##< Endpoint has sent SYN.
#const TCP_SYN_ACK_SENT = 2;     ##< Endpoint has sent SYN/ACK.
#const TCP_PARTIAL = 3;  ##< Endpoint has sent data but no initial SYN.
#const TCP_ESTABLISHED = 4;      ##< Endpoint has finished initial handshake regularly.
#const TCP_CLOSED = 5;   ##< Endpoint has closed connection.
#const TCP_RESET = 6;    ##< Endpoint has sent RST.

# UDP values for :bro:see:`endpoint` *state* field.
# todo:: these should go into an enum to make them autodoc'able.
#const UDP_INACTIVE = 0; ##< Endpoint is still inactive.
#const UDP_ACTIVE = 1;   ##< Endpoint has sent something.


