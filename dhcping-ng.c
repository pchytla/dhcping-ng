/**
** Copyright (C) 2010 Piotr Chytla <pch@packetconsulting.pl>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>
#include <libnet.h>
#include <syslog.h>
#include <signal.h>
#include <signal.h>
#include <netdb.h>
#include <sys/wait.h>

#define VERSION "0.22"

#define ETH_FRAME_LEN 1514
#define DHCP_XID_BASE 0x0a0a0000

#define FIND_DHCP_OPTION(ptr,o) \
  u_char len;			\
  while (*ptr!=o)  		\
  {  				\
   len=*(ptr+1);		\
   ptr+=(len+2);		\
  }				



char *ntoa_hex(u_char *addr)
{
	char *ret=malloc(ETHER_ADDR_LEN*3);
	sprintf(ret,"%02x:%02x:%02x:%02x:%02x:%02x",addr[0], 
					addr[1], 
					addr[2], 
					addr[3],
					addr[4], 
					addr[5]);
	return ret;
}

int count=5;
int verbose=0;
int dhcpflags=0x8000;
u_long *xid;

void main_sigchld_handler(int sig)
{
       int save_errno = errno;
       int status;
       while (waitpid(-1, &status, WNOHANG) > 0);
       signal(SIGCHLD, main_sigchld_handler);
       errno = save_errno;
}

void main_sigalarm_handler(int sig)
{
  printf("Exiting ....\n");
  exit(0);
}

void usage(char *prog)
{
    fprintf(stderr, "Usage: %s -i interface\n\
			       -w waittime between packets\n\
			       -v verbose mode\n\
			       -u force unicast response\n\
			       -c send count packets\n\
			       -r use random ethernet address\n\
			       -x client-IP-address\n\
			       -h client-hardware-address\n\
			       -s server-IP-address\n\
			       -z server-hardware-address\n",prog);
    exit(1);
}

char *find_dns(u_char *buf)
{
  int i;
  char *ret;
  u_char *ptr=buf;
  FIND_DHCP_OPTION(ptr,LIBNET_DHCP_DNS);
  len=*(ptr+1);
  ret=malloc(len*5);
  bzero(ret,len*5);
  for (i=0;i<(len/4);i++)
  {
  sprintf(ret+strlen(ret),"%s,",libnet_addr2name4(*((u_int32_t *)(ptr+2+i*4)),LIBNET_DONT_RESOLVE));
  }
  return ret;
}

char *find_leasetime(u_char *buf)
{
  char *ret;
  u_char *ptr=buf;
  FIND_DHCP_OPTION(ptr,LIBNET_DHCP_LEASETIME);
  len=*(ptr+1);
  ret=malloc(20);
  sprintf(ret,"%u",htonl(*((u_int32_t *)(ptr+2))));
  return ret;
}


void pcap_hdler(u_char *d,struct pcap_pkthdr *pcapphdr,u_char *buf)
{
 int i;
 struct libnet_ethernet_hdr *eth=(struct libnet_ethernet_hdr *)buf;
 struct libnet_ipv4_hdr *ip=(struct libnet_ipv4_hdr *)(buf+LIBNET_ETH_H);
 struct libnet_udp_hdr *udp=(struct libnet_udp_hdr *)(buf+LIBNET_ETH_H+LIBNET_IPV4_H);
 struct libnet_dhcpv4_hdr *dhcp=(struct libnet_dhcpv4_hdr *)(buf+LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_UDP_H);
 u_char *data=(u_char *)(buf+LIBNET_ETH_H+LIBNET_IPV4_H+LIBNET_UDP_H+LIBNET_DHCPV4_H);

 for (i=0;i<count;i++)
 	if (dhcp->dhcp_xid==ntohl(xid[i]))
			break;
  if (i==count)
	  return;

  printf("(%d) Recived Resonse from  %s(%s) IP: %s DNS: %s",htonl(dhcp->dhcp_xid)-DHCP_XID_BASE+1,
				ntoa_hex(eth->ether_shost),
				libnet_addr2name4(ip->ip_src.s_addr,LIBNET_DONT_RESOLVE),
				libnet_addr2name4(dhcp->dhcp_yip,LIBNET_DONT_RESOLVE),
				find_dns(data));

  if (verbose)
	printf(" LEASETIME :%s",find_leasetime(data));

  printf("\n");
  fflush(stdout);
}
  
int pcap_listener(char *intf,int waittime)
{
    int pid,status;
    struct bpf_program flt;
    pcap_handler handler;
    char bpf_filter[100];
    pcap_t *pd;
    char errbuf[LIBNET_ERRBUF_SIZE];
    handler=(pcap_handler)pcap_hdler;

   // For 0 wait time between packets we don't care about answers.
    if (!waittime)
	return 0;

    signal(SIGCHLD, main_sigchld_handler); 
    if (!(pid=fork()))
    {
	signal(SIGALRM, main_sigalarm_handler);
	sprintf(bpf_filter,"src port 67");
	pd=pcap_open_live(intf,ETH_FRAME_LEN,1,500,errbuf);
	if (pd==NULL)
	{
    		fprintf(stderr,"Argh : pcap_open_live err %s\n",errbuf);
    		exit(1);
	} 
	pcap_compile(pd,&flt,bpf_filter,1,0xffffffff);
	pcap_setfilter(pd,&flt);
	pcap_loop(pd,-1,handler,NULL);
	pcap_close(pd);
	exit(0);
    }
    printf("Forking : %d\n",pid);
    waitpid(pid, &status, WNOHANG);
    return pid;
}

int main(int argc, char *argv[])
{
    char a;
    char *intf;
    int i,j,waittime=1,pid,randomether=0;
    int hwaddr_len;
    u_long options_len, orig_len;
    char *src_ip_str=NULL,*dst_ip_str=NULL;
    libnet_t *l;
    libnet_ptag_t t;
    libnet_ptag_t ip;
    libnet_ptag_t udp;
    libnet_ptag_t dhcp;
    u_long src_ip=0;
    u_long dst_ip=0xffffffff; // 255.255.255.255
    u_char ether_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    struct libnet_ether_addr *src_hwaddr=NULL;
    struct libnet_ether_addr *dst_hwaddr=(struct libnet_ether_addr *)&ether_broadcast;
    char errbuf[LIBNET_ERRBUF_SIZE];
 
    u_char options_req[] = { LIBNET_DHCP_SUBNETMASK , LIBNET_DHCP_BROADCASTADDR , LIBNET_DHCP_TIMEOFFSET , LIBNET_DHCP_ROUTER , LIBNET_DHCP_DOMAINNAME , LIBNET_DHCP_DNS , LIBNET_DHCP_HOSTNAME };
    u_char *options;
    u_char *tmp;
    
    if (argc < 2)
        usage(argv[0]);


    while((a=getopt(argc,argv,"i:t:w:c:s:x:z:h:vurH?"))!=EOF)
    {
     switch(a) {
         case 'i' : { 
		     intf=malloc(strlen(optarg));
		     if (intf==NULL) {
				printf("Argh : malloc() - can't allocate %d bytes\n",strlen(optarg));
				exit(1);
		     }
                     strncpy(intf,optarg,strlen(optarg)); 
                     break;
		    }
	 case 'x' : {
		   	src_ip_str=malloc(strlen(optarg));
			if (src_ip_str==NULL) {
				fprintf(stderr,"Argh : malloc() - can't allocate %d bytes\n",strlen(optarg));
				exit(1);
			}
			strncpy(src_ip_str,optarg,strlen(optarg));

			if (optarg[0]=='-') 
				optind--;

 			break;
		     };
	 case 'h' : {
			src_hwaddr=(struct libnet_ether_addr *)libnet_hex_aton(optarg,&hwaddr_len);
			if (src_hwaddr==NULL)
			{
				fprintf(stderr,"Argh : libnet_hex_aton() - can't convert mac-adress %s to bytestring   \n",optarg);
				exit(1);
			}
			break;
		    };
         case 's' : {
		   	dst_ip_str=malloc(strlen(optarg));
			if (dst_ip_str==NULL) {
				fprintf(stderr,"Argh : malloc() - can't allocate %d bytes\n",strlen(optarg));
				exit(1);
			}
			strncpy(dst_ip_str,optarg,strlen(optarg));
			break;
		    };
	 case 'z': {
			dst_hwaddr=(struct libnet_ether_addr *)libnet_hex_aton(optarg,&hwaddr_len);
			if (dst_hwaddr==NULL)
			{
				fprintf(stderr,"Argh : libnet_hex_aton() - can't convert mac-adress %s to bytestring   \n",optarg);
				exit(1);
			}
			break;
		    };
	 case 'r':  { 
			randomether=ETHER_ADDR_LEN;
			break;
			}
	 case 'v': {
			verbose=1;
			break;
		    }
	 case 'u' : {
			// Force unicast dhcp response
			dhcpflags=0; 
			break;
		    }
	 case 'w' : {
		     waittime=atoi(optarg);
		     break;
                    }
	 case 'c' : {
		    count=atoi(optarg);
    		    if (!count)
    		    {
				fprintf(stderr,"Argh : Sorry packet count can't be zero \n");
				exit(1);
    		    }
		    break;
                    }
	 case 'H' : usage(argv[0]);
         default  : usage(argv[0]);
         }
 }




    xid=malloc(count*sizeof(u_long));
    for (i=0;i<count;i++)
	xid[i]=DHCP_XID_BASE+i;


    // Initialize libnet
    l = libnet_init(
            LIBNET_LINK,                            
            intf,                                   
            errbuf);                               

    if (!l)
    {
        fprintf(stderr, "libnet_init: %s", errbuf);
        exit(EXIT_FAILURE);
    }
    
    // random numbers
    libnet_seed_prand(l);
	

    if (src_ip_str!=NULL)
    {
    	src_ip=libnet_name2addr4(l,src_ip_str,LIBNET_DONT_RESOLVE);
    	if (src_ip==-1) 
		src_ip=libnet_get_ipaddr4(l);

	free(src_ip_str);
    }


    if (dst_ip_str!=NULL)
    {
    	if (!memcmp(dst_hwaddr,ether_broadcast,ETHER_ADDR_LEN))
    	{
		fprintf(stderr,"Argh : server IP (-s option) needs also server hardware address (-z option)\n");
		exit(1);
    	}

    	dst_ip=libnet_name2addr4(l,dst_ip_str,LIBNET_DONT_RESOLVE);
    	if (dst_ip==-1) 
    	{
		fprintf(stderr, "Argh : IP: %s - %s\n", dst_ip_str,libnet_geterror(l));
		exit(1);
    	}
	free(dst_ip_str);
    } 

 
    if (randomether && src_hwaddr!=NULL)
    {
		fprintf(stderr,"Argh : You can't specify source mac-adress (-h option) and randomized it (-r option) \n");
		exit(1);
     }

    // ethernet hardware address not specyfied , use interface hardware address
    if (src_hwaddr==NULL)
    {
	if ((src_hwaddr=libnet_get_hwaddr(l))==NULL)
	{
    		fprintf(stderr,"Argh : libnet_get_hwaddr: %s\n", libnet_geterror(l));
                exit(1);
	}
    }

    printf("Sending %d dhcp-discover packets  %d seconds beetwen packets \n",count,waittime);
    // build options packet
    i = 0;
    options_len = 3;                            // update total payload size
    
    // we are a discover packet
    options = malloc(3);
    options[i++] = LIBNET_DHCP_MESSAGETYPE;     // type
    options[i++] = 1;                           // len
    options[i++] = LIBNET_DHCP_MSGDISCOVER;     // data
    
    orig_len = options_len;
    options_len += sizeof(options_req) + 2;     // update total payload size
    
    tmp = malloc(options_len);
    memcpy(tmp, options, orig_len);
    free(options);
    options = tmp;
    
    // we are going to request some parameters
    options[i++] = LIBNET_DHCP_PARAMREQUEST;    // type
    options[i++] = sizeof(options_req);         // len
    memcpy(options + i, options_req, sizeof(options_req)); // data
    i += sizeof(options_req);
    
    // if we have an ip already, let's request it.
    if (src_ip)
    {
        orig_len = options_len;
        options_len += 2 + sizeof(src_ip);
        tmp = malloc(options_len);
        memcpy(tmp, options, orig_len);
        free(options);
        options = tmp;
        
        options[i++] = LIBNET_DHCP_DISCOVERADDR;	// type
        options[i++] = sizeof(src_ip);			    // len
        memcpy(options + i, (char *)&src_ip, sizeof(src_ip));// data
        i += sizeof(src_ip);
    }
    
    orig_len = options_len;
    options_len += 1;
    tmp = malloc(options_len);
    memcpy(tmp, options, orig_len);
    free(options);
    options = tmp;
    options[i++] = LIBNET_DHCP_END;

    
    if (options_len + LIBNET_DHCPV4_H < LIBNET_BOOTP_MIN_LEN)
    {
        orig_len = options_len;
        options_len = LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H;
        
        tmp = malloc(options_len);
        memcpy(tmp, options, orig_len);
        free(options);
        options = tmp;
        
        memset(options + i, 0, options_len - i);
    }

    fflush(stdout);

    pid=pcap_listener(intf,waittime);

    for (i=0;i<count;i++)
    { 
	for (j=0;j<randomether;j++)
    		src_hwaddr->ether_addr_octet[j]=libnet_get_prand(LIBNET_PR8);

    if (verbose)
    {
	printf("(%lu) Sending request : %s(%s) -> %s(%s)\n",xid[i]-DHCP_XID_BASE+1,
						ntoa_hex(src_hwaddr->ether_addr_octet),
						libnet_addr2name4(src_ip,LIBNET_DONT_RESOLVE),
						ntoa_hex(dst_hwaddr->ether_addr_octet),
						libnet_addr2name4(dst_ip,LIBNET_DONT_RESOLVE)
						);
	fflush(stdout);
    }

    dhcp = libnet_build_dhcpv4(
            LIBNET_DHCP_REQUEST,                        
            1,                                          
            6,                                          
            0,                                          
            xid[i],                                     
            0,                                          
            dhcpflags,                                  
            src_ip,                                     
            0,                                          
            0,                                          
            0,                                          
            src_hwaddr->ether_addr_octet,		
            NULL,                                       
            NULL,                                       
            options,                                    
            options_len,                               
            l,                                        
            0);                                        
   
    udp = libnet_build_udp(
            68,                                             
            67,                                            
            LIBNET_UDP_H + LIBNET_DHCPV4_H + options_len,   
            0,                                              
            NULL,                                           
            0,                                             
            l,                                             
            0);                                             
    
    ip = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DHCPV4_H
            + options_len,                                  
            0x10,                                          
            0,                                              
            0,                                              
            16,                                             
            IPPROTO_UDP,                                    
            0,                                              
            src_ip,                                         
            dst_ip,		 	                   
            NULL,                                           
            0,                                              
            l,                                              
            0);                                             
    
    t = libnet_build_ethernet(
		dst_hwaddr->ether_addr_octet,
		src_hwaddr->ether_addr_octet,
		ETHERTYPE_IP,
		NULL,
		0,
		l,
		0);

    // write to the wire
    if (libnet_write(l) == -1)
    {
        fprintf(stderr, " %s: libnet_write: %s\n", argv[0],
                strerror(errno));
	kill(pid,SIGALRM);
        exit(EXIT_FAILURE);
    }
    sleep(waittime);	

    libnet_clear_packet(l);
    }

    libnet_destroy(l);
    free(options);
    if (pid>0) 
    {
    	sleep(2);
        kill(pid,SIGALRM);
    }
    exit(0);
}
