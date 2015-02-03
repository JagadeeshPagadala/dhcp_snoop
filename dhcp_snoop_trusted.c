#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_packet.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/inet.h>
#include <linux/if_vlan.h>
#include <linux/hashtable.h>
#include <linux/netdevice.h>

#define DEBUG // ENABLE this flag to print debug messages

#ifdef DEBUG
#define D(fmt ...) { printk(fmt); }
#else 
#define D(fmt ...)
#endif

#define IPV6 6
#define IPV4 4
#define HASH_TABLE_BITS 8

bool is_dhcp_server = 1;
module_param(is_dhcp_server, bool , S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(is_dhcp_server, "If box is working as DHCP relay agent unset this variable when loading the module, by default it is set\n");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ajeet Vijayvergiya");
MODULE_AUTHOR("Jagadeesh Pagadala");
MODULE_DESCRIPTION("DHCP snoop and IP spoof");

/**************************************/
struct interface{
    char name[IFNAMSIZ];
    u_int8_t is_trusted;
};

struct interface *interface; 
/* following is the DHCP packet format*/
typedef struct {
    u_int8_t  op;       /* 0: Message opcode/type */
    u_int8_t  htype;    /* 1: Hardware addr type (net/if_types.h) */
    u_int8_t  hlen;     /* 2: Hardware addr length */
    u_int8_t  hops;     /* 3: Number of relay agent hops from client */
    u_int32_t xid;      /* 4: Transaction ID */
    u_int16_t secs;     /* 8: Seconds since client started looking */
    u_int16_t flags;    /* 10: Flag bits */
    struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
    struct in_addr yiaddr;  /* 16: Client IP address */
    struct in_addr siaddr;  /* 18: IP address of next server to talk to */
    struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
    unsigned char chaddr [16];  /* 24: Client hardware address */
    char sname [64];    /* 40: Server name */
    char file [128];  /* 104: Boot filename */
    unsigned char options [16];
                /* 212: Optional parameters
 *                    (actual length dependent on MTU). */
}dhcp_packet;


char* inet_ntoa(struct in_addr in, char* buf, size_t* rlen);
int dump_list(char *);
void tick_timer(void);

struct timer_list dhcp_timer;
const int delay = 30; /* time interval for updating DHCP lease time (in sec)*/

struct dhcp_struct
{
    uint32_t ip;
    unsigned char dhcp_mac[6]; /*Client MAC*/
    unsigned char traffic_mac[6]; /* DHCP relay agent MAC*/
    unsigned int lease_time;
    /* For hash table*/
    struct hlist_node dhcp_hash_list;
};

struct router_mac 
{
    unsigned char mac[ETH_ALEN];
    struct router_mac *next;
};

struct router_mac *head = NULL;
/* Allowed routers MAC address linked list related operations*/

void add_router(struct router_mac *ptr)
{

    //printk("\n read mac address %x, %x, %x, %x, %x, %x",ptr->mac[0], ptr->mac[1], ptr->mac[2], ptr->mac[3], ptr->mac[4], ptr->mac[5]);
    
    if(head == NULL)
    {
        head = ptr;        
        return;
    }
    else 
    {
        /* add element at start for reducing adding complexity*/
        ptr->next = head; 
        head = ptr;
        return;
    }
}

void clean_allowed_routers(void)
{
    struct router_mac *ptr;
    struct router_mac *tmp;
    
    if(head == NULL)
        return; 

    ptr = head; 
    while(ptr->next!=NULL)
    {
        tmp = ptr; 
        ptr = ptr->next;
        kfree(tmp);
    }
    head = NULL;
}

/*Hash table declarartion and definition*/
DEFINE_HASHTABLE(dhcp_snoop_table, HASH_TABLE_BITS);

int dump_list(char *buf)
{

    char buff[512]={'\0'};  //Ravi: This buffer can hold only 4 entries, where as the code is not checking for size of buffer and printing all records
 /*
  * Jagadeesh: This buffer(buff) is just used in inet_ntoa() and buf is being used to write data.
  * buf is sysfs provided buffer and can hold max 4K data.
  *
  */
    int i=0;
    struct in_addr saddr;
    int count = 0;
    struct dhcp_struct *ptr;

    hash_for_each(dhcp_snoop_table, i, ptr, dhcp_hash_list)
    {
        saddr.s_addr = ptr->ip;
        count+=sprintf(buf+count,"IP address  		-	%s\n",inet_ntoa(saddr,buff,NULL));
        count+=sprintf(buf+count,"MAC address (DHCP) 	-	%02x:%02x:%02x:%02x:%02x:%02x\n",ptr->dhcp_mac[0],ptr->dhcp_mac[1],ptr->dhcp_mac[2],ptr->dhcp_mac[3],ptr->dhcp_mac[4],ptr->dhcp_mac[5]);
        count+=sprintf(buf+count,"MAC address (Traffic)	-	%02x:%02x:%02x:%02x:%02x:%02x\n",ptr->traffic_mac[0],ptr->traffic_mac[1],ptr->traffic_mac[2],ptr->traffic_mac[3],ptr->traffic_mac[4],ptr->traffic_mac[5]);
        count+=sprintf(buf+count,"Lease Time  		-	%d Seconds\n",ptr->lease_time);
        count+=sprintf(buf+count,"\n\n");
    }

    return count;
}

/*
 * This function will get invoked  for every 30 sec.
 * decreament lease_time by 30 and update same
 *
 */
int dhcp_timer_task(int action)
{

    struct dhcp_struct *ptr;
    int i=0;

    /* Iterate through HASH table and update lease time*/
    hash_for_each(dhcp_snoop_table, i, ptr, dhcp_hash_list)
    {
	    if(ptr->lease_time < 30)
	    	ptr->lease_time=0;
	    else
	        ptr->lease_time-=30; //Ravi: The lease time is an unsinged int. It will never become negative, 
                     //instead it will become very big number when the prev value is less than 30. 
                                 //Hence, the value should be checked before decrementing. It should be assigned 0 if the prev value is less than 30.
                                 //FIXME: Jagadeesh, Is it required to delete an entry when its lease_time reaches to 0.
    }

    return 0;
}

char* inet_ntoa(struct in_addr in, char* buf, size_t* rlen)
{
    int i;
    char* bp;

    /*
     * This implementation is fast because it avoids sprintf(),
     * division/modulo, and global static array lookups.
     */

    bp = buf;
    for (i = 0;i < 4; i++ )
    {
        unsigned int o, n;
        o = ((unsigned char*)&in)[i];
        n = o;
        if ( n >= 200 )
        {
            *bp++ = '2';
            n -= 200;
        }
        else if ( n >= 100 )
        {
            *bp++ = '1';
            n -= 100;
        }
        if ( o >= 10 )
        {
            int i;
            for ( i = 0; n >= 10; i++ )
            {
                n -= 10;
            }
            *bp++ = i + '0';
        }
        *bp++ = n + '0';
        *bp++ = '.';
    }
    *--bp = 0;
    if ( rlen )
    {
        *rlen = bp - buf;
    }

    return buf;
}

/*
 * Function to extract dhcp lease time from DHCP ACK packet
 *
 */
int dhcp_lease_time(struct sk_buff *skb)  //Get DHCP lease time from skb
{
    struct iphdr *iph=ip_hdr(skb);
    int offset,seconds,i;
    unsigned char *buff=skb->data;//pointer to the start of skb.
    offset=0;
    offset+=(int)(iph->ihl)*4;//offset the IP header
    offset+=8;//offset the UDP header

    //Message type+Hardware type+Hardware addr length+Hops
    //+Transaction ID+Seconds elapsed+Bootp flags+
    //+Client IP+Your IP+Next server IP+Relay agent IP
    offset+=1+1+1+1+4+2+2+4+4+4+4;//reference to RFC2131

    //Client MAC address+Server host name+Boot file name+
    //Magic cookie+Option
    offset+=16+64+128+4+3;//reference to RFC2131
    offset+=6+2;
    buff+=offset;
    seconds=0;
    for(i=0;i<4;i++)
        seconds=(seconds*256+*(buff+i));
    return seconds;
}

/*
 * Function to GET IP address allocated from DHCP server.
 */
uint32_t dhcp_ip_address(struct sk_buff *skb)
{

    struct iphdr *iph=ip_hdr(skb);
    int offset;
    unsigned char *buff=skb->data;//pointer to the start of skb.

    offset=0;
    offset+=(int)(iph->ihl)*4;//offset the IP header
    offset+=8;//offset the UDP header

    //Message type+Hardware type+Hardware addr length+Hops
    //+Transaction ID+Seconds elapsed+Bootp flags+
    offset+=1+1+1+1+4+2+2;//reference to RFC2131
    buff+=offset;

    buff+=4;
    return *((uint32_t *)buff);
}

/**
 * This function will add to DHCP table, or update an existing entry 
 * TODO: Handle two cases. 
 * 1. DHCP server (Handled already)
 * 2. DHCP relay agent (need to be implemented)
 */
void dhcp_process_packet(struct sk_buff *skb, bool is_dhcp_server)
{
    int type, i = 0 ;
    struct iphdr *iph=ip_hdr(skb);
    struct ethhdr *mh = eth_hdr(skb);
    int offset=0;
    unsigned char *buff=skb->data;//pointer to the start of skb.
    unsigned char op,htype,hlen,hops;//dhcp field.
    unsigned char *hw;
    struct dhcp_struct *tmp;

    offset+= (int)(iph->ihl)*4;/* 4*ihl will be in bytes, ihl represented in 32 bit words */

	/* Jagadeesh: this is redundant test to find out dhcp packet*/
    if(buff[9]==0x11 &&  ((buff[offset]==0x00 && buff[offset+1]==0x43) || (buff[offset+2]==0x00 && buff[offset+3]==0x43)))//This is dhcp packet /* Jagadeesh This selection is based on port number 0X43( 67 decimal) */
    {
        offset+=8;//UDP header is 8-byte length
        op=buff[offset];
        htype=buff[offset+1];
        hlen=buff[offset+2];
        hops=buff[offset+3];

        //Message type+Hardware type+Hardware addr length+Hops
        //+Transaction ID+Seconds elapsed+Bootp flags+
        //+Client IP+Your IP+Next server IP+Relay agent IP
        offset+=1+1+1+1+4+2+2+4+4+4+4;//reference to RFC2131

        hw=buff+offset; /*hw is CHADDR*/
        //Client MAC address+Server host name+Boot file name+
        //Magic cookie+Option
        offset+=16+64+128+4+2;//reference to RFC2131 /*for +4+2 refer RFC2132*/
        type=*(buff+offset);
        if (type == 5) // DHCP ACK pkt type is 5
        {
            /* Here both cases..... DHCP server and DHCP Relay agent cases are handled*/
            //Search in hash table 
            hash_for_each(dhcp_snoop_table, i, tmp, dhcp_hash_list)
            {
                // compare stored MAC address with PACKET mac address
                // dhcp_mac is previously assigned DHCP IP
                // hw is CHADDR(client HW addr) field of present DHCP transaction
                if(memcmp(tmp->dhcp_mac, hw, ETH_ALEN) == 0)
                {
                    // If entry is found, replace the entry (or) update entry
                    tmp->ip = dhcp_ip_address(skb);
                    memcpy(tmp->traffic_mac, mh->h_dest, ETH_ALEN);
                    tmp->lease_time = dhcp_lease_time(skb);
                    //printk("\n found an entry \n");
                    return;
                }
            }
            // entry is not found, so add to hash table 
            struct dhcp_struct *ptr = kmalloc(sizeof( struct dhcp_struct), GFP_KERNEL);
            if( ptr == NULL )
            {
                D("%s: can't allocate memory\n",__func__);
                return;           
            }
            ptr->ip = dhcp_ip_address(skb);
            memcpy(ptr->dhcp_mac, hw, ETH_ALEN);
            memcpy(ptr->traffic_mac, mh->h_dest, ETH_ALEN);
            ptr->lease_time = dhcp_lease_time(skb);
            // key value is last octate of IP address
            uint8_t key;
            uint32_t ip; 
            ip = dhcp_ip_address(skb);
            key = (uint8_t) ip; /*TODO: find a good way to take last octate */
            hash_add(dhcp_snoop_table, &ptr->dhcp_hash_list, key);
            //printk("\n Last octate in IP addr %d \n",key);
        }
    }
}

/*
 * Verify packet src MAC-IP relation with, existing MAC-IP relation
 *
 */
int verify_packet(struct sk_buff *skb)
{
	
	struct ethhdr *eh;
	struct iphdr *iph;
	unsigned char src_mac[ETH_ALEN];
	uint32_t src_ip;
    int i = 0;
	
    /*TODO: If HASH table is empty.... don't perform check */
    if (hash_empty(dhcp_snoop_table) == true)
    {
        return 1;
    }
    else
	{
		struct dhcp_struct *ptr;
		/* Extract source { MAC, IP }. What to check exactly ??*/
		eh = eth_hdr(skb);
		memcpy(src_mac, eh->h_source, ETH_ALEN);
		iph = ip_hdr(skb);
		src_ip = (iph->saddr); /*TODO: check ntohs() requirement ?*/
        hash_for_each(dhcp_snoop_table, i, ptr, dhcp_hash_list)
		{
			/* check for MAC address */
			if((memcmp(&src_mac, &ptr->dhcp_mac, ETH_ALEN) == 0) || (memcmp(&src_mac, &ptr->traffic_mac, ETH_ALEN) == 0))
			{
                /* check IP address*/
				if(src_ip == ptr->ip)
				{
					//printk("found an entry");
					return 1;
				}
			}
		}
		return 0;
	}
	return 0;
}

/*
 * Function to check, skb for DHCP
 */
int is_dhcp(struct sk_buff *skb)
{

    if (skb->protocol == htons (ETH_P_IP))/*Jagadeesh ETH_P_IP will see only Internet Protocol Packets see if_ether.h */
    {
        if(ip_hdr(skb)->protocol == IPPROTO_UDP)
        { /* 17 is UDP protocol */
            struct udphdr *udp_hdr = (struct udphdr *)(skb->data + ((ip_hdr(skb)->ihl)<<2));
            if(udp_hdr->dest == htons(68) || udp_hdr->dest == htons(67) ||
                udp_hdr->source == htons(67) || udp_hdr->source == htons(68))
	        {
	            return 1;
	        }
	    }
    }
    return 0;
}

/**
 * NF HOOK call back fn. will process only DHCP packets
 * 1. DHCP server case
 * 2. DHCP relay agent case
 *
 * TODO: First thing to be done is check packet is RXD on trusted interface or untrusted interface.
 *          If packet is coming on unterusted interface, Allow only DHCP packets untill IP-MAC relation is found 
 *          If packet is coming on trusted interface, do not apply DHCP snoop and IP source guard.
 */
unsigned int dhcp_hook_function(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out, int (*okfn) (struct sk_buff *))
{
    int ret = 0;
    struct iphdr *ip_header;

    if(skb->protocol != htons(ETH_P_IP))/*Jagadeesh: If not Internet Protocol Packet Just dont touch*/
    {
    	return NF_ACCEPT;
    }
    printk(KERN_INFO"pkt on in:%s out:%s", in->name, out->name);
    /* If packet is IPv6, then just Accept the packet  */
    ip_header = ip_hdr(skb);
    if(ip_header->version != IPV4)
    {
        return NF_ACCEPT;
    }
    /*TODO: Check both cases are handled ? i.e DHCP server and DHCP relay agent*/
    ret = is_dhcp(skb);
    if(ret ==1)
    {
        /*TODO: Check GIADDR to verify packet is being relayed or not*/
        if (is_dhcp_server ==1)
        	dhcp_process_packet(skb, is_dhcp_server);
        else
            dhcp_process_packet(skb, is_dhcp_server);
    }else
    	return NF_ACCEPT;
    
    return NF_ACCEPT;
}

/* sysfs related operations, store method just does nothing */
static ssize_t dhcp_show(struct kobject * kobj, struct kobj_attribute * attr, char * buf)
{
    return dump_list(buf);
}

static ssize_t dhcp_store(struct kobject * kobj, struct kobj_attribute * attr, const char * buf, size_t count)
{
    return count;
}
/* allowed routers configuration */
static ssize_t routers_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct router_mac *ptr = head; 
    int count = 0;

    if (ptr == NULL)
    {
        return sprintf(buf, "router list empty");
    }

    {
        /* iterate through router list and print*/
        while (ptr != NULL)
        {
            count+=sprintf(buf+count,"%02x:%02x:%02x:%02x:%02x:%02x\n", ptr->mac[0], ptr->mac[1], ptr->mac[2], ptr->mac[3], ptr->mac[4], ptr->mac[5]);
            ptr = ptr->next;
        }
    }
    return count;
}

static ssize_t routers_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    /* Read the allowed MAC addresses of routers and maintain them to check against packets MAC IP relation*/
    /** TODO: which format you are expecting ??? ab:cd:ef:gh:ij:kl
     *  1. Handle repeated MAC entries 
     *  2. Handle upper as well as lower case inputs
     *
     */

    struct router_mac *tmp;
    u8 mac[ETH_ALEN] = {0};
    /*
     * mac_pton() will handle case sensitivity. Returns the lower case representation of MAC,
     */
    if (!mac_pton(buf, mac))
    {
            printk("\n mac_pton failed \n");
           return -EINVAL;
    }

    //printk(" read mac address %x, %x, %x, %x, %x, %x",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    //printk(" buf content %s:", buf);

    tmp = kmalloc(sizeof(struct router_mac), GFP_KERNEL);
    if(!tmp)
    {
        printk("%s: can't allocate memory", __func__);
        return -ENOMEM;
    }

    memcpy(tmp->mac, mac, ETH_ALEN);
    tmp->next = NULL;
    /* add this tmp to list */
    add_router( tmp );

    return count;
}

static struct kobj_attribute dhcp_attribute     =
                    __ATTR(dhcp_snoop, 0644, dhcp_show, dhcp_store);
static struct kobj_attribute allowed_routers    = 
                    __ATTR(config_router, 0644, routers_show, routers_store);

static struct attribute * attrs [] = {
    &dhcp_attribute.attr,
    &allowed_routers.attr,
    NULL,
};
/***********************************************************************/
/*       Allowed routers list       */



static struct attribute_group attr_group = {
    .attrs = attrs,
};


static struct kobject *ex_kobj;


static void dhcp_timer_func(unsigned long data)
{
    dhcp_timer_task(0);
    tick_timer();
}


void tick_timer()
{
    dhcp_timer.expires = jiffies + delay * HZ;
    dhcp_timer.data=0;
    dhcp_timer.function = dhcp_timer_func;
    add_timer(&dhcp_timer);
}

/**
 *	DHCP snoop
 *	1. Packet is coming from DHCP server, if box is working as DHCP relay agent 
 *	2. Packet is generated locally in case of DHCP server is inside
 *
 *
 */

/**
 *  IP Spoof
 * 	1. Register a hook for incoming packets.
 *	2. Get IP-MAC of packet and compare with DHCP snoop table.
 *	3. If Match do nothing.
 *	4. If not matched do print some diagnostic message.
 */

/** 
 * NF hook function, deals with only data packets(non DHCP packets)
 */
unsigned int data_hook_function(unsigned int hooknum, struct sk_buff *skb,
				const struct net_device *in, 
				const struct net_device *out, 
				int (*okfn) (struct sk_buff*))
{
	int ret1 = 0;
    char buf[512] = {'\0'};
    unsigned char src_mac[ETH_ALEN];
	struct iphdr *ip_header;
    struct ethhdr *eh;
    struct in_addr saddr;

	/* Check packet is Internet packet or not */
    if (skb->protocol != htons (ETH_P_IP))
	{
		return NF_ACCEPT;
	}
    
    /* If packet is IPv6, then just Accept the packet  */
    ip_header = ip_hdr(skb);
    if(ip_header->version != IPV4)
    {
        return NF_ACCEPT;
    }
    /* There may be chance of DHCP packet, we should not drop the dhcp packet */
    ret1 = is_dhcp(skb);
    if(ret1 == 1)
    {
        return NF_ACCEPT;
    }

	ret1 = verify_packet(skb);
	if (ret1 ==1)
	{
		D("IP-MAC relation is correct \n");
		return NF_ACCEPT;
	}
    else
    {
        D("IP spoof packet found");
        /*FIXME:*/
        /* Debug: print protocol number and src IP*/
        eh = eth_hdr(skb);
        memcpy(src_mac, eh->h_source, ETH_ALEN);
        ip_header = ip_hdr(skb);
        saddr.s_addr = ip_header->saddr; /* do we need to used ntohl()*/
        D("IP protocol:%d\t", ip_header->protocol);
        D("SRC MAC:%02X:%02X:%02X:%02X:%02X:%02X\t", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        D("SRC IP:%s \n", inet_ntoa(saddr, buf, NULL));
        return NF_DROP;
    }

	return NF_ACCEPT;
}

/* *
 * the DHCP snooping hook position depends on box configuration,
 * i.e BOX is DHCP server or DHCP Relay agent
 * If BOX is DHCP server, then hooks should be registered at LOCAL_OUT
 * If BOX is DHCP relay agent, then hook shoud be registered at PRE_ROUTING
 */
static struct nf_hook_ops dhcp_nfho = {
    .owner      = THIS_MODULE,
    .hook       = dhcp_hook_function,
    /* Add some mechanism to choose hooknum, may be module parameter */
    .hooknum    = 3, /* 3 (LOCAL_OUT) or 0 (PRE_ROUTING)PF_BRIDGE*/
    .pf         = PF_BRIDGE,
    .priority   = NF_IP_PRI_FIRST,
};

/**
 * This hook is for packet check it should be at PRE ROUTING always. 
 */
static struct nf_hook_ops packet_nfho = {
	.owner		= THIS_MODULE,
	.hook		= data_hook_function,
	.hooknum	= 0,	/*NF_IP_PRE_ROUTING,*/
	.pf		    = PF_BRIDGE,
	.priority	= NF_IP_PRI_FIRST,
};

static int __init mod_init_func (void)
{
    int retval;
    struct net_device *dev;
    int num_devices = 0;
    int i = 0;

    /*TODO: get all available network interfaces  */
    dev = first_net_device(&init_net);
    while(dev){
        printk(KERN_INFO"interface name %s \n",dev->name);
        num_devices++;
        dev = next_net_device(dev);
    }
    printk(KERN_INFO"there are %d interfaces on the machine",num_devices);
    interface = kmalloc(sizeof(struct interface)*num_devices, GFP_KERNEL);
    if(!interface) {
        printk(KERN_DEBUG"%s: Can't allocate memory for interfaces \n", __func__);
        return -ENOMEM;
    }

    dev = first_net_device(&init_net);
    while(dev) {
        printk(KERN_INFO"interface name %s \n",dev->name);
        //num_devices++;
        memcpy(interface[0].name, dev->name, IFNAMSIZ);
        dev = next_net_device(dev);
    }
    /* Initially all the interfaces are Untrusted */
    for(i = 0; i<num_devices; i++)
    {
        interface[i].is_trusted = 0;
    }

    nf_register_hook(&dhcp_nfho);
    /*nf_register_hook(&packet_nfho);

    ex_kobj = kobject_create_and_add("dhcp", kernel_kobj);
    retval = sysfs_create_group(ex_kobj, &attr_group);
    if(retval)
        kobject_put(ex_kobj);

    init_timer_on_stack(&dhcp_timer);
    tick_timer();
    */
    return 0;
}

static void __exit mod_exit_func (void)
{
    //(kobject_put(ex_kobj);
    //del_timer(&dhcp_timer);

    nf_unregister_hook(&dhcp_nfho);
    //nf_unregister_hook(&packet_nfho);
    //TODO: clean the Hash table
    //TODO: clean the memory associated with allowed router linked list
    //clean_allowed_routers();
    
}

module_init (mod_init_func);
module_exit (mod_exit_func);
