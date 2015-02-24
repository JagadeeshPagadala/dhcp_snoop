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

#define IS_IP(skb) (skb->protocol == htnos(ETH_P_IP))

#define IS_VLAN(skb) (skb->protocol == htons(ETH_P_8021Q) && (vlan_proto(skb) == htons(ETH_P_IP)))

bool is_dhcp_server = 1;
module_param(is_dhcp_server, bool , S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(is_dhcp_server, "If box is working as DHCP relay agent unset this variable when loading the module, by default it is set\n");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jagadeesh Pagadala");
MODULE_DESCRIPTION("DHCP snoop and IP spoof");


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
    unsigned int lease_time;
    /* For hash table*/
    struct hlist_node dhcp_hash_list;
    /* type is to maintain the entry type. 1--> DHCP snoop and 0--> Static entry*/
    uint8_t type;
};

/* This structure maintains list of trusted interfaces*/
struct trusted_interface_list
{
    unsigned char name[IFNAMSIZ];
    int name_len;
    struct trusted_interface_list *next;
};

struct trusted_interface_list *trusted_if_head = NULL;

void clean_trusted_intrerfaces(void)
{
    struct trusted_interface_list *ptr;
    struct trusted_interface_list *tmp;

    if(trusted_if_head == NULL)
        return;

    ptr = trusted_if_head;
    while(ptr->next != NULL)
    {
        tmp = ptr; 
        ptr = ptr->next;
        kfree(tmp);
    }
    trusted_if_head = NULL; 
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
        /*If type is "0"-----static binding so dont decreament lease time */
        if(ptr->type == 0)
            continue;
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
/**
 * function to convert xx.yy.zz.ww dotted decimal to uint32
 */
unsigned int inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];

    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; 
    arr[1] = b; 
    arr[2] = c;
    arr[3] = d;

    return *(unsigned int*)arr;
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
                // dhcp_mac is client MAC that is snooped from previous DHCP transaction 
                // hw is CHADDR(client HW addr) field of present DHCP transaction
                if(memcmp(tmp->dhcp_mac, hw, ETH_ALEN) == 0)
                {
                    // If entry is found, replace the entry (or) update entry
                    tmp->ip = dhcp_ip_address(skb);
                    tmp->lease_time = dhcp_lease_time(skb);
                    tmp->type = 1;
                    //printk(KERN_DEBUG"%s:DHCP spoof entry already present... Updating with new values \n", __func__);
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
            ptr->lease_time = dhcp_lease_time(skb);
            ptr->type = 1;
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
	
    /*TODO:
     * Choose what to do when there is no HASH table is created for DHCP snoop
     * 1.If HASH table is empty.... don't perform check 
     * 2.Just drop the packet
     * */

    if (hash_empty(dhcp_snoop_table) == true)
    {
        return 0;/* I am not accepting untill a static entry or DHCP snoop entry*/
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
			if((memcmp(&src_mac, &ptr->dhcp_mac, ETH_ALEN) == 0))
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
 * NF HOOK call back fn. will process only DHCP packets to snoop the DHCP transaction
 * 1. DHCP server case
 * 2. DHCP relay agent case
 *
 * TODO: First thing to be done is check packet is RXD on trusted interface or untrusted interface.
 *          If packet is coming on unterusted interface, Allow only DHCP packets untill IP-MAC relation is found 
 *          If packet is coming on trusted interface, do not apply DHCP snoop and IP source guard.
 * Steps to be folloewed: 
 *          Check packet is DHCP ack or not.... 
 *          If not a DHCP ack packet, then just allow the packet
 *          If DHCP ack packet
 *              Check if pkt is coming on untrusted interface.... Drop the packet
 *              Check if pkt is coming on trusted interface(DHCP server is connected)...add to DHCP snooping table
 */
/*
 *
 * First Handle the DHCP server case
 * 1. Check pkt is DHCP ACK
 *      If yes just add to DHCP snooping table 
 *      If not Just accept.
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
    //printk(KERN_INFO"pkt on in:%s out:%s", in->name, out->name);

    /* If packet is IPv6, then just Accept the packet  */
    ip_header = ip_hdr(skb);
    if(ip_header->version != IPV4)
    {
        return NF_ACCEPT;
    }

    /*//TODO: Check packet is coming on trutsed interface ?
    {
        eh = eth_hdr(skb);
        if(trusted_if_head != NULL) // there are trusted interfaces configured.
        {
            while(ptr != NULL)
            {
                if(memcmp(eh->h_source, ptr->name, ptr->name_len) == 0)
                {
                    // found in trusted list
                    printk(KERN_DEBUG"%s:pkt rxd on trusted interface %s", __func__, ptr->name);
                    return NF_ACCEPT;
                }
            }
        }
    }*/
   
   /**If I reach here means, DHCP packet is received on untrusted interface
    *Add the IP-MAC relation to DHCP snoop table.
    * 
    */
    
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
    /*TODO: add the MAC-IP as the static entry*/
    /**
     * Take input string and parse the string as comma as delimiter
     */
    unsigned char mac[ETH_ALEN] = {0};
    uint32_t ip;
    uint32_t vlan;
    char *p;
    char *buffer;
    struct in_addr addr;
    struct dhcp_struct *tmp;
    int i = 0;

    //memcpy(buffer, buf, count);
    buffer = buf;
    //parse MAC address
    p = strsep(&buffer,",");
    if(!mac_pton(p, mac))
    {
        printk(KERN_DEBUG"%s: mac_pton failed", __func__);
        return -EINVAL;
    }
    printk(KERN_DEBUG"%s :mac addr is:%s ", __func__, p);
    
    //parse IP address
    p = strsep(&buffer,",");
    //memcpy(&ip, p, ETH_ALEN);
    printk(KERN_DEBUG"%s :IP addr is:%s", __func__, p);
    /*TODO: add API that converts x.y.z.w to uinit32_t */
    ip = inet_addr(p);

    printk(KERN_DEBUG"%s : IP addr in uint32 %u",__func__, ip);
    //parse VLAN.... etc 

    /*Add to hash table */
    /* Here both cases..... DHCP server and DHCP Relay agent cases are handled*/
    //Search in hash table 
    hash_for_each(dhcp_snoop_table, i, tmp, dhcp_hash_list)
    {
        // compare stored MAC address with PACKET mac address
        // dhcp_mac is client MAC that is snooped from previous DHCP transaction 
        // hw is CHADDR(client HW addr) field of present DHCP transaction
        if(memcmp(tmp->dhcp_mac, mac, ETH_ALEN) == 0)
        {
            // If entry is found, replace the entry (or) update entry
            tmp->ip = ip;
            //memcpy(tmp->dhcp_mac, mh->h_dest, ETH_ALEN);
            //tmp->lease_time = dhcp_lease_time(skb);
            tmp->lease_time = 0;
            tmp->type = 0;
            //printk(KERN_DEBUG"%s:DHCP spoof entry already present... Updating with new values \n", __func__);
            return count;
        }
    }
    // entry is not found, so add to hash table 
    struct dhcp_struct *ptr = kmalloc(sizeof( struct dhcp_struct), GFP_KERNEL);
    if( ptr == NULL )
    {
        D("%s: can't allocate memory\n",__func__);
        return count;           
    }
    ptr->ip = ip;
    memcpy(ptr->dhcp_mac, mac, ETH_ALEN);
    ptr->type = 0;// this is a static entry
    ptr->lease_time = 0;
    // key value is last octate of IP address
    uint8_t key;
    key = (uint8_t) ip; /*TODO: find a good way to take last octate */
    hash_add(dhcp_snoop_table, &ptr->dhcp_hash_list, key);

    return count;
}

/*******************************************************************************/
/*********** sysfs for trusted interfaces ********************************/
static ssize_t trusted_interface_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    struct trusted_interface_list *ptr = trusted_if_head;
    int count = 0;
    /* Just traverse through the list and display*/
    if (trusted_if_head == NULL)
    {
        sprintf(buf, "No Trusted Interfaces");
        return count;
    }
    while(ptr != NULL)
    {
        count+=sprintf(buf+count, "%s \t", ptr->name);
        ptr = ptr->next;
    }
    count+=sprintf(buf+count,"\n"); /* This line is just for good alignment*/
    return count;
}

static struct net_device *if_to_netdev(const char *buffer)
{
	char *cp;
	char ifname[IFNAMSIZ + 2];

	if (buffer) {
		strlcpy(ifname, buffer, IFNAMSIZ);
		cp = ifname + strlen(ifname);
		while (--cp >= ifname && *cp == '\n')
			*cp = '\0';
		return dev_get_by_name(&init_net, ifname);
	}
	return NULL;
}

/* Store method is handled correctly*/
static ssize_t trusted_interface_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    /* add to the trusted interfaces list*/
    struct trusted_interface_list *ptr = trusted_if_head;
    struct trusted_interface_list *tmp;
    char ifname[IFNAMSIZ] = {'\0'};
    struct net_device *dev;

    printk(KERN_INFO"inside trusted_interface_store");
    /* Sanity check of interface*/
    dev = if_to_netdev(buf);
    if(!dev)
    {
        printk(KERN_DEBUG"\n Invalid argument\n");
        return -EINVAL;
    }
    printk(KERN_DEBUG"\n device found %s, length:%d\n",dev->name,strlen(dev->name));

    
    printk(KERN_DEBUG"\nbuf:%s interface:%s \n", buf, ifname);
    //dev = dev_get_by_name(&init_net, ifname);
    printk(KERN_DEBUG"\n device found %s\n",dev->name);

    /*TODO: If same interface is entered two or more times? solve this by checking existing name in list*/
    if (trusted_if_head == NULL)
    {
        tmp = kmalloc(sizeof(struct trusted_interface_list), GFP_KERNEL);
        if(!tmp)
        {
            printk(KERN_DEBUG"%s: can't allocate memory", __func__);
            return -ENOMEM;
        }
        /* How much need to copy: solved.... */
        memcpy(tmp->name, dev->name, IFNAMSIZ);
        tmp->name_len = strlen(dev->name);
        tmp->next = NULL;
        trusted_if_head = tmp;
        return count;
    }
    else 
    {
        /*check if the interface is already in trusted ports list*/

        while(ptr != NULL)
        {
            if(memcmp(dev->name, ptr->name, ptr->name_len) == 0)
            {
                printk(KERN_DEBUG"entry already exists");
                return count;
            }
            ptr = ptr->next;
        }

       tmp = kmalloc(sizeof(struct trusted_interface_list), GFP_KERNEL);
       if(!tmp)
       {
            printk(KERN_DEBUG"%s: can't allocate memory", __func__);
            return -ENOMEM;
       }
        /* How much need to copy: solved ....*/
        memcpy(tmp->name, dev->name, IFNAMSIZ);
        tmp->name_len = strlen(dev->name);
        /* Add new element at head*/
        tmp->next = trusted_if_head;
        trusted_if_head = tmp;
    }

    return count;
}
/**************** sysfs for dhcp snoop table *********************************/
static struct kobj_attribute dhcp_attribute     =
                    __ATTR(dhcp_snoop, 0644, dhcp_show, dhcp_store);
/********************** sysfs for trusted interfaces *************************/
static struct kobj_attribute trusted_interfaces = 
                    __ATTR(trusted_interfaces, 0644, trusted_interface_show, trusted_interface_store);


static struct attribute * attrs [] = {
    &dhcp_attribute.attr,
    &trusted_interfaces.attr,
    NULL,
};

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
 * TODO: added 4-2-215
 * If packet is coming on trusted interface, do not verify packet
 * If packet is coming on untrusted interface verify packet.
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
    struct trusted_interface_list *ptr = trusted_if_head;
    u16 vlan_tag;

    /* How to check the vlan packet ... ?*/
    if (vlan_get_tag(skb, &vlan_tag)<0) {
        printk(KERN_DEBUG"%s: packet is not VLAN tagged ",__func__);
    }else 
        printk(KERN_DEBUG"%s: VLAN tag is %d", __func__, vlan_tag);

	/* Check packet is Internet packet or not */
    /* TODO: add a check to verify VLAN tool*/
    if (skb->protocol != htons (ETH_P_IP))
	{
		return NF_ACCEPT;
	}

    /* If packet is IPv6, then just Accept the packet  */
    ip_header = ip_hdr(skb);
    if (ip_header->version != IPV4)
    {
        return NF_ACCEPT;
    }
    /* There may be chance of DHCP packet, we should not drop the dhcp packet */
    /*TODO: Check cisco doc ....when to accept DHCP packets....
     * i.e, what if DHCP ACK is coming on untrused port
     * */
    ret1 = is_dhcp(skb);
    if(ret1 == 1)
    {
        return NF_ACCEPT;
    }
    printk(KERN_DEBUG"%s: pkt rxd on interface %s",__func__,in->name);
    
    /*TODO: Check packet is coming on trutsed interface ?*/

    eh = eth_hdr(skb);
    if(trusted_if_head != NULL)//  there are trusted interfaces configured.
    {
        printk(KERN_DEBUG"%s:checking on interface %s \n", __func__, ptr->name);
        while(ptr != NULL)
        {
            if(memcmp(in->name, ptr->name, ptr->name_len) == 0)
            {
                /// found in trusted list
                printk(KERN_DEBUG"%s:packet is RXD on trusted interface %s", __func__, eh->h_source);
                return NF_ACCEPT;
            }
            ptr = ptr->next;
        }
    }
    
    /* packet is not rxd on trusted interface so, verify packet*/
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

/**
 * NF hook function, which deals with incoming DHCP ACK packets... 
 * i.e in case of Box is connected to DHCP server.
 * If packet is DHCP ACK... 
 *  Then add the IP-MAC relation to DHCP snoop table
 *
 */
unsigned int dhcp_incoming_function(unsigned int hooknum, struct sk_buff *skb,
				const struct net_device *in, 
				const struct net_device *out, 
				int (*okfn) (struct sk_buff*))
{

    int ret = 0;
    struct iphdr *ip_header;


    printk(KERN_DEBUG"%s: packet is RXD on interface %s \n", __func__, in->name);

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

    ret = is_dhcp(skb);
    if(ret == 1)
    {
        dhcp_process_packet(skb, is_dhcp_server);
        return NF_ACCEPT;
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
    .pf         = PF_BRIDGE, // on bridge interface
    .priority   = NF_IP_PRI_FIRST,
};

/**
 * This hook is for packet check it should be at PRE ROUTING always. 
 */
static struct nf_hook_ops packet_nfho = {
	.owner		= THIS_MODULE,
	.hook		= data_hook_function,
	.hooknum	= 0,	/*NF_IP_PRE_ROUTING,*/
	.pf		    = PF_BRIDGE, // on bridge interface
	.priority	= NF_IP_PRI_FIRST,
};

/**
 * This hook is to listen on non brige interface, 
 * i.e to capture incoming DHCP ack packets from DHCP server */
static struct nf_hook_ops dhcp_incoming_nfho = {
    .owner      = THIS_MODULE,
    .hook       = dhcp_incoming_function,
    .hooknum    = 0, // NF_IP_PRE_ROUTING
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static int __init mod_init_func (void)
{
    int retval;
    struct net_device *dev;
    int num_devices = 0;

    /* TODO: have a list of trusted interfaces, to check incoming pkt interface name against */
    /*TODO: get all available network interfaces  */
    dev = first_net_device(&init_net);
    while(dev) {
        printk(KERN_INFO"interface name %s \n",dev->name);
        num_devices++;
        dev = next_net_device(dev);
    }
    printk(KERN_INFO"there are %d interfaces on the machine",num_devices);

    nf_register_hook(&dhcp_nfho);
    nf_register_hook(&packet_nfho);

    /***** If dhcp server is not on the box*******/
    //nf_register_hook(&dhcp_incoming_nfho);

    ex_kobj = kobject_create_and_add("dhcp", kernel_kobj);
    retval = sysfs_create_group(ex_kobj, &attr_group);
    if(retval)
        kobject_put(ex_kobj);

    init_timer_on_stack(&dhcp_timer);
    tick_timer();
    
    return 0;
}

static void __exit mod_exit_func (void)
{
    kobject_put(ex_kobj);
    del_timer(&dhcp_timer);

    nf_unregister_hook(&dhcp_nfho);
    nf_unregister_hook(&packet_nfho);
    //nf_unregister_hook(&dhcp_incoming_nfho);

    //TODO: clean the Hash table
    //TODO: clean memory associated with trusted interfaces 
}

module_init (mod_init_func);
module_exit (mod_exit_func);
