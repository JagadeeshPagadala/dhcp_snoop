#include <linux/kernel.h>
#include <linux/module.h>
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


struct timer_list dhcp_timer;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ajeet Vijayvergiya");

char* inet_ntoa(struct in_addr in, char* buf, size_t* rlen);
int dump_list(char *);
int delete_from_list (unsigned char *);

struct dhcp_struct
{
	uint32_t ip;
	unsigned char dhcp_mac[6];
	unsigned char traffic_mac[6];
	unsigned int lease_time;
	struct dhcp_struct *next;
};

struct dhcp_struct *head = NULL;
struct dhcp_struct *curr = NULL;

	struct dhcp_struct *
create_list (uint32_t ip, unsigned char *dhcp_mac,unsigned char *traffic_mac, int lease_time)
{
	struct dhcp_struct *ptr =
		(struct dhcp_struct *) kmalloc (sizeof (struct dhcp_struct),GFP_KERNEL);
	if (NULL == ptr)
	{
		return NULL;
	}
	ptr->ip = ip;
	memcpy (ptr->dhcp_mac, dhcp_mac, 6);
	memcpy (ptr->traffic_mac, traffic_mac, 6);
	ptr->lease_time = lease_time;
	ptr->next = NULL;

	head = curr = ptr;
	return ptr;
}

	struct dhcp_struct *
add_to_list (uint32_t ip, unsigned char *dhcp_mac,unsigned char *traffic_mac, int lease_time)
{
	if (NULL == head)
	{
		return (create_list (ip, dhcp_mac,traffic_mac, lease_time));
	}

	struct dhcp_struct *ptr =
		(struct dhcp_struct *) kmalloc (sizeof (struct dhcp_struct),GFP_KERNEL);
	if (NULL == ptr)
	{
		return NULL;
	}
	ptr->ip = ip;
	memcpy (ptr->dhcp_mac, dhcp_mac, 6);
	memcpy (ptr->traffic_mac, traffic_mac, 6);
	ptr->lease_time = lease_time;
	ptr->next = NULL;

	ptr->next = head;
	head = ptr;

	return ptr;
}

int dump_list(char *buf)
{
	char buff[512]={'\0'};
	struct in_addr saddr;
	int count;
	struct dhcp_struct *ptr = head;
	count=0;
	while (ptr != NULL)
	{
		saddr.s_addr=ptr->ip;
		count+=sprintf(buf+count,"IP address  		-	%s\n",inet_ntoa(saddr,buff,NULL));
		count+=sprintf(buf+count,"MAC address (DHCP) 	-	%02x:%02x:%02x:%02x:%02x:%02x\n",ptr->dhcp_mac[0],ptr->dhcp_mac[1],ptr->dhcp_mac[2],ptr->dhcp_mac[3],ptr->dhcp_mac[4],ptr->dhcp_mac[5]);
		count+=sprintf(buf+count,"MAC address (Traffic)	-	%02x:%02x:%02x:%02x:%02x:%02x\n",ptr->traffic_mac[0],ptr->traffic_mac[1],ptr->traffic_mac[2],ptr->traffic_mac[3],ptr->traffic_mac[4],ptr->traffic_mac[5]);
		count+=sprintf(buf+count,"Lease Time  		-	%d Seconds\n",ptr->lease_time);
		count+=sprintf(buf+count,"\n\n");
		ptr = ptr->next;
	}
	return count;
}


int dhcp_timer_task(int action)
{
	struct dhcp_struct *ptr = head;
	while (ptr != NULL)
	{
		if (ptr->lease_time<=0)
			ptr->lease_time=0;	
		else
			ptr->lease_time-=30;
		ptr = ptr->next;
	}
	return 0;
}

	struct dhcp_struct *
search_in_list (unsigned char *dhcp_mac, struct dhcp_struct **prev)
{
	struct dhcp_struct *ptr = head;
	struct dhcp_struct *tmp = NULL;
	bool found = false;

	while (ptr != NULL)
	{
		if (memcmp(ptr->dhcp_mac,dhcp_mac,6)==0)
		{
			found = true;
			break;
		}
		else
		{
			tmp = ptr;
			ptr = ptr->next;
		}
	}

	if (true == found)
	{
		if (prev)
			*prev = tmp;
		return ptr;
	}
	else
	{
		return NULL;
	}
}

	int
delete_from_list (unsigned char *dhcp_mac)
{
	struct dhcp_struct *prev = NULL;
	struct dhcp_struct *del = NULL;

	del = search_in_list (dhcp_mac, &prev);
	if (del == NULL)
	{
		return -1;
	}
	else
	{
		if (prev != NULL)
			prev->next = del->next;

		if (del == curr)
		{
			curr = prev;
		}
		else if (del == head)
		{
			head = del->next;
		}
	}

	kfree (del);
	del = NULL;

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

static struct nf_hook_ops nfho;
void tick_timer(void);

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

uint32_t dhcp_ip_address(struct sk_buff *skb)  // Get IP address allocated from skb
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



void dhcp_process_packet(struct sk_buff *skb)
{
	int type;
	struct iphdr *iph=ip_hdr(skb);
	struct ethhdr *mh = eth_hdr(skb);  
	int offset=0;
	unsigned char *buff=skb->data;//pointer to the start of skb.
	unsigned char op,htype,hlen,hops;//dhcp field.
	unsigned char *hw;

	offset+=(int)(iph->ihl)*4;

	if(buff[9]==0x11 &&  ((buff[offset]==0x00 && buff[offset+1]==0x43) || (buff[offset+2]==0x00 && buff[offset+3]==0x43)) )//This is dhcp packet
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

		hw=buff+offset;
		//Client MAC address+Server host name+Boot file name+
		//Magic cookie+Option
		offset+=16+64+128+4+2;//reference to RFC2131
		type=*(buff+offset);
		if (type == 5) {  // DHCP ACK Packet
			struct dhcp_struct *ptr;
			ptr=search_in_list(hw,NULL);
			if (!ptr){
				add_to_list(dhcp_ip_address(skb),hw,mh->h_dest,dhcp_lease_time(skb));
			}
			else
			{
				ptr->ip=dhcp_ip_address(skb);
				memcpy(ptr->traffic_mac,mh->h_dest,6);
				ptr->lease_time=dhcp_lease_time(skb);
			}
		}    
	} 
}

	unsigned int
hook_func (unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out, int (*okfn) (struct sk_buff *))
{
	if (skb->protocol == htons (ETH_P_IP))
	{
		if(ip_hdr(skb)->protocol == IPPROTO_UDP){
			struct udphdr *udp_hdr = (struct udphdr *)(skb->data + ((ip_hdr(skb)->ihl)<<2));
			if(udp_hdr->dest == htons(68) || udp_hdr->dest == htons(67) || udp_hdr->source == htons(67) || udp_hdr->source == htons(68))
				dhcp_process_packet(skb);
		}

	}
	return NF_ACCEPT;
}


static ssize_t dhcp_show(struct kobject * kobj, struct kobj_attribute * attr, char * buf)
{ 
	return dump_list(buf);
}

static ssize_t dhcp_store(struct kobject * kobj, struct kobj_attribute * attr, const char * buf, size_t count)
{
	return count;
}

static struct kobj_attribute dhcp_attribute = __ATTR(dhcp_snoop, 0644, dhcp_show, dhcp_store);

static struct attribute * attrs [] =
{
	&dhcp_attribute.attr,
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
	int delay = 30;
	dhcp_timer.expires = jiffies + delay * HZ;
	dhcp_timer.data=0;
	dhcp_timer.function = dhcp_timer_func;
	add_timer(&dhcp_timer);
}

	static int
mod_init_func (void)
{
	int retval;
	nfho.hook = hook_func;
	nfho.hooknum = 3;
	nfho.pf = PF_BRIDGE;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook (&nfho);
	ex_kobj = kobject_create_and_add("data", kernel_kobj);
	retval = sysfs_create_group(ex_kobj, &attr_group);
	if(retval)
		kobject_put(ex_kobj);

	init_timer_on_stack(&dhcp_timer);
	tick_timer();
	return 0;
}

	static void
mod_exit_func (void)
{
	kobject_put(ex_kobj);
	del_timer(&dhcp_timer);
	nf_unregister_hook (&nfho);
}

module_init (mod_init_func);
module_exit (mod_exit_func);
