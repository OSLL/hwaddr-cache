#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/version.h>

#include "hash.h"
#include "hwaddr.h"
#include "proc.h"

struct dir_list_node
{
	struct proc_dir_entry*		dir_entry;
	struct in_ifaddr const*		ifa;
	struct list_head		list;
};

static LIST_HEAD(dir_list);

static struct proc_dir_entry *proc_info_root = NULL;
static char const proc_info_root_name[] = "hwaddr";

static void hwaddr_show_ifa_cache_entry(struct hwaddr_entry *entry, void *data)
{
	struct seq_file *sf = (struct seq_file *)data;
	struct dir_list_node *node = (struct dir_list_node *)sf->private;
	unsigned long inactive;
	int refs;
	
	if (node->ifa->ifa_local != entry->h_local)
		return;

	inactive = get_seconds() -
			(unsigned long)atomic_long_read(&entry->h_stamp);
	refs = atomic_read(&entry->h_refcnt);
	seq_printf(sf, "%15pI4  %15pI4  %pM  %5d  %10lu\n", &entry->h_local, 
				&entry->h_remote, entry->h_ha, refs, inactive);
}

static int hwaddr_show_ifa_cache(struct seq_file *sf, void *unused)
{
	seq_printf(sf, "%15s  %15s  %17s  %5s  %10s\n", "local ip", "remote ip",
				"mac address", "refcnt", "inactive");
	hwaddr_foreach(hwaddr_show_ifa_cache_entry, sf);

	return 0;
}

static struct dir_list_node *DLN(struct inode const *inode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	return (struct dir_list_node *)PDE(inode)->data;
#else
	return (struct dir_list_node *)PDE_DATA(inode);
#endif
}

static int hwaddr_ifa_cache_open(struct inode *inode, struct file *file)
{
	struct dir_list_node *node = DLN(inode);
	return single_open(file, hwaddr_show_ifa_cache, node);
}

static struct file_operations const hwaddr_ifa_cache_ops = {
	.open = hwaddr_ifa_cache_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

#define IP_MAX_LEN	16

static void hwaddr_ifa_folder_create(struct in_ifaddr const* const ifa)
{
	char buffer[IP_MAX_LEN];
	struct dir_list_node *node = kmalloc((sizeof(struct dir_list_node)),
				GFP_KERNEL);

	if (!node)
	{
		pr_warn("hwaddr-cache: cannot allocate ifa descriptor\n");
		return;
	}

	sprintf(buffer, "%pI4", &ifa->ifa_local);
	node->dir_entry = proc_mkdir(buffer, proc_info_root);
	node->ifa = ifa;
	proc_create_data("cache", 0, node->dir_entry, &hwaddr_ifa_cache_ops,
				node);
	list_add(&node->list, &dir_list);
}

static void hwaddr_ifa_folder_remove(struct in_ifaddr const* const ifa)
{
	char buff[IP_MAX_LEN];
	struct dir_list_node *node = NULL;
	struct list_head *entry = NULL, *temp = NULL;

	list_for_each_safe(entry, temp, &dir_list)
	{
		node = list_entry(entry, struct dir_list_node, list);
		if (node->ifa == ifa)
		{
			list_del(entry);
			remove_proc_entry("cache", node->dir_entry);
			kfree(node);
			break;
		}
	}

	sprintf(buff, "%pI4", &ifa->ifa_local);
	remove_proc_entry(buff, proc_info_root);
}

static int hwaddr_inetaddr_event(struct notifier_block *nb, unsigned long event,
			void *ptr)
{
	struct in_ifaddr const* const ifa = (struct in_ifaddr *)ptr;

	switch (event)
	{
	case NETDEV_UP:
		hwaddr_ifa_folder_create(ifa);
		break;
	case NETDEV_DOWN:
		hwaddr_ifa_folder_remove(ifa);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block hwaddr_inetaddr_notifier = {
	.notifier_call = hwaddr_inetaddr_event,
};

static int hwaddr_netdev_event(struct notifier_block *nb, unsigned long event,
			void *ptr)
{
	struct net_device const* const dev =
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
				(struct net_device const *)ptr;
#else
				netdev_notifier_info_to_dev(ptr);
#endif
	struct in_device const* const in_dev = __in_dev_get_rtnl(dev);

	if (!in_dev)
		return NOTIFY_DONE;

	switch (event)
	{
	case NETDEV_UP:
		for_ifa(in_dev) {
			hwaddr_ifa_folder_create(ifa);
		} endfor_ifa(in_dev);
		break;
	case NETDEV_DOWN:
		for_ifa(in_dev) {
			hwaddr_ifa_folder_remove(ifa);
		} endfor_ifa(in_dev);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block hwaddr_netdev_notifier = {
	.notifier_call = hwaddr_netdev_event,
};

static void hwaddr_register_notifiers(void)
{
	register_netdevice_notifier(&hwaddr_netdev_notifier);
	register_inetaddr_notifier(&hwaddr_inetaddr_notifier);
}

static void hwaddr_unregister_notifiers(void)
{
	unregister_inetaddr_notifier(&hwaddr_inetaddr_notifier);
	unregister_netdevice_notifier(&hwaddr_netdev_notifier);
}

static void hwaddr_show_entry(struct hwaddr_entry *entry, void *data)
{
	struct seq_file *sf = (struct seq_file *)data;
	unsigned long const inactive = get_seconds() -
			(unsigned long)atomic_long_read(&entry->h_stamp);
	int const refs = atomic_read(&entry->h_refcnt);

	seq_printf(sf, "%15pI4  %15pI4  %pM  %5d  %10lu\n", &entry->h_local,
				&entry->h_remote, entry->h_ha, refs, inactive);
}

static int hwaddr_show_cache(struct seq_file *sf, void *unused)
{
	seq_printf(sf, "%15s  %15s  %17s  %5s  %10s\n", "local ip", "remote ip",
				"mac address", "refcnt", "inactive");
	hwaddr_foreach(hwaddr_show_entry, sf);

	return 0;
}

static int hwaddr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hwaddr_show_cache, NULL);
}

struct hwaddr_ref_request
{
	struct in_addr	remote;
	struct in_addr	local;
};

#define HWADDR_IOC_MAGIC	0xFE
#define HWADDR_ENTRY_REF	_IOW(HWADDR_IOC_MAGIC, 1, struct hwaddr_ref_request)
#define HWADDR_ENTRY_UNREF	_IOW(HWADDR_IOC_MAGIC, 2, struct hwaddr_ref_request)

static long hwaddr_ioctl(struct file *fp, unsigned cmd, unsigned long arg)
{
	struct hwaddr_entry *entry = NULL;
	struct hwaddr_ref_request request;

	if (_IOC_TYPE(cmd) != HWADDR_IOC_MAGIC)
	{
		pr_warn("hwaddr-cache: do not know this ioctl\n");
		return -EINVAL;
	}

	if (copy_from_user(&request, (void const *)arg, sizeof(request)))
	{
		pr_warn("hwaddr-cache: cannot copy data\n");
		return -EINVAL;
	}

	entry = hwaddr_lookup(request.remote.s_addr, request.local.s_addr);
	if (!entry)
	{
		pr_warn("hwaddr-cache: cannot find such entry\n");
		return -EINVAL;
	}

	switch (cmd)
	{
	case HWADDR_ENTRY_REF:
		atomic_inc(&entry->h_refcnt);
		break;
	case HWADDR_ENTRY_UNREF:
		if (atomic_dec_return(&entry->h_refcnt) < 0)
			pr_warn("hwaddr-cache: decremented zero\n");
		break;
	default:
		pr_warn("hwaddr-cache: do not support this ioctl\n");
		return 1;
	}
	return 0;
}

static struct file_operations const hwaddr_proc_ops = {
	.open = hwaddr_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.unlocked_ioctl = hwaddr_ioctl,
};

int hwaddr_proc_create(void)
{
	proc_info_root = proc_mkdir(proc_info_root_name, NULL);
	if (!proc_info_root)
		return -ENOMEM;

	proc_create_data("cache", 0, proc_info_root, &hwaddr_proc_ops, NULL);
	hwaddr_register_notifiers();

	return 0;
}

void hwaddr_proc_destroy(void)
{
	hwaddr_unregister_notifiers();
	remove_proc_entry("cache", proc_info_root);
	remove_proc_entry(proc_info_root_name, NULL);
	proc_info_root = NULL;
}
