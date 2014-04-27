#include <linux/proc_fs.h>
#include <linux/version.h>

#include "hash.h"
#include "hwaddr.h"
#include "proc.h"

struct dir_list_node {
  struct dir_list_node* next;
  struct proc_dir_entry* dir_entry;
  struct in_ifaddr const* ifa;
};

static struct dir_list_node *dir_list_head = NULL;
static struct proc_dir_entry *proc_info_root = NULL;
static char const proc_info_root_name[] = "hwaddr";

static void port_folder_create(struct in_ifaddr const* const ifa) {
	char buff[17];
	struct dir_list_node *dir_current = NULL;
	struct dir_list_node *dir_last = NULL;
	
	sprintf(buff,"%pI4", &ifa->ifa_local);
	dir_current = kmalloc((sizeof(struct dir_list_node)), GFP_KERNEL);
	dir_current->next = NULL;
	dir_current->dir_entry = proc_mkdir(buff, proc_info_root);
	dir_current->ifa = ifa;
	dir_last = dir_list_head;
	while (dir_last->next!=NULL) {
		dir_last = dir_last->next;
	}
	dir_last->next = dir_current;
}

static void port_folder_remove(struct in_ifaddr const* const ifa) {
	char buff[17];
	struct dir_list_node *dir_current = NULL;
	
	sprintf(buff,"%pI4", &ifa->ifa_local);
	remove_proc_entry(buff, proc_info_root);
	
	dir_current = dir_list_head;
	while (dir_current->next!=NULL) {
		dir_current = dir_current->next;
		if (dir_current->ifa==ifa) {
			pr_debug("FOUND!\n");
		}
	}
}

static int aufs_inetaddr_event(struct notifier_block *nb, unsigned long event,
			void *ptr)
{
	struct in_ifaddr const* const ifa = (struct in_ifaddr *)ptr;
	switch (event)
	{
	case NETDEV_UP:
		port_folder_create(ifa);
		pr_debug("inet addr %pI4 up\n", &ifa->ifa_local);
		break;
	case NETDEV_DOWN:
		port_folder_remove(ifa);
		pr_debug("inet addr %pI4 down\n", &ifa->ifa_local);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block aufs_inetaddr_notifier = {
	.notifier_call = aufs_inetaddr_event,
};

static int aufs_netdev_event(struct notifier_block *nb, unsigned long event,
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
			port_folder_create(ifa);
			pr_debug("inet addr %pI4 up\n", &ifa->ifa_local);
		} endfor_ifa(in_dev);
		break;
	case NETDEV_DOWN:
		for_ifa(in_dev) {
			port_folder_remove(ifa);
			pr_debug("inet addr %pI4 down\n", &ifa->ifa_local);
		} endfor_ifa(in_dev);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block aufs_netdev_notifier = {
	.notifier_call = aufs_netdev_event,
};

static void hwaddr_register_notifiers(void)
{
	register_netdevice_notifier(&aufs_netdev_notifier);
	register_inetaddr_notifier(&aufs_inetaddr_notifier);
}

static void hwaddr_unregister_notifiers(void)
{
	unregister_inetaddr_notifier(&aufs_inetaddr_notifier);
	unregister_netdevice_notifier(&aufs_netdev_notifier);
}

static void hwaddr_show_entry(struct hwaddr_entry *entry, void *data)
{
	struct seq_file *sf = (struct seq_file *)data;

	read_lock(&entry->lock);
	seq_printf(sf, "local ip = %pI4, remote ip = %pI4, hwaddr = %pM\n",
				&entry->local, &entry->remote, entry->ha);
	read_unlock(&entry->lock);
}

static int hwaddr_show_cache(struct seq_file *sf, void *unused)
{
	hwaddr_foreach(hwaddr_show_entry, sf);

	return 0;
}

static int hwaddr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hwaddr_show_cache, NULL);
}

static struct file_operations const hwaddr_proc_ops = {
	.open = hwaddr_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int hwaddr_proc_create(void)
{
	dir_list_head = kmalloc((sizeof(struct dir_list_node)), GFP_KERNEL);
	dir_list_head->next = NULL;
	dir_list_head->dir_entry = NULL;
	dir_list_head->ifa = NULL;
	
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
	kfree(dir_list_head);
	dir_list_head = NULL;
}
