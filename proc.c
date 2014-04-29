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

static void hwaddr_show_ifa_cache_entry(struct hwaddr_entry *entry, void *data)
{
        struct seq_file *sf = (struct seq_file *)data;
        struct dir_list_node *node = (struct dir_list_node *)sf->private;

        read_lock(&entry->lock);
        if (node->ifa->ifa_local!=entry->local) return;
        seq_printf(sf, "local ip = %pI4, remote ip = %pI4, hwaddr = %pM\n",
                                &entry->local, &entry->remote, entry->ha);
        read_unlock(&entry->lock);
}

static int hwaddr_show_ifa_cache(struct seq_file *sf, void *unused)
{
        hwaddr_foreach(hwaddr_show_ifa_cache_entry, sf);
        return 0;
}

static int hwaddr_ifa_cache_open(struct inode *inode, struct file *file)
{
        struct dir_list_node *node = (struct dir_list_node*)PDE_DATA(inode);
        return single_open(file, hwaddr_show_ifa_cache, node);
}

static struct file_operations const hwaddr_ifa_cache_ops = {
        .open = hwaddr_ifa_cache_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = single_release,
};

static void hwaddr_ifa_folder_create(struct in_ifaddr const* const ifa) {
        struct dir_list_node *node_current = NULL;
        struct dir_list_node *node_last = NULL;
	char buffer[17];
        sprintf(buffer,"%pI4", &ifa->ifa_local);
	
        node_current = kmalloc((sizeof(struct dir_list_node)), GFP_KERNEL);
        node_current->next = NULL;
        node_current->dir_entry = proc_mkdir(buffer, proc_info_root);
        node_current->ifa = ifa;
        proc_create_data("cache", 0, node_current->dir_entry, &hwaddr_ifa_cache_ops, NULL);

        node_last = dir_list_head;
        while (node_last->next!=NULL) {
                node_last = node_last->next;
        }
        node_last->next = node_current;
}

static void hwaddr_ifa_folder_remove(struct in_ifaddr const* const ifa) {
        char buff[17];
        struct dir_list_node *node_current = NULL;
        struct dir_list_node *node_prev = NULL;

        node_current = dir_list_head;
        while (node_current->next!=NULL) {
                node_prev = node_current;
                node_current = node_current->next;
                if (node_current->ifa==ifa) {
                        node_prev->next = node_current->next;
                        remove_proc_entry("cache", node_current->dir_entry);
                        kfree(node_current);
                        break;
                }
        }

        sprintf(buff,"%pI4", &ifa->ifa_local);
        remove_proc_entry(buff, proc_info_root);
}

static int aufs_inetaddr_event(struct notifier_block *nb, unsigned long event,
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