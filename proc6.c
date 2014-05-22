#include <linux/proc_fs.h>
#include <linux/version.h>

#include "hash6.h"
#include "route6.h"

static struct proc_dir_entry *proc_info_root = NULL;
static char const proc_info_root_name[] = "hwaddr6";

static void hwaddr_show_entry(struct hwaddr6_entry *entry, void *data)
{
	struct seq_file *sf = (struct seq_file *)data;
	unsigned long const inactive = get_seconds() -
			(unsigned long)atomic_long_read(&entry->h_stamp);
	int const refs = atomic_read(&entry->h_refcnt);

	seq_printf(sf, "%31pI6  %31pI6  %pM  %5d  %10lu\n", &entry->h_local,
				&entry->h_remote, entry->h_ha, refs, inactive);
}

static int hwaddr_show_cache(struct seq_file *sf, void *unused)
{
	seq_printf(sf, "%31s  %31s  %17s  %5s  %10s\n", "local ip", "remote ip",
				"mac address", "refcnt", "inactive");
	hwaddr6_foreach(hwaddr_show_entry, sf);

	return 0;
}

static int hwaddr_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hwaddr_show_cache, NULL);
}

struct hwaddr_ref_request
{
	struct in6_addr	remote;
	struct in6_addr	local;
};

#define HWADDR_IOC_MAGIC	0xFE
#define HWADDR_ENTRY_REF	_IOW(HWADDR_IOC_MAGIC, 1, struct hwaddr_ref_request)
#define HWADDR_ENTRY_UNREF	_IOW(HWADDR_IOC_MAGIC, 2, struct hwaddr_ref_request)

static long hwaddr_ioctl(struct file *fp, unsigned cmd, unsigned long arg)
{
	struct hwaddr6_entry *entry = NULL;
	struct hwaddr_ref_request request;

	if (_IOC_TYPE(cmd) != HWADDR_IOC_MAGIC)
	{
		pr_warn("hwaddr-cache6: do not know this ioctl\n");
		return -EINVAL;
	}

	if (copy_from_user(&request, (void const *)arg, sizeof(request)))
	{
		pr_warn("hwaddr-cache6: cannot copy data\n");
		return -EINVAL;
	}

	entry = hwaddr6_lookup(&request.remote, &request.local);
	if (!entry)
	{
		pr_warn("hwaddr-cache6: cannot find such entry\n");
		return -EINVAL;
	}

	switch (cmd)
	{
	case HWADDR_ENTRY_REF:
		atomic_inc(&entry->h_refcnt);
		break;
	case HWADDR_ENTRY_UNREF:
		if (atomic_dec_return(&entry->h_refcnt) < 0)
			pr_warn("hwaddr-cache6: decremented zero\n");
		break;
	default:
		pr_warn("hwaddr-cache6: do not support this ioctl\n");
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

int hwaddr6_proc_create(void)
{
	proc_info_root = proc_mkdir(proc_info_root_name, NULL);
	if (!proc_info_root)
		return -ENOMEM;

	proc_create_data("cache", 0, proc_info_root, &hwaddr_proc_ops, NULL);

	return 0;
}

void hwaddr6_proc_destroy(void)
{
	remove_proc_entry("cache", proc_info_root);
	remove_proc_entry(proc_info_root_name, NULL);
	proc_info_root = NULL;
}
