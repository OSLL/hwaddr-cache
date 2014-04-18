#include <linux/init.h>
#include <linux/module.h>

#include "cache.h"
#include "hwaddr.h"
#include "netfilter.h"
#include "proc.h"

static int __init hwaddr_cache_init(void)
{
	int rc = hwaddr_proc_create();
	if (rc)
	{
		pr_err("cannot create proc directory\n");
		return rc;
	}

	rc = hwaddr_slab_create();
	if (rc)
	{
		pr_err("cannot create slab cache\n");
		hwaddr_proc_destroy();
		return rc;
	}

	rc = hwaddr_register_hooks();
	if (rc)
	{
		pr_err("cannot register netfilter hooks\n");
		hwaddr_proc_destroy();
		hwaddr_slab_destroy();
		return rc;
	}

	pr_debug("hwaddr-cache module loaded\n");
	return 0;
}

static void __exit hwaddr_cache_cleanup(void)
{
	hwaddr_unregister_hooks();
	hwaddr_slab_destroy();
	hwaddr_proc_destroy();

	pr_debug("hwaddr-cache module unloaded\n");
}

module_init(hwaddr_cache_init);
module_exit(hwaddr_cache_cleanup);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
