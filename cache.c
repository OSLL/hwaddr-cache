#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "cache.h"
#include "hash.h"
#include "hash6.h"
#include "netfilter.h"
#include "netfilter6.h"
#include "proc.h"
#include "proc6.h"
#include "route.h"
#include "route6.h"

static unsigned long hwaddr_persistent_timeout = 120;
module_param(hwaddr_persistent_timeout, ulong, 0);
MODULE_PARM_DESC(hwaddr_persistent_timeout,
			"Timeout for persistent hwaddr cache entries");

static unsigned long hwaddr_timeout = 1;
module_param(hwaddr_timeout, ulong, 0);
MODULE_PARM_DESC(hwaddr_timeout, "Timeout fot hwaddr cache entries");

static struct delayed_work hwaddr_gc_work;

static void hwaddr_gc_worker(struct work_struct *unused)
{
	(void)unused; //supress warning

	pr_debug("hwaddr-cache: starting gc\n");
	hwaddr_clear_outdated(hwaddr_timeout * 60,
				hwaddr_persistent_timeout * 60);
	hwaddr6_clear_outdated(hwaddr_timeout * 60,
				hwaddr_persistent_timeout * 60);
	schedule_delayed_work(&hwaddr_gc_work, hwaddr_timeout * 60 * HZ);
	pr_debug("hwaddr-cache: gc finished\n");
}

static void hwaddr_gc_start(void)
{
	INIT_DELAYED_WORK(&hwaddr_gc_work, hwaddr_gc_worker);
	schedule_delayed_work(&hwaddr_gc_work, hwaddr_timeout * 60 * HZ);
}

static void hwaddr_gc_finish(void)
{
	flush_delayed_work(&hwaddr_gc_work);
	cancel_delayed_work_sync(&hwaddr_gc_work);
}

static int hwaddr_cache_ipv4_init(void)
{
	int rc = 0;

	rc = hwaddr_cache_create();
	if (rc)
	{
		pr_err("hwaddr-cache: cannot create cache\n");
		return rc;
	}

	rc = hwaddr_netfilter_register();
	if (rc)
	{
		pr_err("hwaddr-cache: cannot register netfilter hooks\n");
		hwaddr_cache_destroy();
		return rc;
	}

	rc = hwaddr_proc_create();
	if (rc)
	{
		pr_err("hwaddr-cache: cannot create proc directory\n");
		hwaddr_netfilter_unregister();
		hwaddr_cache_destroy();
		return rc;
	}

	return 0;
}

static void hwaddr_cache_ipv4_fini(void)
{
	hwaddr_proc_destroy();
	hwaddr_netfilter_unregister();
	hwaddr_cache_destroy();
}

static int hwaddr_cache_ipv6_init(void)
{
	int rc = 0;

	rc = hwaddr6_cache_create();
	if (rc)
	{
		pr_err("hwaddr-cache6: cannot create cache\n");
		return rc;
	}

	rc = hwaddr6_netfilter_register();
	if (rc)
	{
		pr_err("hwaddr-cache6: cannot register netfilter hooks\n");
		hwaddr6_cache_destroy();
		return rc;
	}

	rc = hwaddr6_proc_create();
	if (rc)
	{
		pr_err("hwaddr-cache6: cannot create proc directory\n");
		hwaddr6_netfilter_unregister();
		hwaddr6_cache_destroy();
		return rc;
	}

	return 0;
}

static void hwaddr_cache_ipv6_fini(void)
{
	hwaddr6_proc_destroy();
	hwaddr6_netfilter_unregister();
	hwaddr6_cache_destroy();
}


static int hwaddr_cache_init(void)
{
	int rc = hwaddr_cache_ipv4_init();

	if (rc)
		return rc;

	rc = hwaddr_cache_ipv6_init();
	if (rc)
	{
		hwaddr_cache_ipv4_fini();
		return rc;
	}

	hwaddr_gc_start();

	pr_debug("hwaddr-cache: module loaded\n");
	return 0;
}

static void __exit hwaddr_cache_cleanup(void)
{
	hwaddr_gc_finish();
	hwaddr_cache_ipv6_fini();
	hwaddr_cache_ipv4_fini();

	pr_debug("hwaddr-cache: module unloaded\n");
}

module_init(hwaddr_cache_init);
module_exit(hwaddr_cache_cleanup);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
