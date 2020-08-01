//https://github.com/h33p/kallsyms-lp
#include "kallsyms.h"
#include <linux/livepatch.h>

static struct klp_func funcs[] = {
	{
		.old_name = "kallsyms_lookup_name",
		.new_func = kallsyms_lookup_name,
	}, {}
};

static struct klp_func failfuncs[] = {
	{
		.old_name = "___________________",
	}, {}
};

static struct klp_object objs[] = {
	{
		.funcs = funcs,
	},
	{
		.name = "kallsyms_failing_name",
		.funcs = failfuncs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

unsigned long kallsyms_lookup_name(const char *name)
{
	return ((unsigned long(*)(const char *))funcs->old_func)(name);
}

int init_kallsyms(void)
{
	int r = klp_enable_patch(&patch);

	if (!r)
		return -1;

	return 0;
}
