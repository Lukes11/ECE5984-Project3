#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#define BITS 8

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

//static DEFINE_HASHTABLE(pid_hashtable, BITS);
static pid_t pid;
//entry handler to increment count of times perftop has been called
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *p = regs_return_value(regs);
	pid = p->pid;
	return 0;
}
//create proc file
static int perftop_show(struct seq_file *m, void *v) {
	seq_printf(m, "%d\n", pid);
	return 0;
}

static int perftop_open(struct inode *inode, struct  file *file) {
	return single_open(file, perftop_show, NULL);
}
static struct kretprobe perftop_kretprobe = {
	.handler		= ret_handler,
	.kp.symbol_name = "pick_next_task_fair"
};
static const struct file_operations perftop_fops = {
	.owner = THIS_MODULE,
	.open = perftop_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};


//init module
static int __init proj3_init(void)
{
	int ret;
	proc_create("perftop", 0, NULL, &perftop_fops);
	ret = register_kretprobe(&perftop_kretprobe);
	return 0;
}
//exit module
static void __exit proj3_exit(void)
{
	unregister_kretprobe(&perftop_kretprobe);
	remove_proc_entry("perftop", NULL);
}

module_init(proj3_init);
module_exit(proj3_exit);
