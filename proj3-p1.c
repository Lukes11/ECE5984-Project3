#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOT("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

//create proc file
static int perftop_show(struct seq_file *m, void *v) {
	seq_printf("Hello World!\n");
	return 0;
}

static int perftop_open(struct inode *inode, struct  file *file) {
	return single_open(file, perftop_show, NULL);
}
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
	proc_create("perftop", 0, NULL, &perftop_ops);
	return 0;
}
//exit module
static void __exit proj4_exit(void)
{
	remove_proc_entry("hello_proc", NULL);
}

module_init(proj3_init);
module_exit(proj3_exit);
