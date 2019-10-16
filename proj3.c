#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

static DEFINE_HASHTABLE(pidHashtable, 16);
struct hash_entry {

	int pid_key;
	int numSchedules;
	struct hlist_node hash_list;
};
void addPid(int pid)
{	
	int bkt;
	struct hash_entry *current_hash_entry;
	struct hash_entry *he = kmalloc(sizeof(*he), GFP_ATOMIC);
	if(!hash_empty(pidHashtable))
	{
		hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
		{
			if(current_hash_entry->pid_key == pid)
			{
				current_hash_entry->numSchedules++;
				//printk(KERN_INFO "NumSched: %d\n", current_hash_entry->numSchedules);
				return;
			}
		}
	}

	if(he != NULL)
	{
		he->pid_key = pid;
		he->numSchedules = 1;
		hash_add(pidHashtable, &he->hash_list, pid);
	}

}
void deleteHashTable(void)
{
	int bkt;
	struct hash_entry *current_hash_entry;
	hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
	{
		hash_del(&current_hash_entry->hash_list);
	}
}
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//retrive current task, which is the second argument of pick_next_task_fair,
	//stored in rsi register by standard x86 64-bit calling convention
	if(regs->si)
	{
		struct task_struct *p = (struct task_struct *)regs->si;
		if(p != NULL && p->pid)
		{	
			addPid(p->pid);
		}
	}
	return 0;
}
//create proc file
static int perftop_show(struct seq_file *m, void *v) {
	int bkt;
	struct hash_entry *current_hash_entry;	
	hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
	{
		seq_printf(m, "PID: %d      # Of Schedules: %d\n ", current_hash_entry->pid_key, current_hash_entry->numSchedules);
	}
	return 0;

}

static int perftop_open(struct inode *inode, struct  file *file) {
	return single_open(file, perftop_show, NULL);
}
static struct kretprobe perftop_kretprobe = {
	.entry_handler 		= entry_handler,
	.kp.symbol_name = "pick_next_task_fair",
	.maxactive = 1,

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
	ret = register_kretprobe(&perftop_kretprobe);
	proc_create("perftop", 0, NULL, &perftop_fops);
	return 0;
}
//exit module
static void __exit proj3_exit(void)
{
	//delete hash table
	deleteHashTable();
	unregister_kretprobe(&perftop_kretprobe);
	remove_proc_entry("perftop", NULL);
}

module_init(proj3_init);
module_exit(proj3_exit);
