#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/jhash.h>
#include <linux/stacktrace.h>
#include <linux/kallsyms.h>
#define MAX_TRACE 10

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

static DEFINE_HASHTABLE(pidHashtable, 16);
//static DEFINE_SPINLOCK(my_lock);
//An entry in the hash table
struct hash_entry {

	u32 hash_key;
	int numSchedules;
	struct hlist_node hash_list;
	unsigned long *stack_trace;
	int space;
};
//using kallsyms to get save_stack_trace_user symbol
unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
typedef typeof(&stack_trace_save_user) stack_trace_save_user_fn;
#define stack_trace_save_user (* (stack_trace_save_user_fn)kallsyms_stack_trace_save_user)
void *kallsyms_stack_trace_save_user = NULL;

//function and add and update PIDs in the hash table
void addPid(u32 stackTraceValue, unsigned long *stack_trace, int space_id)
{	
	int bkt;
	struct hash_entry *current_hash_entry;
	struct hash_entry *he = kmalloc(sizeof(*he), GFP_ATOMIC);
	u32 hash;
	//hash the stack trace and PID value
	printk(KERN_INFO "Attempting to hash\n");
	hash = jhash(&stackTraceValue, sizeof(stackTraceValue), 0);	
	printk(KERN_INFO "Hash: %d\n", hash);
	//check if PID is in hash table and update
	if(!hash_empty(pidHashtable))
	{
		hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
		{
			if(current_hash_entry->hash_key == hash)
			{
				current_hash_entry->numSchedules++;
				return;
			}
		}
	}
	//otherwise, add it to the hash table
	if(he != NULL)
	{
		he->hash_key = hash;
		he->numSchedules = 1;
		he->stack_trace = stack_trace;
		he->space = space_id;
		hash_add(pidHashtable, &he->hash_list, hash);
	}
}
//function to delete the PID hash table
void deleteHashTable(void)
{
	int bkt;
	struct hash_entry *current_hash_entry;
	hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
	{
		hash_del(&current_hash_entry->hash_list);
	}
}
//entry handler for Kretprobe
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long *stackTrace = kmalloc(15*sizeof(unsigned long), GFP_ATOMIC);
	u32 stackTraceValue = 0;
	int i = 0;
	u32 pid;
	int entries;
	int space_id;

	//retrive current task, which is the second argument of pick_next_task_fair,
	//stored in rsi register by standard x86 64-bit calling convention
	if(regs->si)
	{
		struct task_struct *p = (struct task_struct *)regs->si;
		if(p != NULL && p->pid)
		{	
			pid = p->pid;
			printk(KERN_INFO "PID: %d\n", pid);
			//kernel space task
			if(p->mm == NULL)
			{
				entries = stack_trace_save(stackTrace, MAX_TRACE, 0);
				space_id= 0;
			}		
			//convert the stack trace into a usable value
			else
			{
				entries = kallsyms_stack_trace_save_user(stackTrace, MAX_TRACE);
				space_id = 1;
			}

			for(i = 0; i < MAX_TRACE; i++)
				stackTraceValue += stackTrace[i];

			printk(KERN_INFO "Stack Trace Value: %d\n", stackTraceValue);

			stackTraceValue += pid;
			addPid(stackTraceValue, stackTrace, space_id);
		}
	}

	return 0;
}
//create proc file
static int perftop_show(struct seq_file *m, void *v) {
	int bkt;
	int i = 0;
	struct hash_entry *current_hash_entry;	
	unsigned long *current_stack_trace;
	int process_num = 1;
	hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
	{
		current_stack_trace = current_hash_entry->stack_trace;
		seq_printf(m, "===Process # %d=== \n", process_num);
		if(current_hash_entry->space)
			seq_printf(m, "KERNEL TASK\n");
		if(!current_hash_entry->space)
			seq_printf(m, "USER TASK\n");

		seq_printf(m, "Stack Trace: \n");
		for(i = 0; i < MAX_TRACE; i++)
		{
			seq_printf(m, "%lx\n", current_stack_trace[i]);
		}	
		seq_printf(m, "# Of Schedules: %d\n ", current_hash_entry->numSchedules);
		process_num++;
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
	kallsyms_stack_trace_save_user = (void*)kallsyms_lookup_name("stack_trace_save_user");
	//register KProbe
	ret = register_kretprobe(&perftop_kretprobe);
	//create Proc File "perftop"
	proc_create("perftop", 0, NULL, &perftop_fops);
	return 0;
}
//exit module
static void __exit proj3_exit(void)
{
	//delete hash table
	deleteHashTable();
	//un-register KProbe
	unregister_kretprobe(&perftop_kretprobe);
	//delete proc File
	remove_proc_entry("perftop", NULL);
}

module_init(proj3_init);
module_exit(proj3_exit);
