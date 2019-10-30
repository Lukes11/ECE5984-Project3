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
#define MAX_TRACE 2

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

static DEFINE_HASHTABLE(pidHashtable, 16);
//static DEFINE_SPINLOCK(my_lock);
//An entry in the hash table
struct hash_entry {

	u32 hash_key;
	int numSchedules;
	unsigned long *stack_trace;
	int space;
	unsigned long long currentTime;
	unsigned long long cumulativeTime;
	struct hlist_node hash_list;
};
//Create function pointer to stack_trace_save_user, since it's not an exported function
//Obtained the function address from /proc/kallsyms
static unsigned int (*stack_trace_save_user_p)(unsigned long *, unsigned int) = (unsigned int (*)(unsigned long*, unsigned int)) 0xffffffffae15e050;

//function and add and update PIDs in the hash table
void addPid(u32 stackTraceValue, unsigned long *stack_trace, int space_id, unsigned long long time)
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
			//Increment the number of schedules and update the current time
			if(current_hash_entry->hash_key == hash)
			{
				current_hash_entry->numSchedules++;
				current_hash_entry->currentTime = time;
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
		he->currentTime = time;
		he->cumulativeTime = 0;
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
	unsigned long *stackTrace = kmalloc(2*sizeof(unsigned long), GFP_ATOMIC);
	u32 stackTraceValue = 0;
	int i = 0;
	u32 pid;
	int bkt;
	struct hash_entry *current_hash_entry;
	unsigned long hash;


	//retrive current task, which is the second argument of pick_next_task_fair,
	//stored in rsi register by standard x86 64-bit calling convention
	if(regs->si)
	{
		//scheduled out task
		struct task_struct *p = (struct task_struct *)regs->si;
		if(p != NULL && p->pid)
		{	
			pid = p->pid;
			printk(KERN_INFO "SCHEDULED OUT PID: %d\n", pid);
			//kernel space task
			if(p->mm == NULL)
				stack_trace_save(stackTrace, MAX_TRACE, 0);
			else
				(*stack_trace_save_user_p)(stackTrace, MAX_TRACE);

			for(i = 0; i < MAX_TRACE; i++)
				stackTraceValue += stackTrace[i];

			stackTraceValue += pid;	
			hash = jhash(&stackTraceValue, sizeof(stackTraceValue), 0);	
			if(!hash_empty(pidHashtable))
			{
				hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
				{
					//Increment the number of schedules and update the current time
					if(current_hash_entry->hash_key == hash)
					{
						current_hash_entry->cumulativeTime += rdtsc() - current_hash_entry->currentTime;
						current_hash_entry->currentTime = 0;
						return 1;
					}
				}
			}

		}
	}

	return 0;
}
static int return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//scheduled in task
	struct task_struct *p = (struct task_struct *)regs_return_value(regs);
	u32 pid = p->pid;
	unsigned long *stackTrace = kmalloc(2*sizeof(unsigned long), GFP_ATOMIC);
	unsigned long long currentTime;
	int space_id;
	u32 stackTraceValue = 0;
	int i;

	printk(KERN_INFO "SCHEDULED OUT PID: %d\n", pid);
	if(p->mm == NULL)
	{
		stack_trace_save(stackTrace, MAX_TRACE, 0);
		space_id = 0;
	}	
	else
	{
		(*stack_trace_save_user_p)(stackTrace, MAX_TRACE);
		space_id = 1;
	}
	for(i = 0; i < MAX_TRACE; i++)
		stackTraceValue += stackTrace[i];

	stackTraceValue += pid;
	currentTime = rdtsc();
	addPid(stackTraceValue, stackTrace, space_id, currentTime);
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
	.handler 		= return_handler,
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
