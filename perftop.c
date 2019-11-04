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
#include <linux/spinlock.h>
#define MAX_TRACE 1

#define MASK_1 0x0000000000000000
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

static DEFINE_HASHTABLE(pidHashtable, 16);
//static DEFINE_SPINLOCK(my_lock);
//An entry in the hash table
//space = user or kernel, 0 for kernel, 1 for user
//current time, time stamp when schedueld int
//cumulative time, total time spent on by CPU
struct hash_entry {

	unsigned long hash_key;
	int numSchedules;
	unsigned long *stack_trace;
	int space;
	unsigned long long currentTime;
	unsigned long long cumulativeTime;
	struct hlist_node hash_list;
};
//Create function pointer to stack_trace_save_user, since it's not an exported function
//Obtained the function address from /proc/kallsyms
static unsigned int (*stack_trace_save_user_p)(unsigned long *, unsigned int) = NULL; 

//function and add and update PIDs in the hash table
//space_id = 0 for kernel, 1 for user
//curr_time = current time from rdtsc() when scheduled in
//direction = scheduled in/out, 0 for in, 1 for out
void addPid(unsigned long stackTraceValue, unsigned long *stack_trace, int space_id, unsigned long long curr_time, int direction)
{	
	int bkt;
	struct hash_entry *current_hash_entry;
	struct hash_entry *he = kmalloc(sizeof(*he), GFP_ATOMIC);
	unsigned long  hash;
	//hash the stack trace and PID value
	//hash = jhash(&stackTraceValue, sizeof(stackTraceValue), 0);
	hash = stackTraceValue;
	//check if PID is in hash table and update
	if(!hash_empty(pidHashtable))
	{
		hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
		{
			//Increment the number of schedules and update the current time
			if(current_hash_entry->hash_key == hash)
			{
				if(direction)
				{
					current_hash_entry->currentTime = curr_time;
					current_hash_entry->numSchedules++;
				}
				/*
				if(direction)
				{
					current_hash_entry->cumulativeTime += rdtsc() - current_hash_entry->currentTime;
					current_hash_entry->currentTime = 0;
				}
				*/
				return;
			}
		}
	}
	//otherwise, add it to the hash table
	if(he != NULL && direction == 1)
	{
		he->hash_key = hash;
		he->numSchedules = 1;
		he->stack_trace = stack_trace;
		he->space = space_id;
		he->currentTime = curr_time;
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
	unsigned long *stackTrace = kmalloc(15*sizeof(unsigned long), GFP_ATOMIC);
	unsigned long stackTraceValue = 0;
	u32 pid;
	unsigned long long currentTime;
	int space_id;
	

	//retrive current task, which is the second argument of pick_next_task_fair,
	//stored in rsi register by standard x86 64-bit calling convention
	if(regs->si)
	{
		//scheduled out task, previous task, second argmument of pick_next_task_fair
		struct task_struct *p = (struct task_struct *)regs->si;
		if(p != NULL && p->pid)
		{	
			pid = p->pid;
			//kernel space task
			if(p->mm == NULL)
			{
				stack_trace_save(stackTrace, MAX_TRACE, 0);
				space_id = 0;
				//dovetail 2 element stack trace to combine
				stackTraceValue += pid;
				stackTraceValue += stackTrace[0];
				currentTime = rdtsc();
				addPid(stackTraceValue, stackTrace, space_id, currentTime, 1);
				printk(KERN_INFO "PID: %u\nSTACKT1: %lu\nSTACKT2:%lu\nSTACKVAL: %lu\n", pid,stackTrace[0], stackTrace[1],  stackTraceValue);
			}
			//user task
			/*
			else 
			{				
				(*stack_trace_save_user_p)(stackTrace, MAX_TRACE);
				space_id = 1;

			}
			*/
			//dovetail 2 element stack trace to combine
			//addPid(stackTraceValue, stackTrace, space_id, currentTime, 1);
		}
	}
	return 0;
}
/*
static int return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//scheduled in task, result of pick_next_task_fair
	struct task_struct *p = (struct task_struct *)regs_return_value(regs);
	u32 pid;
	unsigned long *stackTrace;
	unsigned long long currentTime;
	int space_id;
	unsigned long stackTraceValue = 0;
	if(p != NULL && p->pid)
	{
		pid = p->pid;
		stackTrace = kmalloc(15*sizeof(unsigned long), GFP_ATOMIC);
		//kernel task
		if(p->mm == NULL)
		{
			stack_trace_save(stackTrace, MAX_TRACE, 0);
			space_id = 0;
		}
		//user task
		else
		{
			(*stack_trace_save_user_p)(stackTrace, MAX_TRACE);
			space_id = 1;
		}

		//dovetail 2 element stack trace to combine
		stackTraceValue = (((stackTrace[0] + stackTrace[1]) * (stackTrace[0] + stackTrace[1] + 1)) / 2) + stackTrace[1]; 
		stackTraceValue += pid;
		currentTime = rdtsc();
		addPid(stackTraceValue, stackTrace, space_id, currentTime, 0);
	}
	return 0;

}
*/
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

		if(!current_hash_entry->space)
			seq_printf(m, "KERNEL TASK\n");
		if(current_hash_entry->space)
			seq_printf(m, "USER TASK\n");
		seq_printf(m, "Stack Trace: \n");
		for(i = 0; i < MAX_TRACE; i++)
		{
			seq_printf(m, "%lx\n", current_stack_trace[i]);
		}	
		seq_printf(m, "# Of Schedules: %d\n ", current_hash_entry->numSchedules);
		seq_printf(m, "Cumulative Time: %llu\n", current_hash_entry->cumulativeTime);
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
	stack_trace_save_user_p = (unsigned int (*)(unsigned long*, unsigned int))kallsyms_lookup_name("stack_trace_save_user");
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
