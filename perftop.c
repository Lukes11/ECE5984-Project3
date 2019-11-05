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
#define MAX_TRACE 2
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Sanyour");
MODULE_DESCRIPTION("Project 3 Perftop");

static DEFINE_HASHTABLE(pidHashtable, 16);
//An entry in the hash table
//space = user or kernel, 0 for kernel, 1 for user
//current time, time stamp when schedueld int
//cumulative time, total time spent on by CPU
struct hash_entry {

	unsigned long hash_key;
	int numSchedules;
	unsigned long *stack_trace;
	int space;
	unsigned long inTime;
	unsigned long long cumulativeTime;
	struct hlist_node hash_list;
};
//defind red-black tree
struct my_rb_tree {
	struct rb_root root_node;
};
static struct my_rb_tree tree;
//an entry into an rb tree
struct rbEntry {

	unsigned long long cumulativeTime;
	unsigned long* stack_trace;
	unsigned long hash;
	struct rb_node node;
};

//Create function pointer to stack_trace_save_user, since it's not an exported function
//Obtained the function address from /proc/kallsyms
static unsigned int (*stack_trace_save_user_p)(unsigned long *, unsigned int) = NULL; 

//function to insert a value into the rb tree
void rb_insert_entry(struct my_rb_tree *root, struct rbEntry *en)
{
	struct rb_node **link = &(root->root_node.rb_node);
	struct rb_node *parent = NULL;
	struct rbEntry *entry;
	while(*link)
	{
		parent = *link;
		entry = rb_entry(parent, struct rbEntry, node);
		if(en->cumulativeTime > entry->cumulativeTime)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&en->node, parent, link);
	rb_insert_color(&en->node, &root->root_node);
}
//function and add and update PIDs in the hash table
//space_id = 0 for kernel, 1 for user
//curr_time = current time from rdtsc() when scheduled in
//direction = scheduled in/out, 0 for in, 1 for out
void addPid(unsigned long stackTraceValue, unsigned long *stack_trace, int space_id, unsigned long long curr_time)
{	
	int bkt;
	struct hash_entry *current_hash_entry;
	struct hash_entry *he = kmalloc(sizeof(*he), GFP_ATOMIC);
	struct rbEntry *rb = kmalloc(sizeof(*rb), GFP_ATOMIC);
	struct rb_node *node;
	static unsigned long currentHash = 0;
	static int entries = 0;
	unsigned long  hash = 0;
	bool found = false;
	bool timeUpdate = false;
	//hash the stack trace and PID value
	hash = jhash(&stackTraceValue, sizeof(stackTraceValue), 0);
	//hash = stackTraceValue;
	//check if PID is in hash table and update
	if(!hash_empty(pidHashtable))
	{
		hash_for_each(pidHashtable, bkt, current_hash_entry, hash_list)
		{
			//Increment the number of schedules and update the current time
			if(current_hash_entry->hash_key == hash)
			{
				current_hash_entry->numSchedules++;
				current_hash_entry->inTime = curr_time;
				found = true;
			}
			if(current_hash_entry->hash_key == currentHash)
			{
				current_hash_entry->cumulativeTime += curr_time - current_hash_entry->inTime;
				current_hash_entry->inTime = 0;
				rb->cumulativeTime = current_hash_entry->cumulativeTime;
				rb->stack_trace = current_hash_entry->stack_trace; 
				rb->hash = currentHash;
				timeUpdate = true;
			}
		}
	}	
	if(timeUpdate)
	{
		for(node = rb_first(&(tree.root_node)); node; node = rb_next(node))
		{

			if(rb_entry(node, struct rbEntry, node)->hash == currentHash)
			{
				rb_erase(node, &(tree.root_node));
				break;
			}

		}
		rb_insert_entry(&tree, rb);
	}
	currentHash = hash;
	if(found) 
		return;

	//otherwise, add it to the hash table and to the rb tree
	if(he != NULL && rb != NULL && !timeUpdate)
	{
		he->hash_key = hash;
		he->numSchedules = 1;
		he->stack_trace = stack_trace;
		he->space = space_id;
		he->inTime = curr_time;
		he->cumulativeTime = 0;
		rb->cumulativeTime = ++entries;
		rb->stack_trace = stack_trace; 
		rb->hash = hash;
		rb_insert_entry(&tree, rb);
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
//function to delete rb tree
void deleteRBTree(void)
{
	struct rb_node *node;
	for (node = rb_last(&(tree.root_node)); node; node = rb_prev(node))
	{
		rb_erase(node, &(tree.root_node));
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
				stackTraceValue += pid;
				stackTraceValue += stackTrace[0] + stackTrace[1];
				currentTime = rdtsc();
				addPid(stackTraceValue, stackTrace, space_id, currentTime);
			}
			//user task
			else 
			{				
				/*
				   (*stack_trace_save_user_p)(stackTrace, MAX_TRACE);
				   space_id = 1;
				   */

			}
		}
	}
	return 0;
}

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
	deleteRBTree();
	//un-register KProbe
	unregister_kretprobe(&perftop_kretprobe);
	//delete proc File
	remove_proc_entry("perftop", NULL);
}

module_init(proj3_init);
module_exit(proj3_exit);
