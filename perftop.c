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
	unsigned long inTime;
	unsigned long long cumulativeTime;
	char* name;
	int pid;
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
	char* name;
	int pid;
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
//function and add and update PIDs in the hash table and red black tree
void addPid(unsigned long stackTraceValue, unsigned long *stack_trace, unsigned long long curr_time, int pid, char* name)
{	
	struct hash_entry *current_hash_entry;
	struct hash_entry *he = kmalloc(sizeof(*he), GFP_ATOMIC);
	struct rbEntry *rb = kmalloc(sizeof(*rb), GFP_ATOMIC);
	struct rb_node *node;
	static unsigned long currentHash = 0;
	unsigned long  hash = 0;
	bool found = false;
	bool timeUpdate = false;
	int bkt;
	//hash the stack trace and PID value
	hash = jhash(&stackTraceValue, sizeof(stackTraceValue), 0);
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
			//update cumulative time for previous task, and create rb tree entry
			if(current_hash_entry->hash_key == currentHash)
			{
				current_hash_entry->cumulativeTime += curr_time - current_hash_entry->inTime;
				current_hash_entry->inTime = 0;
				rb->cumulativeTime = current_hash_entry->cumulativeTime;
				rb->stack_trace = current_hash_entry->stack_trace; 
				rb->pid = current_hash_entry->pid;
				rb->name = current_hash_entry->name;
				rb->hash = currentHash;
				timeUpdate = true;
			}
		}
	}	
	//if a cumulative time entry has been changed, update the red black tree
	if(timeUpdate)
	{
		//erase old entry
		for(node = rb_first(&(tree.root_node)); node; node = rb_next(node))
		{

			if(rb_entry(node, struct rbEntry, node)->hash == currentHash)
			{
				rb_erase(node, &(tree.root_node));
				break;
			}

		}
		//insert new entry
		rb_insert_entry(&tree, rb);
	}
	currentHash = hash;
	if(found) 
		return;

	//if not in hash table, add it to the hash table and to the rb tree
	if(he != NULL && rb != NULL && !timeUpdate)
	{
		he->hash_key = hash;
		he->numSchedules = 1;
		he->stack_trace = stack_trace;
		he->inTime = curr_time;
		he->pid = pid;
		he->name = name;
		he->cumulativeTime = 0;
		rb->cumulativeTime = 0;
		rb->stack_trace = stack_trace; 
		rb->hash = hash;
		rb->name = name;
		rb->pid = pid;
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
				stack_trace_save(stackTrace, MAX_TRACE, 0);
			//user task
			else 
				(*stack_trace_save_user_p)(stackTrace, MAX_TRACE);

			//get a single value from stack trace and pid to pass to hashing function
			stackTraceValue += pid;
			stackTraceValue += stackTrace[0] + stackTrace[1];
			//get current time stamp
			currentTime = rdtsc();
			addPid(stackTraceValue, stackTrace, currentTime, pid, p->comm);
		}
	}
	return 0;
}

static int perftop_show(struct seq_file *m, void *v) {
	struct rb_node *node;
	int i = 1;
	struct rbEntry *currentEntry;
	//display 20 tasks with greatest cumulative time
	for (node = rb_first(&(tree.root_node)); node; node = rb_next(node))
	{
		currentEntry = rb_entry(node, struct rbEntry, node);
		seq_printf(m, "-----------------------------------------\n");
		seq_printf(m, "Task #: %d\n", i);
		seq_printf(m, "PID: %d  NAME: %s\n", currentEntry->pid, currentEntry->name);
		seq_printf(m, "Cumulative Time: %llu\n", currentEntry->cumulativeTime);
		seq_printf(m, "===Stack Trace===\n");
		seq_printf(m, "%*c%pS\n", 2, ' ', (void*)currentEntry->stack_trace[0]);
		seq_printf(m, "%*c%pS\n", 2, ' ', (void*)currentEntry->stack_trace[1]);
		if(i == 20)
			break;
		i++;
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
	//setup function pointer for stack_trace_save_user
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
	//delete red black tree
	deleteRBTree();
	//un-register KProbe
	unregister_kretprobe(&perftop_kretprobe);
	//delete proc File
	remove_proc_entry("perftop", NULL);
}

module_init(proj3_init);
module_exit(proj3_exit);
