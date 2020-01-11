#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/ptrace.h>
#include <linux/stacktrace.h>
#include <linux/jhash.h>
#include <linux/kallsyms.h>


extern unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
typedef typeof(&stack_trace_save_user) stack_trace_save_user_fn;
#define stack_trace_save_user (* (stack_trace_save_user_fn)kallsyms_stack_trace_save_user)
void *kallsyms_stack_trace_save_user = NULL;

static DEFINE_SPINLOCK(hash_sp_lock);

#define MAX_TRACE_SIZE 16
#define HASHTABLE_SIZE 10
#define JHASH_INITVAL 0xdeadbeef


// Red Black Tree Data Structure

struct rb_root the_root = RB_ROOT;

struct rb_struct
{
	int val;
	int schedule_counter;
	unsigned long timestamp;
	unsigned long hash_key;
	unsigned long stack_trace[MAX_TRACE_SIZE];
	int stack_trace_length;
	unsigned long pid;
	struct rb_node node_pointer;
};


static DEFINE_HASHTABLE(kprobe_hashtable, HASHTABLE_SIZE);

struct hash_entries
{
	int schedule_counter;
	unsigned long timestamp;
	unsigned long hash_key;
	unsigned long stack_trace[MAX_TRACE_SIZE];
	int stack_trace_length;
	unsigned long pid;
	struct hlist_node hash_address;
};

// Stores the values in a hashtable whereas the key is generated using jenkin's hash and value is counter for the first part
// And for the second part the value is time spent by a process on CPU
static int store_stack_trace_in_hashtable(unsigned long key, unsigned long *stack_trace_start_ptr, int stack_trace_length, unsigned long pid, unsigned long current_timestamp)
{
	struct hash_entries* hash_element;
	int i=0;

	hash_for_each_possible(kprobe_hashtable, hash_element, hash_address, key)
	{
		if(hash_element != NULL)
		{
			hash_element->schedule_counter += 1;
			hash_element->timestamp = current_timestamp;
			
			return 0;
		}
	}	
	
	hash_element = kmalloc(sizeof(struct hash_entries), GFP_ATOMIC);
	if(hash_element == NULL)
		return -ENOMEM;
	
	hash_element->schedule_counter = 1;
	hash_element->timestamp = current_timestamp;
	
	for(i=0; i<stack_trace_length; i++)
	{
		hash_element->stack_trace[i] = *stack_trace_start_ptr;
		stack_trace_start_ptr++;
	}

	hash_element->pid = pid;
	hash_element->stack_trace_length = stack_trace_length;
	hash_element->hash_key = key;
	hash_add(kprobe_hashtable, &hash_element->hash_address, key);
	
	return 0;
}

// Stores the value in RB tree according to the total time spent on CPU along with stack trace and PID for that particular process
// If the process already exists in the RB tree, the program stores the timestamp and delets the node, adds the current timestamo to the previous timestamp
// Then adds the new node with according to the total time spent
static int store_stack_trace_in_redblack_tree(struct rb_root *root, unsigned long jhash_key, unsigned long *stack_trace_start_ptr, int stack_trace_length, unsigned long pid, unsigned long current_timestamp)
{
	struct rb_struct *rb_element;
	struct rb_node *current_element;
	struct rb_node **link = &root->rb_node, *parent = NULL;
	unsigned long previous_timestamp = 0;
	struct rb_struct *next_rb_element; 
	int i = 0;

	current_element = rb_first(&the_root);

	while(current_element)
	{
		rb_element = rb_entry(current_element, struct rb_struct, node_pointer);

		if(rb_element->hash_key == jhash_key)
		{
			previous_timestamp = rb_element->timestamp;
			rb_erase(&rb_element->node_pointer, &the_root);
			kfree(rb_element);
			break;
		}

		current_element = rb_next(current_element);
	}

	rb_element = kmalloc(sizeof(struct rb_struct), GFP_ATOMIC);
	rb_element->timestamp = current_timestamp + previous_timestamp;
	for(i=0; i<stack_trace_length; i++)
	{
		rb_element->stack_trace[i] = *stack_trace_start_ptr;
		stack_trace_start_ptr++;
	}
	rb_element->pid = pid;
	rb_element->hash_key = jhash_key;
	rb_element->stack_trace_length = stack_trace_length;

	while(*link)
	{
		parent = *link;
		next_rb_element = rb_entry(parent, struct rb_struct, node_pointer);

		if(next_rb_element->timestamp < rb_element->timestamp)
		{
			link = &(*link)->rb_right;
		}
		else
		{
			link = &(*link)->rb_left;
		}
	}

	rb_link_node(&rb_element->node_pointer, parent, link);
	rb_insert_color(&rb_element->node_pointer, root);
	return 0;
}

static int perftop_proc_show(struct seq_file *m, void *v) 
{
	// Prints top 20 tasks that spent max time on CPU using RB tree
	struct rb_struct *rb_element;
	struct rb_node *current_node;
	int i = 0;
	int j = 0;

	current_node = rb_last(&the_root);

	for(i=0; i<20;i++)
	{
		if(current_node == NULL)
		{
			seq_printf(m, "End of the Red Black Tree\n");
			break;
		}
	
		rb_element = rb_entry(current_node, struct rb_struct, node_pointer);
		seq_printf(m, "Rank:%d, Funtion Name:\n", i+1);
		for(j=0; j<rb_element->stack_trace_length; j++)
		{
			//seq_printf(m, "0x%p, ", (void *)rb_element->stack_trace[j]);
			seq_printf(m, "\t%pS\n", (void *)rb_element->stack_trace[j]);
		}
		seq_printf(m, "Time spent on CPU: %ld\n\n", rb_element->timestamp);
		current_node = rb_prev(current_node);
	}
	

	// Prints hashtable to perftop file in proc
	/*
	struct hash_entries* hash_element;
	int bkt;

	hash_for_each(kprobe_hashtable, bkt, hash_element, hash_address)
	{
		int i=0;
		//seq_printf(m, "PID: %ld, Stack Trace: ", hash_element->pid);
		seq_printf(m, "Stack Trace: ");
		for(i=0; i<hash_element->stack_trace_length; i++)
		{
			seq_printf(m, "0x%p, ", (void *)hash_element->stack_trace[i]);
		}
		//seq_printf(m, ", Time Spent on CPU: %ld \n", hash_element->timestamp);
		seq_printf(m,", Counter: %d\n", hash_element->schedule_counter);
		
  	}
	*/

	return 0;
}

static int perftop_proc_open(struct inode *inode, struct  file *file) {
  	return single_open(file, perftop_proc_show, NULL);
}

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	
	unsigned long temp = regs->si;
	unsigned long flag;
	struct task_struct *current_task = (struct task_struct*)temp;
	
	unsigned int trace_length;
	unsigned long trace_start_pointer[MAX_TRACE_SIZE];
	u32 jhash_element;
	u32 init_val = 0;
	unsigned long start_timestamp;
	unsigned long total_time_spent;
	
	spin_lock_irqsave(&hash_sp_lock, flag);	// Acquires the spin lock
	if(current_task->mm == NULL)	// Taking mm to check wether it is a kernel invocation or user space invocation
	{
		trace_length = stack_trace_save(&trace_start_pointer[1], MAX_TRACE_SIZE-1, 0);
	}
	else // User space invocation
	{
		trace_length = stack_trace_save_user(&trace_start_pointer[1], MAX_TRACE_SIZE-1);
	}

	start_timestamp = (unsigned long)ri->data;
	total_time_spent = rdtsc() - start_timestamp;

	trace_start_pointer[0] = current_task->pid;
	jhash_element = jhash((u32*)trace_start_pointer, (trace_length+1)*2, init_val);
	store_stack_trace_in_hashtable(jhash_element, &trace_start_pointer[1], trace_length, current_task->pid, total_time_spent);
	
	store_stack_trace_in_redblack_tree(&the_root, jhash_element, &trace_start_pointer[1], trace_length, current_task->pid, total_time_spent);
	
	spin_unlock_irqrestore(&hash_sp_lock, flag);	// Releases the spin lock
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long start_timestamp;
	start_timestamp = (unsigned  long)ri->data;
	start_timestamp = rdtsc();
	return 0;
}

static const struct file_operations perftop_proc_fops = {
	.owner = THIS_MODULE,
  	.open = perftop_proc_open,
  	.read = seq_read,
  	.llseek = seq_lseek,
  	.release = single_release,
};

static struct kretprobe perftop_kretprobe = {
	.handler = ret_handler,
	.entry_handler = entry_handler,
	//.data_size = sizeof(unsigned int),
	.data_size = sizeof(unsigned long),
	/* Probe up to 20 instances concurrently. */
	.maxactive = 20,
};

static int __init kretprobe_init(void)
{
	int ret;
	
	//perftop_kretprobe.kp.symbol_name = "perftop_proc_show";
	perftop_kretprobe.kp.symbol_name = "pick_next_task_fair";

//	function init() 
	//kallsyms_save_stack_trace_user = (void*)kallsyms_lookup_name(save_stack_trace_user);
	kallsyms_stack_trace_save_user = (void *)kallsyms_lookup_name("stack_trace_save_user");
	

	ret = register_kretprobe(&perftop_kretprobe);
	if(ret < 0)
	{
		return -1;
	}

  	proc_create("perftop", 0, NULL, &perftop_proc_fops);
  	return 0;
}

static void __exit kretprobe_exit(void)
{
	unregister_kretprobe(&perftop_kretprobe);

  	remove_proc_entry("perftop", NULL);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("shaunakm");
MODULE_DESCRIPTION("LKP Project 3");

module_init(kretprobe_init);
module_exit(kretprobe_exit);
