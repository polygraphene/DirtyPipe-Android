#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <net/inet_sock.h>
#include <linux/securebits.h>
#include <linux/user_namespace.h>
#include <linux/prctl.h>
#include <linux/security.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/lsm_hooks.h>
#include <linux/rcupdate.h>

struct ebitmap;

// Dummy
struct policydb {};

struct selinux_policy {
	struct sidtab *sidtab;
	// only need offset of policydb
	struct policydb policydb;
	//struct selinux_map map;
	//u32 latest_granting;
} __randomize_layout;

#define __POLICYDB_CAPABILITY_MAX 7
struct selinux_state {
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
	bool disabled;
#endif
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	bool enforcing;
#endif
	bool checkreqprot;
	bool initialized;
	bool policycap[__POLICYDB_CAPABILITY_MAX];
	bool android_netlink_route;
	bool android_netlink_getneigh;

	struct page *status_page;
	struct mutex status_lock;

	struct selinux_avc *avc;
	struct selinux_policy __rcu *policy;
	struct mutex policy_mutex;
} __randomize_layout;

struct task_security_struct {
	u32 osid;		/* SID prior to last execve */
	u32 sid;		/* current SID */
	u32 exec_sid;		/* exec SID */
	u32 create_sid;		/* fscreate SID */
	u32 keycreate_sid;	/* keycreate SID */
	u32 sockcreate_sid;	/* fscreate SID */
} __randomize_layout;

struct context {
	u32 user;
	u32 role;
	u32 type;
	u32 len;        /* length of string in bytes */
	//struct mls_range range;
	char range[48];
	char *str;	/* string representation if context cannot be mapped. */
};

struct sidtab_entry {
	u32 sid;
	u32 hash;
	struct context context;
#if CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE > 0
	struct sidtab_str_cache __rcu *cache;
#endif
	struct hlist_node list;
};


struct selinux_state *selinux_state_ = NULL;

int (*security_context_to_sid_)(struct selinux_state *state,
			    const char *scontext, u32 scontext_len,
			    u32 *out_sid, gfp_t gfp) = NULL;

int (*ebitmap_set_bit_)(struct ebitmap *e, unsigned long bit, int value) = NULL;
struct sidtab_entry *(*sidtab_search_entry_)(struct sidtab *s, u32 sid) = NULL;
struct lsm_blob_sizes *selinux_blob_sizes_ = NULL;

// https://github.com/c-sh0/lkm_ftrace_example/blob/main/inet_bind_mod.c

static int kallsyms_walk_callback(void *data, const char *name, struct module *mod, unsigned long addr) {
	if(mod) {
		return 0;
	}

	if(strcmp(name, "selinux_state") == 0) {
		selinux_state_ = (struct selinux_state *)addr;
	}else if(strcmp(name, "security_context_to_sid") == 0) {
		security_context_to_sid_ = (typeof(security_context_to_sid_))addr;
	}else if(strcmp(name, "selinux_blob_sizes") == 0) {
		selinux_blob_sizes_ = (struct lsm_blob_sizes *)addr;
	}else if(strcmp(name, "ebitmap_set_bit") == 0) {
		ebitmap_set_bit_ = (typeof(ebitmap_set_bit_))addr;
	}else if(strcmp(name, "sidtab_search_entry") == 0) {
		sidtab_search_entry_ = (typeof(sidtab_search_entry_))addr;
	}

	return 0;
}

static int __init mymod_init(void) {
	int rc = 0;

	pr_info("mymod_init: called!\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	static struct kprobe kp = {
		.symbol_name = "kallsyms_on_each_symbol"
	};

	typedef int (*kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
	kallsyms_on_each_symbol_t kallsyms_on_each_symbol;

	rc = register_kprobe(&kp);
	if(rc < 0) {
		pr_info("mymod_init: register_kprobe failed: %d\n", rc);
		return rc;
	}
	pr_info("mymod_init: register_kprobe: %d\n", rc);

	kallsyms_on_each_symbol = (kallsyms_on_each_symbol_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	pr_info("mymod_init: kallsyms_on_each_symbol : 0x%lx\n", (unsigned long)kallsyms_on_each_symbol);

	/* walk /proc/kallsyms */
	rc = kallsyms_on_each_symbol(kallsyms_walk_callback, NULL);
	pr_info("mymod_init: kallsyms_on_each_symbol returned: %d\n", rc);
	if(rc) {
	  	return rc;
	}

	/* if not found, exit with `Bad address` */
	if(selinux_state_ == NULL) {
		pr_info("mymod_init: real_selinux_state == NULL\n");
		return -EFAULT;
	}
#define USE_PERMISSIVE_DOMAIN
#ifdef USE_PERMISSIVE_DOMAIN
	if(selinux_blob_sizes_ == NULL){
		pr_info("mymod_init: selinux_blob_sizes = NULL");
	}else{
		// Set context of current process (u:r:vendor_modprobe:s0) to permissive.
		// Current process refers the process that is calling finit_module.
		const struct cred *cred = current->cred;
		if(cred == NULL){
			pr_info("mymod_init: cred == NULL");
			return -EFAULT;
		}
		if(cred->security == NULL){
			pr_info("mymod_init: cred->security == NULL");
			return -EFAULT;
		}
		if(ebitmap_set_bit_ == NULL){
			pr_info("mymod_init: ebitmap_set_bit_ == NULL");
			return -EFAULT;
		}
		if(sidtab_search_entry_ == NULL){
			pr_info("mymod_init: ebitmap_set_bit_ == NULL");
			return -EFAULT;
		}
		struct task_security_struct *tsec = cred->security + selinux_blob_sizes_->lbs_cred;
		pr_info("mymod_init: Set current sid (%d) to permissive.", tsec->sid);

		rcu_read_lock();
		struct selinux_policy *policy = rcu_dereference(selinux_state_->policy);

		struct sidtab_entry *entry = sidtab_search_entry_(policy->sidtab, tsec->sid);
		if(entry == NULL){
			pr_info("mymod_init: entry == NULL");
			rcu_read_unlock();
			return -EFAULT;
		}
		struct ebitmap *permissive = (struct ebitmap *)(((char*)&policy->policydb) + 560);
		ebitmap_set_bit_(permissive, entry->context.type, 1);

		rcu_read_unlock();
	}
#else
	// It will set whole system permissive. A bit unsecure, I think.
	pr_info("mymod_init: Setting selinux_state.enforcing=false. %lx %lx\n", (unsigned long)selinux_state_,
			(unsigned long)&selinux_state_->enforcing);
	bool old = READ_ONCE(selinux_state_->enforcing);
	pr_info("mymod_init: Current value of selinux_state.enforcing=%d\n", old);
	WRITE_ONCE(selinux_state_->enforcing, false);
	bool b = READ_ONCE(selinux_state_->enforcing);
	pr_info("mymod_init: New value of selinux_state.enforcing=%d\n", old);
#endif

	// It won't work because update_engine (permissive domain) doesn't exist before magisk policy patch.
	//rc = security_context_to_sid_(selinux_state_, "update_engine", strlen("update_engine"),
	//		&sid, GFP_KERNEL);
	//if(rc != 0){
	//	pr_info("mymod_init: failed to security_context_to_sid\n");
	//	return -ENOENT;
	//}else{
	//	struct cred *new;

	//	if(selinux_blob_sizes_ == NULL){
	//		pr_info("mymod_init: selinux_blob_sizes = NULL");
	//	}else{
	//		pr_info("mymod_init: Change sid %d", sid);
	//		struct task_security_struct *tsec = new->security + selinux_blob_sizes_->lbs_cred;
	//		tsec->sid = sid;
	//	}
	//}

	return -ENOMSG;
}


static void __exit mymod_exit(void)
{
	pr_info("mymod_exit: end\n");
}
module_init(mymod_init);
module_exit(mymod_exit);

MODULE_LICENSE("GPL v2");
__asm__(".space 32, 0\n");
