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

static int __init mymod_init(void) {
	
	int rc = 0;
	struct selinux_state *selinux_state_ = NULL;

	pr_info("mymod_init: called!\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	
	kallsyms_lookup_name_t kallsyms_lookup_name = NULL;
	
	static struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name"
	};
	rc = register_kprobe(&kp);
	if(rc < 0) {
		pr_info("mymod_init: register_kprobe failed: %d\n", rc);
		return rc;
	}
	pr_info("mymod_init: register_kprobe: %d\n", rc);

	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	selinux_state_ = (typeof(selinux_state_))kallsyms_lookup_name("selinux_state");
	// if not found, exit with `Bad address`
	if(selinux_state_ == NULL) {
		pr_info("mymod_init: real_selinux_state == NULL\n");
		return -EFAULT;
	}
#define USE_PERMISSIVE_DOMAIN
#ifdef USE_PERMISSIVE_DOMAIN
	int (*ebitmap_set_bit_)(struct ebitmap *e, unsigned long bit, int value) = NULL;
	struct sidtab_entry *(*sidtab_search_entry_)(struct sidtab *s, u32 sid) = NULL;
	struct lsm_blob_sizes *selinux_blob_sizes_ = NULL;
	
	selinux_blob_sizes_ = (typeof(selinux_blob_sizes_))kallsyms_lookup_name("selinux_blob_sizes");
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
		ebitmap_set_bit_ = (typeof(ebitmap_set_bit_))kallsyms_lookup_name("ebitmap_set_bit");
		if(ebitmap_set_bit_ == NULL){
			pr_info("mymod_init: ebitmap_set_bit_ == NULL");
			return -EFAULT;
		}
		sidtab_search_entry_ = (typeof(sidtab_search_entry_))kallsyms_lookup_name("sidtab_search_entry");
		if(sidtab_search_entry_ == NULL){
			pr_info("mymod_init: sidtab_search_entry_ == NULL");
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
	bool enforcing_status = READ_ONCE(selinux_state_->enforcing);
	pr_info("mymod_init: Current value of selinux_state.enforcing=%d\n", enforcing_status);
	WRITE_ONCE(selinux_state_->enforcing, false);
	enforcing_status = READ_ONCE(selinux_state_->enforcing);
	pr_info("mymod_init: New value of selinux_state.enforcing=%d\n", enforcing_status);
#endif

	//int (*security_context_to_sid_)(struct selinux_state *state,
	//		    const char *scontext, u32 scontext_len,
	//		    u32 *out_sid, gfp_t gfp) = NULL;
	// It won't work because update_engine (permissive domain) doesn't exist before magisk policy patch.
	//security_context_to_sid_ = (typeof(security_context_to_sid_))kallsyms_lookup_name("security_context_to_sid");
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

