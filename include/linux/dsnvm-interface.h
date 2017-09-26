#define DSNVM_BEGIN_XACT_FLAG 8
#define DSNVM_COMMIT_XACT_FLAG 16
#define DSNVM_BEGIN_XACT_SINGLE_FLAG 32
#define DSNVM_COMMIT_XACT_SINGLE_FLAG 64

struct dsnvm_apis {
	int (*begin_or_commit_xact_user)(unsigned long start, size_t len, int if_begin_xact);
	int (*begin_or_commit_xact_user_single)(unsigned long start, size_t len, int if_begin_xact);
};

extern struct dsnvm_apis *dsnvmapi;

void dsnvm_reg_begin_or_commit_xact_user(void *funcptr);
void dsnvm_reg_begin_or_commit_xact_user_single(void *funcptr);
