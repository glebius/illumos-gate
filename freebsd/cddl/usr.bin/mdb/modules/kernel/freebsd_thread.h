/*-
 * XXX: License.
 */

#ifndef _MDB_KERNEL_THREAD_H_
#define _MDB_KERNEL_THREAD_H_

enum mdb_kthread_states {
	TS_NEW,			/* PRS_NEW */
	TS_RUNNING,		/* PRS_NORMAL, td_state */
	TS_RUNQ,
	TS_CAN_RUN,
	TS_INACTIVE,
	TS_INHIBITED,
	TS_ZOMBIE,		/* PRS_ZOMBIE */
	TS_FREE			/* unused */
};

void thread_state_to_text(uint_t, char *, size_t);
int thread_text_to_state(const char *, uint_t *);
void thread_walk_states(void (*)(uint_t, const char *, void *), void *);

#endif /* !_MDB_KERNEL_THREAD_H_ */
