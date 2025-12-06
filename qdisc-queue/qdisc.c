
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "dropreason-core.h"


#define TCQ_F_BUILTIN		1
#define TCQ_F_INGRESS		2
#define TCQ_F_CAN_BYPASS	4
#define TCQ_F_MQROOT		8
#define TCQ_F_ONETXQUEUE	0x10 /* dequeue_skb() can assume all skbs are for
				      * q->dev_queue : It can test
				      * netif_xmit_frozen_or_stopped() before
				      * dequeueing next packet.
				      * Its true for MQ/MQPRIO slaves, or non
				      * multiqueue device.
				      */
#define TCQ_F_WARN_NONWC	(1 << 16)
#define TCQ_F_CPUSTATS		0x20 /* run using percpu statistics */
#define TCQ_F_NOPARENT		0x40 /* root of its hierarchy :
				      * qdisc_tree_decrease_qlen() should stop.
				      */
#define TCQ_F_INVISIBLE		0x80 /* invisible by default in dump */
#define TCQ_F_NOLOCK		0x100 /* qdisc does not require locking */
#define TCQ_F_OFFLOADED		0x200 /* qdisc is offloaded to HW */

/* qdisc ->enqueue() return codes. */
#define NET_XMIT_SUCCESS	0x00
#define NET_XMIT_DROP		0x01	/* skb dropped			*/
#define NET_XMIT_CN		0x02	/* congestion notification	*/
#define NET_XMIT_MASK		0x0f	/* qdisc flags in net/sch_generic.h */


pthread_mutex_t root_lock = PTHREAD_MUTEX_INITIALIZER;

struct sk_buff
{
    struct net_device	*dev;
    struct sk_buff *prev;
    struct sk_buff *next;
	uint32_t			priority;
};

struct netdev_queue;
struct net_device
{
    struct netdev_queue	*_tx;
	unsigned int		tx_queue_len;
};

struct netdev_queue
{
    struct net_device	*dev;
    struct Qdisc *qdisc;
    unsigned long		state;
};

struct qdisc_skb_head {
	struct sk_buff	*head;
	struct sk_buff	*tail;
	uint32_t		qlen;
	pthread_mutex_t	lock;
};

#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	} ATTRS

#define struct_group_tagged(TAG, NAME, MEMBERS...) \
	__struct_group(TAG, NAME, /* no attrs */, MEMBERS)

struct sk_buff_head {
	/* These two members must be first to match sk_buff. */
	struct_group_tagged(sk_buff_list, list,
		struct sk_buff	*next;
		struct sk_buff	*prev;
	);

	uint32_t		qlen;
	pthread_mutex_t	lock;
};

struct Qdisc
{
    unsigned int		flags;
    struct qdisc_skb_head	q;
    struct sk_buff_head	gso_skb;
    unsigned long		state;
	unsigned long		state2; /* must be written under qdisc spinlock */
    struct netdev_queue	*dev_queue;
    /* data */
	long privdata[];
};

enum qdisc_state2_t {
	/* Only for !TCQ_F_NOLOCK qdisc. Never access it directly.
	 * Use qdisc_run_begin/end() or qdisc_is_running() instead.
	 */
	__QDISC_STATE2_RUNNING,
};

static inline int qdisc_qlen(const struct Qdisc *q)
{
	return q->q.qlen;
}

static inline bool qdisc_run_begin(struct Qdisc *qdisc)
{
	// if (qdisc->flags & TCQ_F_NOLOCK) {
	// 	if (spin_trylock(&qdisc->seqlock))
	// 		return true;

	// 	/* No need to insist if the MISSED flag was already set.
	// 	 * Note that test_and_set_bit() also gives us memory ordering
	// 	 * guarantees wrt potential earlier enqueue() and below
	// 	 * spin_trylock(), both of which are necessary to prevent races
	// 	 */
	// 	if (test_and_set_bit(__QDISC_STATE_MISSED, &qdisc->state))
	// 		return false;

	// 	/* Try to take the lock again to make sure that we will either
	// 	 * grab it or the CPU that still has it will see MISSED set
	// 	 * when testing it in qdisc_run_end()
	// 	 */
	// 	return spin_trylock(&qdisc->seqlock);
	// }
	// return !__test_and_set_bit(__QDISC_STATE2_RUNNING, &qdisc->state2);
    bool ret = (qdisc->state2 & (1 << __QDISC_STATE2_RUNNING));
    qdisc->state2 |= (1 << __QDISC_STATE2_RUNNING);
    return !ret;
}

enum netdev_tx {
	// __NETDEV_TX_MIN	 = INT_MIN,	/* make sure enum is signed */
	NETDEV_TX_OK	 = 0x00,	/* driver took care of packet */
	NETDEV_TX_BUSY	 = 0x10,	/* driver tx path was busy*/
};

static inline bool dev_xmit_complete(int rc)
{
	/*
	 * Positive cases with an skb consumed by a driver:
	 * - successful transmission (rc == NETDEV_TX_OK)
	 * - error while transmitting (rc < 0)
	 * - error while queueing to a different device (rc & NET_XMIT_MASK)
	 */
	if (rc < NET_XMIT_MASK)
		return true;

	return false;
}

static inline void __skb_insert(struct sk_buff *newsk,
				struct sk_buff *prev, struct sk_buff *next,
				struct sk_buff_head *list)
{
	/* See skb_queue_empty_lockless() and skb_peek_tail()
	 * for the opposite READ_ONCE()
	 */
	// WRITE_ONCE(newsk->next, next);
	// WRITE_ONCE(newsk->prev, prev);
	// WRITE_ONCE(((struct sk_buff_list *)next)->prev, newsk);
	// WRITE_ONCE(((struct sk_buff_list *)prev)->next, newsk);
	// WRITE_ONCE(list->qlen, list->qlen + 1);

    newsk->next = next;
	newsk->prev = prev;
	((struct sk_buff_list *)next)->prev = newsk;
	((struct sk_buff_list *)prev)->next = newsk;
	list->qlen = list->qlen + 1;
}

static inline void __skb_queue_before(struct sk_buff_head *list,
				      struct sk_buff *next,
				      struct sk_buff *newsk)
{
	__skb_insert(newsk, ((struct sk_buff_list *)next)->prev, next, list);
}

static inline void __skb_queue_tail(struct sk_buff_head *list,
				   struct sk_buff *newsk)
{
	__skb_queue_before(list, (struct sk_buff *)list, newsk);
}

void __netif_schedule(struct Qdisc *q)
{
	// if (!test_and_set_bit(__QDISC_STATE_SCHED, &q->state))
		// __netif_reschedule(q);
    // raise_softirq_irqoff(NET_TX_SOFTIRQ);
}

static inline void dev_requeue_skb(struct sk_buff *skb, struct Qdisc *q)
{
	// pthread_mutex_t *lock = NULL;

	// if (q->flags & TCQ_F_NOLOCK) {
	// 	lock = qdisc_lock(q);
	// 	pthread_mutex_lock(lock);
	// }

	while (skb) {
		struct sk_buff *next = skb->next;

		__skb_queue_tail(&q->gso_skb, skb);

		// /* it's still part of the queue */
		// if (qdisc_is_percpu_stats(q)) {
		// 	qdisc_qstats_cpu_requeues_inc(q);
		// 	qdisc_qstats_cpu_backlog_inc(q, skb);
		// 	qdisc_qstats_cpu_qlen_inc(q);
		// } else {
		// 	q->qstats.requeues++;
		// 	qdisc_qstats_backlog_inc(q, skb);
			q->q.qlen++;
		// }
		printf("[%p] dev_requeue_skb\n", skb);
		skb = next;
	}

	// if (lock) {
	// 	pthread_mutex_unlock(lock);
	// 	set_bit(__QDISC_STATE_MISSED, &q->state);
	// } else {
		__netif_schedule(q);
	// }
}

enum netdev_queue_state_t {
	__QUEUE_STATE_DRV_XOFF,
	__QUEUE_STATE_STACK_XOFF,
	__QUEUE_STATE_FROZEN,
};

static inline bool netif_tx_queue_stopped(const struct netdev_queue *dev_queue)
{
	return dev_queue->state & (1 << __QUEUE_STATE_DRV_XOFF);
}

static int xmit_one(struct sk_buff *skb, struct net_device *dev,
		    struct netdev_queue *txq, bool more)
{
	unsigned int len;
	int rc = NETDEV_TX_BUSY;  // 模拟发包时驱动返回错误

	// if (dev_nit_active(dev))
	// 	dev_queue_xmit_nit(skb, dev);

	// len = skb->len;
	// trace_net_dev_start_xmit(skb, dev);
	// rc = netdev_start_xmit(skb, dev, txq, more);
	// trace_net_dev_xmit(skb, rc, dev, len);
	printf("[%p] try send skb return rd = %d\n", skb, rc);

	return rc;
}

struct sk_buff *dev_hard_start_xmit(struct sk_buff *first, struct net_device *dev,
				    struct netdev_queue *txq, int *ret)
{
	struct sk_buff *skb = first;
	int rc = NETDEV_TX_OK;

	while (skb) {
		struct sk_buff *next = skb->next;

		// skb_mark_not_on_list(skb);
		rc = xmit_one(skb, dev, txq, next != NULL);
		if (!dev_xmit_complete(rc)) {
			skb->next = next;
			goto out;
		}

		skb = next;
		if (netif_tx_queue_stopped(txq) && skb) {
			rc = NETDEV_TX_BUSY;
			break;
		}
	}

out:
	*ret = rc;
	return skb;
}
#define QUEUE_STATE_DRV_XOFF	(1 << __QUEUE_STATE_DRV_XOFF)
#define QUEUE_STATE_STACK_XOFF	(1 << __QUEUE_STATE_STACK_XOFF)
#define QUEUE_STATE_FROZEN	(1 << __QUEUE_STATE_FROZEN)

#define QUEUE_STATE_ANY_XOFF	(QUEUE_STATE_DRV_XOFF | QUEUE_STATE_STACK_XOFF)
#define QUEUE_STATE_ANY_XOFF_OR_FROZEN (QUEUE_STATE_ANY_XOFF | \
					QUEUE_STATE_FROZEN)

static inline bool
netif_xmit_frozen_or_stopped(const struct netdev_queue *dev_queue)
{
	return dev_queue->state & QUEUE_STATE_ANY_XOFF_OR_FROZEN;
}

bool sch_direct_xmit(struct sk_buff *skb, struct Qdisc *q,
		     struct net_device *dev, struct netdev_queue *txq,
		     pthread_mutex_t *root_lock, bool validate)
{
	int ret = NETDEV_TX_BUSY;
	// bool again = false;

	/* And release qdisc */
	if (root_lock)
		pthread_mutex_unlock(root_lock);

// 	/* Note that we validate skb (GSO, checksum, ...) outside of locks */
// 	if (validate)
// 		skb = validate_xmit_skb_list(skb, dev, &again);

// #ifdef CONFIG_XFRM_OFFLOAD
// 	if (unlikely(again)) {
// 		if (root_lock)
// 			pthread_mutex_lock(root_lock);

// 		dev_requeue_skb(skb, q);
// 		return false;
// 	}
// #endif

	// if (likely(skb)) {
	// 	HARD_TX_LOCK(dev, txq, smp_processor_id());
		if (!netif_xmit_frozen_or_stopped(txq))
			skb = dev_hard_start_xmit(skb, dev, txq, &ret);
	// 	else
	// 		qdisc_maybe_clear_missed(q, txq);

	// 	HARD_TX_UNLOCK(dev, txq);
	// } // else {
	// 	if (root_lock)
	// 		pthread_mutex_lock(root_lock);
	// 	return true;
	// }

	if (root_lock)
		pthread_mutex_lock(root_lock);

	if (!dev_xmit_complete(ret)) {
		// /* Driver returned NETDEV_TX_BUSY - requeue skb */
		// if (unlikely(ret != NETDEV_TX_BUSY))
		// 	net_warn_ratelimited("BUG %s code %d qlen %d\n",
		// 			     dev->name, ret, q->q.qlen);

		dev_requeue_skb(skb, q);
		return false;
	}

	return true;
}

static struct sk_buff *pfifo_fast_dequeue(struct Qdisc *qdisc)
{
// 	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	struct sk_buff *skb = NULL;
// 	bool need_retry = true;
// 	int band;

// retry:
// 	for (band = 0; band < PFIFO_FAST_BANDS && !skb; band++) {
// 		struct skb_array *q = band2list(priv, band);

// 		if (__skb_array_empty(q))
// 			continue;

// 		skb = __skb_array_consume(q);
// 	}
// 	if (likely(skb)) {
// 		qdisc_update_stats_at_dequeue(qdisc, skb);
// 	} else if (need_retry &&
// 		   READ_ONCE(qdisc->state) & QDISC_STATE_NON_EMPTY) {
// 		/* Delay clearing the STATE_MISSED here to reduce
// 		 * the overhead of the second spin_trylock() in
// 		 * qdisc_run_begin() and __netif_schedule() calling
// 		 * in qdisc_run_end().
// 		 */
// 		clear_bit(__QDISC_STATE_MISSED, &qdisc->state);
// 		clear_bit(__QDISC_STATE_DRAINING, &qdisc->state);

// 		/* Make sure dequeuing happens after clearing
// 		 * STATE_MISSED.
// 		 */
// 		smp_mb__after_atomic();

// 		need_retry = false;

// 		goto retry;
// 	}

	return skb;
}

static inline struct sk_buff *skb_peek(const struct sk_buff_head *list_)
{
	struct sk_buff *skb = list_->next;

	if (skb == (struct sk_buff *)list_)
		skb = NULL;
	return skb;
}

static inline struct xfrm_offload *xfrm_offload(struct sk_buff *skb)
{
#ifdef CONFIG_XFRM
	struct sec_path *sp = skb_sec_path(skb);

	if (!sp || !sp->olen || sp->len != sp->olen)
		return NULL;

	return &sp->ovec[sp->olen - 1];
#else
	return NULL;
#endif
}

static inline int skb_queue_empty(const struct sk_buff_head *list)
{
	return list->next == (const struct sk_buff *) list;
}

static inline struct netdev_queue *skb_get_tx_queue(const struct net_device *dev,
						    const struct sk_buff *skb)
{
	// return netdev_get_tx_queue(dev, skb_get_queue_mapping(skb));
    return dev->_tx;
}

static inline pthread_mutex_t *qdisc_lock(struct Qdisc *qdisc)
{
	return &qdisc->q.lock;
}

static inline void __skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	struct sk_buff *next, *prev;

	list->qlen = list->qlen - 1;
	next	   = skb->next;
	prev	   = skb->prev;
	skb->next  = skb->prev = NULL;
	next->prev = prev;
	prev->next = next;
}

static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *list)
{
	struct sk_buff *skb = skb_peek(list);
	if (skb)
		__skb_unlink(skb, list);
	return skb;
}

static struct sk_buff *dequeue_skb(struct Qdisc *q, bool *validate,
				   int *packets)
{
    const struct netdev_queue *txq = q->dev_queue;
	struct sk_buff *skb = NULL;

	*packets = 1;
	if (!skb_queue_empty(&q->gso_skb)) {
		pthread_mutex_t *lock = NULL;

		if (q->flags & TCQ_F_NOLOCK) {
			lock = qdisc_lock(q);
			pthread_mutex_lock(lock);
		}

		skb = skb_peek(&q->gso_skb);

		/* skb may be null if another cpu pulls gso_skb off in between
		 * empty check and lock.
		 */
		if (!skb) {
			if (lock)
				pthread_mutex_unlock(lock);
			goto validate;
		}

		/* skb in gso_skb were already validated */
		*validate = false;
		if (xfrm_offload(skb))
			*validate = true;
		/* check the reason of requeuing without tx lock first */
		txq = skb_get_tx_queue(txq->dev, skb);
		if (!netif_xmit_frozen_or_stopped(txq)) {
			skb = __skb_dequeue(&q->gso_skb);
			// if (qdisc_is_percpu_stats(q)) {
			// 	qdisc_qstats_cpu_backlog_dec(q, skb);
			// 	qdisc_qstats_cpu_qlen_dec(q);
			// } else {
			// 	qdisc_qstats_backlog_dec(q, skb);
				q->q.qlen--;
			// }
		} else {
			skb = NULL;
			// qdisc_maybe_clear_missed(q, txq);
		}
		if (lock)
			pthread_mutex_unlock(lock);
		goto trace;
	}
validate:
// 	*validate = true;

// 	if ((q->flags & TCQ_F_ONETXQUEUE) &&
// 	    netif_xmit_frozen_or_stopped(txq)) {
// 		// qdisc_maybe_clear_missed(q, txq);
// 		return skb;
// 	}

// 	skb = qdisc_dequeue_skb_bad_txq(q);
// 	if (skb) {
// 		if (skb == SKB_XOFF_MAGIC)
// 			return NULL;
// 		goto bulk;
// 	}
    skb = pfifo_fast_dequeue(q);
//     if (skb) {
// bulk:
// 		if (qdisc_may_bulk(q))
// 			try_bulk_dequeue_skb(q, skb, txq, packets);
// 		else
// 			try_bulk_dequeue_skb_slow(q, skb, packets);
// 	}
trace:
// 	trace_qdisc_dequeue(q, txq, *packets, skb);
	printf("[%p] dequeue_skb \n");
	return skb;
}

static inline struct net_device *qdisc_dev(const struct Qdisc *qdisc)
{
	return qdisc->dev_queue->dev;
}

static inline bool qdisc_restart(struct Qdisc *q, int *packets)
{
	pthread_mutex_t *root_lock = NULL;
	struct netdev_queue *txq;
	struct net_device *dev;
	struct sk_buff *skb;
	bool validate;

	/* Dequeue packet */
	skb = dequeue_skb(q, &validate, packets);
	if (!skb)
		return false;

	if (!(q->flags & TCQ_F_NOLOCK))
		root_lock = qdisc_lock(q);

	dev = qdisc_dev(q);
	txq = skb_get_tx_queue(dev, skb);

	return sch_direct_xmit(skb, q, dev, txq, root_lock, validate);
}

void __qdisc_run(struct Qdisc *q)
{
	// int quota = READ_ONCE(dev_tx_weight);
	int packets;

	while (qdisc_restart(q, &packets)) {
		// quota -= packets;
		// if (quota <= 0) {
			// if (q->flags & TCQ_F_NOLOCK)
			// 	set_bit(__QDISC_STATE_MISSED, &q->state);
			// else
				__netif_schedule(q);

			break;
		// }
	}
}

static inline void qdisc_run_end(struct Qdisc *qdisc)
{
	// if (qdisc->flags & TCQ_F_NOLOCK) {
	// 	pthread_mutex_unlock(&qdisc->seqlock);

	// 	/* pthread_mutex_unlock() only has store-release semantic. The unlock
	// 	 * and test_bit() ordering is a store-load ordering, so a full
	// 	 * memory barrier is needed here.
	// 	 */
	// 	smp_mb();

	// 	if (unlikely(test_bit(__QDISC_STATE_MISSED,
	// 			      &qdisc->state)))
	// 		__netif_schedule(qdisc);
	// } else {
		// __clear_bit(__QDISC_STATE2_RUNNING, &qdisc->state2);
    qdisc->state2 &= ~(1 << __QDISC_STATE2_RUNNING);
	// }
}

#define TC_PRIO_BESTEFFORT		0
#define TC_PRIO_FILLER			1
#define TC_PRIO_BULK			2
#define TC_PRIO_INTERACTIVE_BULK	4
#define TC_PRIO_INTERACTIVE		6
#define TC_PRIO_CONTROL			7

#define TC_PRIO_MAX			15

static const uint8_t prio2band[TC_PRIO_MAX + 1] = {
	1, 2, 2, 2, 1, 2, 0, 0 , 1, 1, 1, 1, 1, 1, 1, 1
};

struct ptr_ring {
	int producer;
	pthread_mutex_t producer_lock;
	int consumer_head; /* next valid entry */
	int consumer_tail; /* next entry to invalidate */
	pthread_mutex_t consumer_lock;
	/* Shared consumer/producer data */
	/* Read-only by both the producer and the consumer */
	int size; /* max entries in queue */
	int batch; /* number of entries to consume in a batch */
	void **queue;
};

struct skb_array {
	struct ptr_ring ring;
};

#define PFIFO_FAST_BANDS 3

struct pfifo_fast_priv {
	struct skb_array q[PFIFO_FAST_BANDS];
};

static inline struct skb_array *band2list(struct pfifo_fast_priv *priv,
					  int band)
{
	return &priv->q[band];
}

static inline void *qdisc_priv(struct Qdisc *q)
{
	return &q->privdata;
}

#define	ENOSPC		28	/* No space left on device */

static inline int __ptr_ring_produce(struct ptr_ring *r, void *ptr)
{
	if (!r->size || r->queue[r->producer])
		return -ENOSPC;

	/* Make sure the pointer we are storing points to a valid data. */
	/* Pairs with the dependency ordering in __ptr_ring_consume. */
	// smp_wmb();

	r->queue[r->producer++] = ptr;
	if (r->producer >= r->size)
		r->producer = 0;
	return 0;
}

/*
 * Note: resize (below) nests producer lock within consumer lock, so if you
 * consume in interrupt or BH context, you must disable interrupts/BH when
 * calling this.
 */
static inline int ptr_ring_produce(struct ptr_ring *r, void *ptr)
{
	int ret;

	pthread_mutex_lock(&r->producer_lock);
	ret = __ptr_ring_produce(r, ptr);
	pthread_mutex_unlock(&r->producer_lock);

	return ret;
}

static inline int skb_array_produce(struct skb_array *a, struct sk_buff *skb)
{
	return ptr_ring_produce(&a->ring, skb);
}

static int pfifo_fast_enqueue(struct sk_buff *skb, struct Qdisc *qdisc,
			      struct sk_buff **to_free)
{
	int band = prio2band[skb->priority & TC_PRIO_MAX];
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	struct skb_array *q = band2list(priv, band);
	// unsigned int pkt_len = qdisc_pkt_len(skb);
	int err;

	err = skb_array_produce(q, skb);

	if (err) {
		// if (qdisc_is_percpu_stats(qdisc))
		// 	return qdisc_drop_cpu(skb, qdisc, to_free);
		// else
		// 	return qdisc_drop(skb, qdisc, to_free);
		*to_free = skb;
		printf("[%p] qdisc enqueue fail\n", skb);
		return NET_XMIT_DROP;
	}

	// qdisc_update_stats_at_enqueue(qdisc, pkt_len);
	printf("[%p] qdisc enqueue success\n", skb);
	return NET_XMIT_SUCCESS;
}

static int dev_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *q,
			     struct sk_buff **to_free,
			     struct netdev_queue *txq)
{
	int rc;

	rc = pfifo_fast_enqueue(skb, q, to_free) & NET_XMIT_MASK;
	// if (rc == NET_XMIT_SUCCESS)
	// 	trace_qdisc_enqueue(q, txq, skb);
	return rc;
}

#define KFREE_SKB_BULK_SIZE	16

struct skb_free_array {
	unsigned int skb_count;
	void *skb_array[KFREE_SKB_BULK_SIZE];
};

void
kfree_skb_list_reason(struct sk_buff *segs, enum skb_drop_reason reason)
{
	struct skb_free_array sa;

	sa.skb_count = 0;

	while (segs) {
		struct sk_buff *next = segs->next;

		// if (__kfree_skb_reason(segs, reason)) {
		// 	skb_poison_list(segs);
		// 	kfree_skb_add_bulk(segs, &sa, reason);
		// }
		free(segs);
		printf("[%p] free skb because of SKB_DROP_REASON_QDISC_DROP\n", segs);

		segs = next;
	}

	// if (sa.skb_count)
		// kmem_cache_free_bulk(skbuff_cache, sa.skb_count, sa.skb_array);
}

static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
                                 struct net_device *dev,
                                 struct netdev_queue *txq)
{
    int rc;
    struct sk_buff *to_free = NULL;

    pthread_mutex_lock(&root_lock);
    if ((q->flags & TCQ_F_CAN_BYPASS) && !qdisc_qlen(q) &&
             qdisc_run_begin(q))
    {
        /*
         * This is a work-conserving queue; there are no old skbs
         * waiting to be sent out; and the qdisc is not running -
         * xmit the skb directly.
         */

        // qdisc_bstats_update(q, skb);

        if (sch_direct_xmit(skb, q, dev, txq, &root_lock, true))
        {
            __qdisc_run(q);
        }

        qdisc_run_end(q);
        rc = NET_XMIT_SUCCESS;
    }
    else
    {
        rc = dev_qdisc_enqueue(skb, q, &to_free, txq);
        if (qdisc_run_begin(q))
        {
            __qdisc_run(q);
            qdisc_run_end(q);
        }
    }
    pthread_mutex_unlock(&root_lock);
    if (to_free)
        kfree_skb_list_reason(to_free, SKB_DROP_REASON_QDISC_DROP);
		
    return rc;
}

struct netdev_queue *netdev_core_pick_tx(struct net_device *dev,
					 struct sk_buff *skb,
					 struct net_device *sb_dev)
{
    return &(dev->_tx[0]);
}

int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
{
    struct Qdisc *q;
    struct net_device *dev = skb->dev;
    struct netdev_queue *txq = NULL;

    if (!txq)
		txq = netdev_core_pick_tx(dev, skb, sb_dev);

    q = txq->qdisc;

    __dev_xmit_skb(skb, q, dev, txq);
}

static void net_tx_action()
{
	// struct softnet_data *sd = this_cpu_ptr(&softnet_data);

	// if (sd->completion_queue) {
	// 	struct sk_buff *clist;

	// 	local_irq_disable();
	// 	clist = sd->completion_queue;
	// 	sd->completion_queue = NULL;
	// 	local_irq_enable();

	// 	while (clist) {
	// 		struct sk_buff *skb = clist;

	// 		clist = clist->next;

	// 		WARN_ON(refcount_read(&skb->users));
	// 		if (likely(get_kfree_skb_cb(skb)->reason == SKB_CONSUMED))
	// 			trace_consume_skb(skb, net_tx_action);
	// 		else
	// 			trace_kfree_skb(skb, net_tx_action,
	// 					get_kfree_skb_cb(skb)->reason);

	// 		if (skb->fclone != SKB_FCLONE_UNAVAILABLE)
	// 			__kfree_skb(skb);
	// 		else
	// 			__napi_kfree_skb(skb,
	// 					 get_kfree_skb_cb(skb)->reason);
	// 	}
	// }

	// if (sd->output_queue) {
	// 	struct Qdisc *head;

	// 	local_irq_disable();
	// 	head = sd->output_queue;
	// 	sd->output_queue = NULL;
	// 	sd->output_queue_tailp = &sd->output_queue;
	// 	local_irq_enable();

	// 	rcu_read_lock();

	// 	while (head) {
	// 		struct Qdisc *q = head;
	// 		spinlock_t *root_lock = NULL;

	// 		head = head->next_sched;

	// 		/* We need to make sure head->next_sched is read
	// 		 * before clearing __QDISC_STATE_SCHED
	// 		 */
	// 		smp_mb__before_atomic();

	// 		if (!(q->flags & TCQ_F_NOLOCK)) {
	// 			root_lock = qdisc_lock(q);
	// 			spin_lock(root_lock);
	// 		} else if (unlikely(test_bit(__QDISC_STATE_DEACTIVATED,
	// 					     &q->state))) {
	// 			/* There is a synchronize_net() between
	// 			 * STATE_DEACTIVATED flag being set and
	// 			 * qdisc_reset()/some_qdisc_is_busy() in
	// 			 * dev_deactivate(), so we can safely bail out
	// 			 * early here to avoid data race between
	// 			 * qdisc_deactivate() and some_qdisc_is_busy()
	// 			 * for lockless qdisc.
	// 			 */
	// 			clear_bit(__QDISC_STATE_SCHED, &q->state);
	// 			continue;
	// 		}

	// 		clear_bit(__QDISC_STATE_SCHED, &q->state);
	// 		qdisc_run(q);
	// 		if (root_lock)
	// 			spin_unlock(root_lock);
	// 	}

	// 	rcu_read_unlock();
	// }

	// xfrm_dev_backlog(sd);
}

static inline void __skb_queue_head_init(struct sk_buff_head *list)
{
	list->prev = list->next = (struct sk_buff *)list;
	list->qlen = 0;
}

#define EINVAL          22
#define ENOMEM          12

typedef unsigned int gfp_t;

static inline void **__ptr_ring_init_queue_alloc(unsigned int size, gfp_t gfp)
{
	// if (size > KMALLOC_MAX_SIZE / sizeof(void *))
	// 	return NULL;

	// return kvmalloc_array(size, sizeof(void *), gfp | __GFP_ZERO);
	return malloc(sizeof(void *) * size);
}

#define SMP_CACHE_BYTES 64

static inline void __ptr_ring_set_size(struct ptr_ring *r, int size)
{
	r->size = size;
	r->batch = SMP_CACHE_BYTES * 2 / sizeof(*(r->queue));
	/* We need to set batch at least to 1 to make logic
	 * in __ptr_ring_discard_one work correctly.
	 * Batching too much (because ring is small) would cause a lot of
	 * burstiness. Needs tuning, for now disable batching.
	 */
	if (r->batch > r->size / 2 || !r->batch)
		r->batch = 1;
}

static inline int ptr_ring_init(struct ptr_ring *r, int size, gfp_t gfp)
{
	r->queue = __ptr_ring_init_queue_alloc(size, gfp);
	if (!r->queue)
		return -ENOMEM;

	__ptr_ring_set_size(r, size);
	r->producer = r->consumer_head = r->consumer_tail = 0;

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutex_init(&r->producer_lock, &attr);
	pthread_mutexattr_init(&attr);
	pthread_mutex_init(&r->consumer_lock, &attr);

	return 0;
}

static inline int skb_array_init(struct skb_array *a, int size, gfp_t gfp)
{
	return ptr_ring_init(&a->ring, size, gfp);
}

struct nlattr
{
	/* data */
};

struct netlink_ext_ack
{
	/* data */
};


static int pfifo_fast_init(struct Qdisc *qdisc, struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	unsigned int qlen = qdisc_dev(qdisc)->tx_queue_len;
	struct pfifo_fast_priv *priv = qdisc_priv(qdisc);
	int prio;

	/* guard against zero length rings */
	if (!qlen)
		return -EINVAL;

	for (prio = 0; prio < PFIFO_FAST_BANDS; prio++) {
		struct skb_array *q = band2list(priv, prio);
		int err;

		err = skb_array_init(q, qlen, 0);
		if (err)
			return -ENOMEM;
	}

	/* Can by-pass the queue discipline */
	qdisc->flags |= TCQ_F_CAN_BYPASS;
	return 0;
}

int main(int argc, char *argv[])
{
    // struct sk_buff skb;
    struct net_device sk_dev;
    struct Qdisc *qdisc = malloc(sizeof(struct Qdisc) + sizeof(struct pfifo_fast_priv));
    struct netdev_queue _tx;

    // memset(&skb, 0, sizeof(skb));
    memset(&sk_dev, 0, sizeof(sk_dev));
    memset(qdisc, 0, sizeof(sizeof(struct Qdisc) + sizeof(struct pfifo_fast_priv)));
    memset(&_tx, 0, sizeof(_tx));

    sk_dev._tx = &_tx;
	sk_dev.tx_queue_len = 3;

    _tx.qdisc = qdisc;



    // _tx.state |= (1 << __QUEUE_STATE_DRV_XOFF);  // 模拟队列被驱动关闭

    __skb_queue_head_init(&qdisc->gso_skb);

    qdisc->dev_queue = &_tx;

    _tx.dev = &sk_dev;

	pfifo_fast_init(qdisc, NULL, NULL);

    while(true)
    {
        struct sk_buff *skb = malloc(sizeof(struct sk_buff));
		printf("[%p] ready send\n", skb);
        memset(skb, 0, sizeof(struct sk_buff));
        skb->dev = &sk_dev;
        __dev_queue_xmit(skb, &sk_dev);
		sleep(1);
    }
    return 0;
}