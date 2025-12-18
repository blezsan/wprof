// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Meta Platforms, Inc. */
/*
 * SCX (sched_ext) specific BPF functionality for wprof.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wprof.h"
#include "wprof.bpf.h"

/* DSQ ID parsing macros for scx_layered scheduler */
#define DSQ_ID_SPECIAL_MASK 0xc0000000
#define DSQ_ID_LAYER_SHIFT  16
#define DSQ_ID_LLC_MASK	    ((1LLU << DSQ_ID_LAYER_SHIFT) - 1) /* 0x0000ffff */
#define DSQ_ID_LAYER_MASK   (~DSQ_ID_LAYER_SHIFT & ~DSQ_ID_SPECIAL_MASK) /* 0x3fff0000 */

extern const volatile bool capture_scx_layer_id;

/* handlers for tracking DSQ insertions - modeled after scxtop's on_insert() */
static int on_dsq_insert(struct task_struct *p, u64 dsq, const char *probe_name)
{
	struct task_state *scur;

	if (!capture_scx_layer_id)
		return 0;

	if (!p)
		return 0;

	scur = task_state(p->pid);
	if (!scur)
		return 0;

	scur->dsq_insert_time = bpf_ktime_get_ns();
	scur->dsq_id = dsq;
	/* NB: layer_id may be bogus if we're not running scx_layered scheduler */
	scur->layer_id = (dsq & DSQ_ID_LAYER_MASK) >> DSQ_ID_LAYER_SHIFT;
	__builtin_memcpy(scur->dsq_probe_name, probe_name, sizeof(scur->dsq_probe_name));

	return 0;
}

SEC("?fentry/scx_bpf_dsq_insert")
int BPF_PROG(wprof_dsq_insert, struct task_struct *p, u64 dsq)
{
	return on_dsq_insert(p, dsq, "dsq_insert");
}

SEC("?fentry/scx_bpf_dispatch")
int BPF_PROG(wprof_dispatch, struct task_struct *p, u64 dsq)
{
	return on_dsq_insert(p, dsq, "dispatch");
}

SEC("?fentry/scx_bpf_dsq_insert_vtime")
int BPF_PROG(wprof_dsq_insert_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return on_dsq_insert(p, dsq, "dsq_insert_vt");
}

SEC("?fentry/scx_bpf_dispatch_vtime")
int BPF_PROG(wprof_dispatch_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return on_dsq_insert(p, dsq, "dispatch_vt");
}

__hidden int handle_dsq(u64 now_ts, struct task_struct *task, struct task_state *s)
{
	u64 data[] = { (u64)&s->dsq_probe_name, s->dsq_id };
	char label[WORKER_DESC_LEN];

	if (s->dsq_insert_time == 0) /* we never recorded matching start, ignore */
		return 0;

	bpf_snprintf(label, sizeof(label), "%s_0x%llx", data, sizeof(data));
	emit_wq_event(s->dsq_insert_time, now_ts, task, label);

	s->dsq_insert_time = 0;

	return 0;
}

static int on_dsq_move(struct task_struct *p, u64 dsq, const char *probe_name)
{
	struct task_state *scur;
	u64 now_ts;

	if (!capture_scx_layer_id)
		return 0;

	if (!p)
		return 0;

	scur = task_state(p->pid);
	if (!scur)
		return 0;

	now_ts = bpf_ktime_get_ns();
	/* record data for previous dsq for this task */
	handle_dsq(now_ts, p, scur);

	scur->dsq_insert_time = now_ts;
	scur->dsq_id = dsq;
	/* NB: layer_id may be bogus if we're not running scx_layered scheduler */
	scur->layer_id = (dsq & DSQ_ID_LAYER_MASK) >> DSQ_ID_LAYER_SHIFT;
	__builtin_memcpy(scur->dsq_probe_name, probe_name, sizeof(scur->dsq_probe_name));

	return 0;
}

SEC("?fentry/scx_bpf_dsq_move")
int BPF_PROG(wprof_dsq_move, void *it__iter,
         struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
  return on_dsq_move(p, dsq_id, "dsq_move");
}

SEC("?fentry/scx_bpf_dispatch_from_dsq")
int BPF_PROG(wprof_dispatch_from_dsq, void *it__iter,
         struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
  return on_dsq_move(p, dsq_id, "dispatch_from_dsq");
}

SEC("?fentry/scx_bpf_dsq_move_vtime")
int BPF_PROG(wprof_dsq_move_vtime, void *it__iter,
         struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
  return on_dsq_move(p, dsq_id, "dsq_move_vt");
}

SEC("?fentry/scx_bpf_dispatch_vtime_from_dsq")
int BPF_PROG(wprof_dispatch_vtime_from_dsq, void *it__iter,
         struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
  return on_dsq_move(p, dsq_id, "dispatch_vt_from_dsq");
}
