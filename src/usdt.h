/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __USDT_H_
#define __USDT_H_

#include "wprof_types.h"

struct bpf_state;

int setup_usdt_discovery(void);
int attach_usdt_probes(struct bpf_state *st);

/* USDT definition stored in data dump for replay */
struct wevent_usdt_def {
	u32 provider_stroff;
	u32 name_stroff;
};

#endif /* __USDT_H_ */
