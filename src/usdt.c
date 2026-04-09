// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "usdt.h"
#include "requests.h"
#include "proc.h"
#include "env.h"
#include "bpf_utils.h"
#include "wprof.skel.h"

static int add_usdt_binary(u64 dev, u64 inode, const char *path, const char *attach_path)
{
	struct uprobe_binary *binary, key = {};

	if (!env.usdt_binaries) {
		env.usdt_binaries = hashmap__new(uprobe_binary_hash_fn, uprobe_binary_equal_fn, NULL);
		if (!env.usdt_binaries)
			return -ENOMEM;
	}

	key.dev = dev;
	key.inode = inode;
	key.path = strdup(path);
	if (!key.path)
		return -ENOMEM;

	if (hashmap__find(env.usdt_binaries, &key, NULL)) {
		free(key.path);
		return 0;
	}

	binary = calloc(1, sizeof(*binary));
	if (!binary) {
		free(key.path);
		return -ENOMEM;
	}

	*binary = key;
	if (attach_path)
		binary->attach_path = strdup(attach_path);

	hashmap__set(env.usdt_binaries, binary, binary, NULL, NULL);

	return 0;
}

static int discover_pid_usdt_binaries(int pid)
{
	struct vma_info *vma;
	int err = 0;

	wprof_for_each(vma, vma, pid,
		       VMA_QUERY_VMA_EXECUTABLE | VMA_QUERY_FILE_BACKED_VMA) {
		if (vma->vma_name[0] != '/')
			continue;

		char tmp[1024];
		snprintf(tmp, sizeof(tmp), "/proc/%d/map_files/%llx-%llx",
			 pid, vma->vma_start, vma->vma_end);

		u64 dev = makedev(vma->dev_major, vma->dev_minor);
		err = add_usdt_binary(dev, vma->inode, vma->vma_name, tmp);
		if (err)
			return err;
		errno = 0;
	}
	if (errno && (errno != ENOENT && errno != ESRCH)) {
		err = -errno;
		eprintf("Failed VMA iteration for PID %d: %d\n", pid, err);
		return err;
	}

	return 0;
}

int setup_usdt_discovery(void)
{
	int err = 0;

	for (int p = 0; p < env.usdt_probe_cnt; p++) {
		struct usdt_probe_def *probe = &env.usdt_probes[p];

		if (probe->global_discovery) {
			int *pidp, pid;

			wprof_for_each(proc, pidp) {
				pid = *pidp;
				err = discover_pid_usdt_binaries(pid);
				if (err) {
					eprintf("Failed to discover USDT binaries for PID %d: %d (skipping...)\n", pid, err);
					continue;
				}
			}
		}

		for (int i = 0; i < probe->path_cnt; i++) {
			struct stat st;

			err = stat(probe->paths[i], &st);
			if (err) {
				err = -errno;
				eprintf("Failed to stat() binary '%s' for USDT probe: %d (skipping...)\n",
					probe->paths[i], err);
				continue;
			}

			err = add_usdt_binary(st.st_dev, st.st_ino, probe->paths[i], NULL);
			if (err) {
				eprintf("Failed to record binary '%s' for USDT probe: %d (skipping...)\n",
					probe->paths[i], err);
				continue;
			}
		}

		for (int i = 0; i < probe->pid_cnt; i++) {
			int pid = probe->pids[i];

			err = discover_pid_usdt_binaries(pid);
			if (err) {
				eprintf("Failed to discover USDT binaries for PID %d: %d (skipping...)\n", pid, err);
				continue;
			}
		}
	}

	return 0;
}

static bool ignore_libbpf_warns_usdt;

static int libbpf_print_fn_usdt(enum libbpf_print_level level, const char *format, va_list args)
{
	if (ignore_libbpf_warns_usdt)
		return 0;
	return vfprintf(stderr, format, args);
}

int attach_usdt_probes(struct bpf_state *st)
{
	struct hashmap_entry *entry;
	size_t bkt;
	int err;
	libbpf_print_fn_t old_print_fn;

	old_print_fn = libbpf_set_print(libbpf_print_fn_usdt);

	hashmap__for_each_entry(env.usdt_binaries, entry, bkt) {
		struct uprobe_binary *binary = (struct uprobe_binary *)entry->value;

		for (int i = 0; i < env.usdt_probe_cnt; i++) {
			struct usdt_probe_def *probe = &env.usdt_probes[i];
			struct bpf_link *link, **tmp;

			LIBBPF_OPTS(bpf_usdt_opts, usdt_opts,
				.usdt_cookie = i,
			);

			ignore_libbpf_warns_usdt = true;
			link = bpf_program__attach_usdt(st->skel->progs.wprof_usdt, -1,
							binary->attach_path ?: binary->path,
							probe->provider, probe->name,
							&usdt_opts);
			ignore_libbpf_warns_usdt = false;

			if (!link) {
				dlogf(USDT, 2, "Failed to attach USDT %s:%s to %s, ignoring...\n",
				      probe->provider, probe->name, binary->path);
				continue;
			}

			dlogf(USDT, 1, "Attached USDT %s:%s to %s (cookie=%d).\n",
			      probe->provider, probe->name, binary->path, i);

			tmp = realloc(st->links, (st->link_cnt + 1) * sizeof(struct bpf_link *));
			if (!tmp) {
				bpf_link__destroy(link);
				err = -ENOMEM;
				goto out;
			}
			st->links = tmp;
			st->links[st->link_cnt] = link;
			st->link_cnt++;
		}
	}

	err = 0;
out:
	libbpf_set_print(old_print_fn);
	return err;
}
