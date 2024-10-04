/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h"
#include <sys/stat.h>

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir)
{
    char map_filename[PATH_MAX];
    char pin_dir[PATH_MAX];
    int err, len;
    int fd;

    // Construct the pin directory path
    len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    // Construct the full path for the pinned map
    len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, subdir, map_name);
    if (len < 0) {
        fprintf(stderr, "ERR: creating map_name\n");
        return EXIT_FAIL_OPTION;
    }

    // Check if the pinned map exists
    if (access(map_filename, F_OK) != -1) {
        if (verbose) {
            printf(" - Reusing pinned map at: %s\n", map_filename);
        }

        // Get the file descriptor for the existing map
        fd = bpf_obj_get(map_filename);
        if (fd < 0) {
            fprintf(stderr, "ERR: Failed to get pinned map at %s\n", map_filename);
            return EXIT_FAIL_BPF;
        }

        // Reuse the pinned map with the existing map
        struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, map_name);
        if (!map) {
            fprintf(stderr, "ERR: Could not find map in object: %s\n", map_name);
            close(fd);
            return EXIT_FAIL_BPF;
        }

        err = bpf_map__reuse_fd(map, fd);
        if (err) {
            fprintf(stderr, "ERR: Reusing pinned map failed\n");
            close(fd);
            return EXIT_FAIL_BPF;
        }
        close(fd);

    } else {
        if (verbose) {
            printf(" - Pinning new maps in %s/\n", pin_dir);
        }
        err = bpf_object__pin_maps(bpf_obj, pin_dir);
        if (err) {
            fprintf(stderr, "ERR: Pinning maps failed\n");
            return EXIT_FAIL_BPF;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
	struct xdp_program *program;
	int err;

	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		/* TODO: Miss unpin of maps on unload */
		/* return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
	}

	program = load_bpf_and_xdp_attach(&cfg);
	if (!program)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	err = pin_maps_in_bpf_object(xdp_program__bpf_obj(program), cfg.ifname);
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}

	return EXIT_OK;
}
