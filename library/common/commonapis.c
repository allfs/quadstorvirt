/* 
 * Copyright (C) Shivaram Upadhyayula <shivaram.u@quadstor.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * Version 2 as published by the Free Software Foundation
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, 
 * Boston, MA  02110-1301, USA.
 */

#include <stdarg.h>
#include <apicommon.h>

#ifdef FREEBSD
static int
iodev_check(void )
{
	return 0;
}
#else
static int iodev;
static int
iodev_check(void )
{
	FILE *fp;
	char devname[256];
	char buf[256];
	int major = 0, tmp;

	if (iodev)
		return 0;

	fp = fopen("/proc/devices", "r");
	if (!fp) {
		DEBUG_WARN("Cannot open /proc/devices\n");
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (sscanf(buf, "%d %s", &tmp, devname) != 2) {
			continue;
		}

		if (strcmp(devname, TL_DEV_NAME))
			continue;
		major = tmp;
		break;
	}
	fclose(fp);

	if (!major) {
		DEBUG_WARN("Cannot locate iodev in /proc/devices");
		return -1;
	}

	unlink(TL_DEV);
	if (mknod(TL_DEV, (S_IFCHR | 0600), (major << 8))) {
		DEBUG_WARN("Cannot create iodev\n");
		return -1;
	}
	iodev = 1;
	return 0;
}
#endif

static char *
print_ioc_cmd(unsigned long cmd)
{
	switch (cmd) {
		case TLTARGIOCNEWBLKDEV:
			return "TLTARGIOCNEWBLKDEV";
		case TLTARGIOCDELBLKDEV:
			return "TLTARGIOCDELBLKDEV";
		case TLTARGIOCGETBLKDEV:
			return "TLTARGIOCGETBLKDEV";
		case TLTARGIOCDAEMONSETINFO:
			return "TLTARGIOCDAEMONSETINFO";
		case TLTARGIOCCHECKDISKS:
			return "TLTARGIOCCHECKDISKS";
		case TLTARGIOCLOADDONE:
			return "TLTARGIOCLOADDONE";
		case TLTARGIOCENABLEDEVICE:
			return "TLTARGIOCENABLEDEVICE";
		case TLTARGIOCDISABLEDEVICE:
			return "TLTARGIOCDISABLEDEVICE";
		case TLTARGIOCNEWTDISK:
			return "TLTARGIOCNEWTDISK";
		case TLTARGIOCLOADTDISK:
			return "TLTARGIOCLOADTDISK";
		case TLTARGIOCDELETETDISK:
			return "TLTARGIOCDELETETDISK";
		case TLTARGIOCMODIFYTDISK:
			return "TLTARGIOCMODIFYTDISK";
		case TLTARGIOCATTACHTDISK:
			return "TLTARGIOCATTACHTDISK";
		case TLTARGIOCTDISKSTATS:
			return "TLTARGIOCTDISKSTATS";
		case TLTARGIOCTDISKRESETSTATS:
			return "TLTARGIOCTDISKRESETSTATS";
		case TLTARGIOCBINTRESETSTATS:
			return "TLTARGIOCBINTRESETSTATS";
		case TLTARGIOCRESETLOGS:
			return "TLTARGIOCRESETLOGS";
		case TLTARGIOCUNLOAD:
			return "TLTARGIOCUNLOAD";
		case TLTARGIOCNODECONFIG:
			return "TLTARGIOCNODECONFIG";
		case TLTARGIOCNEWBDEVSTUB:
			return "TLTARGIOCNEWBDEVSTUB";
		case TLTARGIOCDELETEBDEVSTUB:
			return "TLTARGIOCDELETEBDEVSTUB";
		case TLTARGIOCNEWTDISKSTUB:
			return "TLTARGIOCNEWTDISKSTUB";
		case TLTARGIOCDELETETDISKSTUB:
			return "TLTARGIOCDELETETDISKSTUB";
		case TLTARGIOCCLONEVDISK:
			return "TLTARGIOCCLONEVDISK";
		case TLTARGIOCCLONESTATUS:
			return "TLTARGIOCCLONESTATUS";
		case TLTARGIOCMIRRORVDISK:
			return "TLTARGIOCMIRRORVDISK";
		case TLTARGIOCMIRRORSTATUS:
			return "TLTARGIOCMIRRORSTATUS";
	}
	return "Unknown";
}

int
tl_ioctl2(char *dev, unsigned long int request, void *arg)
{
	int fd;
	int retval;

	if (iodev_check() < 0)
		return -1;

	if ((fd = open(dev, O_RDONLY)) < 0)
	{
		DEBUG_WARN("failed to open %s errno %d %s\n", dev, errno, strerror(errno));
		return -1;
	}
	retval = ioctl(fd, request, arg);
	if (retval != 0) {
		DEBUG_WARN("failed to exect cmd %s errno %d %s\n", print_ioc_cmd(request), errno, strerror(errno));
	}
	close(fd);
	return retval;
}

int
tl_ioctl(unsigned long int request, void *arg)
{
	return tl_ioctl2(TL_DEV, request, arg);
}

int
tl_ioctl_void(unsigned long int request)
{
	int fd;
	int retval;

	if (iodev_check() < 0)
		return -1;

	if ((fd = open(TL_DEV, O_RDONLY)) < 0)
	{
		return -1;
	}
	retval = ioctl(fd, request);
	close(fd);
	return retval;
}

#define LOG_BUFFER_SIZE		(1024 * 1024)

int
usage_percentage(uint64_t size, uint64_t used)
{
	if (used > size)
		return 100;

	return (100 - (((double)(size - used)/size) * 100));
}

void
get_transfer_rate(double bytes, long elapsed, char *buf)
{
	double trate = bytes/elapsed;

	if (trate >= (1024 * 1024 * 1024)) {
		sprintf(buf, "%.2f GB/s", (trate / (1024.00 * 1024.00 * 1024.00)));
	}
	else if (trate >= (1024 * 1024)) {
		sprintf(buf, "%.2f MB/s", (trate / (1024.00 * 1024.00)));
	}
	else {
		sprintf(buf, "%.2f KB/s", (trate / (1024.00)));
	}
}

void
get_data_str(double bytes, char *buf)
{
	if (bytes >= (1024ULL * 1024ULL * 1024ULL * 1024ULL)) {
		sprintf(buf, "%.3f TB", (bytes / (1024.00 * 1024.00 * 1024.00 * 1024.00)));
	}
	else if (bytes >= (1024 * 1024 * 1024)) {
		sprintf(buf, "%.2f GB", (bytes / (1024.00 * 1024.00 * 1024.00)));
	}
	else if (bytes >= (1024 * 1024)) {
		sprintf(buf, "%.2f MB", (bytes / (1024.00 * 1024.00)));
	}
	else {
		sprintf(buf, "%.2f KB", (bytes / (1024.00)));
	}
}

void
get_data_str_int(uint64_t bytes, char *buf)
{
#if 0 
	if (bytes >= (1ULL << 40)) {
		sprintf(buf, "%llu TB", (unsigned long long)(bytes >> 40));
	}
	else if (bytes >= (1ULL << 30)) {
#endif
	if (bytes >= (1ULL << 30)) {
		sprintf(buf, "%llu GB", (unsigned long long)(bytes >> 30));
	}
	else if (bytes >= (1ULL << 20)) {
		sprintf(buf, "%llu MB", (unsigned long long)(bytes >> 20));
	}
	else {
		sprintf(buf, "%llu KB", (unsigned long long)(bytes >> 10));
	}
}

int
ipaddr_valid(char *addr)
{
	struct sockaddr_in in_addr;
	int retval;
	uint32_t a = 0, b = 0, c = 0, d = 0;

	retval = inet_pton(AF_INET, addr, &in_addr);
	if (retval <= 0)
		return 0;

	if (strlen(addr) > 15)
		return 0;

	if (sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return 0;

	if (!a)
		return 0;

	if (d == 0 || d == 255)
		return 0;

	return 1;
}

#define atomic_test_bit(b, p)                                           \
({                                                                      \
	int __ret;                                                      \
	__ret = ((volatile int *)p)[b >> 5] & (1 << (b & 0x1f));        \
	__ret;                                                          \
})

void
get_mirror_status_str(struct mirror_state *mirror_state, char *status)
{
	status[0] = 0;
	if (atomic_test_bit(MIRROR_FLAGS_STATE_INVALID, &mirror_state->mirror_flags)) {
		strcpy(status, "Invalid state!");
	}
	else if (atomic_test_bit(MIRROR_FLAGS_WAIT_FOR_MASTER, &mirror_state->mirror_flags)) {
		strcpy(status, "Peer wait");
	}
	else if (atomic_test_bit(MIRROR_FLAGS_WAIT_FOR_PEER, &mirror_state->mirror_flags)) {
		strcpy(status, "Peer wait");
	}
	else if (atomic_test_bit(MIRROR_FLAGS_DISABLED, &mirror_state->mirror_flags)) {
		strcpy(status, "Disabled");
	}
	else {
		if (atomic_test_bit(MIRROR_FLAGS_NEED_RESYNC, &mirror_state->mirror_flags))
			strcpy(status, "Resync needed");
		else if (atomic_test_bit(MIRROR_FLAGS_IN_RESYNC, &mirror_state->mirror_flags))
			strcpy(status, "Resyncing");
		else
			strcpy(status, "Enabled");
	}
}

