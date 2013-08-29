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

#include <apicommon.h>
#include <pthread.h>
#include "cluster.h"

static FILE *fp;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

#define QUADSTOR_SYSTEM_LOG	"/quadstor/etc/quadstor.log"
#define QUADSTOR_SYSTEM_LOG1	"/quadstor/etc/quadstor.log.1"
#define MAX_LOG_SIZE	(1 * 1024 * 1024)

int
server_openlog(void)
{
	fp = fopen(QUADSTOR_SYSTEM_LOG, "a");
	if (!fp)
		return -1;
	else
		return 0;
}

static void
server_log_trim(void)
{
	char cmd[256];

	fclose(fp);
	unlink(QUADSTOR_SYSTEM_LOG1);
	snprintf(cmd, sizeof(cmd), "cp -f %s %s", QUADSTOR_SYSTEM_LOG, QUADSTOR_SYSTEM_LOG1);
	system(cmd);
	fp = fopen(QUADSTOR_SYSTEM_LOG, "w");
}

void
server_log(char *sev, char *fmt, ...)
{
	va_list args;
	char date[256];
	time_t curtime;
	struct stat statbuf;
	int retval;

	pthread_mutex_lock(&log_lock);
	if (!fp) {
		pthread_mutex_unlock(&log_lock);
		return;
	}

	retval = stat(QUADSTOR_SYSTEM_LOG, &statbuf);

        if (retval == 0 && (statbuf.st_size > MAX_LOG_SIZE))
                server_log_trim();

	curtime = time(NULL);
	date[0] = 0;
	ctime_r(&curtime, date);
	if (date[strlen(date) - 1] == '\n')
		date[strlen(date) - 1] = 0;
	va_start(args, fmt);
	fprintf(fp, "%s %s ", date, sev);
	vfprintf(fp, fmt, args);
	va_end(args);
	fflush(fp);
	pthread_mutex_unlock(&log_lock);
}
