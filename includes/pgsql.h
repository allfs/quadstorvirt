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

#ifndef QUADSTOR_PGSQL_H_
#define QUADSTOR_PGSQL_H_
#include <physlib.h>
#include <libpq-fe.h>

extern PGresult *pgsql_exec_query(char *sqlcmd, PGconn **ret_conn);
uint64_t pgsql_exec_query2(char *sqlcmd, int isinsert, int *error, char *table, char *seqcol);
PGconn *pgsql_make_conn(void);
extern uint64_t pgsql_exec_query3(PGconn *conn, char *sqlcmd, int isinsert, int *error, char *table, char *seqcol);
extern PGconn *pgsql_begin(void);
extern int pgsql_commit(PGconn *conn);
extern int pgsql_rollback(PGconn *conn);

#endif
