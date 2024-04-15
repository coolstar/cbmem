// cbmem.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "getopt.h"
#include "regex.h"
#include "loglevel.h"
#include "timestamp_serialized.h"
#include "cbtable.h"
#include "cbmem_id.h"

#define strncasecmp(x,y,z) _strnicmp(x,y,z)
#define isstdouttty false //isatty(fileno(stdout))

#define ARRAY_SIZE(x) sizeof(x)/sizeof(x[0])

#define CBMEM_VERSION "1.0 (Compatible with 1.1 upstream)"

#define CBMEM_NAME L"BOOT0000"
#define CBMEM_SYMBOLIC_NAME L"\\DosDevices\\" CBMEM_NAME
#define CBMEM_USERMODE_PATH L"\\\\.\\" CBMEM_NAME
#define CBMEM_USERMODE_PATH_SIZE sizeof(CBMEM_USERMODE_PATH)

/* verbose output? */
static int verbose = 0;
HANDLE cbmemDrv;

#define debug(x, ...) do {\
	if (verbose)\
		printf(x, __VA_ARGS__); \
} while (false)

#define die(x, ...) do {\
	fprintf(stderr, x, __VA_ARGS__);\
	exit(-1); \
} while (false)
	
enum NextRequest {
	NextRequestConsole,
	NextRequestTimestamps,
	NextRequestRoot,
	NextRequestTcpa,
	NextRequestReserved
};

static bool writeDriverCommand(PVOID buffer, DWORD len) {
	if (cbmemDrv == NULL)
		return false;

	ULONG bytesWritten;

	if ((WriteFile(cbmemDrv,
		buffer,
		len,
		&bytesWritten,
		NULL) == TRUE) ||
		(GetLastError() != ERROR_IO_PENDING)) {
		return true;
	}
	return false;
}

static ULONG readDriverCommand(PVOID buffer, DWORD len) {
	if (cbmemDrv == NULL)
		return 0;

	ULONG bytesRead;

	if ((ReadFile(cbmemDrv,
		buffer,
		len,
		&bytesRead,
		NULL) == TRUE) ||
		(GetLastError() != ERROR_IO_PENDING)) {
		debug("Read %d bytes (wanted %d)\n", bytesRead, len);
		return bytesRead;
	}
	return 0;
}

static UINT8* mapMemory(enum NextRequest request, size_t size) {
	debug("Writing command to driver\n");
	if (!writeDriverCommand(&request, sizeof(request)))
		return NULL;

	UINT8* buf = malloc(size);
	RtlZeroMemory(buf, size);

	debug("Reading memory from driver\n");

	if (!readDriverCommand(buf, (DWORD)size)) {
		free(buf);
		return NULL;
	}

	if (size > 4) {
		debug("First 4 bytes: 0x%x 0x%x 0x%x 0x%x\n", buf[0], buf[1], buf[2], buf[3]);
	}

	debug("Mapped requested memory\n");
	return buf;
}

static unsigned long arch_tick_frequency(void)
{
	DWORD BufSize = _MAX_PATH;
	DWORD dwMHz = _MAX_PATH;
	HKEY hKey;

	// open the key where the proc speed is hidden:
	long lError = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
		0,
		KEY_READ,
		&hKey);
	assert(lError == ERROR_SUCCESS);

	// query the key:
	RegQueryValueEx(hKey, "~MHz", NULL, NULL, (LPBYTE)&dwMHz, &BufSize);
	return dwMHz;
}

static unsigned long tick_freq_mhz;
static void timestamp_set_tick_freq(unsigned long table_tick_freq_mhz)
{
	tick_freq_mhz = table_tick_freq_mhz;

	/* Honor table frequency if present. */
	if (!tick_freq_mhz)
		tick_freq_mhz = arch_tick_frequency();

	if (!tick_freq_mhz) {
		fprintf(stderr, "Cannot determine timestamp tick frequency.\n");
		exit(1);
	}

	debug("Timestamp tick frequency: %ld MHz\n", tick_freq_mhz);
}

static uint64_t arch_convert_raw_ts_entry(uint64_t ts)
{
	return ts / tick_freq_mhz;
}

/*
 * Print an integer in 'normalized' form - with commas separating every three
 * decimal orders.
 */
static void print_norm(uint64_t v)
{
	if (v >= 1000) {
		/* print the higher order sections first */
		print_norm(v / 1000);
		printf(",%3.3u", (uint32_t)(v % 1000));
	}
	else {
		printf("%u", (uint32_t)(v % 1000));
	}
}

static const char* timestamp_name(uint32_t id)
{
	for (size_t i = 0; i < ARRAY_SIZE(timestamp_ids); i++) {
		if (timestamp_ids[i].id == id)
			return timestamp_ids[i].name;
	}
	return "<unknown>";
}

static uint32_t timestamp_enum_name_to_id(const char* name)
{
	for (size_t i = 0; i < ARRAY_SIZE(timestamp_ids); i++) {
		if (!strcmp(timestamp_ids[i].enum_name, name))
			return timestamp_ids[i].id;
	}
	return 0;
}

static uint64_t timestamp_print_parseable_entry(uint32_t id, uint64_t stamp,
	uint64_t prev_stamp)
{
	const char* name;
	uint64_t step_time;

	name = timestamp_name(id);

	step_time = arch_convert_raw_ts_entry(stamp - prev_stamp);

	/* ID<tab>absolute time<tab>relative time<tab>description */
	printf("%d\t", id);
	printf("%llu\t", (long long)arch_convert_raw_ts_entry(stamp));
	printf("%llu\t", (long long)step_time);
	printf("%s\n", name);

	return step_time;
}

static uint64_t timestamp_print_entry(uint32_t id, uint64_t stamp, uint64_t prev_stamp)
{
	const char* name;
	uint64_t step_time;

	name = timestamp_name(id);

	printf("%4d:", id);
	printf("%-50s", name);
	print_norm(arch_convert_raw_ts_entry(stamp));
	step_time = arch_convert_raw_ts_entry(stamp - prev_stamp);
	if (prev_stamp) {
		printf(" (");
		print_norm(step_time);
		printf(")");
	}
	printf("\n");

	return step_time;
}

static int compare_timestamp_entries(const void* a, const void* b)
{
	const struct timestamp_entry* tse_a = (struct timestamp_entry*)a;
	const struct timestamp_entry* tse_b = (struct timestamp_entry*)b;

	if (tse_a->entry_stamp > tse_b->entry_stamp)
		return 1;
	else if (tse_a->entry_stamp < tse_b->entry_stamp)
		return -1;

	return 0;
}

static int find_matching_end(struct timestamp_table* sorted_tst_p, uint32_t start, uint32_t end)
{
	uint32_t id = sorted_tst_p->entries[start].entry_id;
	uint32_t possible_match = 0;

	for (uint32_t i = 0; i < ARRAY_SIZE(timestamp_ids); ++i) {
		if (timestamp_ids[i].id == id) {
			possible_match = timestamp_ids[i].id_end;
			break;
		}
	}

	/* No match found or timestamp not defined in IDs table */
	if (!possible_match)
		return -1;

	for (uint32_t i = start + 1; i < end; i++)
		if (sorted_tst_p->entries[i].entry_id == possible_match)
			return i;

	return -1;
}

static const char* get_timestamp_name(const uint32_t id)
{
	for (uint32_t i = 0; i < ARRAY_SIZE(timestamp_ids); i++)
		if (timestamp_ids[i].id == id)
			return timestamp_ids[i].enum_name;

	return "UNKNOWN";
}

struct ts_range_stack {
	const char* name;
	const char* end_name;
	uint32_t end;
};

static void print_with_path(struct ts_range_stack* range_stack, const int stacklvl,
	const uint64_t stamp, const char* last_part)
{
	for (int i = 1; i <= stacklvl; ++i) {
		printf("%s -> %s", range_stack[i].name, range_stack[i].end_name);
		if (i < stacklvl || last_part)
			putchar(';');
	}
	if (last_part)
		printf("%s", last_part);
	printf(" %llu\n", (long long)arch_convert_raw_ts_entry(stamp));
}

enum timestamps_print_type {
	TIMESTAMPS_PRINT_NONE,
	TIMESTAMPS_PRINT_NORMAL,
	TIMESTAMPS_PRINT_MACHINE_READABLE,
	TIMESTAMPS_PRINT_STACKED,
};

/* dump the timestamp table */
static void dump_timestamps(enum timestamps_print_type output_type)
{
	const struct timestamp_table* tst_p;
	struct timestamp_table* sorted_tst_p;
	size_t size;
	uint64_t prev_stamp = 0;
	uint64_t total_time = 0;

	size = sizeof(*tst_p);
	tst_p = mapMemory(NextRequestTimestamps, size);
	if (!tst_p)
		die("Unable to map timestamp header\n");

	timestamp_set_tick_freq(tst_p->tick_freq_mhz);

	if (output_type == TIMESTAMPS_PRINT_NORMAL)
		printf("%d entries total:\n\n", tst_p->num_entries);
	size += tst_p->num_entries * sizeof(tst_p->entries[0]);

	free(tst_p);

	tst_p = mapMemory(NextRequestTimestamps, size);
	if (!tst_p)
		die("Unable to map full timestamp table\n");

	sorted_tst_p = malloc(size + sizeof(struct timestamp_entry));
	if (!sorted_tst_p)
		die("Failed to allocate memory");
	memcpy(sorted_tst_p, tst_p, size);

	/*
	 * Insert a timestamp to represent the base time (start of coreboot),
	 * in case we have to rebase for negative timestamps below.
	 */
	sorted_tst_p->entries[tst_p->num_entries].entry_id = 0;
	sorted_tst_p->entries[tst_p->num_entries].entry_stamp = 0;
	sorted_tst_p->num_entries += 1;

	qsort(&sorted_tst_p->entries[0], sorted_tst_p->num_entries,
		sizeof(struct timestamp_entry), compare_timestamp_entries);

	/*
	 * If there are negative timestamp entries, rebase all of the
	 * timestamps to the lowest one in the list.
	 */
	if (sorted_tst_p->entries[0].entry_stamp < 0) {
		sorted_tst_p->base_time = -sorted_tst_p->entries[0].entry_stamp;
		prev_stamp = 0;
	}
	else {
		prev_stamp = tst_p->base_time;
	}

	struct ts_range_stack range_stack[20];
	range_stack[0].end = sorted_tst_p->num_entries;
	int stacklvl = 0;

	for (uint32_t i = 0; i < sorted_tst_p->num_entries; i++) {
		uint64_t stamp;
		const struct timestamp_entry* tse = &sorted_tst_p->entries[i];

		/* Make all timestamps absolute. */
		stamp = tse->entry_stamp + sorted_tst_p->base_time;
		if (output_type == TIMESTAMPS_PRINT_MACHINE_READABLE) {
			timestamp_print_parseable_entry(tse->entry_id, stamp, prev_stamp);
		}
		else if (output_type == TIMESTAMPS_PRINT_NORMAL) {
			total_time += timestamp_print_entry(tse->entry_id, stamp, prev_stamp);
		}
		else if (output_type == TIMESTAMPS_PRINT_STACKED) {
			bool end_of_range = false;
			/* Iterate over stacked entries to pop all ranges, which are closed by
			   current element. For example, assuming two ranges: (TS_A, TS_C),
			   (TS_B, TS_C) it will pop all of them instead of just last one. */
			while (stacklvl > 0 && range_stack[stacklvl].end == i) {
				end_of_range = true;
				stacklvl--;
			}

			int match =
				find_matching_end(sorted_tst_p, i, range_stack[stacklvl].end);
			if (match != -1) {
				const uint64_t match_stamp =
					sorted_tst_p->entries[match].entry_stamp
					+ sorted_tst_p->base_time;
				stacklvl++;
				assert(stacklvl < (int)ARRAY_SIZE(range_stack));
				range_stack[stacklvl].name = get_timestamp_name(tse->entry_id);
				range_stack[stacklvl].end_name = get_timestamp_name(
					sorted_tst_p->entries[match].entry_id);
				range_stack[stacklvl].end = match;
				print_with_path(range_stack, stacklvl, match_stamp - stamp,
					NULL);
			}
			else if (!end_of_range) {
				print_with_path(range_stack, stacklvl, stamp - prev_stamp,
					get_timestamp_name(tse->entry_id));
			}
			/* else: No match && end_of_range == true */
		}
		prev_stamp = stamp;
	}

	if (output_type == TIMESTAMPS_PRINT_NORMAL) {
		printf("\nTotal Time: ");
		print_norm(total_time);
		printf("\n");
	}

	free(tst_p);
	free(sorted_tst_p);
}

/* dump the tcpa log table */
static void dump_tcpa_log(void)
{
	const struct tcpa_table* tclt_p;
	size_t size;

	size = sizeof(*tclt_p);
	tclt_p = mapMemory(NextRequestTcpa, size);
	if (!tclt_p)
		die("Unable to map tcpa log header\n");

	size += tclt_p->num_entries * sizeof(tclt_p->entries[0]);

	free(tclt_p);

	tclt_p = mapMemory(NextRequestTcpa, size);
	if (!tclt_p)
		die("Unable to map full tcpa log table\n");

	printf("coreboot TCPA log:\n\n");

	for (uint16_t i = 0; i < tclt_p->num_entries; i++) {
		const struct tcpa_entry* tce = &tclt_p->entries[i];

		printf(" PCR-%u ", tce->pcr);

		for (uint32_t j = 0; j < tce->digest_length; j++)
			printf("%02x", tce->digest[j]);

		printf(" %s [%s]\n", tce->digest_type, tce->name);
	}

	free(tclt_p);
}

enum console_print_type {
	CONSOLE_PRINT_FULL = 0,
	CONSOLE_PRINT_LAST,
	CONSOLE_PRINT_PREVIOUS,
};

static int parse_loglevel(char* arg, int* print_unknown_logs)
{
	if (arg[0] == '+') {
		*print_unknown_logs = 1;
		arg++;
	}
	else {
		*print_unknown_logs = 0;
	}

	char* endptr;
	int loglevel = strtol(arg, &endptr, 0);
	if (*endptr == '\0' && loglevel >= BIOS_EMERG && loglevel <= BIOS_LOG_PREFIX_MAX_LEVEL)
		return loglevel;

	/* Only match first 3 characters so `NOTE` and `NOTICE` both match. */
	for (int i = BIOS_EMERG; i <= BIOS_LOG_PREFIX_MAX_LEVEL; i++)
		if (!strncasecmp(arg, bios_log_prefix[i], 3))
			return i;

	*print_unknown_logs = 1;
	return BIOS_NEVER;
}

/* dump the cbmem console */
static void dump_console(enum console_print_type type, int max_loglevel, int print_unknown_logs)
{
	const struct cbmem_console* console_p;
	char* console_c;
	size_t size, cursor, previous;

	debug("Mapping initial console\n");

	size = sizeof(*console_p);
	console_p = (const struct cbmem_console *)mapMemory(NextRequestConsole, size);
	if (!console_p)
		die("Unable to map console object.\n");

	debug("Mapped initial console\n");

	cursor = console_p->cursor & CBMC_CURSOR_MASK;
	if (!(console_p->cursor & CBMC_OVERFLOW) && cursor < console_p->size)
		size = cursor;
	else
		size = console_p->size;
	free((void *)console_p);

	debug("Remapping full console size %d\n", size);

	console_c = malloc(size + 1);
	if (!console_c) {
		fprintf(stderr, "Not enough memory for console.\n");
		exit(1);
	}
	console_c[size] = '\0';

	console_p = (const struct cbmem_console*)mapMemory(NextRequestConsole,
		size + sizeof(*console_p));

	debug("Mapped full console\n");

	if (!console_p)
		die("Unable to map full console object.\n");

	if (console_p->cursor & CBMC_OVERFLOW) {
		if (cursor >= size) {
			printf("cbmem: ERROR: CBMEM console struct is illegal, "
				"output may be corrupt or out of order!\n\n");
			cursor = 0;
		}
		memcpy(console_c, console_p->body + cursor,
			size - cursor);
		memcpy(console_c + size - cursor,
			console_p->body, cursor);
	}
	else {
		memcpy(console_c, console_p->body, size);
	}

	/* Slight memory corruption may occur between reboots and give us a few
	   unprintable characters like '\0'. Replace them with '?' on output. */
	for (cursor = 0; cursor < size; cursor++)
		if (!isprint(console_c[cursor]) && !isspace(console_c[cursor])
			&& !BIOS_LOG_IS_MARKER(console_c[cursor]))
			console_c[cursor] = '?';

	/* We detect the reboot cutoff by looking for a bootblock, romstage or
	   ramstage banner, in that order (to account for platforms without
	   CONFIG_BOOTBLOCK_CONSOLE and/or CONFIG_EARLY_CONSOLE). Once we find
	   a banner, store the last two matches for that stage and stop. */
	cursor = previous = 0;
	if (type != CONSOLE_PRINT_FULL) {
#define BANNER_REGEX(stage) \
		"\n\n.?coreboot-[^\n]* " stage " starting.*\\.\\.\\.\n"
#define OVERFLOW_REGEX(stage) "\n.?\\*\\*\\* Pre-CBMEM " stage " console overflow"
		const char* regex[] = { BANNER_REGEX("verstage-before-bootblock"),
					BANNER_REGEX("bootblock"),
					BANNER_REGEX("verstage"),
					OVERFLOW_REGEX("romstage"),
					BANNER_REGEX("romstage"),
					OVERFLOW_REGEX("ramstage"),
					BANNER_REGEX("ramstage") };

		for (size_t i = 0; !cursor && i < ARRAY_SIZE(regex); i++) {
			regex_t re;
			regmatch_t match;
			int res = tre_regcomp(&re, regex[i], REG_EXTENDED);
			assert(res == 0);

			/* Keep looking for matches so we find the last one. */
			while (!tre_regexec(&re, console_c + cursor, 1, &match, 0)) {
				previous = cursor;
				cursor += match.rm_so + 1;
			}
			tre_regfree(&re);
		}
	}

	if (type == CONSOLE_PRINT_PREVIOUS) {
		console_c[cursor] = '\0';
		cursor = previous;
	}

	char c;
	int suppressed = 0;
	int tty = isstdouttty;
	while ((c = console_c[cursor++])) {
		if (BIOS_LOG_IS_MARKER(c)) {
			int lvl = BIOS_LOG_MARKER_TO_LEVEL(c);
			if (lvl > max_loglevel) {
				suppressed = 1;
				continue;
			}
			suppressed = 0;
			if (tty)
				printf(BIOS_LOG_ESCAPE_PATTERN, bios_log_escape[lvl]);
			printf(BIOS_LOG_PREFIX_PATTERN, bios_log_prefix[lvl]);
		}
		else {
			if (!suppressed)
				putchar(c);
			if (c == '\n') {
				if (tty && !suppressed)
					printf(BIOS_LOG_ESCAPE_RESET);
				suppressed = !print_unknown_logs;
			}
		}
	}
	if (tty)
		printf(BIOS_LOG_ESCAPE_RESET);

	free(console_c);
	free(console_p);
}

static void hexdump(const uint8_t* m, int length)
{
	int i;
	int all_zero = 0;

	for (i = 0; i < length; i += 16) {
		int j;

		all_zero++;
		for (j = 0; j < 16; j++) {
			if (m[i + j] != 0) {
				all_zero = 0;
				break;
			}
		}

		if (all_zero < 2) {
			printf("%08lx:", i);
			for (j = 0; j < 16; j++)
				printf(" %02x", m[i + j]);
			printf("  ");
			for (j = 0; j < 16; j++)
				printf("%c", isprint(m[i + j]) ? m[i + j] : '.');
			printf("\n");
		}
		else if (all_zero == 2) {
			printf("...\n");
		}
	}
}

static void dump_cbmem_hex(void)
{
	int i;
	const uint8_t* table;
	size_t offset;

	const struct coreboot_table_header* header = mapMemory(NextRequestRoot, sizeof(struct coreboot_table_header));
	if (!header)
		die("Unable to get root table header\n");

	size_t tableSize = header->table_bytes + header->header_bytes;
	table = mapMemory(NextRequestRoot, tableSize);
	free(header);

	if (table == NULL)
		return;

	hexdump(table, tableSize);
	free(table);
}

struct cbmem_id_to_name {
	uint32_t id;
	const char* name;
};
static const struct cbmem_id_to_name cbmem_ids[] = { CBMEM_ID_TO_NAME_TABLE };

#define MAX_STAGEx 10
static void cbmem_print_entry(int n, uint32_t id, uint64_t base, uint64_t size)
{
	const char* name;
	char stage_x[20];

	name = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(cbmem_ids); i++) {
		if (cbmem_ids[i].id == id) {
			name = cbmem_ids[i].name;
			break;
		}
		if (id >= CBMEM_ID_STAGEx_META &&
			id < CBMEM_ID_STAGEx_META + MAX_STAGEx) {
			snprintf(stage_x, sizeof(stage_x), "STAGE%d META",
				(id - CBMEM_ID_STAGEx_META));
			name = stage_x;
		}
		if (id >= CBMEM_ID_STAGEx_CACHE &&
			id < CBMEM_ID_STAGEx_CACHE + MAX_STAGEx) {
			snprintf(stage_x, sizeof(stage_x), "STAGE%d $  ",
				(id - CBMEM_ID_STAGEx_CACHE));
			name = stage_x;
		}
	}

	printf("%2d. ", n);
	if (name == NULL)
		printf("\t\t%08x", id);
	else
		printf("%s\t%08x", name, id);
	printf("  %08" PRIx64 " ", base);
	printf("  %08" PRIx64 "\n", size);
}

static void dump_cbmem_toc(void)
{
	int i;
	const uint8_t* table;
	size_t offset;

	const struct coreboot_table_header* header = mapMemory(NextRequestRoot, sizeof(struct coreboot_table_header));
	if (!header)
		die("Unable to get root table header\n");

	size_t tableSize = header->table_bytes + header->header_bytes;
	table = mapMemory(NextRequestRoot, tableSize);
	free(header);

	if (table == NULL)
		return;

	printf("CBMEM table of contents:\n");
	printf("    NAME          ID           START      LENGTH\n");

	i = 0;
	offset = 0;

	while (offset < tableSize) {
		const struct coreboot_table_entry* lbr;
		struct lb_cbmem_entry lbe;

		lbr = (const void*)(table + offset);
		offset += lbr->size;

		if (lbr->tag != LB_TAG_CBMEM_ENTRY)
			continue;

		memcpy(&lbe, lbr, sizeof(lbe));
		cbmem_print_entry(i, lbe.id, lbe.address, lbe.entry_size);
		i++;
	}

	free(table);
}

static void print_usage(const char* name, int exit_code)
{
	printf("usage: %s [-cltTLxVvh?]\n", name);
	printf("\n"
		"   -c | --console:                   print cbmem console\n"
		"   -1 | --oneboot:                   print cbmem console for last boot only\n"
		"   -2 | --2ndtolast:                 print cbmem console for the boot that came before the last one only\n"
		"   -B | --loglevel:                  maximum loglevel to print; prefix `+` (e.g. -B +INFO) to also print lines that have no level\n"
		"   -l | --list:                      print cbmem table of contents\n"
		"   -x | --hexdump:                   print hexdump of cbmem area\n"
		"   -t | --timestamps:                print timestamp information\n"
		"   -T | --parseable-timestamps:      print parseable timestamps\n"
		"   -S | --stacked-timestamps:        print stacked timestamps (e.g. for flame graph tools)\n"
		"   -L | --tcpa-log                   print TCPA log\n"
		"   -V | --verbose:                   verbose (debugging) output\n"
		"   -v | --version:                   print the version\n"
		"   -h | --help:                      print this help\n"
		"\n");
	exit(exit_code);
}

static void print_version(void)
{
	printf("cbmem for Windows v%s -- ", CBMEM_VERSION);
	printf("Copyright (C) 2022 CoolStar.  All rights reserved.\n\n");
	printf(
		"This program is free software: you can redistribute it and/or modify\n"
		"it under the terms of the GNU General Public License as published by\n"
		"the Free Software Foundation, version 2 of the License.\n\n"
		"This program is distributed in the hope that it will be useful,\n"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
		"GNU General Public License for more details.\n\n");
}

int main(int argc, char** argv)
{
	int print_defaults = 1;
	int print_console = 0;
	int print_list = 0;
	int print_hexdump = 0;
	int print_tcpa_log = 0;
	enum timestamps_print_type timestamp_type = TIMESTAMPS_PRINT_NONE;
	enum console_print_type console_type = CONSOLE_PRINT_FULL;
	int max_loglevel = BIOS_NEVER;
	int print_unknown_logs = 1;

	int opt, option_index = 0;
	static struct option long_options[] = {
		{"console", 0, 0, 'c'},
		{"oneboot", 0, 0, '1'},
		{"2ndtolast", 0, 0, '2'},
		{"loglevel", required_argument, 0, 'B'},
		{"list", 0, 0, 'l'},
		{"tcpa-log", 0, 0, 'L'},
		{"timestamps", 0, 0, 't'},
		{"parseable-timestamps", 0, 0, 'T'},
		{"stacked-timestamps", 0, 0, 'S'},
		{"hexdump", 0, 0, 'x'},
		{"verbose", 0, 0, 'V'},
		{"version", 0, 0, 'v'},
		{"help", 0, 0, 'h'},
		{0, 0, 0, 0}
	};
	while ((opt = getopt_long(argc, argv, "c12B:ltTS:LxVvh?:",
		long_options, &option_index)) != EOF) {
		switch (opt) {
		case 'c':
			print_console = 1;
			print_defaults = 0;
			break;
		case '1':
			print_console = 1;
			console_type = CONSOLE_PRINT_LAST;
			print_defaults = 0;
			break;
		case '2':
			print_console = 1;
			console_type = CONSOLE_PRINT_PREVIOUS;
			print_defaults = 0;
			break;
		case 'B':
			max_loglevel = parse_loglevel(optarg, &print_unknown_logs);
			break;
		case 'l':
			print_list = 1;
			print_defaults = 0;
			break;
		case 'L':
			print_tcpa_log = 1;
			print_defaults = 0;
			break;
		case 'x':
			print_hexdump = 1;
			print_defaults = 0;
			break;
		case 't':
			timestamp_type = TIMESTAMPS_PRINT_NORMAL;
			print_defaults = 0;
			break;
		case 'T':
			timestamp_type = TIMESTAMPS_PRINT_MACHINE_READABLE;
			print_defaults = 0;
			break;
		case 'S':
			timestamp_type = TIMESTAMPS_PRINT_STACKED;
			print_defaults = 0;
			break;
		case 'V':
			verbose = 1;
			break;
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_usage(argv[0], 0);
			break;
		case '?':
		default:
			print_usage(argv[0], 1);
			break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Error: Extra parameter found.\n");
		print_usage(argv[0], 1);
	}

	cbmemDrv = CreateFileW(
		CBMEM_USERMODE_PATH,
		(GENERIC_READ | GENERIC_WRITE),
		0,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL
	);
	if (cbmemDrv == INVALID_HANDLE_VALUE) {
		printf("Error opening cbmem driver - %u\n", GetLastError());
		return 0;
	}

	if (print_console)
		dump_console(console_type, max_loglevel, print_unknown_logs);

	if (print_list)
		dump_cbmem_toc();

	if (print_hexdump)
		dump_cbmem_hex();

	if (print_defaults)
		timestamp_type = TIMESTAMPS_PRINT_NORMAL;

	if (timestamp_type != TIMESTAMPS_PRINT_NONE)
		dump_timestamps(timestamp_type);

	if (print_tcpa_log)
		dump_tcpa_log();

exit:
	CloseHandle(cbmemDrv);
	return 0;
}
