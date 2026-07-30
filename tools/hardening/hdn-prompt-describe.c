// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef HDN_PROMPT_METADATA_CONFIG
#define HDN_PROMPT_METADATA_CONFIG "/etc/hdn/prompt-metadata.conf"
#endif

#define HDN_PROMPT_METADATA_MAX_ACTIONS 64
#define HDN_PROMPT_METADATA_MAX_VALUE 512

struct hdn_prompt_metadata {
	char *name;
	char *title;
	char *message;
	char *consequence;
	char *risk;
};

struct hdn_prompt_metadata_config {
	struct hdn_prompt_metadata actions[HDN_PROMPT_METADATA_MAX_ACTIONS];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] ACTION\n"
		"\n"
		"Prints product-approved prompt metadata for a named action.\n"
		"Config lines: prompt NAME FIELD VALUE\n"
		"Known fields: title, message, consequence, risk\n",
		prog);
}

static char *trim(char *line)
{
	char *end;

	while (*line == ' ' || *line == '\t' || *line == '\r' ||
	       *line == '\n')
		line++;

	end = line + strlen(line);
	while (end > line &&
	       (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
		end[-1] == '\n'))
		*--end = '\0';

	return line;
}

static char *next_word(char **cursor)
{
	char *word;
	char *end;

	*cursor = trim(*cursor);
	if (!(*cursor)[0])
		return NULL;

	word = *cursor;
	end = strpbrk(word, " \t");
	if (!end) {
		*cursor = word + strlen(word);
		return word;
	}

	*end++ = '\0';
	*cursor = end;
	return word;
}

static bool safe_name(const char *name)
{
	const char *p;

	if (!name || !name[0] || !strcmp(name, ".") || !strcmp(name, ".."))
		return false;

	for (p = name; *p; p++) {
		if ((*p >= 'A' && *p <= 'Z') ||
		    (*p >= 'a' && *p <= 'z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '.' || *p == '_' || *p == '-')
			continue;
		return false;
	}

	return true;
}

static int require_safe_text(const char *field, const char *value,
			     unsigned int lineno)
{
	const unsigned char *p;
	size_t len;

	if (!value || !value[0]) {
		fprintf(stderr,
			"hdn-prompt-describe: missing %s text at line %u\n",
			field, lineno);
		return -EINVAL;
	}

	len = strlen(value);
	if (len > HDN_PROMPT_METADATA_MAX_VALUE) {
		fprintf(stderr,
			"hdn-prompt-describe: %s text too long at line %u\n",
			field, lineno);
		return -E2BIG;
	}

	for (p = (const unsigned char *)value; *p; p++) {
		if (*p >= 0x20 && *p <= 0x7e)
			continue;
		fprintf(stderr,
			"hdn-prompt-describe: unsafe %s text at line %u\n",
			field, lineno);
		return -EINVAL;
	}

	return 0;
}

static struct hdn_prompt_metadata *
find_metadata(struct hdn_prompt_metadata_config *config, const char *name)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->actions[i].name, name))
			return &config->actions[i];
	}

	return NULL;
}

static struct hdn_prompt_metadata *
find_or_add_metadata(struct hdn_prompt_metadata_config *config,
		     const char *name, unsigned int lineno)
{
	struct hdn_prompt_metadata *meta;

	meta = find_metadata(config, name);
	if (meta)
		return meta;

	if (config->count >= HDN_PROMPT_METADATA_MAX_ACTIONS) {
		fprintf(stderr,
			"hdn-prompt-describe: too many prompt metadata actions\n");
		errno = E2BIG;
		return NULL;
	}

	meta = &config->actions[config->count];
	meta->name = strdup(name);
	if (!meta->name) {
		errno = ENOMEM;
		return NULL;
	}

	config->count++;
	(void)lineno;
	return meta;
}

static int set_field(char **slot, const char *field, const char *value,
		     unsigned int lineno)
{
	char *copy;
	int ret;

	if (*slot) {
		fprintf(stderr,
			"hdn-prompt-describe: duplicate %s field at line %u\n",
			field, lineno);
		return -EINVAL;
	}

	ret = require_safe_text(field, value, lineno);
	if (ret)
		return ret;

	copy = strdup(value);
	if (!copy)
		return -ENOMEM;

	*slot = copy;
	return 0;
}

static int parse_config_line(struct hdn_prompt_metadata_config *config,
			     char *line, unsigned int lineno)
{
	struct hdn_prompt_metadata *meta;
	char *cursor;
	char *key;
	char *name;
	char *field;
	char *value;

	cursor = trim(line);
	if (!cursor[0] || cursor[0] == '#')
		return 0;

	key = next_word(&cursor);
	name = next_word(&cursor);
	field = next_word(&cursor);
	value = trim(cursor);

	if (!key || strcmp(key, "prompt")) {
		fprintf(stderr,
			"hdn-prompt-describe: unknown config key at line %u: %s\n",
			lineno, key ? key : "(null)");
		return -EINVAL;
	}
	if (!name || !field || !value[0]) {
		fprintf(stderr,
			"hdn-prompt-describe: prompt line %u needs NAME FIELD VALUE\n",
			lineno);
		return -EINVAL;
	}
	if (!safe_name(name)) {
		fprintf(stderr,
			"hdn-prompt-describe: unsafe action name at line %u: %s\n",
			lineno, name);
		return -EINVAL;
	}

	meta = find_or_add_metadata(config, name, lineno);
	if (!meta)
		return -errno;

	if (!strcmp(field, "title"))
		return set_field(&meta->title, field, value, lineno);
	if (!strcmp(field, "message"))
		return set_field(&meta->message, field, value, lineno);
	if (!strcmp(field, "consequence"))
		return set_field(&meta->consequence, field, value, lineno);
	if (!strcmp(field, "risk"))
		return set_field(&meta->risk, field, value, lineno);

	fprintf(stderr,
		"hdn-prompt-describe: unknown prompt metadata field at line %u: %s\n",
		lineno, field);
	return -EINVAL;
}

static int open_config(const char *path)
{
	struct stat st;
	int flags = O_RDONLY | O_CLOEXEC;
	int fd;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(path, flags);
	if (fd < 0) {
		fprintf(stderr, "hdn-prompt-describe: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-prompt-describe: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-prompt-describe: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_prompt_metadata_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret = 0;
	int fd;

	memset(config, 0, sizeof(*config));

	fd = open_config(path);
	if (fd < 0)
		return fd;

	file = fdopen(fd, "r");
	if (!file) {
		ret = -errno;
		close(fd);
		return ret;
	}

	while ((len = getline(&line, &size, file)) >= 0) {
		(void)len;
		lineno++;
		ret = parse_config_line(config, line, lineno);
		if (ret)
			break;
	}
	if (ferror(file) && !ret)
		ret = -EIO;

	free(line);
	fclose(file);
	return ret;
}

static void free_config(struct hdn_prompt_metadata_config *config)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		free(config->actions[i].name);
		free(config->actions[i].title);
		free(config->actions[i].message);
		free(config->actions[i].consequence);
		free(config->actions[i].risk);
	}
}

static int describe_action(struct hdn_prompt_metadata_config *config,
			   const char *action)
{
	struct hdn_prompt_metadata *meta;

	meta = find_metadata(config, action);
	if (!meta) {
		fprintf(stderr,
			"hdn-prompt-describe: prompt action is not product-approved: %s\n",
			action);
		return 1;
	}

	if (!meta->title || !meta->message || !meta->consequence) {
		fprintf(stderr,
			"hdn-prompt-describe: prompt action has incomplete metadata: %s\n",
			action);
		return 1;
	}

	printf("HDN_PROMPT_METADATA_V1\n");
	printf("action=%s\n", meta->name);
	printf("title=%s\n", meta->title);
	printf("message=%s\n", meta->message);
	printf("consequence=%s\n", meta->consequence);
	if (meta->risk)
		printf("risk=%s\n", meta->risk);
	return ferror(stdout) ? 1 : 0;
}

int main(int argc, char **argv)
{
	struct hdn_prompt_metadata_config config;
	const char *config_path = HDN_PROMPT_METADATA_CONFIG;
	const char *action = NULL;
	int ret;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			config_path = argv[i];
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else if (!action) {
			action = argv[i];
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (!action || !safe_name(action)) {
		usage(argv[0]);
		return 2;
	}

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	ret = describe_action(&config, action);
	free_config(&config);
	return ret;
}
