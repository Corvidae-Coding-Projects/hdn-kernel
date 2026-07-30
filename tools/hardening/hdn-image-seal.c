// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef HDN_IMAGE_SEAL_CONFIG
#define HDN_IMAGE_SEAL_CONFIG "/etc/hdn/image-seals.conf"
#endif

#ifndef HDN_ADMIN_BROKER_PATH
#define HDN_ADMIN_BROKER_PATH "/usr/libexec/hdn-admin-broker"
#endif

#define HDN_IMAGE_SEAL_MAX_STEPS 64

enum hdn_image_seal_op {
	HDN_IMAGE_SEAL_POLICY_COMMIT,
	HDN_IMAGE_SEAL_ROFS_APPLY,
};

struct hdn_image_seal_step {
	char *name;
	enum hdn_image_seal_op op;
	char *argument;
};

struct hdn_image_seal_config {
	struct hdn_image_seal_step steps[HDN_IMAGE_SEAL_MAX_STEPS];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--broker PATH] [--dry-run] SEAL_NAME\n"
		"\n"
		"Runs a product-approved image sealing sequence through hdn-admin-broker.\n"
		"Config lines:\n"
		"  seal NAME policy-commit SIGNED_POLICY\n"
		"  seal NAME rofs-apply READONLY_LIST\n",
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

static bool path_has_dot_component(const char *path)
{
	const char *part = path;

	while (*part) {
		const char *slash;
		size_t len;

		while (*part == '/')
			part++;
		if (!*part)
			break;

		slash = strchr(part, '/');
		len = slash ? (size_t)(slash - part) : strlen(part);
		if ((len == 1 && part[0] == '.') ||
		    (len == 2 && part[0] == '.' && part[1] == '.'))
			return true;
		part += len;
	}

	return false;
}

static int require_safe_absolute(const char *what, const char *path)
{
	if (!path || path[0] != '/') {
		fprintf(stderr, "hdn-image-seal: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-image-seal: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int add_step(struct hdn_image_seal_config *config, char **tokens,
		    unsigned int count, unsigned int lineno)
{
	struct hdn_image_seal_step *step;
	enum hdn_image_seal_op op;

	if (count != 4) {
		fprintf(stderr,
			"hdn-image-seal: seal line %u needs NAME OP ARGUMENT\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_IMAGE_SEAL_MAX_STEPS) {
		fprintf(stderr, "hdn-image-seal: too many seal steps\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1])) {
		fprintf(stderr,
			"hdn-image-seal: unsafe seal name at line %u: %s\n",
			lineno, tokens[1]);
		return -EINVAL;
	}
	if (!strcmp(tokens[2], "policy-commit"))
		op = HDN_IMAGE_SEAL_POLICY_COMMIT;
	else if (!strcmp(tokens[2], "rofs-apply"))
		op = HDN_IMAGE_SEAL_ROFS_APPLY;
	else {
		fprintf(stderr,
			"hdn-image-seal: unknown seal operation at line %u: %s\n",
			lineno, tokens[2]);
		return -EINVAL;
	}
	if (require_safe_absolute(tokens[2], tokens[3]))
		return -EINVAL;

	step = &config->steps[config->count];
	step->name = strdup(tokens[1]);
	step->argument = strdup(tokens[3]);
	if (!step->name || !step->argument)
		return -ENOMEM;
	step->op = op;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_image_seal_config *config, char *line,
			     unsigned int lineno)
{
	char *tokens[4];
	unsigned int count = 0;
	char *save = NULL;
	char *word;

	line = trim(line);
	if (!line[0] || line[0] == '#')
		return 0;

	for (word = strtok_r(line, " \t", &save); word;
	     word = strtok_r(NULL, " \t", &save)) {
		if (count >= sizeof(tokens) / sizeof(tokens[0])) {
			fprintf(stderr,
				"hdn-image-seal: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (strcmp(tokens[0], "seal")) {
		fprintf(stderr,
			"hdn-image-seal: unknown config key at line %u: %s\n",
			lineno, tokens[0]);
		return -EINVAL;
	}

	return add_step(config, tokens, count, lineno);
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
		fprintf(stderr, "hdn-image-seal: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-image-seal: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-image-seal: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path, struct hdn_image_seal_config *config)
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

static void free_config(struct hdn_image_seal_config *config)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		free(config->steps[i].name);
		free(config->steps[i].argument);
	}
}

static int run_broker_step(const char *broker, bool dry_run,
			   const struct hdn_image_seal_step *step)
{
	char *const policy_argv[] = {
		(char *)broker,
		"policy-commit",
		step->argument,
		NULL,
	};
	char *const dry_policy_argv[] = {
		(char *)broker,
		"--dry-run",
		"policy-commit",
		step->argument,
		NULL,
	};
	char *const rofs_argv[] = {
		(char *)broker,
		"seal-readonly",
		"-f",
		step->argument,
		NULL,
	};
	char *const dry_rofs_argv[] = {
		(char *)broker,
		"--dry-run",
		"seal-readonly",
		"-f",
		step->argument,
		NULL,
	};
	char *const *argv;
	int status;
	pid_t child;

	if (step->op == HDN_IMAGE_SEAL_POLICY_COMMIT)
		argv = dry_run ? dry_policy_argv : policy_argv;
	else
		argv = dry_run ? dry_rofs_argv : rofs_argv;

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-image-seal: fork failed: %s\n",
			strerror(errno));
		return 1;
	}

	if (!child) {
		execv(broker, argv);
		fprintf(stderr, "hdn-image-seal: exec %s failed: %s\n",
			broker, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "hdn-image-seal: wait failed: %s\n",
			strerror(errno));
		return 1;
	}
	if (!WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

static int run_seal(const char *broker,
		    const struct hdn_image_seal_config *config,
		    const char *name, bool dry_run)
{
	bool found = false;
	unsigned int i;
	int ret;

	for (i = 0; i < config->count; i++) {
		if (strcmp(config->steps[i].name, name))
			continue;
		found = true;
		ret = run_broker_step(broker, dry_run, &config->steps[i]);
		if (ret)
			return ret;
	}

	if (!found) {
		fprintf(stderr,
			"hdn-image-seal: seal is not product-approved: %s\n",
			name);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *config_path = HDN_IMAGE_SEAL_CONFIG;
	const char *broker_path = HDN_ADMIN_BROKER_PATH;
	struct hdn_image_seal_config config;
	const char *seal = NULL;
	bool dry_run = false;
	int ret;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		}
		if (!strcmp(argv[i], "--config")) {
			if (++i >= argc)
				goto bad_args;
			config_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--broker")) {
			if (++i >= argc)
				goto bad_args;
			broker_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
			continue;
		}
		if (argv[i][0] == '-')
			goto bad_args;
		if (seal)
			goto bad_args;
		seal = argv[i];
	}

	if (!seal || !safe_name(seal))
		goto bad_args;
	if (require_safe_absolute("config", config_path) ||
	    require_safe_absolute("broker", broker_path))
		return 1;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	ret = run_seal(broker_path, &config, seal, dry_run);
	free_config(&config);
	return ret;

bad_args:
	usage(argv[0]);
	return 2;
}
