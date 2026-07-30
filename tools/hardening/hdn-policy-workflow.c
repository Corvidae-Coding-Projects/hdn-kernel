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

#ifndef HDN_POLICY_WORKFLOW_CONFIG
#define HDN_POLICY_WORKFLOW_CONFIG "/etc/hdn/policy-workflows.conf"
#endif

#ifndef HDN_POLICY_LEARN_PATH
#define HDN_POLICY_LEARN_PATH "/usr/libexec/hdn-policy-learn"
#endif

#ifndef HDN_POLICY_MERGE_PATH
#define HDN_POLICY_MERGE_PATH "/usr/libexec/hdn-policy-merge"
#endif

#ifndef HDN_POLICY_COMPILER_PATH
#define HDN_POLICY_COMPILER_PATH "/usr/libexec/hdn-policy"
#endif

#ifndef HDN_ADMIN_BROKER_PATH
#define HDN_ADMIN_BROKER_PATH "/usr/libexec/hdn-admin-broker"
#endif

#define HDN_POLICY_WORKFLOW_MAX_RULES 64

struct hdn_policy_workflow_rule {
	char *name;
	char *base_policy;
	char *event_log;
	char *suggestions;
	char *candidate;
	char *binary_policy;
	char *signed_policy;
};

struct hdn_policy_workflow_config {
	char *learn_helper;
	char *merge_helper;
	char *compiler_helper;
	char *admin_broker;
	struct hdn_policy_workflow_rule rules[HDN_POLICY_WORKFLOW_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--learn-helper PATH] [--merge-helper PATH] [--compiler-helper PATH] [--admin-broker PATH] learn WORKFLOW\n"
		"       %s [--config FILE] [--learn-helper PATH] [--merge-helper PATH] [--compiler-helper PATH] [--admin-broker PATH] candidate WORKFLOW\n"
		"       %s [--config FILE] [--learn-helper PATH] [--merge-helper PATH] [--compiler-helper PATH] [--admin-broker PATH] compile WORKFLOW\n"
		"       %s [--config FILE] [--learn-helper PATH] [--merge-helper PATH] [--compiler-helper PATH] [--admin-broker PATH] [--dry-run] commit WORKFLOW\n"
		"\n"
		"Runs named policy learning, candidate-generation, compile, and brokered commit workflows.\n"
		"Config lines:\n"
		"  learn-helper PATH\n"
		"  merge-helper PATH\n"
		"  compiler-helper PATH\n"
		"  admin-broker PATH\n"
		"  workflow NAME BASE_POLICY EVENT_LOG SUGGESTIONS CANDIDATE_POLICY [BINARY_POLICY [SIGNED_POLICY]]\n",
		prog, prog, prog, prog);
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
		fprintf(stderr,
			"hdn-policy-workflow: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-policy-workflow: %s / is too broad\n", what);
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-policy-workflow: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int replace_string(char **slot, const char *value)
{
	char *copy = strdup(value);

	if (!copy)
		return -ENOMEM;
	free(*slot);
	*slot = copy;
	return 0;
}

static int set_helper(char **slot, const char *what, char **tokens,
		      unsigned int count, unsigned int lineno)
{
	if (count != 2) {
		fprintf(stderr,
			"hdn-policy-workflow: %s line %u needs exactly one path\n",
			what, lineno);
		return -EINVAL;
	}
	if (require_safe_absolute(what, tokens[1]))
		return -EINVAL;
	return replace_string(slot, tokens[1]);
}

static int add_workflow(struct hdn_policy_workflow_config *config,
			char **tokens, unsigned int count, unsigned int lineno)
{
	struct hdn_policy_workflow_rule *rule;

	if (count != 6 && count != 7 && count != 8) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow line %u needs NAME BASE EVENTS SUGGESTIONS CANDIDATE [BINARY [SIGNED]]\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_POLICY_WORKFLOW_MAX_RULES) {
		fprintf(stderr,
			"hdn-policy-workflow: too many workflow rules\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1])) {
		fprintf(stderr,
			"hdn-policy-workflow: unsafe workflow name at line %u: %s\n",
			lineno, tokens[1]);
		return -EINVAL;
	}
	if (require_safe_absolute("base policy", tokens[2]) ||
	    require_safe_absolute("event log", tokens[3]) ||
	    require_safe_absolute("suggestions", tokens[4]) ||
	    require_safe_absolute("candidate policy", tokens[5]))
		return -EINVAL;
	if (count == 7 && require_safe_absolute("binary policy", tokens[6]))
		return -EINVAL;
	if (count == 8 &&
	    (require_safe_absolute("binary policy", tokens[6]) ||
	     require_safe_absolute("signed policy", tokens[7])))
		return -EINVAL;
	if (!strcmp(tokens[2], tokens[3]) || !strcmp(tokens[2], tokens[4]) ||
	    !strcmp(tokens[2], tokens[5]) || !strcmp(tokens[3], tokens[4]) ||
	    !strcmp(tokens[3], tokens[5]) || !strcmp(tokens[4], tokens[5])) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow line %u reuses input/output paths\n",
			lineno);
		return -EINVAL;
	}
	if (count >= 7 &&
	    (!strcmp(tokens[6], tokens[2]) || !strcmp(tokens[6], tokens[3]) ||
	     !strcmp(tokens[6], tokens[4]) || !strcmp(tokens[6], tokens[5]))) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow line %u reuses binary output path\n",
			lineno);
		return -EINVAL;
	}
	if (count == 8 &&
	    (!strcmp(tokens[7], tokens[2]) || !strcmp(tokens[7], tokens[3]) ||
	     !strcmp(tokens[7], tokens[4]) || !strcmp(tokens[7], tokens[5]) ||
	     !strcmp(tokens[7], tokens[6]))) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow line %u reuses signed policy path\n",
			lineno);
		return -EINVAL;
	}

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->base_policy = strdup(tokens[2]);
	rule->event_log = strdup(tokens[3]);
	rule->suggestions = strdup(tokens[4]);
	rule->candidate = strdup(tokens[5]);
	if (count >= 7)
		rule->binary_policy = strdup(tokens[6]);
	if (count == 8)
		rule->signed_policy = strdup(tokens[7]);
	if (!rule->name || !rule->base_policy || !rule->event_log ||
	    !rule->suggestions || !rule->candidate ||
	    (count >= 7 && !rule->binary_policy) ||
	    (count == 8 && !rule->signed_policy))
		return -ENOMEM;

	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_policy_workflow_config *config,
			     char *line, unsigned int lineno)
{
	char *tokens[8];
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
				"hdn-policy-workflow: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (!strcmp(tokens[0], "learn-helper"))
		return set_helper(&config->learn_helper, "learn-helper",
				  tokens, count, lineno);
	if (!strcmp(tokens[0], "merge-helper"))
		return set_helper(&config->merge_helper, "merge-helper",
				  tokens, count, lineno);
	if (!strcmp(tokens[0], "compiler-helper"))
		return set_helper(&config->compiler_helper, "compiler-helper",
				  tokens, count, lineno);
	if (!strcmp(tokens[0], "admin-broker"))
		return set_helper(&config->admin_broker, "admin-broker",
				  tokens, count, lineno);
	if (!strcmp(tokens[0], "workflow"))
		return add_workflow(config, tokens, count, lineno);

	fprintf(stderr,
		"hdn-policy-workflow: unknown config key at line %u: %s\n",
		lineno, tokens[0]);
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
		fprintf(stderr, "hdn-policy-workflow: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-policy-workflow: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-policy-workflow: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path,
		       struct hdn_policy_workflow_config *config)
{
	char *line = NULL;
	size_t size = 0;
	unsigned int lineno = 0;
	ssize_t len;
	FILE *file;
	int ret;
	int fd;

	memset(config, 0, sizeof(*config));

	ret = replace_string(&config->learn_helper, HDN_POLICY_LEARN_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->merge_helper, HDN_POLICY_MERGE_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->compiler_helper, HDN_POLICY_COMPILER_PATH);
	if (ret)
		return ret;
	ret = replace_string(&config->admin_broker, HDN_ADMIN_BROKER_PATH);
	if (ret)
		return ret;

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

static void free_config(struct hdn_policy_workflow_config *config)
{
	unsigned int i;

	free(config->learn_helper);
	free(config->merge_helper);
	free(config->compiler_helper);
	free(config->admin_broker);
	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].base_policy);
		free(config->rules[i].event_log);
		free(config->rules[i].suggestions);
		free(config->rules[i].candidate);
		free(config->rules[i].binary_policy);
		free(config->rules[i].signed_policy);
	}
}

static const struct hdn_policy_workflow_rule *
find_workflow(const struct hdn_policy_workflow_config *config,
	      const char *name)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->rules[i].name, name))
			return &config->rules[i];
	}

	return NULL;
}

static int wait_for_child(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) < 0)
		return 2;
	if (!WIFEXITED(status))
		return 2;
	return WEXITSTATUS(status);
}

static int run_learn(const char *learn_helper,
		     const struct hdn_policy_workflow_rule *rule)
{
	pid_t child;
	int fd;

	fd = open(rule->suggestions,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		fprintf(stderr, "hdn-policy-workflow: cannot open %s: %s\n",
			rule->suggestions, strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		close(fd);
		return 2;
	}

	if (!child) {
		if (dup2(fd, STDOUT_FILENO) < 0)
			_exit(2);
		close(fd);
		execl(learn_helper, "hdn-policy-learn", "--input",
		      rule->event_log, NULL);
		fprintf(stderr, "hdn-policy-workflow: exec %s failed: %s\n",
			learn_helper, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	close(fd);
	return wait_for_child(child);
}

static int run_candidate(const char *merge_helper,
			 const struct hdn_policy_workflow_rule *rule)
{
	execl(merge_helper, "hdn-policy-merge", rule->base_policy,
	      rule->suggestions, rule->candidate, NULL);
	fprintf(stderr, "hdn-policy-workflow: exec %s failed: %s\n",
		merge_helper, strerror(errno));
	return errno == ENOENT ? 127 : 126;
}

static int run_compile(const char *compiler_helper,
		       const struct hdn_policy_workflow_rule *rule)
{
	if (!rule->binary_policy) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow has no binary policy output\n");
		return 1;
	}

	execl(compiler_helper, "hdn-policy", rule->candidate,
	      rule->binary_policy, NULL);
	fprintf(stderr, "hdn-policy-workflow: exec %s failed: %s\n",
		compiler_helper, strerror(errno));
	return errno == ENOENT ? 127 : 126;
}

static int run_commit(const char *admin_broker, bool dry_run,
		      const struct hdn_policy_workflow_rule *rule)
{
	if (!rule->signed_policy) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow has no signed policy input\n");
		return 1;
	}

	if (dry_run)
		execl(admin_broker, "hdn-admin-broker", "--dry-run",
		      "policy-commit", rule->signed_policy, NULL);
	else
		execl(admin_broker, "hdn-admin-broker", "policy-commit",
		      rule->signed_policy, NULL);
	fprintf(stderr, "hdn-policy-workflow: exec %s failed: %s\n",
		admin_broker, strerror(errno));
	return errno == ENOENT ? 127 : 126;
}

int main(int argc, char **argv)
{
	struct hdn_policy_workflow_config config;
	const struct hdn_policy_workflow_rule *rule;
	const char *config_path = HDN_POLICY_WORKFLOW_CONFIG;
	const char *learn_helper_override = NULL;
	const char *merge_helper_override = NULL;
	const char *compiler_helper_override = NULL;
	const char *admin_broker_override = NULL;
	const char *command = NULL;
	const char *workflow = NULL;
	bool dry_run = false;
	int i;
	int ret;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			config_path = argv[i];
		} else if (!strcmp(argv[i], "--learn-helper")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			learn_helper_override = argv[i];
		} else if (!strcmp(argv[i], "--merge-helper")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			merge_helper_override = argv[i];
		} else if (!strcmp(argv[i], "--compiler-helper")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			compiler_helper_override = argv[i];
		} else if (!strcmp(argv[i], "--admin-broker")) {
			if (++i >= argc) {
				usage(argv[0]);
				return 2;
			}
			admin_broker_override = argv[i];
		} else if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
		} else if (!strcmp(argv[i], "-h") ||
			   !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			return 0;
		} else {
			command = argv[i];
			if (++i < argc)
				workflow = argv[i];
			break;
		}
	}

	if (!command || !workflow || i + 1 != argc ||
	    (strcmp(command, "learn") && strcmp(command, "candidate") &&
	     strcmp(command, "compile") && strcmp(command, "commit"))) {
		usage(argv[0]);
		return 2;
	}
	if (dry_run && strcmp(command, "commit")) {
		fprintf(stderr,
			"hdn-policy-workflow: --dry-run is only valid with commit\n");
		return 2;
	}

	if (!safe_name(workflow)) {
		fprintf(stderr,
			"hdn-policy-workflow: unsafe workflow name: %s\n",
			workflow);
		return 1;
	}
	if (require_safe_absolute("config", config_path))
		return 1;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	if (learn_helper_override) {
		if (require_safe_absolute("learn-helper", learn_helper_override)) {
			free_config(&config);
			return 1;
		}
		ret = replace_string(&config.learn_helper, learn_helper_override);
		if (ret) {
			free_config(&config);
			return 2;
		}
	}
	if (compiler_helper_override) {
		if (require_safe_absolute("compiler-helper",
					  compiler_helper_override)) {
			free_config(&config);
			return 1;
		}
		ret = replace_string(&config.compiler_helper,
				     compiler_helper_override);
		if (ret) {
			free_config(&config);
			return 2;
		}
	}
	if (admin_broker_override) {
		if (require_safe_absolute("admin-broker",
					  admin_broker_override)) {
			free_config(&config);
			return 1;
		}
		ret = replace_string(&config.admin_broker, admin_broker_override);
		if (ret) {
			free_config(&config);
			return 2;
		}
	}
	if (merge_helper_override) {
		if (require_safe_absolute("merge-helper", merge_helper_override)) {
			free_config(&config);
			return 1;
		}
		ret = replace_string(&config.merge_helper, merge_helper_override);
		if (ret) {
			free_config(&config);
			return 2;
		}
	}

	rule = find_workflow(&config, workflow);
	if (!rule) {
		fprintf(stderr,
			"hdn-policy-workflow: workflow not approved: %s\n",
			workflow);
		free_config(&config);
		return 1;
	}

	if (!strcmp(command, "learn"))
		ret = run_learn(config.learn_helper, rule);
	else if (!strcmp(command, "candidate"))
		ret = run_candidate(config.merge_helper, rule);
	else if (!strcmp(command, "compile"))
		ret = run_compile(config.compiler_helper, rule);
	else
		ret = run_commit(config.admin_broker, dry_run, rule);

	free_config(&config);
	return ret;
}
