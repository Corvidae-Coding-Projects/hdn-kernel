// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef HDN_PROMPT_DISPATCH_CONFIG
#define HDN_PROMPT_DISPATCH_CONFIG "/etc/hdn/prompt-actions.conf"
#endif

#ifndef HDN_ADMIN_BROKER_PATH
#define HDN_ADMIN_BROKER_PATH "/usr/libexec/hdn-admin-broker"
#endif

#ifndef HDN_APPROVAL_TOKEN_PATH
#define HDN_APPROVAL_TOKEN_PATH "/usr/libexec/hdn-approval-token"
#endif

#ifndef HDN_APPROVAL_TOKEN_DIR
#define HDN_APPROVAL_TOKEN_DIR "/run/hdn/approvals"
#endif

#define HDN_PROMPT_MAX_RULES 64
#define HDN_PROMPT_MAX_ARGS 32
#define HDN_PROMPT_TOKEN_TTL_DEFAULT_MS 30000ULL
#define HDN_PROMPT_TOKEN_TTL_MAX_MS 300000ULL

struct hdn_prompt_rule {
	char *name;
	char *intent;
	char *args[HDN_PROMPT_MAX_ARGS + 1];
	unsigned int argc;
};

struct hdn_prompt_config {
	struct hdn_prompt_rule rules[HDN_PROMPT_MAX_RULES];
	unsigned int count;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [--config FILE] [--broker PATH] [--token-issuer PATH]\n"
		"       [--token-dir DIR] [--ttl-ms MS] [--dry-run] ACTION\n"
		"\n"
		"Runs a named post-auth product action through hdn-admin-broker.\n"
		"Config lines: action NAME INTENT [ARG...]\n"
		"Known intents: rofs-apply, rofs-transaction, policy-commit, policy-rollback\n",
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

static bool known_intent(const char *intent)
{
	return !strcmp(intent, "rofs-apply") ||
	       !strcmp(intent, "rofs-transaction") ||
	       !strcmp(intent, "policy-commit") ||
	       !strcmp(intent, "policy-rollback");
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
			"hdn-prompt-dispatch: %s must be absolute: %s\n",
			what, path ? path : "(null)");
		return -EINVAL;
	}
	if (path_has_dot_component(path)) {
		fprintf(stderr,
			"hdn-prompt-dispatch: %s must not contain . or .. path components: %s\n",
			what, path);
		return -EINVAL;
	}

	return 0;
}

static int require_safe_dir(const char *path)
{
	int ret = require_safe_absolute("token directory", path);

	if (ret)
		return ret;
	if (!strcmp(path, "/")) {
		fprintf(stderr,
			"hdn-prompt-dispatch: token directory / is too broad\n");
		return -EINVAL;
	}

	return 0;
}

static int parse_u64(const char *text, unsigned long long *value)
{
	char *end;

	errno = 0;
	*value = strtoull(text, &end, 10);
	if (errno || end == text || *end)
		return -EINVAL;
	return 0;
}

static int validate_rofs_apply_args(char **args, unsigned int argc,
				    unsigned int lineno)
{
	bool saw_target = false;
	unsigned int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(args[i], "-r") || !strcmp(args[i], "--recursive"))
			continue;
		if (!strcmp(args[i], "-f") || !strcmp(args[i], "--file")) {
			if (++i >= argc)
				goto bad;
			if (require_safe_absolute("readonly mount list",
						  args[i]))
				return -EINVAL;
			saw_target = true;
			continue;
		}
		if (args[i][0] == '-')
			goto bad;
		if (require_safe_absolute("mountpoint", args[i]))
			return -EINVAL;
		saw_target = true;
	}

	if (saw_target)
		return 0;

bad:
	fprintf(stderr,
		"hdn-prompt-dispatch: invalid rofs-apply action at line %u\n",
		lineno);
	return -EINVAL;
}

static int validate_rofs_transaction_args(char **args, unsigned int argc,
					  unsigned int lineno)
{
	if (argc < 3 || strcmp(args[1], "--")) {
		fprintf(stderr,
			"hdn-prompt-dispatch: rofs-transaction action at line %u needs MOUNTPOINT -- WORKER [ARG...]\n",
			lineno);
		return -EINVAL;
	}
	if (require_safe_absolute("mountpoint", args[0]) ||
	    require_safe_absolute("worker", args[2]))
		return -EINVAL;

	return 0;
}

static int validate_policy_commit_args(char **args, unsigned int argc,
				       unsigned int lineno)
{
	if (argc != 1) {
		fprintf(stderr,
			"hdn-prompt-dispatch: policy-commit action at line %u needs SIGNED_POLICY\n",
			lineno);
		return -EINVAL;
	}

	return require_safe_absolute("signed policy", args[0]);
}

static int validate_rule_args(const char *intent, char **args,
			      unsigned int argc, unsigned int lineno)
{
	if (!strcmp(intent, "rofs-apply"))
		return validate_rofs_apply_args(args, argc, lineno);
	if (!strcmp(intent, "rofs-transaction"))
		return validate_rofs_transaction_args(args, argc, lineno);
	if (!strcmp(intent, "policy-commit"))
		return validate_policy_commit_args(args, argc, lineno);
	if (!strcmp(intent, "policy-rollback")) {
		if (!argc)
			return 0;
		fprintf(stderr,
			"hdn-prompt-dispatch: policy-rollback takes no arguments at line %u\n",
			lineno);
		return -EINVAL;
	}

	return -EINVAL;
}

static int add_rule(struct hdn_prompt_config *config, char **tokens,
		    unsigned int count, unsigned int lineno)
{
	struct hdn_prompt_rule *rule;
	unsigned int argc;
	unsigned int i;

	if (count < 3) {
		fprintf(stderr,
			"hdn-prompt-dispatch: action line %u needs NAME INTENT\n",
			lineno);
		return -EINVAL;
	}
	if (config->count >= HDN_PROMPT_MAX_RULES) {
		fprintf(stderr,
			"hdn-prompt-dispatch: too many prompt actions\n");
		return -E2BIG;
	}
	if (!safe_name(tokens[1])) {
		fprintf(stderr,
			"hdn-prompt-dispatch: unsafe action name at line %u: %s\n",
			lineno, tokens[1]);
		return -EINVAL;
	}
	if (!known_intent(tokens[2])) {
		fprintf(stderr,
			"hdn-prompt-dispatch: unknown intent at line %u: %s\n",
			lineno, tokens[2]);
		return -EINVAL;
	}

	argc = count - 3;
	if (argc > HDN_PROMPT_MAX_ARGS) {
		fprintf(stderr,
			"hdn-prompt-dispatch: too many action arguments at line %u\n",
			lineno);
		return -E2BIG;
	}
	if (validate_rule_args(tokens[2], &tokens[3], argc, lineno))
		return -EINVAL;

	rule = &config->rules[config->count];
	rule->name = strdup(tokens[1]);
	rule->intent = strdup(tokens[2]);
	if (!rule->name || !rule->intent)
		return -ENOMEM;

	for (i = 0; i < argc; i++) {
		rule->args[rule->argc] = strdup(tokens[i + 3]);
		if (!rule->args[rule->argc])
			return -ENOMEM;
		rule->argc++;
	}
	rule->args[rule->argc] = NULL;
	config->count++;
	return 0;
}

static int parse_config_line(struct hdn_prompt_config *config, char *line,
			     unsigned int lineno)
{
	char *tokens[HDN_PROMPT_MAX_ARGS + 3];
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
				"hdn-prompt-dispatch: too many fields at line %u\n",
				lineno);
			return -E2BIG;
		}
		tokens[count++] = word;
	}

	if (!count)
		return 0;
	if (strcmp(tokens[0], "action")) {
		fprintf(stderr,
			"hdn-prompt-dispatch: unknown config key at line %u: %s\n",
			lineno, tokens[0]);
		return -EINVAL;
	}

	return add_rule(config, tokens, count, lineno);
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
		fprintf(stderr, "hdn-prompt-dispatch: cannot open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	if (fstat(fd, &st)) {
		int ret = -errno;

		fprintf(stderr, "hdn-prompt-dispatch: cannot stat %s: %s\n",
			path, strerror(errno));
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 022)) {
		fprintf(stderr,
			"hdn-prompt-dispatch: refusing unsafe config %s\n",
			path);
		close(fd);
		return -EACCES;
	}

	return fd;
}

static int load_config(const char *path, struct hdn_prompt_config *config)
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

static void free_config(struct hdn_prompt_config *config)
{
	unsigned int i;
	unsigned int j;

	for (i = 0; i < config->count; i++) {
		free(config->rules[i].name);
		free(config->rules[i].intent);
		for (j = 0; j < config->rules[i].argc; j++)
			free(config->rules[i].args[j]);
	}
}

static const struct hdn_prompt_rule *
find_rule(const struct hdn_prompt_config *config, const char *action)
{
	unsigned int i;

	for (i = 0; i < config->count; i++) {
		if (!strcmp(config->rules[i].name, action))
			return &config->rules[i];
	}

	return NULL;
}

static int read_token_path(int fd, char *token, size_t size)
{
	size_t done = 0;

	while (done + 1 < size) {
		ssize_t ret = read(fd, token + done, size - done - 1);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			break;
		done += (size_t)ret;
	}
	token[done] = '\0';

	while (done && (token[done - 1] == '\n' ||
			token[done - 1] == '\r' ||
			token[done - 1] == ' ' ||
			token[done - 1] == '\t'))
		token[--done] = '\0';

	if (!done || strchr(token, '\n'))
		return -EINVAL;

	return 0;
}

static int issue_token(const char *issuer, const char *intent,
		       const char *token_dir, unsigned long long ttl_ms,
		       char *token, size_t token_size)
{
	char ttl_text[32];
	int pipefd[2];
	int status;
	pid_t child;
	int ret;

	if (snprintf(ttl_text, sizeof(ttl_text), "%llu", ttl_ms) >=
	    (int)sizeof(ttl_text))
		return 1;
	if (pipe(pipefd)) {
		fprintf(stderr, "hdn-prompt-dispatch: pipe failed: %s\n",
			strerror(errno));
		return 1;
	}

	child = fork();
	if (child < 0) {
		fprintf(stderr, "hdn-prompt-dispatch: fork failed: %s\n",
			strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (!child) {
		close(pipefd[0]);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(126);
		close(pipefd[1]);
		execl(issuer, "hdn-approval-token", "--dir", token_dir,
		      "--intent", intent, "--ttl-ms", ttl_text, NULL);
		fprintf(stderr, "hdn-prompt-dispatch: exec %s failed: %s\n",
			issuer, strerror(errno));
		_exit(errno == ENOENT ? 127 : 126);
	}

	close(pipefd[1]);
	ret = read_token_path(pipefd[0], token, token_size);
	close(pipefd[0]);

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "hdn-prompt-dispatch: wait failed: %s\n",
			strerror(errno));
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		if (WIFEXITED(status))
			return WEXITSTATUS(status) ? WEXITSTATUS(status) : 1;
		return 1;
	}
	if (ret) {
		fprintf(stderr,
			"hdn-prompt-dispatch: token issuer returned an invalid token path\n");
		return 1;
	}
	if (require_safe_absolute("approval token", token))
		return 1;

	return 0;
}

static int child_status_result(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) < 0)
		return 1;
	if (!WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

static int run_rule(const char *broker, const char *token,
		    const struct hdn_prompt_rule *rule, bool dry_run)
{
	char **argv;
	unsigned int argc = 0;
	unsigned int i;
	int exec_errno;

	argv = calloc((size_t)rule->argc + 6, sizeof(*argv));
	if (!argv) {
		fprintf(stderr, "hdn-prompt-dispatch: allocation failed\n");
		unlink(token);
		return 1;
	}

	argv[argc++] = (char *)broker;
	if (dry_run)
		argv[argc++] = "--dry-run";
	argv[argc++] = "--approval-token";
	argv[argc++] = (char *)token;
	argv[argc++] = rule->intent;
	for (i = 0; i < rule->argc; i++)
		argv[argc++] = rule->args[i];
	argv[argc] = NULL;

	if (dry_run) {
		pid_t child;
		int ret;

		child = fork();
		if (child < 0) {
			fprintf(stderr, "hdn-prompt-dispatch: fork failed: %s\n",
				strerror(errno));
			free(argv);
			unlink(token);
			return 1;
		}

		if (!child) {
			execv(broker, argv);
			exec_errno = errno;
			fprintf(stderr,
				"hdn-prompt-dispatch: exec %s failed: %s\n",
				broker, strerror(exec_errno));
			_exit(exec_errno == ENOENT ? 127 : 126);
		}

		ret = child_status_result(child);
		free(argv);
		if (unlink(token)) {
			fprintf(stderr,
				"hdn-prompt-dispatch: cleanup token %s failed: %s\n",
				token, strerror(errno));
			if (!ret)
				ret = 1;
		}
		return ret;
	}

		execv(broker, argv);
	exec_errno = errno;
	fprintf(stderr, "hdn-prompt-dispatch: exec %s failed: %s\n",
		broker, strerror(exec_errno));
	free(argv);
	unlink(token);
	return exec_errno == ENOENT ? 127 : 126;
}

int main(int argc, char **argv)
{
	const char *config_path = HDN_PROMPT_DISPATCH_CONFIG;
	const char *broker_path = HDN_ADMIN_BROKER_PATH;
	const char *issuer_path = HDN_APPROVAL_TOKEN_PATH;
	const char *token_dir = HDN_APPROVAL_TOKEN_DIR;
	unsigned long long ttl_ms = HDN_PROMPT_TOKEN_TTL_DEFAULT_MS;
	const struct hdn_prompt_rule *rule;
	struct hdn_prompt_config config;
	const char *action = NULL;
	bool dry_run = false;
	char token[PATH_MAX];
	int ret = 0;
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
		if (!strcmp(argv[i], "--token-issuer")) {
			if (++i >= argc)
				goto bad_args;
			issuer_path = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--token-dir")) {
			if (++i >= argc)
				goto bad_args;
			token_dir = argv[i];
			continue;
		}
		if (!strcmp(argv[i], "--ttl-ms")) {
			if (++i >= argc || parse_u64(argv[i], &ttl_ms))
				goto bad_args;
			continue;
		}
		if (!strcmp(argv[i], "--dry-run")) {
			dry_run = true;
			continue;
		}
		if (argv[i][0] == '-')
			goto bad_args;
		if (action)
			goto bad_args;
		action = argv[i];
	}

	if (!action || !safe_name(action))
		goto bad_args;
	if (geteuid() != 0) {
		fprintf(stderr, "hdn-prompt-dispatch: must run as root\n");
		return 1;
	}
	if (!ttl_ms || ttl_ms > HDN_PROMPT_TOKEN_TTL_MAX_MS) {
		fprintf(stderr,
			"hdn-prompt-dispatch: ttl-ms must be between 1 and %llu\n",
			HDN_PROMPT_TOKEN_TTL_MAX_MS);
		return 1;
	}
	if (require_safe_absolute("config", config_path) ||
	    require_safe_absolute("broker", broker_path) ||
	    require_safe_absolute("token issuer", issuer_path) ||
	    require_safe_dir(token_dir))
		return 1;

	ret = load_config(config_path, &config);
	if (ret)
		return 1;

	rule = find_rule(&config, action);
	if (!rule) {
		fprintf(stderr,
			"hdn-prompt-dispatch: action is not product-approved: %s\n",
			action);
		free_config(&config);
		return 1;
	}

	ret = issue_token(issuer_path, rule->intent, token_dir, ttl_ms, token,
			  sizeof(token));
	if (!ret)
		ret = run_rule(broker_path, token, rule, dry_run);
	free_config(&config);
	return ret;

bad_args:
	usage(argv[0]);
	return 2;
}
