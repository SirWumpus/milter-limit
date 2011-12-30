/*
 * milter-limit.c
 *
 * Copyright 2003, 2006 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-limit',
 *		`S=unix:/var/lib/milter-limit/socket, T=S:10s;R:10s'
 *	)dnl
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef SENDMAIL_CF
#define SENDMAIL_CF			"/etc/mail/sendmail.cf"
#endif

/*
 * Prefered cache implementation when available is Berkeley DB.
 *
 *	NULL		(default)
 * 	"bdb"		(memory/disk, persistant)
 *	"hash"		(in memory, not persistant across restarts)
 *	"flatfile"	(memory/disk, persistant, not recommend for performance)
 */
#ifndef CACHE_TYPE
#define CACHE_TYPE			NULL
#endif

#ifndef CACHE_FILE
#define CACHE_FILE			"/var/cache/" MILTER_NAME ".db"
#endif

#ifndef CACHE_TTL
#define CACHE_TTL			(7 * 24 * 3600)
#endif

/*
 * Expire entries in the cache every N connections.
 */
#ifndef GC_FREQUENCY
#define GC_FREQUENCY			250
#endif

/*
 * Policy choices are: none, tag, quarantine, later, reject, discard
 * The first letter of the policy must be unique as its the only part
 * tested.
 */
#ifndef POLICY
#define POLICY				"later"
#endif

#ifndef SUBJECT_TAG
#define SUBJECT_TAG			"[OVERLIMIT]"
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netdb.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <com/snert/lib/version.h>
#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/Cache.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/util/setBitWord.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 63
# error "LibSnert/1.63 or better is required"
#endif

#define MILTER_STRING	MILTER_NAME"/"MILTER_VERSION

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT			"%05d %s: "
#define	TAG_ARGS			data->work.cid, data->work.qid

#define X_SCANNED_BY			"X-Scanned-By"
#define X_MILTER_PASS			"X-" MILTER_NAME "-Pass"
#define X_MILTER_REPORT			"X-" MILTER_NAME "-Report"

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

typedef struct {
	time_t expires;
	unsigned long count;
} CacheEntry;

static Cache cache;
static CacheEntry cacheUndefinedEntry = { 0, 0 };

typedef struct {
	sfsistat over;
	char *key;
	char *value;
	ParsePath *path;
	CacheEntry stats;
} LimitInfo;

typedef struct {
	smfWork work;

	LimitInfo client;			/* per connection */
	LimitInfo auth;				/* per message */
	LimitInfo mail;				/* per message */
	Vector rcpts;				/* per message */
	int maxRcptConnect;			/* per connection */
	int maxRcptSender;			/* per message */
	int hasPass;				/* per message */
	int hasReport;				/* per message */
	int hasSubject;				/* per message */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */

	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
	char reply[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
} *workspace;

#define USAGE_CACHE_BY_INDIVIDUAL					\
  "Cache entries are stored by matching rule group, except those\n"	\
"# matching a bare milter specific tag with no associated IP,\n"	\
"# domain, or mail address (which are always cached by individual\n"	\
"# regardless). This option will cache all entries according to\n"	\
"# individual IP address, AUTH ID, or mail address.\n"			\
"#"

#define USAGE_POLICY							\
  "Policy to apply if a message limit has been exceeded. Specify\n"	\
"# either none, tag, quarantine, later, reject, or discard\n"		\
"#"

static const char usage_absolute_rcpt_limit[] =
  "The " MILTER_NAME "-rcpt-* tags are an absolute limit on the\n"
"# number of recipients per message and result in a 550 response.\n"
"# When disabled, the recipient limit is per message transaction\n"
"# and result in a 452 response. See RFC 2821 section 4.5.3.1.\n"
"#"
;

static Option optIntro			= { "",			NULL,		"\n# " MILTER_NAME "/" MILTER_VERSION "." MILTER_BUILD_STRING "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optCacheGcFrequency	= { "cache-gc-frequency", "250",	"Cache garbadge collection frequency." };
static Option optCacheType		= { "cache-type",	"bdb",		"Cache type from one of: bdb, flatfile, hash" };
static Option optCacheFile		= { "cache-file",	CACHE_FILE,	"Cache file path for bdb or flatfile types." };
static Option optCacheByIndividual	= { "cache-by-individual",	"-",	USAGE_CACHE_BY_INDIVIDUAL };
static Option optCountNullSender	= { "count-null-sender",	"-",	"Count the DSN null address in connecting client limits." };
static Option optPolicy			= { "policy",		POLICY,		USAGE_POLICY };
static Option optSubjectTag		= { "subject-tag",	SUBJECT_TAG,	"Subject tag for messages identified as spam." };
static Option optAbsoluteRcptLimit	= { "absolute-rcpt-limit",	"+",	usage_absolute_rcpt_limit };


#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders		= { "add-headers",	"-",			"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
	&optAbsoluteRcptLimit,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&optCacheByIndividual,
	&optCacheFile,
	&optCacheGcFrequency,
	&optCacheType,
	&optCountNullSender,
	&optPolicy,
	&optSubjectTag,
	NULL
};

/***********************************************************************
 *** Cache Support
 ***********************************************************************/

static int
cacheGet(workspace data, char *name, CacheEntry *entry)
{
	Data value;
	int rc = -1;
	struct data key;

	*entry = cacheUndefinedEntry;

	if (name == NULL)
		goto error0;

	DataInitWithBytes(&key, (unsigned char *) name, strlen(name)+1);

	smfLog(SMF_LOG_DEBUG, "cache get {%s}", name);

	if (pthread_mutex_lock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex lock in cacheGet() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	value = cache->get(cache, &key);

	if (pthread_mutex_unlock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex unlock in cacheGet() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	if (value == NULL)
		goto error0;

	if (value->length(value) == sizeof (CacheEntry)) {
		*entry = *(CacheEntry *)(value->base(value));
		rc = 0;
	}
	value->destroy(value);
error0:
	smfLog(SMF_LOG_CACHE, TAG_FORMAT "cache get key={%s} value={%lu, %ld} rc=%d", TAG_ARGS, name, entry->expires, entry->count, rc);

	return rc;
}

static int
cacheUpdate(workspace data, LimitInfo *limit)
{
	Data value;
	int rc = -1;
	struct data key;
	CacheEntry *counter;

	if (limit == NULL || limit->key == NULL || limit->over < 0)
		return 0;

	DataInitWithBytes(&key, (unsigned char *) limit->key, strlen(limit->key)+1);

	if (pthread_mutex_lock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex lock in cacheUpdate() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	value = cache->get(cache, &key);
	if (value == NULL)
		value = DataCreateCopyBytes((void *) &limit->stats, sizeof (limit->stats));

	if (value != NULL) {
		if (value->length(value) == sizeof (*counter)) {
			counter = (CacheEntry *) value->base(value);

			if (counter->expires < limit->stats.expires) {
				counter->expires = limit->stats.expires;
				counter->count = limit->stats.count;
			} else {
				limit->stats.expires = counter->expires;
			}

			limit->stats.count = ++counter->count;

			rc = cache->put(cache, &key, value);
		}

		value->destroy(value);
	}

	if (pthread_mutex_unlock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex unlock in cacheUpdate() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

	smfLog(SMF_LOG_CACHE, TAG_FORMAT "cache update key={%s} value={%lu, %ld} rc=%d", TAG_ARGS, limit->key, limit->stats.expires, limit->stats.count, rc);

	return rc;
}

static int
cacheExpireEntries(void *key, void *value, void *dataless)
{
	time_t now = time(NULL);
	workspace data = dataless;
	CacheEntry *entry = (CacheEntry *) ((Data) value)->base(value);

	if (now < entry->expires)
		return 1;

	smfLog(SMF_LOG_CACHE, TAG_FORMAT "cache remove {%s}", TAG_ARGS, ((Data) key)->base(key));

	return -1;
}

static int
cacheGarbageCollect(workspace data)
{
	unsigned long count = data->work.cid % optCacheGcFrequency.value;

	smfLog(SMF_LOG_CACHE, TAG_FORMAT "%lu connections", TAG_ARGS, count);

	if (count == 1) {
		if (pthread_mutex_lock(&smfMutex))
			syslog(LOG_ERR, TAG_FORMAT "mutex lock in cacheGarbageCollect() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);

		smfLog(SMF_LOG_CACHE, TAG_FORMAT "garbage collecting cache", TAG_ARGS);

		cache->walk(cache, cacheExpireEntries, data);

		smfLog(SMF_LOG_CACHE, TAG_FORMAT "syncing cache", TAG_ARGS);

		if (cache->sync(cache))
			syslog(LOG_ERR, TAG_FORMAT "cache sync error: %s (%d)", TAG_ARGS, strerror(errno), errno);

		if (pthread_mutex_unlock(&smfMutex))
			syslog(LOG_ERR, TAG_FORMAT "mutex unlock in cacheGarbageCollect() failed: %s (%d) ", TAG_ARGS, strerror(errno), errno);
	}

	return 0;
}

/***********************************************************************
 *** Handlers
 ***********************************************************************/

static char *
assignCacheKey(const char *prefix, char *key_found, const char *suffix)
{
	size_t length;
	char *new_key;

	/* By default we record results by rule group. The exception
	 * is the default rule (the empty tag prefix), which is always
	 * cached individually, because the default rule could otherwise
	 * exceed its limits too easily for things with large name spaces
	 * like IP addresses.
	 */
	if (!optCacheByIndividual.value && strcmp(prefix, key_found) != 0)
		return key_found;

	length = strlen(prefix) + strlen(suffix) + 1;
	if ((new_key = realloc(key_found, length)) == NULL)
		return key_found;

	(void) snprintf(new_key, length, "%s%s", prefix, suffix);

	return new_key;
}

static int
isOverLimit(workspace data, LimitInfo *limit)
{
	time_t now;
	int unit = 's';
	char *next, *stop;
	long max = -1, seconds = 1, value;

	now = time(NULL);

	if (limit == NULL || limit->value == NULL)
		return -1;

	value = strtol(limit->value, &stop, 10);
	if (limit->value < stop)
		max = value;
	if (0 <= max && *stop == '/') {
		next = stop + 1;
		value = strtol(next, &stop, 10);
		if (next < stop)
			seconds = value;
		if (*stop != '\0')
			unit = *stop;
	}

	switch (unit) {
	case 'w': seconds *= 7;
	case 'd': seconds *= 24;
	case 'h': seconds *= 60;
	case 'm': seconds *= 60;
	}

	smfLog(SMF_LOG_PARSE, TAG_FORMAT "limit max=%ld seconds=%ld", TAG_ARGS, max, seconds);

	if (cacheGet(data, (char *) limit->key, &limit->stats) || limit->stats.expires <= now) {
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "cache key={%s} has expired, reset", TAG_ARGS, limit->key);

		/* Specifying when this entry will expire simplifies
		 * cacheExpireEntries() by avoiding extra access DB
		 * lookups and parsing of time limits.
		 */
		limit->stats.expires = now + seconds;
		limit->stats.count = 0;
	}

	limit->over = (max < 0 || limit->stats.count < max) ? SMFIS_CONTINUE : SMFIS_REJECT;

	smfLog(
		SMF_LOG_DEBUG, TAG_FORMAT "isOverLimit(%lx, %lx) {%s, %s, %ld, %lx} rc=%d",
		TAG_ARGS, (long) data, (long) limit, limit->key, limit->value,
		limit->stats.count, limit->stats.expires, limit->over
	);

	return limit->over;
}

static sfsistat
limitExceeded(workspace data, const char *who, const char *limit)
{
	int unit = 's';
	char *word, *stop;
	long max = -1, time = 1, value;

	value = strtol(limit, &stop, 10);
	if (limit < stop)
		max = value;
	if (0 <= max && *stop == '/') {
		limit = stop + 1;
		value = strtol(limit, &stop, 10);
		if (limit < stop)
			time = value;
		if (*stop != '\0')
			unit = *stop;
	}

	switch (unit) {
	case 'w': word = "week";   break;
	case 'd': word = "day";    break;
	case 'h': word = "hour";   break;
	case 'm': word = "minute"; break;
	default:  word = "second";
	}

	/* NOTE that `who' will be NULL or the access DB key like
	 *
	 *	milter-limit-connect:ip
	 *	milter-limit-connect:domain
	 *	milter-limit-from:sender
	 *	milter-limit-to:recipient
	 *
	 * In which case we want to strip off the tag portion of
	 * the key for the error response.
	 */
	if (who != NULL && (who = strchr(who, ':')) != NULL)
		who++;

	(void) snprintf(
		data->reply, sizeof (data->reply), "%s has exceeded %ld message%s per %ld %s%s",
		who == NULL ? "" : who, max, max == 1 ? "" : "s", time, word, time == 1 ? "" : "s"
	);

	switch (*optPolicy.string) {
	case 'd':
		return SMFIS_DISCARD;
	case 'l':
		return smfReply(&data->work, 450, NULL, "%s", data->reply);
	case 'r':
		return smfReply(&data->work, 550, NULL, "%s", data->reply);
	}

	return SMFIS_CONTINUE;
}

static void
freeLimitInfo(void *data)
{
	LimitInfo *li = (LimitInfo *) data;

	if (li != NULL) {
		free(li->value);
		free(li->path);
		free(li->key);
		free(li);
	}
}

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	char *value;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	if ((data->rcpts = VectorCreate(10)) == NULL)
		goto error1;

	VectorSetDestroyEntry(data->rcpts, freeLimitInfo);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error2;
	}

	TextCopy(data->client_name, sizeof (data->client_name), client_name);

	if (!isReservedIP(data->client_addr, IS_IP_LOCALHOST)) {
		access = smfAccessClient(&data->work, MILTER_NAME "-connect:", data->client_name, data->client_addr, &data->client.key, &data->client.value);
		if (access != SMDB_ACCESS_NOT_FOUND) {
			data->client.key = assignCacheKey(MILTER_NAME "-connect:", data->client.key, data->client_addr);

			/* If the connection exceeded limit, wait until the
			 * RCPT TO: command to return the error. This should
			 * prevent most legitimate connections from trying
			 * another MX server.
			 */
		}
	}

	access = smfAccessClient(&data->work, MILTER_NAME "-rcpt-connect:", data->client_name, data->client_addr, NULL, &value);
	if (access != SMDB_ACCESS_NOT_FOUND) {
		data->maxRcptConnect = (int) strtol(value, NULL, 10);
		free(value);
	}

	return SMFIS_CONTINUE;
error2:
	VectorDestroy(data->rcpts);
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;
	const char *error;
	char *auth_authen, *value;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);
	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s' auth=%s", TAG_ARGS, (long) ctx, (long) args, args[0], auth_authen == NULL ? "" : auth_authen);

	data->client.over = -1;

	free(data->auth.key);
	free(data->auth.path);
	free(data->auth.value);

	data->auth.over = -1;
	data->auth.key = NULL;
	data->auth.path = NULL;
	data->auth.value = NULL;

	free(data->mail.key);
	free(data->mail.path);
	free(data->mail.value);

	data->mail.over = -1;
	data->mail.key = NULL;
	data->mail.path = NULL;
	data->mail.value = NULL;

	VectorRemoveAll(data->rcpts);

	data->reply[0] = '\0';

	data->maxRcptSender = data->maxRcptConnect;

	/* We assume that an authenticated user is trusted not to send spam. */
	if (smfOptSmtpAuthOk.value && auth_authen != NULL) {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "authenticated \"%s\"", TAG_ARGS, auth_authen);
		data->work.skipConnection = 1;
	}

	data->work.skipMessage = data->work.skipConnection;

	if (data->work.skipMessage) {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "connection white listed or authenticated, skipping", TAG_ARGS);
		return SMFIS_CONTINUE;
	}

	if ((error = parsePath(args[0], smfFlags, 1, &data->mail.path)) != NULL)
		return smfReply(&data->work, 553, NULL, error);

	/* We might want to include or not DSN messages in a host's message
	 * limit. This will have an impact on valid DSN messages and call
	 * back tests.
	 */
	if (data->client.key != NULL && (optCountNullSender.value || *data->mail.path->address.string != '\0')) {
		(void) isOverLimit(data, &data->client);
	}

	/* Do not apply message limits on the DSN address, since the number
	 * of hosts that might send DSN messages, including call-backs or
	 * call-aheads, would probably mean this value is always max'ed
	 * out. See -n option to count DSN messages per connecting client.
	 */
	if (*data->mail.path->address.string != '\0') {
		/* Lookup
		 *
		 *	milter-limit-from:account@some.sub.domain.tld	RHS
		 *	milter-limit-from:some.sub.domain.tld		RHS
		 *	milter-limit-from:sub.domain.tld		RHS
		 *	milter-limit-from:domain.tld			RHS
		 *	milter-limit-from:tld				RHS
		 *	milter-limit-from:account@			RHS
		 *	milter-limit-from:				RHS
		 */
		access = smfAccessEmail(&data->work, MILTER_NAME "-from:", data->mail.path->address.string, &data->mail.key, &data->mail.value);
		if (access != SMDB_ACCESS_NOT_FOUND) {
			data->mail.key = assignCacheKey(MILTER_NAME "-from:", data->mail.key, data->mail.path->address.string);
			(void) isOverLimit(data, &data->mail);
		}

		/* Lookup
		 *
		 *	milter-limit-auth:auth_authen			RHS
		 *	milter-limit-auth:				RHS
		 */
		access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, data->mail.path->address.string, &data->auth.key, &data->auth.value);
		if (access != SMDB_ACCESS_NOT_FOUND) {
			data->auth.key = assignCacheKey(MILTER_NAME "-auth:", data->auth.key, auth_authen);
			(void) isOverLimit(data, &data->auth);
		}
	}

	access = smfAccessEmail(&data->work, MILTER_NAME "-rcpt-from:", data->mail.path->address.string, NULL, &value);
	if (access != SMDB_ACCESS_NOT_FOUND) {
		data->maxRcptSender = (int) strtol(value, NULL, 10);
		free(value);
	}

	access = smfAccessClient(&data->work, MILTER_NAME "-rcpt-auth:", auth_authen, data->mail.path->address.string, NULL, &value);
	if (access != SMDB_ACCESS_NOT_FOUND) {
		data->maxRcptSender = (int) strtol(value, NULL, 10);
		free(value);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	workspace data;
	LimitInfo *rcpt;
	const char *error;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	if ((rcpt = calloc(1, sizeof (*rcpt))) == NULL)
		return smfReply(&data->work, 450, NULL, "internal error: out of memory");

	rcpt->over = -1;

	if ((error = parsePath(args[0], smfFlags, 0, &rcpt->path)) != NULL)
		return smfReply(&data->work, 553, NULL, error);

	if (smfAccessEmail(&data->work, MILTER_NAME "-to:", rcpt->path->address.string, &rcpt->key, &rcpt->value) != SMDB_ACCESS_NOT_FOUND) {
		rcpt->key = assignCacheKey(MILTER_NAME "-to:", rcpt->key, rcpt->path->address.string);

 		(void) isOverLimit(data, rcpt);

		if (VectorAdd(data->rcpts, rcpt))
			freeLimitInfo(rcpt);
	}

	/*** The following represents the precedence from highest to lowest. ***/

	if (data->auth.over != -1) {
		if (data->auth.over != SMFIS_CONTINUE)
			return limitExceeded(data, data->auth.key, data->auth.value);

		return SMFIS_CONTINUE;
	}

	if (rcpt->over != -1) {
		if (rcpt->over != SMFIS_CONTINUE)
			return limitExceeded(data, NULL, rcpt->value);

		return SMFIS_CONTINUE;
	}

	if (data->mail.over != -1) {
		if (data->mail.over != SMFIS_CONTINUE)
			return limitExceeded(data, data->mail.key, data->mail.value);

		return SMFIS_CONTINUE;
	}

	if (data->client.over != -1) {
		if (data->client.over != SMFIS_CONTINUE)
			return limitExceeded(data, data->client.key, data->client.value);

		return SMFIS_CONTINUE;
	}

	if (0 <= data->maxRcptSender && data->maxRcptSender < VectorLength(data->rcpts)) {
		if (optAbsoluteRcptLimit.value)
			return smfReply(&data->work, 550, "5.5.3", "absolute recipient limit %d exceeded", data->maxRcptSender);
		return smfReply(&data->work, 452, "4.5.3", "recipient limit %d exceeded", data->maxRcptSender);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%.20s...')", TAG_ARGS, (long) ctx, name, value);

	if (TextInsensitiveCompare(name, "Subject") == 0) {
		TextCopy(data->subject, sizeof (data->subject), value);
		data->hasSubject = 1;
	} else if (TextInsensitiveCompare(name, X_MILTER_PASS) == 0) {
		data->hasPass = 1;
	} else if (TextInsensitiveCompare(name, X_MILTER_REPORT) == 0) {
		data->hasReport = 1;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	long i;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	/* Only update the cache if the message was accepted. */

	if (cacheUpdate(data, &data->client))
		syslog(LOG_WARNING, TAG_FORMAT "cache update error for connection {%s}", TAG_ARGS, data->client.key);

	if (cacheUpdate(data, &data->auth))
		syslog(LOG_WARNING, TAG_FORMAT "cache update error for AUTH {%s}", TAG_ARGS, data->auth.key);

	if (cacheUpdate(data, &data->mail))
		syslog(LOG_WARNING, TAG_FORMAT "cache update error for sender {%s}", TAG_ARGS, data->mail.key);

	for (i = 0; i < VectorLength(data->rcpts); i++) {
		LimitInfo *rcpt;

		if ((rcpt = VectorGet(data->rcpts, i)) == NULL)
			continue;

		if (cacheUpdate(data, rcpt))
			syslog(LOG_WARNING, TAG_FORMAT "cache update error for recipient {%s}", TAG_ARGS, rcpt->key);
	}

#ifdef DROPPED_ADD_HEADERS
	/* Add trace to the message. There can be many of these, one
	 * for each filter/host that looks at the message.
	 */
	if (optAddHeaders.value) {
		int length;
		const char *if_name, *if_addr;

		if ((if_name = smfi_getsymval(ctx, smMacro_if_name)) == NULL)
			if_name = smfUndefined;
		if ((if_addr = smfi_getsymval(ctx, smMacro_if_addr)) == NULL)
			if_addr = "0.0.0.0";

		length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
		length += TimeStampAdd(data->line + length, sizeof (data->line) - length);
		(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);
	}
#endif

	if (data->reply[0] != '\0') {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "%s", TAG_ARGS, data->reply);

		switch (*optPolicy.string) {
#ifdef HAVE_SMFI_QUARANTINE
		case 'q':
			if (smfi_quarantine(ctx, data->reply) == MI_SUCCESS)
				return SMFIS_CONTINUE;
			/*@fallthrough@*/
#endif
		case 't':
			if (TextInsensitiveStartsWith(data->subject, optSubjectTag.string) < 0) {
				(void) snprintf(data->line, sizeof (data->line), "%s %s", optSubjectTag.string, data->subject);
				(void) smfHeaderSet(ctx, "Subject", data->line, 1, data->hasSubject);
			}
			break;
		}

		(void) smfHeaderSet(ctx, X_MILTER_REPORT, data->reply, 1, data->hasReport);
	}

	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		cacheGarbageCollect(data);
		VectorDestroy(data->rcpts);

		free(data->client.path);
		free(data->client.value);
		free(data->client.key);

		free(data->auth.path);
		free(data->auth.value);
		free(data->auth.key);

		free(data->mail.path);
		free(data->mail.value);
		free(data->mail.key);

		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}


/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_VERSION,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		0,			/* flags */
		filterOpen,		/* connection info filter */
		NULL,			/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		NULL,			/* header filter */
		NULL,			/* end of header */
		NULL,			/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

void
atExitCleanUp()
{
	smdbClose(smdbAccess);

	if (pthread_mutex_lock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex lock in atExitCleanUp() failed: %s (%d) ", 0, smfNoQueue, strerror(errno), errno);

	if (cache != NULL) {
		cache->sync(cache);
		cache->destroy(cache);
	}

	if (pthread_mutex_unlock(&smfMutex))
		syslog(LOG_ERR, TAG_FORMAT "mutex unlock in atExitCleanUp() failed: %s (%d) ", 0, smfNoQueue, strerror(errno), errno);

	smfAtExitCleanUp();
}

int
main(int argc, char **argv)
{
	int argi;

	/* Default is OFF. */
	smfOptSmtpAuthOk.initial = "-";

	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	switch (*optPolicy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case 'q':
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		break;
#endif
	case 't':
		milter.handlers.xxfi_flags |= SMFIF_CHGHDRS;
		/*@fallthrough@*/
	case 'n':
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS;
		milter.handlers.xxfi_header = filterHeader;
		break;
	}

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	CacheSetDebug(smfLogDetail & SMF_LOG_CACHE);

	if ((cache = CacheCreate(optCacheType.string, optCacheFile.string)) == NULL) {
		syslog(LOG_ERR, "failed to create cache\n");
		return 1;
	}

	(void) smfSetFileOwner(&milter, optCacheFile.string);

	return smfMainStart(&milter);
}
