/*
   php-firing-range fuzz target: multipart POST -> rfc1867 parser ->
   session upload-progress callback (ext/session/session.c) -> files handler.

   Flow: set SG(request_info) BEFORE php_request_startup(); inside startup,
   sapi_activate() sees server_context != NULL + POST + content_type and runs
   the registered multipart post-entry => php_parse_file_upload() => the real
   upload-progress callback with stock-default INIs. Note this also exercises
   GLM's flagged ordering (POST parsing before module RINIT) naturally.

   Upstream sapi/fuzzer has no multipart/progress target — this fills the gap.

   Input contract:
     byte[0] selector %4:
       0 content-type: multipart/form-data (boundary from body headers only)
       1 content-type: multipart/form-data; boundary="b"
       2 content-type: multipart/form-data; boundary=<body head, up to 70 raw
         bytes — fuzzes boundary too long/invalid>
       3 content-type: text/plain (control)
     bytes[1..] = POST body
     Cookie channel: from first "@@CK" to next NUL in body is the Cookie
       header value (SID injection channel), e.g. "PHPSESSID=<raw bytes>".
*/

#include <main/php.h>
#include <main/php_main.h>
#include <main/SAPI.h>
#include <main/php_variables.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "fuzzer.h"
#include "fuzzer-sapi.h"

static const char *post_data;
static size_t post_len;
static size_t post_pos;
static char *cookie_dup;
static char ct_buf[256];

static size_t fuzz_ub_write(const char *s, size_t l) { (void)s; return l; }
static void fuzz_flush(void *srv) { (void)srv; }
static void fuzz_log(const char *m, int l) { (void)m; (void)l; }
static void fuzz_send_header(sapi_header_struct *h, void *srv) { (void)h; (void)srv; }
static void fuzz_register_vars(zval *arr) { php_import_environment_variables(arr); }

/* read_post contract (see main/rfc1867.c:231): fill buf with up to
 * bytes_to_read body bytes, return count actually delivered; 0/negative = EOF. */
static int fuzzer_read_post(char *buf, uint32_t bytes_to_read)
{
	size_t remain = post_len - post_pos;
	size_t n = (size_t) bytes_to_read < remain ? (size_t) bytes_to_read : remain;
	if (n == 0) {
		return 0; /* EOF -> truncated-body parser paths */
	}
	memcpy(buf, post_data + post_pos, n);
	post_pos += n;
	return (int) n;
}

static char *fuzzer_read_cookies(void)
{
	return cookie_dup ? estrdup(cookie_dup) : NULL;
}

static int fuzz_startup(sapi_module_struct *mod)
{
	return php_module_startup(mod, NULL);
}

static sapi_module_struct mpf_module = {
	"multipartfuzz", "multipart+progress fuzzer",
	fuzz_startup,
	php_module_shutdown_wrapper,
	NULL, NULL,
	fuzz_ub_write, fuzz_flush,
	NULL, NULL,
	php_error,
	NULL, NULL, fuzz_send_header,
	fuzzer_read_post, fuzzer_read_cookies,
	fuzz_register_vars, fuzz_log,
	NULL, NULL,
	STANDARD_SAPI_MODULE_PROPERTIES
};

static int inited = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void) argc; (void) argv;

	mpf_module.phpinfo_as_text = 1;
	mpf_module.ini_entries = strdup(
		"html_errors=0\n"
		"implicit_flush=1\noutput_buffering=0\nerror_reporting=0\n"
		"max_execution_time=0\nallow_url_fopen=0\nmemory_limit=64M\n"
		"session.upload_progress.enabled=1\n"
		"session.upload_progress.cleanup=1\n"
		"session.upload_progress.prefix=upload_progress_\n"
		"session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS\n"
		"session.upload_progress.freq=1%\n"
		"session.upload_progress.min_freq=1\n"
		"session.use_strict_mode=0\n"
		"session.serialize_handler=php\n"
		"session.save_handler=files\n"
		"session.save_path=/tmp/fuzz_savesess\n"
		"session.use_cookies=1\nsession.use_only_cookies=1\n"
		"session.cache_limiter=\n"
		"display_errors=0\nlog_errors=0\n"
	);
	putenv("USE_ZEND_ALLOC=0");

	mkdir("/tmp/fuzz_savesess", 0700);
	sapi_startup(&mpf_module);
	if (mpf_module.startup(&mpf_module) == FAILURE) {
		return FAILURE;
	}
	inited = 1;
	return SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!inited || size < 2) return 0;

	unsigned sel = data[0] % 4;
	post_data = (const char *) data + 1;
	post_len = size - 1;
	post_pos = 0;
	cookie_dup = NULL;

	const char *ck = memmem(post_data, post_len, "@@CK", 4);
	if (ck) {
		size_t off = (ck + 4) - post_data;
		size_t clen = post_len - off;
		const char *nul = memchr(post_data + off, '\0', clen);
		if (nul) clen = nul - (post_data + off);
		if (clen > 0 && clen < 4096) {
			cookie_dup = malloc(clen + 1);
			memcpy(cookie_dup, post_data + off, clen);
			cookie_dup[clen] = '\0';
		}
	}

	switch (sel) {
		case 0: snprintf(ct_buf, sizeof(ct_buf), "multipart/form-data"); break;
		case 1: snprintf(ct_buf, sizeof(ct_buf), "multipart/form-data; boundary=\"b\""); break;
		case 2: {
			size_t blen = post_len < 70 ? post_len : 70;
			snprintf(ct_buf, sizeof(ct_buf), "multipart/form-data; boundary=%.*s", (int) blen, post_data);
			break;
		}
		default: snprintf(ct_buf, sizeof(ct_buf), "text/plain"); break;
	}

	/* request_info BEFORE startup: sapi_activate() inside
	 * php_request_startup() reads POST when server_context is set. */
	SG(server_context) = (void *) &inited; /* non-NULL sentinel, never deref'd */
	SG(request_info).request_method = "POST";
	SG(request_info).content_type = ct_buf;
	SG(request_info).content_length = post_len;
	SG(request_info).query_string = "";
	SG(request_info).path_translated = NULL;
	SG(request_info).request_uri = "/fuzz.php";
	SG(request_info).current_user = NULL;
	SG(request_info).auth_user = NULL;
	SG(request_info).auth_password = NULL;
	SG(request_info).auth_digest = NULL;

	zend_try {
		if (php_request_startup() == SUCCESS) {
			/* POST already parsed inside startup; environment registration
			 * happens there too (php_hash_environment). Nothing more to do —
			 * shutdown exercises cleanup/teardown paths (progress key
			 * removal, files handler close, session globals teardown). */
		}
	} zend_catch {
	} zend_end_try();

	/* ensure a shutdown happens even if startup failed mid-way */
	php_request_shutdown(NULL);
	free(cookie_dup); cookie_dup = NULL;
	SG(server_context) = NULL;
	return 0;
}
