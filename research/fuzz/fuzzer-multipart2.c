/*
   php-firing-range fuzz target v2: multipart POST -> rfc1867 ->
   session upload-progress, with MULTI-REQUEST + CROSS-INPUT SESSION STATE.

   v1 limitation exposed by intel (php-up-2026 write-up, 05:40Z): the
   suspected UAF needs request A to leave a poisoned session file
   (upload_progress_<key> array) and request B with the SAME session id to
   arm caches and hit decode-then-zend_hash_update free. One request per
   input cannot express that.

   v2 contract:
     byte[0] selector %4 = content-type mode (as v1):
       0 multipart/form-data            1 multipart/form-data; boundary="b"
       2 boundary from body head        3 text/plain (control)
     byte[1] session tag (0..255): harness FORCES the effective session id
       to "ftag%02u" for every segment of this input, so segments (and
       later inputs with the same tag) share one on-disk session file.
       session.save_path persists in-process; GC off.
     bytes[2..] request stream: segments separated by "@@RQ@@"; each runs
       as a full request (startup -> POST parse -> shutdown), same SID.
     Cookie channel "@@CK" as v1; SID value overridden by the tag, rest of
       the cookie text kept.
*/

#include <main/php.h>
#include <main/php_main.h>
#include <main/SAPI.h>
#include <main/php_variables.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "fuzzer.h"
#include "fuzzer-sapi.h"

static const char *post_data;
static size_t post_len;
static size_t post_pos;
static char cookie_buf[4096];
static char *cookie_dup;
static char forced_sid[16];
static char ct_buf[256];
static int requests_done;

static size_t fuzz_ub_write(const char *s, size_t l) { (void)s; return l; }
static void fuzz_flush(void *srv) { (void)srv; }
static void fuzz_log(const char *m, int l) { (void)m; (void)l; }
static void fuzz_send_header(sapi_header_struct *h, void *srv) { (void)h; (void)srv; }
static void fuzz_register_vars(zval *arr) { php_import_environment_variables(arr); }

static size_t fuzzer_read_post(char *buf, size_t bytes_to_read)
{
	size_t remain = post_len - post_pos;
	size_t n = bytes_to_read < remain ? bytes_to_read : remain;
	if (n == 0) {
		return 0; /* EOF -> truncated-body parser paths */
	}
	memcpy(buf, post_data + post_pos, n);
	post_pos += n;
	return n;
}

static char *fuzzer_read_cookies(void)
{
	return cookie_dup ? estrdup(cookie_dup) : NULL;
}

static int fuzz_startup(sapi_module_struct *mod)
{
	return php_module_startup(mod, NULL);
}

static sapi_module_struct mpf2_module = {
	"multipartfuzz2", "multipart+progress fuzzer v2",
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

	mpf2_module.phpinfo_as_text = 1;
	mpf2_module.ini_entries = strdup(
		"html_errors=0\n"
		"implicit_flush=1\noutput_buffering=0\nerror_reporting=0\n"
		"max_execution_time=0\nallow_url_fopen=0\nmemory_limit=128M\n"
		"session.upload_progress.enabled=1\n"
		"session.upload_progress.cleanup=1\n"
		"session.upload_progress.prefix=upload_progress_\n"
		"session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS\n"
		"session.upload_progress.freq=1%\n"
		"session.upload_progress.min_freq=0\n"
		"session.use_strict_mode=0\n"
		"session.serialize_handler=php\n"
		"session.save_handler=files\n"
		"session.save_path=/tmp/fuzz_savesess\n"
		"session.gc_probability=0\n"
		"session.use_cookies=1\nsession.use_only_cookies=1\n"
		"session.cache_limiter=\n"
		"display_errors=0\nlog_errors=0\n"
	);
	putenv("USE_ZEND_ALLOC=0");

	mkdir("/tmp/fuzz_savesess", 0700);
	sapi_startup(&mpf2_module);
	if (mpf2_module.startup(&mpf2_module) == FAILURE) {
		return FAILURE;
	}
	inited = 1;
	return SUCCESS;
}

static void set_cookie_from_segment(const char *seg, size_t seg_len)
{
	cookie_dup = NULL;
	const char *ck = memmem(seg, seg_len, "@@CK", 4);
	if (ck) {
		size_t off = (ck + 4) - seg;
		size_t clen = seg_len - off;
		const char *nul = memchr(seg + off, '\0', clen);
		if (nul) clen = nul - (seg + off);
		if (clen > sizeof(cookie_buf) - 32) clen = sizeof(cookie_buf) - 32;
		memcpy(cookie_buf, seg + off, clen);
		snprintf(cookie_buf + clen, sizeof(cookie_buf) - clen, "%sPHPSESSID=%s", clen ? "; " : "", forced_sid);
	} else {
		snprintf(cookie_buf, sizeof(cookie_buf), "PHPSESSID=%s", forced_sid);
	}
	cookie_dup = cookie_buf;
}

/* read_post_bytes copies content_type via strlen on a NUL-terminated string;
 * fuzzer buffers are NOT NUL-terminated -> keep our own terminated copy. */
static char ct_copy[256];

static void run_one_request(const char *seg, size_t seg_len, unsigned sel)
{
	post_data = seg;
	post_len = seg_len;
	post_pos = 0;

	switch (sel) {
		case 0: snprintf(ct_buf, sizeof(ct_buf), "multipart/form-data"); break;
		case 1: snprintf(ct_buf, sizeof(ct_buf), "multipart/form-data; boundary=\"b\""); break;
		case 2: {
			size_t blen = seg_len < 70 ? seg_len : 70;
			/* sanitize boundary copy: strip NULs, keep length sane */
			char btmp[71];
			memcpy(btmp, seg, blen);
			for (size_t i = 0; i < blen; i++) if (!btmp[i]) btmp[i] = '_';
			btmp[blen] = '\0';
			snprintf(ct_buf, sizeof(ct_buf), "multipart/form-data; boundary=%s", btmp);
			break;
		}
		default: snprintf(ct_buf, sizeof(ct_buf), "text/plain"); break;
	}
	strncpy(ct_copy, ct_buf, sizeof(ct_copy) - 1);
	ct_copy[sizeof(ct_copy) - 1] = '\0';

	SG(server_context) = (void *) &inited;
	SG(request_info).request_method = "POST";
	SG(request_info).content_type = ct_buf;
	SG(request_info).content_length = seg_len;
	SG(request_info).query_string = "";
	SG(request_info).path_translated = NULL;
	SG(request_info).request_uri = "/fuzz.php";
	SG(request_info).current_user = NULL;
	SG(request_info).auth_user = NULL;
	SG(request_info).auth_password = NULL;
	SG(request_info).auth_digest = NULL;

	set_cookie_from_segment(seg, seg_len);

	zend_try {
		php_request_startup();
		php_request_shutdown(NULL);
	} zend_catch {
		php_request_shutdown(NULL);
	} zend_end_try();

	requests_done++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!inited || size < 3) return 0;

	unsigned sel = data[0] % 4;
	unsigned tag = data[1];
	snprintf(forced_sid, sizeof(forced_sid), "ftag%02u", tag);

	const char *stream = (const char *) data + 2;
	size_t remaining = size - 2;
	requests_done = 0;

	const char RQ[] = "@@RQ@@";
	const size_t RQ_LEN = 6;

	while (remaining > 0 && requests_done < 16) {
		const char *sep = memmem(stream, remaining, RQ, RQ_LEN);
		size_t seg_len = sep ? (size_t) (sep - stream) : remaining;
		run_one_request(stream, seg_len, sel);
		if (!sep) break;
		stream = sep + RQ_LEN;
		remaining -= seg_len + RQ_LEN;
	}
	return 0;
}
