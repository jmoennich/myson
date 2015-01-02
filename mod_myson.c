/*
 * Copyright 2013 Jan Mönnich 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <mysql.h>

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_base64.h"
#include "apr_lib.h"
#include "apr_json.h"
#include "apr_hash.h"

typedef struct {
    char database[256];
} myson_config;


/* Prototypes */
void* myson_merge_dir_conf(apr_pool_t* pool, void* BASE, void* ADD);
void* myson_create_dir_conf(apr_pool_t* pool, char* context);
const char *myson_set_database(cmd_parms *cmd, void *cfg, const char *arg);
static int myson_handler(request_rec *r);


static const command_rec myson_directives[] = {
    AP_INIT_TAKE1("MysonDatabase", myson_set_database, NULL, ACCESS_CONF, "Database Name"), {
        NULL
    }
};

static void myson_register_hooks(apr_pool_t *p) {
    ap_hook_handler(myson_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA myson_module = {
    STANDARD20_MODULE_STUFF,
    myson_create_dir_conf, /* create per-dir    config structures */
    myson_merge_dir_conf, /* merge  per-dir    config structures */
    NULL, /* create per-server config structures */
    NULL, /* merge  per-server config structures */
    myson_directives, /* table of config file commands       */
    myson_register_hooks /* register hooks                      */
};


static int util_read(request_rec *r, const char **rbuf, apr_off_t *size) {

    int rc = OK;
    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return (rc);
    }

    if (ap_should_client_block(r)) {
        char argsbuffer[HUGE_STRING_LEN];
        apr_off_t rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        *rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof (argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = length - rpos;
            } else {
                rsize = len_read;
            }
            memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
        }
    }
    return (rc);
}

void send_json_error(request_rec *r, const char *text) {
    ap_rprintf(r, "{\"error\":\"%s\"}", text);
}

/* from mod_basic_auth.c */
static void note_basic_auth_failure(request_rec *r) {
    apr_table_setn(r->err_headers_out,
            (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate"
            : "WWW-Authenticate", "Basic realm=myson");
}

/* from mod_basic_auth.c */
static int get_basic_auth(request_rec *r, const char **user, const char **pw) {

    const char *auth_line;
    char *decoded_line;
    int length;

    /* Get the appropriate header */
    auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
            ? "Proxy-Authorization" : "Authorization");

    if (!auth_line) {
        note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }
    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        note_basic_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }
    while (apr_isspace(*auth_line)) {
        auth_line++;
    }

    decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
    length = apr_base64_decode(decoded_line, auth_line);
    decoded_line[length] = '\0';

    *user = ap_getword_nulls(r->pool, (const char**) &decoded_line, ':');
    *pw = decoded_line;
    r->user = (char *) *user;

    return OK;
}

int nextvar(char *src, char **start, char **end) {
    int esc = 0;
    char *buf = src;
    do {
        esc = (*buf == '\\');
        if (!esc) {
            if (*buf == '{') {
                *buf = '\0';
                *start = ++buf;
            } else if (*buf == '}') {
                *buf = '\0';
                *end = ++buf;
                return *end - *start - 1;
            }
        }
    } while (*(buf++));
    return 0;
}

void print_json_key_and_value(request_rec *r, MYSQL_FIELD *field, char *value) {

    char *ptr = value;
    ap_rprintf(r, "\"%s\":", field->name);

    if (field->type == MYSQL_TYPE_BIT) {
        ap_rputs(ptr ? "true" : "false", r);
    } else if (!ptr) {
        ap_rputs("null", r);
    } else {
        if (!IS_NUM(field->type)) {
            ap_rputc('"', r);
        }
        while (*ptr) {
            if (*ptr == '"') {
                ap_rputc('\\', r);
            }
            ap_rputc(*ptr, r);
            ptr++;
        }
        if (!IS_NUM(field->type)) {
            ap_rputc('"', r);
        }
    }
}

/* The sample content handler */
static int myson_handler(request_rec *r) {

    if (strcmp(r->handler, "myson")) {
        return DECLINED;
    }

    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    const char *ctype = apr_table_get(r->headers_in, "Content-Type");
    if (!ctype || strncmp("application/json", ctype, 16)) {
        send_json_error(r, "expected mimetype application/json");
        return OK;
    }

    const char *user, *password;
    int res = get_basic_auth(r, &user, &password);
    if (res) {
        return res;
    }

    myson_config *config = (myson_config *) ap_get_module_config(
            r->per_dir_config, &myson_module);
    
    /* always json */
    ap_set_content_type(r, "application/json");

    MYSQL *con = mysql_init(NULL);
    if (con == NULL) {
        send_json_error(r, mysql_error(con));
        return OK;
    }


    if (mysql_real_connect(con, "localhost", user, password, 
            config->database, 0, NULL, 0) == NULL) {
        send_json_error(r, mysql_error(con));
        mysql_close(con);
        return OK;
    }

    mysql_set_character_set(con, "utf8");

    apr_off_t size;
    const char *buffer;
    if (util_read(r, &buffer, &size) != OK) {
        send_json_error(r, "read post data failed");
        return OK;
    }

    apr_json_value_t *json;
    if (apr_json_decode(&json, buffer, size, r->pool) != APR_SUCCESS) {
        send_json_error(r, "bad json data");
        return OK;
    }

    /* get file stat */
    struct stat sb;
    if (stat(r->filename, &sb)) {
        send_json_error(r, "stat failed");
        return OK;
    };

    /* read whole file into buffer */
    char *src = apr_palloc(r->pool, sb.st_size + 1);
    FILE *f = fopen(r->filename, "r");
    if (!f) {
        send_json_error(r, "fopen failed");
        return OK;
    }
    if (fread(src, sb.st_size, 1, f) != 1) {
        fclose(f);
        send_json_error(r, "fread failed");
        return OK;
    }
    fclose(f);
    src[sb.st_size] = '\0';


    int keylen;
    char *key;
    char *next;
    char *sql = "\0";

    while ((keylen = nextvar(src, &key, &next))) {

        // get value of key from object
        apr_json_value_t *jval = apr_hash_get(json->value.object, key, keylen);

        // format JSON value to string 
        char *val = NULL;
        if (jval) {
            switch (jval->type) {

                case APR_JSON_OBJECT:
                    send_json_error(r, "not implemented: object as key");
                    return OK;

                case APR_JSON_ARRAY:
                    send_json_error(r, "not implemented: object as key");
                    return OK;

                case APR_JSON_STRING:
                    // escape string value to prevent SQL injection
                    val = apr_palloc(r->pool, keylen * 2 + 1);
                    mysql_real_escape_string(
                            con, val, jval->value.string.p,
                            strlen(jval->value.string.p));
                    break;

                case APR_JSON_LONG:
                    val = apr_psprintf(r->pool, "%ld", jval->value.lnumber);
                    break;

                case APR_JSON_DOUBLE:
                    val = apr_psprintf(r->pool, "%f", jval->value.dnumber);
                    break;

                case APR_JSON_BOOLEAN:
                    val = jval->value.boolean ? "true" : "false";
                    break;

                case APR_JSON_NULL:
                    val = "null";
                    break;
            }
        }

        // append value to SQL statement
        if (val) {
            sql = apr_pstrcat(r->pool, sql, src, val, NULL);
        }

        // start from end of current key
        src = next;
    }

    // append the rest to SQL statement
    sql = apr_pstrcat(r->pool, sql, src, NULL);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", sql);

    // execute SQL
    if (mysql_query(con, sql)) {
        send_json_error(r, mysql_error(con));
        mysql_close(con);
        return OK;
    }

    MYSQL_ROW row;
    MYSQL_RES *result = mysql_store_result(con);
    MYSQL_FIELD *fields = mysql_fetch_fields(result);
    int num_fields = mysql_num_fields(result);
    my_ulonglong rows = 0;
    int pretty = 1;

    ap_rprintf(r, "{\"row_count\":%lld", result->row_count);
    ap_rputs(",\"rows\":[", r);

    while ((row = mysql_fetch_row(result))) {
        ap_rputc('{', r);
        for (int i = 0; i < num_fields; i++) {
            print_json_key_and_value(r, &fields[i], row[i]);
            if (i != (num_fields - 1)) {
                ap_rputc(',', r);
            }
            if (pretty) {
                ap_rputc('\n', r);
            }
        }
        rows++;
        ap_rputc('}', r);
        if (rows != result->row_count) {
            ap_rputc(',', r);
        }
    }
    ap_rputs("]}", r);
    mysql_free_result(result);
    mysql_close(con);

    return OK;
}

const char *myson_set_database(cmd_parms *cmd, void *cfg, const char *arg) {
    myson_config *conf = (myson_config *) cfg;
    if (conf) {
        strcpy(conf->database, arg);
    }
    return NULL;
}

void* myson_create_dir_conf(apr_pool_t* pool, char* context) {
    context = context ? context : "(undefined context)";
    myson_config *cfg = apr_pcalloc(pool, sizeof (myson_config));
    if (cfg) {
        memset(cfg->database, 0, 256);
    }
    return cfg;
}

void* myson_merge_dir_conf(apr_pool_t* pool, void* BASE, void* ADD) {
    
    myson_config* base = (myson_config *) BASE; /* This is what was set in the parent context */
    myson_config* add = (myson_config *) ADD; /* This is what is set in the new context */
    myson_config* conf = (myson_config *) myson_create_dir_conf(pool, "Merged configuration"); /* This will be the merged configuration */

    /* Merge configurations */
    if(conf) {
        strcpy(conf->database, add->database);
    }
    
    return conf;
}

