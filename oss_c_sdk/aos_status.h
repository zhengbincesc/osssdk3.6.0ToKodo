#ifndef LIBAOS_STATUS_H
#define LIBAOS_STATUS_H

#include "aos_define.h"
#include "aos_list.h"

AOS_CPP_START

typedef struct aos_status_s aos_status_t;

#define KODO_NOT_EXIST_CODE 612
#define KODO_BUCKET_EXIST_CODE 614
#define OSS_BUCKET_EXIST_CODE 409
#define OSS_BUCKET_NOT_EMPTY_CODE 409
#define OSS_BUCKET_NOT_EXIST_CODE 404
#define OSS_OBJECT_NOT_EXIST_CODE 204

struct aos_status_s {
    int code; // > 0 http code
    char *error_code; // can't modify
    char *error_msg; // can't modify
    char *req_id;   // can't modify
};

static APR_INLINE int aos_status_is_ok(aos_status_t *s)
{
    return s->code > 0 && s->code / 100 == 2;
}

static APR_INLINE int aos_http_is_ok(int st)
{
    return st / 100 == 2;
}

#define aos_status_set(s, c, ec, es)                                    \
    (s)->code = c; (s)->error_code = (char *)ec; (s)->error_msg = (char *)es

/**
 * @brief determine whether the request should be retried
 * @param[in]   s             the return status of api, such as oss_put_object_from_buffer
 * @return      int           AOS_FALSE indicates no retries, AOS_TRUE retry
 */
int aos_should_retry(aos_status_t *s);

aos_status_t *aos_status_create(aos_pool_t *p);

aos_status_t *aos_status_dup(aos_pool_t *p, aos_status_t *src);

aos_status_t *aos_status_parse_from_body(aos_pool_t *p, aos_list_t *bc, int code, aos_status_t *s);

aos_status_t *oss_transfer_err_to_aos(aos_pool_t *pool, int code, const char *message);

extern const char AOS_XML_PARSE_ERROR_CODE[];
extern const char AOS_OPEN_FILE_ERROR_CODE[];
extern const char AOS_WRITE_FILE_ERROR_CODE[];
extern const char AOS_RENAME_FILE_ERROR_CODE[];
extern const char AOS_HTTP_IO_ERROR_CODE[];
extern const char AOS_UNKNOWN_ERROR_CODE[];
extern const char AOS_CLIENT_ERROR_CODE[];
extern const char AOS_SERVER_ERROR_CODE[];
extern const char AOS_UTF8_ENCODE_ERROR_CODE[];
extern const char AOS_URL_ENCODE_ERROR_CODE[];
extern const char AOS_INCONSISTENT_ERROR_CODE[];
extern const char AOS_CREATE_QUEUE_ERROR_CODE[];
extern const char AOS_CREATE_THREAD_POOL_ERROR_CODE[];

AOS_CPP_END

#endif
