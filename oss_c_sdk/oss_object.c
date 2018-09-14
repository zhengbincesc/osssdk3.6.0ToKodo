#include "aos_log.h"
#include "aos_util.h"
#include "aos_string.h"
#include "aos_status.h"
#include "oss_auth.h"
#include "oss_util.h"
#include "oss_xml.h"
#include "oss_api.h"
#include "c-sdk/qiniu/io.h"
#include "c-sdk/qiniu/rs.h"
#include "c-sdk/cJSON/cJSON.h"

char *oss_gen_signed_url(const oss_request_options_t *options,
                         const aos_string_t *bucket, 
                         const aos_string_t *object,
                         int64_t expires, 
                         aos_http_request_t *req)
{
    aos_string_t signed_url;
    char *expires_str = NULL;
    aos_string_t expires_time;
    int res = AOSE_OK;

    expires_str = apr_psprintf(options->pool, "%" APR_INT64_T_FMT, expires);
    aos_str_set(&expires_time, expires_str);
    oss_get_object_uri(options, bucket, object, req);
    res = oss_get_signed_url(options, req, &expires_time, &signed_url);
    if (res != AOSE_OK) {
        return NULL;
    }
    return signed_url.data;
}

aos_status_t *oss_put_object_from_buffer(const oss_request_options_t *options,
                                         const aos_string_t *bucket, 
                                         const aos_string_t *object, 
                                         aos_list_t *buffer,
                                         aos_table_t *headers, 
                                         aos_table_t **resp_headers)
{
    return oss_do_put_object_from_buffer(options, bucket, object, buffer, 
                                         headers, NULL, NULL, resp_headers, NULL);
}

aos_status_t *oss_do_put_object_from_buffer(const oss_request_options_t *options,
                                            const aos_string_t *bucket, 
                                            const aos_string_t *object, 
                                            aos_list_t *buffer,
                                            aos_table_t *headers, 
                                            aos_table_t *params,
                                            oss_progress_callback progress_callback,
                                            aos_table_t **resp_headers,
                                            aos_list_t *resp_body)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;

    headers = aos_table_create_if_null(options, headers, 2);
    set_content_type(NULL, object->data, headers);
    apr_table_add(headers, OSS_EXPECT, "");

    query_params = aos_table_create_if_null(options, params, 0);

    oss_init_object_request(options, bucket, object, HTTP_PUT, 
                            &req, query_params, headers, progress_callback, 0, &resp);
    oss_write_request_body_from_buffer(buffer, req);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_body(resp, resp_body);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        oss_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_put_object_from_file(const oss_request_options_t *options,
                                       const aos_string_t *bucket, 
                                       const aos_string_t *object, 
                                       const aos_string_t *filename,
                                       aos_table_t *headers, 
                                       aos_table_t **resp_headers)
{
    aos_status_t      *s       = NULL;
    char              *uptoken = NULL;
    Qiniu_Io_PutRet    putRet;
    Qiniu_Client       client;
    Qiniu_RS_PutPolicy putPolicy;
    Qiniu_Io_PutExtra  putExtra;
    Qiniu_Mac          mac;
    Qiniu_Error        error;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Zero(putPolicy);
    Qiniu_Zero(putExtra);
    putPolicy.scope = bucket->data;
    QINIU_UP_HOST = options->config->up_host.data;

    uptoken = Qiniu_RS_PutPolicy_Token(&putPolicy, &mac);
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    Qiniu_Client_SetLowSpeedLimit(&client, options->ctl->options->speed_limit, options->ctl->options->speed_time);
    error = Qiniu_Io_PutFile(&client, &putRet, uptoken, object->data, filename->data, &putExtra);

    if (aos_http_is_ok(error.code)) {
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, error.code, error.message);

    Qiniu_Free(uptoken);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_do_put_object_from_file(const oss_request_options_t *options,
                                          const aos_string_t *bucket, 
                                          const aos_string_t *object, 
                                          const aos_string_t *filename,
                                          aos_table_t *headers, 
                                          aos_table_t *params,
                                          oss_progress_callback progress_callback,
                                          aos_table_t **resp_headers,
                                          aos_list_t *resp_body)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    int res = AOSE_OK;

    s = aos_status_create(options->pool);

    headers = aos_table_create_if_null(options, headers, 2);
    set_content_type(filename->data, object->data, headers);
    apr_table_add(headers, OSS_EXPECT, "");

    query_params = aos_table_create_if_null(options, params, 0);

    oss_init_object_request(options, bucket, object, HTTP_PUT, &req, 
                            query_params, headers, progress_callback, 0, &resp);

    res = oss_write_request_body_from_file(options->pool, filename, req);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_body(resp, resp_body);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        oss_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_get_object_to_buffer(const oss_request_options_t *options, 
                                       const aos_string_t *bucket, 
                                       const aos_string_t *object,
                                       aos_table_t *headers, 
                                       aos_table_t *params,
                                       aos_list_t *buffer, 
                                       aos_table_t **resp_headers)
{
    return oss_do_get_object_to_buffer(options, bucket, object, headers, 
                                       params, buffer, NULL, resp_headers);
}

aos_status_t *oss_do_get_object_to_buffer(const oss_request_options_t *options, 
                                          const aos_string_t *bucket, 
                                          const aos_string_t *object,
                                          aos_table_t *headers, 
                                          aos_table_t *params,
                                          aos_list_t *buffer,
                                          oss_progress_callback progress_callback, 
                                          aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;

    headers = aos_table_create_if_null(options, headers, 0);
    params = aos_table_create_if_null(options, params, 0);

    oss_init_object_request(options, bucket, object, HTTP_GET, 
                            &req, params, headers, progress_callback, 0, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_body(resp, buffer);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) &&  
        !has_range_or_process_in_request(req)) {
        oss_check_crc_consistent(resp->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_restore_object(const oss_request_options_t *options, 
                                          const aos_string_t *bucket, 
                                          const aos_string_t *object,
                                          aos_table_t *headers, 
                                          aos_table_t **resp_headers)
{
    aos_table_t *params = NULL;
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;

    params = aos_table_create_if_null(options, params, 0);
    apr_table_add(params, OSS_RESTORE, "");

    headers = aos_table_create_if_null(options, headers, 0);

    /* 
     * Because this framework will auto add content-length for HTTP_POST and HTTP_PUT method,
     * it has to add content type as well. Otherwise oss server will fail at signature
     * mismatch. 
     * With set content type, it works.
     * But in future, it's better refactor framework to fix this problem.
     */
    set_content_type(NULL, object->data, headers);

    oss_init_object_request(options, bucket, object, HTTP_POST, 
                            &req, params, headers, NULL, 0, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_get_object_address(const oss_request_options_t *options,
                                     const aos_string_t *bucket,
                                     const aos_string_t *object,
                                     aos_string_t *objectAddress,
                                     int timeout,
                                     aos_table_t **resp_headers)
{
    aos_status_t      *s           = NULL;
    char              *baseUrl     = NULL;
    char              *privateURL  = NULL;
    char              *domainUrl   = NULL;
    const char        *domain      = NULL;
    int                domainCount = 0;
    Qiniu_Json        *root        = NULL;
    Qiniu_Json        *item        = NULL;
    Qiniu_Error        err;
    Qiniu_Mac          mac;
    Qiniu_RS_GetPolicy getPolicy;
    Qiniu_Client       client;


    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;

    //timeout should be between 1 and 3600
    if ((timeout < 1) || (timeout > 3600)) {
        s = aos_status_create(options->pool);
        aos_status_set(s, AOSE_INVALID_ARGUMENT, "timeout should be between 1 and 3600", NULL);
        return s;
    }

    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    domainUrl = Qiniu_String_Concat3("https://api.qiniu.com", "/v7/domain/list?tbl=", bucket->data);
    err = Qiniu_Client_Call(&client, &root, domainUrl);

    if (aos_http_is_ok(err.code)) {
        domainCount = cJSON_GetArraySize(root);
        if (0 == domainCount) {
            Qiniu_Free(domainUrl);
            Qiniu_Client_Cleanup(&client);
            s = aos_status_create(options->pool);
            aos_status_set(s, AOSE_SERVICE_ERROR, "need config at least one domain", NULL);
            return s;
        }
        item = cJSON_GetArrayItem(root, 0);
        //just get first domain
        domain = Qiniu_Json_GetString(item, "domain", NULL);
        if (NULL == domain) {
            Qiniu_Free(domainUrl);
            Qiniu_Client_Cleanup(&client);
            s = aos_status_create(options->pool);
            aos_status_set(s, AOSE_SERVICE_ERROR, "need config at least one domain", NULL);
            return s;
        }
    } else {
        Qiniu_Free(domainUrl);
        Qiniu_Client_Cleanup(&client);
        return oss_transfer_err_to_aos(options->pool, err.code, err.message);
    }

    Qiniu_Zero(getPolicy);
    getPolicy.expires = timeout;
    baseUrl = Qiniu_String_Concat("http://", domain, "/", object->data, NULL);
    privateURL = Qiniu_RS_GetPolicy_MakeRequest(&getPolicy, baseUrl, &mac);

    aos_str_set(objectAddress, apr_pstrdup(options->pool, privateURL));

    aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);

    s = aos_status_create(options->pool);
    s->code = 200;

    Qiniu_Free(domainUrl);
    Qiniu_Client_Cleanup(&client);
    Qiniu_Free(baseUrl);
    Qiniu_Free(privateURL);

    return s;
}

aos_status_t *oss_get_object_to_file(const oss_request_options_t *options,
                                     const aos_string_t *bucket, 
                                     const aos_string_t *object,
                                     aos_table_t *headers, 
                                     aos_table_t *params,
                                     aos_string_t *filename, 
                                     aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    int res = AOSE_OK;
    aos_string_t tmp_filename;

    headers = aos_table_create_if_null(options, headers, 0);
    params = aos_table_create_if_null(options, params, 0);

    oss_get_temporary_file_name(options->pool, filename, &tmp_filename);

    kodo_init_object_request(options, bucket, object, HTTP_GET,
                            &req, params, headers, &resp);

    s = aos_status_create(options->pool);
    res = oss_init_read_response_body_to_file(options->pool, &tmp_filename, resp);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) &&
        !has_range_or_process_in_request(req)) {
            oss_check_crc_consistent(resp->crc64, resp->headers, s);
    }

    oss_temp_file_rename(s, tmp_filename.data, filename->data, options->pool);

    return s;
}

aos_status_t *oss_do_get_object_to_file(const oss_request_options_t *options,
                                        const aos_string_t *bucket, 
                                        const aos_string_t *object,
                                        aos_table_t *headers, 
                                        aos_table_t *params,
                                        aos_string_t *filename, 
                                        oss_progress_callback progress_callback,
                                        aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    int res = AOSE_OK;
    aos_string_t tmp_filename;

    headers = aos_table_create_if_null(options, headers, 0);
    params = aos_table_create_if_null(options, params, 0);

    oss_get_temporary_file_name(options->pool, filename, &tmp_filename);

    oss_init_object_request(options, bucket, object, HTTP_GET, 
                            &req, params, headers, progress_callback, 0, &resp);

    s = aos_status_create(options->pool);
    res = oss_init_read_response_body_to_file(options->pool, &tmp_filename, resp);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) && 
        !has_range_or_process_in_request(req)) {
            oss_check_crc_consistent(resp->crc64, resp->headers, s);
    }

    oss_temp_file_rename(s, tmp_filename.data, filename->data, options->pool);

    return s;
}

aos_status_t *oss_head_object(const oss_request_options_t *options, 
                              const aos_string_t *bucket, 
                              const aos_string_t *object,
                              aos_table_t *headers, 
                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;

    headers = aos_table_create_if_null(options, headers, 0);    

    query_params = aos_table_create_if_null(options, query_params, 0);

    oss_init_object_request(options, bucket, object, HTTP_HEAD, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_put_symlink(const oss_request_options_t *options, 
                              const aos_string_t *bucket, 
                              const aos_string_t *sym_object,
                              const aos_string_t *target_object,
                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    headers = aos_table_make(options->pool, 1);
    apr_table_set(headers, OSS_CANNONICALIZED_HEADER_SYMLINK, target_object->data);
    headers = aos_table_create_if_null(options, headers, 0);    

    query_params = aos_table_create_if_null(options, query_params, 0);
    apr_table_add(query_params, OSS_SYMLINK, "");

    oss_init_object_request(options, bucket, sym_object, HTTP_PUT, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_get_symlink(const oss_request_options_t *options, 
                              const aos_string_t *bucket, 
                              const aos_string_t *sym_object,
                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL; 

    headers = aos_table_create_if_null(options, headers, 0);    

    query_params = aos_table_create_if_null(options, query_params, 0);
    apr_table_add(query_params, OSS_SYMLINK, "");

    oss_init_object_request(options, bucket, sym_object, HTTP_GET, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_delete_object(const oss_request_options_t *options,
                                const aos_string_t *bucket, 
                                const aos_string_t *object, 
                                aos_table_t **resp_headers)
{
    aos_status_t *s               = NULL;
    char         *url             = NULL;
    char         *entryURI        = NULL;
    char         *entryURIEncoded = NULL;
    Qiniu_Error   err;
    Qiniu_Client  client;
    Qiniu_Mac     mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    entryURI = Qiniu_String_Concat3(bucket->data, ":", object->data);
    entryURIEncoded = Qiniu_String_Encode(entryURI);
    url = Qiniu_String_Concat3(options->config->rs_host.data, "/delete/", entryURIEncoded);

    Qiniu_Free(entryURI);
    Qiniu_Free(entryURIEncoded);

    err = Qiniu_Client_CallNoRet(&client, url);

    if (aos_http_is_ok(err.code)) {
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_copy_object(const oss_request_options_t *options, 
                              const aos_string_t *source_bucket, 
                              const aos_string_t *source_object, 
                              const aos_string_t *dest_bucket, 
                              const aos_string_t *dest_object,
                              aos_table_t *headers, 
                              aos_table_t **resp_headers)
{
    char *copy_source = NULL;
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    char buffer[AOS_MAX_QUERY_ARG_LEN*3+1];
    int res = -1;

    s = aos_status_create(options->pool);

    headers = aos_table_create_if_null(options, headers, 2);
    query_params = aos_table_create_if_null(options, query_params, 0);

    /* init headers */
    res = aos_url_encode(buffer, source_object->data, AOS_MAX_QUERY_ARG_LEN);
    if (res != AOSE_OK) {
        aos_status_set(s, res, AOS_URL_ENCODE_ERROR_CODE, NULL);
        return s;
    }

    copy_source = apr_psprintf(options->pool, "/%.*s/%s", 
        source_bucket->len, source_bucket->data, buffer);
    apr_table_set(headers, OSS_CANNONICALIZED_HEADER_COPY_SOURCE, copy_source);
    set_content_type(NULL, dest_object->data, headers);

    oss_init_object_request(options, dest_bucket, dest_object, HTTP_PUT, 
                            &req, query_params, headers, NULL, 0, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_append_object_from_buffer(const oss_request_options_t *options,
                                            const aos_string_t *bucket, 
                                            const aos_string_t *object, 
                                            int64_t position,
                                            aos_list_t *buffer, 
                                            aos_table_t *headers, 
                                            aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    
    /* init query_params */
    query_params = aos_table_create_if_null(options, query_params, 2);
    apr_table_add(query_params, OSS_APPEND, "");
    aos_table_add_int64(query_params, OSS_POSITION, position);

    /* init headers */
    headers = aos_table_create_if_null(options, headers, 2);
    set_content_type(NULL, object->data, headers);
    apr_table_add(headers, OSS_EXPECT, "");

    oss_init_object_request(options, bucket, object, HTTP_POST, 
                            &req, query_params, headers, NULL, 0, &resp);
    oss_write_request_body_from_buffer(buffer, req);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_do_append_object_from_buffer(const oss_request_options_t *options,
                                               const aos_string_t *bucket, 
                                               const aos_string_t *object, 
                                               int64_t position,
                                               uint64_t init_crc,
                                               aos_list_t *buffer, 
                                               aos_table_t *headers,
                                               aos_table_t *params,
                                               oss_progress_callback progress_callback,
                                               aos_table_t **resp_headers,
                                               aos_list_t *resp_body)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    
    /* init query_params */
    query_params = aos_table_create_if_null(options, params, 2);
    apr_table_add(query_params, OSS_APPEND, "");
    aos_table_add_int64(query_params, OSS_POSITION, position);

    /* init headers */
    headers = aos_table_create_if_null(options, headers, 2);
    set_content_type(NULL, object->data, headers);
    apr_table_add(headers, OSS_EXPECT, "");

    oss_init_object_request(options, bucket, object, HTTP_POST, &req, query_params, 
                            headers, progress_callback, init_crc, &resp);
    oss_write_request_body_from_buffer(buffer, req);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    oss_fill_read_response_body(resp, resp_body);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        oss_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_append_object_from_file(const oss_request_options_t *options,
                                          const aos_string_t *bucket, 
                                          const aos_string_t *object, 
                                          int64_t position,
                                          const aos_string_t *append_file, 
                                          aos_table_t *headers, 
                                          aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    int res = AOSE_OK;

    /* init query_params */
    query_params = aos_table_create_if_null(options, query_params, 2);
    apr_table_add(query_params, OSS_APPEND, "");
    aos_table_add_int64(query_params, OSS_POSITION, position);
    
    /* init headers */
    headers = aos_table_create_if_null(options, headers, 2);
    set_content_type(append_file->data, object->data, headers);
    apr_table_add(headers, OSS_EXPECT, "");

    oss_init_object_request(options, bucket, object, HTTP_POST, 
                            &req, query_params, headers, NULL, 0, &resp);
    res = oss_write_request_body_from_file(options->pool, append_file, req);

    s = aos_status_create(options->pool);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_do_append_object_from_file(const oss_request_options_t *options,
                                             const aos_string_t *bucket, 
                                             const aos_string_t *object, 
                                             int64_t position,
                                             uint64_t init_crc,
                                             const aos_string_t *append_file, 
                                             aos_table_t *headers, 
                                             aos_table_t *params,
                                             oss_progress_callback progress_callback,
                                             aos_table_t **resp_headers,
                                             aos_list_t *resp_body)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    int res = AOSE_OK;

    /* init query_params */
    query_params = aos_table_create_if_null(options, params, 2);
    apr_table_add(query_params, OSS_APPEND, "");
    aos_table_add_int64(query_params, OSS_POSITION, position);
    
    /* init headers */
    headers = aos_table_create_if_null(options, headers, 2);
    set_content_type(append_file->data, object->data, headers);
    apr_table_add(headers, OSS_EXPECT, "");

    oss_init_object_request(options, bucket, object, HTTP_POST,  &req, query_params, 
                            headers, progress_callback, init_crc, &resp);
    res = oss_write_request_body_from_file(options->pool, append_file, req);

    s = aos_status_create(options->pool);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    oss_fill_read_response_body(resp, resp_body);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        oss_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_put_object_from_buffer_by_url(const oss_request_options_t *options,
                                                const aos_string_t *signed_url, 
                                                aos_list_t *buffer, 
                                                aos_table_t *headers,
                                                aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;

    /* init query_params */
    headers = aos_table_create_if_null(options, headers, 0);
    query_params = aos_table_create_if_null(options, query_params, 0);

    oss_init_signed_url_request(options, signed_url, HTTP_PUT, 
                                &req, query_params, headers, &resp);

    oss_write_request_body_from_buffer(buffer, req);

    s = oss_process_signed_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        oss_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_put_object_from_file_by_url(const oss_request_options_t *options,
                                              const aos_string_t *signed_url, 
                                              aos_string_t *filename, 
                                              aos_table_t *headers,
                                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    int res = AOSE_OK;

    s = aos_status_create(options->pool);

    headers = aos_table_create_if_null(options, headers, 0);
    query_params = aos_table_create_if_null(options, query_params, 0);

    oss_init_signed_url_request(options, signed_url, HTTP_PUT, 
                                &req, query_params, headers, &resp);
    res = oss_write_request_body_from_file(options->pool, filename, req);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_signed_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp)) {
        oss_check_crc_consistent(req->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_get_object_to_buffer_by_url(const oss_request_options_t *options,
                                              const aos_string_t *signed_url, 
                                              aos_table_t *headers,
                                              aos_table_t *params,
                                              aos_list_t *buffer,
                                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;

    headers = aos_table_create_if_null(options, headers, 0);
    params = aos_table_create_if_null(options, params, 0);
    
    oss_init_signed_url_request(options, signed_url, HTTP_GET, 
                                &req, params, headers, &resp);

    s = oss_process_signed_request(options, req, resp);
    oss_fill_read_response_body(resp, buffer);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) &&  
        !has_range_or_process_in_request(req)) {
            oss_check_crc_consistent(resp->crc64, resp->headers, s);
    }

    return s;
}

aos_status_t *oss_get_object_to_file_by_url(const oss_request_options_t *options,
                                            const aos_string_t *signed_url, 
                                            aos_table_t *headers, 
                                            aos_table_t *params,
                                            aos_string_t *filename,
                                            aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    int res = AOSE_OK;
    aos_string_t tmp_filename;

    s = aos_status_create(options->pool);

    headers = aos_table_create_if_null(options, headers, 0);
    params = aos_table_create_if_null(options, params, 0);

    oss_get_temporary_file_name(options->pool, filename, &tmp_filename);
 
    oss_init_signed_url_request(options, signed_url, HTTP_GET, 
                                &req, params, headers, &resp);

    res = oss_init_read_response_body_to_file(options->pool, filename, resp);
    if (res != AOSE_OK) {
        aos_file_error_status_set(s, res);
        return s;
    }

    s = oss_process_signed_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_enable_crc(options) && has_crc_in_response(resp) && 
        !has_range_or_process_in_request(req)) {
            oss_check_crc_consistent(resp->crc64, resp->headers, s);
    }

    oss_temp_file_rename(s, tmp_filename.data, filename->data, options->pool);

    return s;
}


aos_status_t *oss_head_object_by_url(const oss_request_options_t *options,
                                     const aos_string_t *signed_url, 
                                     aos_table_t *headers, 
                                     aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;

    headers = aos_table_create_if_null(options, headers, 0);
    query_params = aos_table_create_if_null(options, query_params, 0);
    
    oss_init_signed_url_request(options, signed_url, HTTP_HEAD, 
                                &req, query_params, headers, &resp);

    s = oss_process_signed_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}
