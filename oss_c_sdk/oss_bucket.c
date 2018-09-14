#include "aos_log.h"
#include "aos_define.h"
#include "aos_util.h"
#include "aos_string.h"
#include "aos_status.h"
#include "oss_auth.h"
#include "oss_util.h"
#include "oss_xml.h"
#include "oss_api.h"
#include "c-sdk/qiniu/http.h"
#include "c-sdk/qiniu/rsf.h"
#include "c-sdk/cJSON/cJSON.h"

#define KODO_BUCKET_NOT_FOUND_CODE 612

static inline int oss_str_empty(const char *s) {
    return (s == NULL) || strcmp("", s) == 0;
}

static void oss_transfer_item_to_content(aos_pool_t *pool, const Qiniu_RSF_ListItem *pitem,
                                         oss_list_object_content_t *content)
{
    struct tm  *tmp         = NULL;
    long int    secondtime  = 0;
    char        size[21];   /* 2^64+1 can be represented in 21 chars. */
    char        puttime[64];

    aos_str_set(&content->key, apr_pstrdup(pool, pitem->key));
    sprintf(size, "%lld", pitem->fsize);
    aos_str_set(&content->size, apr_pstrdup(pool, size));
    aos_str_set(&content->etag, apr_pstrdup(pool, pitem->hash));

    secondtime = (long int)(pitem->putTime/1e7);
    tmp = localtime(&secondtime);
    if (0 != strftime(puttime, 64, "%Y-%m-%d %H:%M:%S", tmp) ) {
        aos_str_set(&content->last_modified, apr_pstrdup(pool, puttime));
    }

    return;
}

static aos_status_t *oss_create_bucket_with_params(const oss_request_options_t *options, 
                                                   const aos_string_t *bucket, 
                                                   oss_create_bucket_params_t *params, 
                                                   aos_table_t **resp_headers)
{
    const char *oss_acl_str = NULL;
    const char *oss_storage_class_str = NULL;
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *query_params = NULL;

    query_params = aos_table_create_if_null(options, query_params, 0);

    //init headers
    headers = aos_table_create_if_null(options, headers, 1);
    oss_acl_str = get_oss_acl_str(params->acl);
    if (oss_acl_str) {
        apr_table_set(headers, OSS_CANNONICALIZED_HEADER_ACL, oss_acl_str);
    }

    oss_init_bucket_request(options, bucket, HTTP_PUT, &req, 
                            query_params, headers, &resp);

    oss_storage_class_str = get_oss_storage_class_str(params->storage_class);
    if (oss_storage_class_str != NULL) {
        aos_list_t body;
        build_bucket_storage_class(options->pool, params->storage_class, &body);
        oss_write_request_body_from_buffer(&body, req); 
    }

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_create_bucket(const oss_request_options_t *options, 
                                const aos_string_t *bucket, 
                                oss_acl_e oss_acl, 
                                aos_table_t **resp_headers)
{
    char         *encBucket = NULL;
    aos_status_t *s         = NULL;
    char         *url       = NULL;
    Qiniu_Error   err;
    Qiniu_Client  client;
    Qiniu_Mac     mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    encBucket = Qiniu_String_Encode(bucket->data);

    url = Qiniu_String_Concat(options->config->rs_host.data, "/mkbucketv2/", encBucket, NULL);
    err = Qiniu_Client_CallNoRet(&client, url);

    //If oss acl is private, create private bucket, else create public bucket
    if ((OSS_ACL_PRIVATE == oss_acl) && aos_http_is_ok(err.code)) {
        Qiniu_Free(url);
        Qiniu_Client_Cleanup(&client);

        Qiniu_Client_InitMacAuth(&client, 1024, &mac);
        url = Qiniu_String_Concat(options->config->uc_host.data, "/private?bucket=", bucket->data, "&private=1", NULL);
        err = Qiniu_Client_CallNoRet(&client, url);
    }

    if (aos_http_is_ok(err.code)) {
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Free(encBucket);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_create_bucket_with_storage_class(const oss_request_options_t *options, 
                                const aos_string_t *bucket, 
                                oss_acl_e oss_acl, 
                                oss_storage_class_type_e storage_class, 
                                aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    oss_create_bucket_params_t params;
    params.acl = oss_acl;
    params.storage_class = storage_class;
    
    s = oss_create_bucket_with_params(options, 
                                bucket, 
                                &params, 
                                resp_headers);
    return s;
}

aos_status_t *oss_delete_bucket(const oss_request_options_t *options,
                                const aos_string_t *bucket, 
                                aos_table_t **resp_headers)
{
    aos_status_t *s   = NULL;
    char         *url = NULL;
    Qiniu_Error   err;
    Qiniu_Client  client;
    Qiniu_Mac     mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    url = Qiniu_String_Concat3(options->config->rs_host.data, "/drop/", bucket->data);
    err = Qiniu_Client_CallNoRet(&client, url);

    if (aos_http_is_ok(err.code)) {
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_put_bucket_acl(const oss_request_options_t *options, 
                                 const aos_string_t *bucket, 
                                 oss_acl_e oss_acl,
                                 aos_table_t **resp_headers)
{
    aos_status_t *s         = NULL;
    char         *url       = NULL;
    char         *private   = "0";
    Qiniu_Error   err;
    Qiniu_Client  client;
    Qiniu_Mac     mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);

    //If oss acl is private, set private bucket, else set public bucket
    if (OSS_ACL_PRIVATE == oss_acl) {
        private = "1";
    }

    url = Qiniu_String_Concat(options->config->uc_host.data, "/private?bucket=", bucket->data, "&private=", private,  NULL);
    err = Qiniu_Client_CallNoRet(&client, url);

    if (aos_http_is_ok(err.code)) {
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_get_bucket_acl(const oss_request_options_t *options, 
                                 const aos_string_t *bucket, 
                                 aos_string_t *oss_acl, 
                                 aos_table_t **resp_headers)
{
    aos_status_t   *s         = NULL;
    Qiniu_Json     *root      = NULL;
    char           *url       = NULL;
    char           *pacl      = "public-read-write";
    Qiniu_Error     err;
    Qiniu_Client    client;
    Qiniu_Mac       mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;

    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    url = Qiniu_String_Concat3(options->config->uc_host.data, "/v2/bucketInfo?bucket=", bucket->data);
    err = Qiniu_Client_Call(&client, &root, url);

    if (aos_http_is_ok(err.code)) {
        //If bucket is private,return private. else return public-read-write
        if (1 == Qiniu_Json_GetInt(root, "private", 0)) {
            pacl = "private";
        }
        aos_str_set(oss_acl, apr_pstrdup(options->pool, pacl));
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_check_bucket(const oss_request_options_t *options,
                               const aos_string_t *bucket,
                               int *pIsExist,
                               aos_table_t **resp_headers)
{
    aos_status_t   *s        = NULL;
    Qiniu_Json     *root     = NULL;
    char           *url      = NULL;
    Qiniu_Error     err;
    Qiniu_Client    client;
    Qiniu_Mac       mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;

    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    url = Qiniu_String_Concat3(options->config->uc_host.data, "/v2/bucketInfo?bucket=", bucket->data);
    err = Qiniu_Client_Call(&client, &root, url);

    *pIsExist = 0;
    if (aos_http_is_ok(err.code)) {
        *pIsExist = 1;
         aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    } else if (KODO_BUCKET_NOT_FOUND_CODE == err.code) {
        //If code is not found, reset code to 200
        err.code = 200;
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_head_bucket(const oss_request_options_t *options, 
                              const aos_string_t *bucket, 
                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 0);
    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_HEAD, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    return s;
}

aos_status_t *oss_get_bucket_location(const oss_request_options_t *options, 
                                      const aos_string_t *bucket, 
                                      aos_string_t *oss_location, 
                                      aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    int res;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LOCATION, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_location_parse_from_body(options->pool, &resp->body, oss_location);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_get_bucket_info(const oss_request_options_t *options, 
                                  const aos_string_t *bucket, 
                                  oss_bucket_info_t *bucket_info, 
                                  aos_table_t **resp_headers)
{
    aos_status_t   *s         = NULL;
    Qiniu_Json     *root      = NULL;
    char           *url       = NULL;
    const char     *location  = NULL;
    char           *pacl      = "public-read-write";
    Qiniu_Error     err;
    Qiniu_Client    client;
    Qiniu_Mac       mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;

    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    url = Qiniu_String_Concat3(options->config->uc_host.data, "/v2/bucketInfo?bucket=", bucket->data);
    err = Qiniu_Client_Call(&client, &root, url);
    if (aos_http_is_ok(err.code)) {
        //If bucket is private,return private. else return public-read-write
        if (1 == Qiniu_Json_GetInt(root, "private", 0)) {
            pacl = "private";
        }
        aos_str_set(&bucket_info->acl, apr_pstrdup(options->pool, pacl));
        location = Qiniu_Json_GetString(root, "region", "");
        aos_str_set(&bucket_info->location, apr_pstrdup(options->pool, location));
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_get_bucket_stat(const oss_request_options_t *options, 
                                  const aos_string_t *bucket, 
                                  oss_bucket_stat_t *bucket_stat, 
                                  aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    int res;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_BUCKETSTAT, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_get_bucket_stat_parse_from_body(options->pool, &resp->body, bucket_stat);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_get_bucket_referer(const oss_request_options_t *options, 
                                     const aos_string_t *bucket, 
                                     oss_referer_config_t *referer_config, 
                                     aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    int res;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_REFERER, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_get_bucket_referer_config_parse_from_body(options->pool, &resp->body, referer_config);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_put_bucket_storage_capacity(const oss_request_options_t *options, 
                                              const aos_string_t *bucket, 
                                              long storage_capacity, 
                                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;
    aos_list_t body;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_addn(query_params, OSS_QOS, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_PUT, &req, 
                            query_params, headers, &resp);

    build_bucket_storage_capacity_body(options->pool, storage_capacity, &body);
    oss_write_request_body_from_buffer(&body, req); 

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_get_bucket_storage_capacity(const oss_request_options_t *options, 
                                              const aos_string_t *bucket, 
                                              long *storage_capacity, 
                                              aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    int res;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_QOS, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_storage_capacity_parse_from_body(options->pool, &resp->body, storage_capacity);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_list_object(const oss_request_options_t *options,
                              const aos_string_t *bucket, 
                              oss_list_object_params_t *params, 
                              aos_table_t **resp_headers)
{
    aos_status_t                    *s             = NULL;
    oss_list_object_common_prefix_t *common_prefix = NULL;
    oss_list_object_content_t       *content       = NULL;
    char                            *prefix        = NULL;
    char                            *delimiter     = NULL;
    char                            *marker        = NULL;
    int                              limit         = 0;
    int                              i             = 0;
    Qiniu_Client                     client;
    Qiniu_Mac                        mac;
    Qiniu_Error                      err;
    Qiniu_RSF_ListRet                listRet;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);

    prefix = params->prefix.data;
    delimiter = params->delimiter.data;
    marker = params->marker.data;
    limit = params->max_ret;

    QINIU_RSF_HOST = options->config->rsf_host.data;
    err = Qiniu_RSF_ListFiles(&client, &listRet, bucket->data, prefix, delimiter, marker, limit);

    if (!aos_http_is_ok(err.code)) {
        s = oss_transfer_err_to_aos(options->pool, err.code, err.message);
        Qiniu_Client_Cleanup(&client);
        return s;
    }

    params->truncated = AOS_FALSE;
    if (!oss_str_empty(listRet.marker)) {
        params->truncated = AOS_TRUE;
        aos_str_set(&params->next_marker, apr_pstrdup(options->pool, listRet.marker));
    }

    for (i = 0; i < listRet.commonPrefixesCount; i++) {
        common_prefix = oss_create_list_object_common_prefix(options->pool);
        prefix = apr_pstrdup(options->pool, listRet.commonPrefixes[i]);
        aos_str_set(&common_prefix->prefix, prefix);
        aos_list_add_tail(&common_prefix->node, &params->common_prefix_list);
    }

    for (i = 0; i < listRet.itemsCount; i++) {
        content = oss_create_list_object_content(options->pool);
        oss_transfer_item_to_content(options->pool, &listRet.items[i], content);
        aos_list_add_tail(&content->node, &params->object_list);
    }

    aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    if (listRet.commonPrefixes != NULL) {
        Qiniu_Free(listRet.commonPrefixes);
    }
    if (listRet.items != NULL) {
        Qiniu_Free(listRet.items);
    }

    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_list_bucket(const oss_request_options_t *options,
                              oss_list_buckets_params_t *params, 
                              aos_table_t **resp_headers)
{
    aos_status_t   *s           = NULL;
    cJSON          *root        = NULL;
    char           *bucket      = NULL;
    char           *value       = NULL;
    int             bucketCount = 0;
    Qiniu_Error     err;
    Qiniu_Client    client;
    Qiniu_Mac       mac;
    int             i;
    oss_list_bucket_content_t *content;

    /* kodo does not support prefix, marker, max-keys, so just return all buckets
    owner_id, owner_name,CreationDate, ExtranetEndpoint, IntranetEndpoint, Location, StorageClass does not support too  */
    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;

    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    char *url = Qiniu_String_Concat2(options->config->rs_host.data, "/buckets");
    err = Qiniu_Client_Call(&client, &root, url);
    Qiniu_Free(url);

    if (aos_http_is_ok(err.code)) {
        params->truncated = 0;  //we just return all buckets, so this is 0(not truncated)
        bucketCount = cJSON_GetArraySize(root);
        for (i = 0; i < bucketCount; i++) {
            bucket = cJSON_GetArrayItem(root, i)->valuestring;
            content = oss_create_list_bucket_content(options->pool);
            if (NULL == content) {
                aos_error_log("malloc memory for list bucket failed");
                break;
            }
            value = apr_pstrdup(options->pool, bucket);
            aos_str_set(&content->name, value);
            aos_list_add_tail(&content->node, &params->bucket_list);
        }

        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_put_bucket_logging(const oss_request_options_t *options,
                                       const aos_string_t *bucket, 
                                       oss_logging_config_content_t *content, 
                                       aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    apr_table_t *query_params = NULL;
    aos_table_t *headers = NULL;
    aos_list_t body;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LOGGING, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 0);

    oss_init_bucket_request(options, bucket, HTTP_PUT, &req, 
                            query_params, headers, &resp);

    build_bucket_logging_body(options->pool, content, &body);
    oss_write_request_body_from_buffer(&body, req);
    s = oss_process_request(options, req, resp);

    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_get_bucket_logging(const oss_request_options_t *options, 
                                 const aos_string_t *bucket, 
                                 oss_logging_config_content_t *content, 
                                 aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    int res;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LOGGING, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_logging_parse_from_body(options->pool, &resp->body, content);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_delete_bucket_logging(const oss_request_options_t *options, 
                                 const aos_string_t *bucket, 
                                 aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LOGGING, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_DELETE, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_put_bucket_lifecycle(const oss_request_options_t *options,
                                       const aos_string_t *bucket, 
                                       aos_list_t *lifecycle_rule_list, 
                                       aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    apr_table_t *query_params = NULL;
    aos_table_t *headers = NULL;
    aos_list_t body;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LIFECYCLE, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 0);

    oss_init_bucket_request(options, bucket, HTTP_PUT, &req, 
                            query_params, headers, &resp);

    build_lifecycle_body(options->pool, lifecycle_rule_list, &body);
    oss_write_request_body_from_buffer(&body, req);
    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_put_bucket_cors(const oss_request_options_t *options,
                                  const aos_string_t *bucket, 
                                  aos_list_t *rule_list,
                                  aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    apr_table_t *query_params = NULL;
    aos_table_t *headers = NULL;
    aos_list_t body;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_CORS, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 0);

    oss_init_bucket_request(options, bucket, HTTP_PUT, &req, 
                            query_params, headers, &resp);

    build_cors_rule_body(options->pool, rule_list, &body);
    oss_write_request_body_from_buffer(&body, req);
    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_get_bucket_cors(const oss_request_options_t *options, 
                                  const aos_string_t *bucket, 
                                  aos_list_t *rule_list, 
                                  aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    int res;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_CORS, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_get_bucket_cors_parse_from_body(options->pool, &resp->body, rule_list);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_delete_bucket_cors(const oss_request_options_t *options, 
                                     const aos_string_t *bucket, 
                                     aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_CORS, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_DELETE, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_put_bucket_referer(const oss_request_options_t *options,
                                     const aos_string_t *bucket, 
                                     oss_referer_config_t *referer_config,
                                     aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    apr_table_t *query_params = NULL;
    aos_table_t *headers = NULL;
    aos_list_t body;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_REFERER, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 0);

    oss_init_bucket_request(options, bucket, HTTP_PUT, &req, 
                            query_params, headers, &resp);

    build_referer_config_body(options->pool, referer_config, &body);
    oss_write_request_body_from_buffer(&body, req);
    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_put_bucket_website(const oss_request_options_t *options,
                                     const aos_string_t *bucket, 
                                     oss_website_config_t *website_config,
                                     aos_table_t **resp_headers)
{
    aos_status_t *s         = NULL;
    char         *url       = NULL;
    Qiniu_Error   err;
    Qiniu_Client  client;
    Qiniu_Mac     mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;
    Qiniu_Client_InitMacAuth(&client, 1024, &mac);

    url = Qiniu_String_Concat(options->config->uc_host.data, "/noIndexPage?bucket=", bucket->data, "&noIndexPage=0", NULL);
    err = Qiniu_Client_CallNoRet(&client, url);

    if (aos_http_is_ok(err.code)) {
        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_get_bucket_website(const oss_request_options_t *options, 
                                     const aos_string_t *bucket, 
                                     oss_website_config_t *website_config, 
                                     aos_table_t **resp_headers)
{
    aos_status_t   *s         = NULL;
    Qiniu_Json     *root      = NULL;
    char           *url       = NULL;
    Qiniu_Error     err;
    Qiniu_Client    client;
    Qiniu_Mac       mac;

    mac.accessKey = options->config->access_key_id.data;
    mac.secretKey = options->config->access_key_secret.data;

    Qiniu_Client_InitMacAuth(&client, 1024, &mac);
    url = Qiniu_String_Concat3(options->config->uc_host.data, "/v2/bucketInfo?bucket=", bucket->data);
    err = Qiniu_Client_Call(&client, &root, url);
    if (aos_http_is_ok(err.code)) {
        if (0 == Qiniu_Json_GetInt(root, "no_index_page", 0)) {
            aos_str_set(&website_config->suffix_str, apr_pstrdup(options->pool, "index.html"));
            aos_str_set(&website_config->key_str, apr_pstrdup(options->pool, "error-404"));
        }

        aos_transport_headers(options->pool, Qiniu_Buffer_CStr(&client.respHeader), resp_headers);
    }

    s = oss_transfer_err_to_aos(options->pool, err.code, err.message);

    Qiniu_Free(url);
    Qiniu_Client_Cleanup(&client);

    return s;
}

aos_status_t *oss_delete_bucket_website(const oss_request_options_t *options, 
                                        const aos_string_t *bucket, 
                                        aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_WEBSITE, "");

    headers = aos_table_create_if_null(options, headers, 0);    

    oss_init_bucket_request(options, bucket, HTTP_DELETE, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_get_bucket_lifecycle(const oss_request_options_t *options,
                                       const aos_string_t *bucket, 
                                       aos_list_t *lifecycle_rule_list, 
                                       aos_table_t **resp_headers)
{
    int res;
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LIFECYCLE, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 0);

    oss_init_bucket_request(options, bucket, HTTP_GET, &req, 
                            query_params, headers, &resp);
    
    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);
    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_lifecycle_rules_parse_from_body(options->pool, 
            &resp->body, lifecycle_rule_list);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_delete_bucket_lifecycle(const oss_request_options_t *options,
                                          const aos_string_t *bucket, 
                                          aos_table_t **resp_headers)
{
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *query_params = NULL;
    aos_table_t *headers = NULL;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_LIFECYCLE, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 0);

    oss_init_bucket_request(options, bucket, HTTP_DELETE, &req, 
                            query_params, headers, &resp);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    return s;
}

aos_status_t *oss_delete_objects(const oss_request_options_t *options,
                                 const aos_string_t *bucket, 
                                 aos_list_t *object_list, 
                                 int is_quiet,
                                 aos_table_t **resp_headers, 
                                 aos_list_t *deleted_object_list)
{
    int res;
    aos_status_t *s = NULL;
    aos_http_request_t *req = NULL;
    aos_http_response_t *resp = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *query_params = NULL;
    aos_list_t body;
    unsigned char *md5 = NULL;
    char *buf = NULL;
    int64_t body_len;
    char *b64_value = NULL;
    int b64_buf_len = (20 + 1) * 4 / 3;
    int b64_len;

    //init query_params
    query_params = aos_table_create_if_null(options, query_params, 1);
    apr_table_add(query_params, OSS_DELETE, "");

    //init headers
    headers = aos_table_create_if_null(options, headers, 1);
    apr_table_set(headers, OSS_CONTENT_TYPE, OSS_MULTIPART_CONTENT_TYPE);

    oss_init_bucket_request(options, bucket, HTTP_POST, &req, 
                            query_params, headers, &resp);

    build_delete_objects_body(options->pool, object_list, is_quiet, &body);

    //add Content-MD5
    body_len = aos_buf_list_len(&body);
    buf = aos_buf_list_content(options->pool, &body);
    md5 = aos_md5(options->pool, buf, (apr_size_t)body_len);
    b64_value = aos_pcalloc(options->pool, b64_buf_len);
    b64_len = aos_base64_encode(md5, 20, b64_value);
    b64_value[b64_len] = '\0';
    apr_table_addn(headers, OSS_CONTENT_MD5, b64_value);

    oss_write_request_body_from_buffer(&body, req);

    s = oss_process_request(options, req, resp);
    oss_fill_read_response_header(resp, resp_headers);

    if (is_quiet) {
        return s;
    }

    if (!aos_status_is_ok(s)) {
        return s;
    }

    res = oss_delete_objects_parse_from_body(options->pool, &resp->body, 
                                             deleted_object_list);
    if (res != AOSE_OK) {
        aos_xml_error_status_set(s, res);
    }

    return s;
}

aos_status_t *oss_delete_objects_by_prefix(oss_request_options_t *options,
                                           const aos_string_t *bucket, 
                                           const aos_string_t *prefix)
{
    aos_pool_t *subpool = NULL;
    aos_pool_t *parent_pool = NULL;
    int is_quiet = 1;
    aos_status_t *s = NULL;
    aos_status_t *ret = NULL;
    oss_list_object_params_t *params = NULL;
    int list_object_count = 0;
    const char *next_marker = NULL;
    
    parent_pool = options->pool;
    params = oss_create_list_object_params(parent_pool);
    if (prefix->data == NULL) {
        aos_str_set(&params->prefix, "");
    } else {
        aos_str_set(&params->prefix, prefix->data);
    }
    while (params->truncated) {
        aos_table_t *list_object_resp_headers = NULL;
        aos_list_t object_list;
        aos_list_t deleted_object_list;
        oss_list_object_content_t *list_content = NULL;
        aos_table_t *delete_objects_resp_headers = NULL;
        char *key = NULL;

        aos_pool_create(&subpool, parent_pool);
        options->pool = subpool;
        list_object_count = 0;
        aos_list_init(&object_list);
        s = oss_list_object(options, bucket, params, &list_object_resp_headers);
        if (!aos_status_is_ok(s)) {
            ret = aos_status_dup(parent_pool, s);
            aos_pool_destroy(subpool);
            options->pool = parent_pool;
            return ret;
        }

        aos_list_for_each_entry(oss_list_object_content_t, list_content, &params->object_list, node) {
            oss_object_key_t *object_key = oss_create_oss_object_key(parent_pool);
            key = apr_psprintf(parent_pool, "%.*s", list_content->key.len, 
                               list_content->key.data);
            aos_str_set(&object_key->key, key);
            aos_list_add_tail(&object_key->node, &object_list);
            list_object_count += 1;
        }
        if (list_object_count == 0)
        {
            ret = aos_status_dup(parent_pool, s);
            aos_pool_destroy(subpool);
            options->pool = parent_pool;
            return ret;
        }
        // swap pool
        if (params->next_marker.data != NULL) {
            next_marker = apr_pstrdup(parent_pool, params->next_marker.data);
            aos_str_set(&params->next_marker, next_marker);
        }
        aos_pool_destroy(subpool);

        aos_list_init(&deleted_object_list);
        aos_pool_create(&subpool, parent_pool);
        options->pool = subpool;
        s = oss_delete_objects(options, bucket, &object_list, is_quiet,
                               &delete_objects_resp_headers, &deleted_object_list);
        if (!aos_status_is_ok(s)) {
            ret = aos_status_dup(parent_pool, s);
            aos_pool_destroy(subpool);
            options->pool = parent_pool;
            return ret;
        }
        if (!params->truncated) {
            ret = aos_status_dup(parent_pool, s);
        }

        aos_pool_destroy(subpool);

        aos_list_init(&params->object_list);
        if (params->next_marker.data) {
            aos_str_set(&params->marker, params->next_marker.data);
        }
    }
    options->pool = parent_pool;
    return ret;
}
