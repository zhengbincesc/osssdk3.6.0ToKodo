#include "aos_log.h"
#include "aos_util.h"
#include "aos_string.h"
#include "aos_status.h"
#include "oss_auth.h"
#include "oss_util.h"
#include "oss_api.h"
#include "oss_config.h"
#include "oss_sample_util.h"

void get_object_to_buffer()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    aos_string_t object;
    int is_cname = 0;
    oss_request_options_t *options = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *params = NULL;
    aos_table_t *resp_headers = NULL;
    aos_status_t *s = NULL;
    aos_list_t buffer;
    aos_buf_t *content = NULL;
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;

    aos_pool_create(&p, NULL);
    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);
    aos_str_set(&bucket, BUCKET_NAME);
    aos_str_set(&object, OBJECT_NAME);
    aos_list_init(&buffer);

    s = oss_get_object_to_buffer(options, &bucket, &object, 
                                 headers, params, &buffer, &resp_headers);

    if (aos_status_is_ok(s)) {
        printf("get object to buffer succeeded\n");
    }
    else {
        printf("get object to buffer failed\n");  
    }

    //get buffer len
    aos_list_for_each_entry(aos_buf_t, content, &buffer, node) {
        len += aos_buf_size(content);
    }

    buf = aos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';

    //copy buffer content to memory
    aos_list_for_each_entry(aos_buf_t, content, &buffer, node) {
        size = aos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }

    aos_pool_destroy(p);
}

void get_object_to_local_file()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    char *download_filename = "get_object_to_local_file.txt";
    aos_string_t object;
    int is_cname = 0;
    oss_request_options_t *options = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *params = NULL;
    aos_table_t *resp_headers = NULL;
    aos_status_t *s = NULL;
    aos_string_t file;

    aos_pool_create(&p, NULL);
    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);
    aos_str_set(&bucket, BUCKET_NAME);
    aos_str_set(&object, OBJECT_NAME);
    headers = aos_table_make(p, 0);
    aos_str_set(&file, download_filename);

    s = oss_get_object_to_file(options, &bucket, &object, headers, 
                               params, &file, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("get object to local file succeeded\n");
    } else {
        printf("get object to local file failed\n");
    }

    aos_pool_destroy(p);
}

void get_object_to_buffer_with_range()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    aos_string_t object;
    int is_cname = 0;
    oss_request_options_t *options = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *params = NULL;
    aos_table_t *resp_headers = NULL;
    aos_status_t *s = NULL;
    aos_list_t buffer;
    aos_buf_t *content = NULL;
    char *buf = NULL;
    int64_t len = 0;
    int64_t size = 0;
    int64_t pos = 0;

    aos_pool_create(&p, NULL);
    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);
    aos_str_set(&bucket, BUCKET_NAME);
    aos_str_set(&object, OBJECT_NAME);
    aos_list_init(&buffer);
    headers = aos_table_make(p, 1);

    /* 设置Range，读取文件的指定范围，bytes=20-100包括第20和第100个字符 */
    apr_table_set(headers, "Range", "bytes=20-100");

    s = oss_get_object_to_buffer(options, &bucket, &object, 
                                 headers, params, &buffer, &resp_headers);

    if (aos_status_is_ok(s)) {
        printf("get object to buffer succeeded\n");
    }
    else {
        printf("get object to buffer failed\n");  
    }

    //get buffer len
    aos_list_for_each_entry(aos_buf_t, content, &buffer, node) {
        len += aos_buf_size(content);
    }

    buf = aos_pcalloc(p, (apr_size_t)(len + 1));
    buf[len] = '\0';

    //copy buffer content to memory
    aos_list_for_each_entry(aos_buf_t, content, &buffer, node) {
        size = aos_buf_size(content);
        memcpy(buf + pos, content->pos, (size_t)size);
        pos += size;
    }

    aos_pool_destroy(p);
}

void get_object_to_local_file_with_range()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    char *download_filename = "get_object_to_local_file.txt";
    aos_string_t object;
    int is_cname = 0;
    oss_request_options_t *options = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *params = NULL;
    aos_table_t *resp_headers = NULL;
    aos_status_t *s = NULL;
    aos_string_t file;

    aos_pool_create(&p, NULL);
    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);
    aos_str_set(&bucket, BUCKET_NAME);
    aos_str_set(&object, OBJECT_NAME);
    aos_str_set(&file, download_filename);
    headers = aos_table_make(p, 1);

    /* 设置Range，读取文件的指定范围，bytes=20-100包括第20和第100个字符 */
    apr_table_set(headers, "Range", "bytes=20-100");

    s = oss_get_object_to_file(options, &bucket, &object, headers, 
                               params, &file, &resp_headers);

    if (aos_status_is_ok(s)) {
        printf("get object to local file succeeded\n");
    } else {
        printf("get object to local file failed\n");
    }

    aos_pool_destroy(p);
}

void get_object_address()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    aos_string_t object;
    aos_string_t objectAddress;
    int is_cname = 0;
    aos_table_t *resp_headers = NULL;
    oss_request_options_t *options = NULL;
    aos_status_t *s = NULL;  

    aos_pool_create(&p, NULL);

    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);

    // set value
    aos_str_set(&bucket, BUCKET_NAME);
    aos_str_set(&object, OBJECT_NAME);

    s = oss_get_object_address(options, &bucket, &object, &objectAddress, 60, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("get object address succeeded, address is %s\r\n", objectAddress.data);
    } else {
        printf("get object address failed\r\n");
    }

    aos_pool_destroy(p);
}

void get_object_by_signed_url()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    aos_string_t object;
    aos_string_t url;
    int is_cname = 0;
    aos_http_request_t *request = NULL;
    aos_table_t *headers = NULL;
    aos_table_t *params = NULL;
    aos_table_t *resp_headers = NULL;
    oss_request_options_t *options = NULL;
    aos_list_t buffer;
    aos_status_t *s = NULL;    
    char *signed_url = NULL;
    int64_t expires_time;

    aos_pool_create(&p, NULL);

    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);

    // create request
    request = aos_http_request_create(p);
    request->method = HTTP_GET;

    // create headers
    headers = aos_table_make(options->pool, 0);

    // set value
    aos_str_set(&bucket, BUCKET_NAME);
    aos_str_set(&object, OBJECT_NAME);
    aos_list_init(&buffer);

    // expires time
    expires_time = apr_time_now() / 1000000 + 120;    

    // generate signed url for put 
    signed_url = oss_gen_signed_url(options, &bucket, &object, 
                                    expires_time, request);
    aos_str_set(&url, signed_url);
    
    printf("signed get url : %s\n", signed_url);

    // put object by signed url
    s = oss_get_object_to_buffer_by_url(options, &url, 
            headers, params, &buffer, &resp_headers);

    if (aos_status_is_ok(s)) {
        printf("get object by signed url succeeded\n");
    } else {
        printf("get object by signed url failed\n");
    }

    aos_pool_destroy(p);
}

void get_oss_dir_to_local_dir()
{
    aos_pool_t *parent_pool = NULL;
    aos_string_t bucket;
    int is_cname = 0;
    aos_status_t *s = NULL;
    oss_request_options_t *options = NULL;
    oss_list_object_params_t *params = NULL;

    aos_pool_create(&parent_pool, NULL);
    options = oss_request_options_create(parent_pool);
    init_sample_request_options(options, is_cname);
    aos_str_set(&bucket, BUCKET_NAME);
    params = oss_create_list_object_params(parent_pool);
    aos_str_set(&params->prefix, DIR_NAME);
    params->truncated = 1;

    while (params->truncated) {
        aos_pool_t *list_object_pool = NULL;
        aos_table_t *list_object_resp_headers = NULL;
        oss_list_object_content_t *list_content = NULL;
        
        aos_pool_create(&list_object_pool, parent_pool);
        options->pool = list_object_pool;
        s = oss_list_object(options, &bucket, params, &list_object_resp_headers);
        if (!aos_status_is_ok(s)) {
            aos_error_log("list objects of dir[%s] fail\n", DIR_NAME);
            aos_status_dup(parent_pool, s);
            aos_pool_destroy(list_object_pool);
            options->pool = parent_pool;
            return;
        }        

        aos_list_for_each_entry(oss_list_object_content_t, list_content, &params->object_list, node) {
            if ('/' == list_content->key.data[strlen(list_content->key.data) - 1]) {
                apr_dir_make_recursive(list_content->key.data, 
                        APR_OS_DEFAULT, parent_pool);                
            } else {
                aos_string_t object;
                aos_pool_t *get_object_pool = NULL;
                aos_table_t *headers = NULL;
                aos_table_t *query_params = NULL;
                aos_table_t *get_object_resp_headers = NULL;

                aos_str_set(&object, list_content->key.data);

                aos_pool_create(&get_object_pool, parent_pool);
                options->pool = get_object_pool;

                s = oss_get_object_to_file(options, &bucket, &object, 
                        headers, query_params, &object, &get_object_resp_headers);
                if (!aos_status_is_ok(s)) {
                    aos_error_log("get object[%s] fail\n", object.data);
                }

                aos_pool_destroy(get_object_pool);
                options->pool = list_object_pool;
            }
        }

        aos_list_init(&params->object_list);
        if (params->next_marker.data) {
            aos_str_set(&params->marker, params->next_marker.data);
        }

        aos_pool_destroy(list_object_pool);
    }

    if (aos_status_is_ok(s)) {
        printf("get dir succeeded\n");
    } else {
        printf("get dir failed\n");
    }
    aos_pool_destroy(parent_pool);
}

void get_object_sample()
{
    get_object_to_buffer();
    get_object_to_local_file();

    get_object_to_buffer_with_range();
    get_object_to_local_file_with_range();

    get_object_by_signed_url();

    get_oss_dir_to_local_dir();
}

void operate_bucket_sample()
{
    aos_pool_t *p = NULL;
    aos_string_t bucket;
    int is_cname = 0;
    oss_request_options_t *options = NULL;
    aos_table_t *resp_headers = NULL;
    aos_status_t *s = NULL;
    oss_list_buckets_params_t *params = NULL;
    oss_list_bucket_content_t *content = NULL;
    aos_string_t oss_acl;
    int isExist = 0;
    oss_bucket_info_t bucket_info;

    aos_pool_create(&p, NULL);
    options = oss_request_options_create(p);
    init_sample_request_options(options, is_cname);
    aos_str_set(&bucket, BUCKET_NAME);
    oss_website_config_t website_config;

    s = oss_put_bucket_website(options, &bucket, &website_config, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("put bucket %s weisite success\r\n", bucket.data);
    } else {
        printf("v bucket %s weisite failed.\r\n", bucket.data);
    }

    s = oss_get_bucket_website(options, &bucket, &website_config, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("get bucket %s weisite success, index is %s, error is %s\r\n", bucket.data,
               website_config.suffix_str.data, website_config.key_str.data);
    } else {
        printf("get bucket %s weisite failed.\r\n", bucket.data);
    }

    s = oss_put_bucket_acl(options, &bucket, OSS_ACL_PRIVATE, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("put bucket %s acl private success.\r\n", bucket.data);
    } else {
        printf("put bucket %s acl private failed.\r\n", bucket.data);
    }

    s = oss_get_bucket_acl(options, &bucket, &oss_acl, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("get bucket %s acl success, acl is %s\r\n", bucket.data, oss_acl.data);
    } else {
        printf("get bucket %s acl failed.\r\n", bucket.data);
    }

    s = oss_put_bucket_acl(options, &bucket, OSS_ACL_PUBLIC_READ, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("put bucket %s acl public success.\r\n", bucket.data);
    } else {
        printf("put bucket %s acl public failed.\r\n", bucket.data);
    }

    s = oss_get_bucket_acl(options, &bucket, &oss_acl, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("get bucket %s acl success, acl is %s\r\n", bucket.data, oss_acl.data);
    } else {
        printf("get bucket %s acl failed.\r\n", bucket.data);
    }

    s = oss_check_bucket(options, &bucket, &isExist, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("check bucket %s success, isExist is %d\r\n", bucket.data, isExist);
    } else {
        printf("check bucket %s failed.\r\n", bucket.data);
    }

    s = oss_get_bucket_info(options, &bucket, &bucket_info, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("get bucket %s info success\r\n", bucket.data);
    } else {
        printf("get bucket %s info failed.\r\n", bucket.data);
    }

    params = oss_create_list_buckets_params(p);
    params->max_keys = 100;
    s = oss_list_bucket(options, params, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("bucket is ");
        aos_list_for_each_entry(oss_list_bucket_content_t, content, &params->bucket_list, node) {
            printf("%s ", content->name.data);

        }
        printf("\r\nlistbucket success.\r\n");
    } else {
        printf("listbucket fail.\r\n");
    }

    s = oss_delete_bucket(options, &bucket, &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("rmbucket %s success.\r\n", bucket.data);
    } else {
        printf("rmbucket %s fail.\r\n", bucket.data);
    }

    s = oss_create_bucket(options, &bucket, OSS_ACL_PRIVATE,
                          &resp_headers);
    if (aos_status_is_ok(s)) {
        printf("mkbucket %s success.\r\n", bucket.data);
    } else {
        printf("mkbucket %s fail.\r\n", bucket.data);
    }

    aos_pool_destroy(p);
}
