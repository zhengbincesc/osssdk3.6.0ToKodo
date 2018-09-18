#include "aos_log.h"
#include "aos_util.h"
#include "aos_string.h"
#include "aos_status.h"
#include "oss_auth.h"
#include "oss_util.h"
#include "oss_api.h"
#include "oss_config.h"
#include "oss_sample_util.h"

extern void append_object_sample();
extern void delete_object_sample();
extern void put_object_sample();
extern void get_object_sample();
extern void head_object_sample();
extern void list_object_sample();
extern void multipart_object_sample();
extern void callback_sample();
extern void progress_sample();
extern void crc_sample();
extern void image_sample();
extern void resumable_upload_sample();
extern void resumable_download_sample();
extern void put_object_from_file();
extern void get_object_to_local_file();
extern void delete_object();
extern void operate_bucket_sample();
extern void get_object_address();

int main(int argc, char *argv[])
{
    if (aos_http_io_initialize(NULL, 0) != AOSE_OK) {
        exit(1);
    }

    /*
    put_object_sample();
    append_object_sample();
    get_object_sample();
    head_object_sample();
    list_object_sample();
    multipart_object_sample();
    delete_object_sample();
    callback_sample();
    progress_sample();
    crc_sample();
    image_sample();
    resumable_upload_sample();
    resumable_download_sample();
    operate_bucket_sample(); */
    
    operate_bucket_sample();
    get_object_to_local_file();
    delete_object();
    put_object_from_file();
    list_object_sample();
    get_object_address();

    aos_http_io_deinitialize();

    system("pause");

    return 0;
}
