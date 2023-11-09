#pragma once
#include "aws_signing_config_aws.h"
#include <aws/s3/s3_client.h>

struct zig_aws_s3_meta_request_options_wrapper {
    enum aws_s3_meta_request_type type;
    const struct zig_aws_signing_config_aws_bytes *signing_config;

    struct aws_http_message *message;
    struct aws_byte_cursor send_filepath;
    struct aws_async_input_stream *send_async_stream;
    const struct aws_s3_checksum_config *checksum_config;

    void *user_data;
    aws_s3_meta_request_headers_callback_fn *headers_callback;
    aws_s3_meta_request_receive_body_callback_fn *body_callback;
    aws_s3_meta_request_finish_fn *finish_callback;
    aws_s3_meta_request_shutdown_fn *shutdown_callback;
    aws_s3_meta_request_progress_fn *progress_callback;
    aws_s3_meta_request_telemetry_fn *telemetry_callback;
    aws_s3_meta_request_upload_review_fn *upload_review_callback;

    struct aws_uri *endpoint;
    struct aws_s3_meta_request_resume_token *resume_token;
};

struct aws_s3_meta_request *zig_aws_s3_client_make_meta_request_wrapper(
    struct aws_s3_client *client,
    const struct zig_aws_s3_meta_request_options_wrapper *options_wrapper
);
