#include "aws_meta_request.h"

struct aws_s3_meta_request *zig_aws_s3_client_make_meta_request_wrapper(
    struct aws_s3_client *client,
    const struct zig_aws_s3_meta_request_options_wrapper *opt_wrapper
) {
    struct aws_s3_meta_request_options options;
    AWS_ZERO_STRUCT(options);

    options.type = opt_wrapper->type;
    options.signing_config = (struct aws_signing_config_aws const*)opt_wrapper->signing_config->bytes;

    options.message = opt_wrapper->message;
    options.send_filepath = opt_wrapper->send_filepath;
    options.send_async_stream = opt_wrapper->send_async_stream;
    options.checksum_config = opt_wrapper->checksum_config;

    options.user_data = opt_wrapper->user_data;
    options.headers_callback = opt_wrapper->headers_callback;
    options.body_callback = opt_wrapper->body_callback;
    options.finish_callback = opt_wrapper->finish_callback;
    options.shutdown_callback = opt_wrapper->shutdown_callback;
    options.progress_callback = opt_wrapper->progress_callback;
    options.telemetry_callback = opt_wrapper->telemetry_callback;
    options.upload_review_callback = opt_wrapper->upload_review_callback;

    options.endpoint = opt_wrapper->endpoint;
    options.resume_token = opt_wrapper->resume_token;

    return aws_s3_client_make_meta_request(client, &options);
}
