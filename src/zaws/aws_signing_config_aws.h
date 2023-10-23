#pragma once
#include <aws/auth/signing_config.h>
#include <aws/s3/s3_client.h>

// We can't rely on `sizeof` directly since that would
// reference the actual struct with the bitfield in the
// generated code.
#define        ZIG_AWS_SIGNING_CONFIG_AWS_SIZE 256
_Static_assert(ZIG_AWS_SIGNING_CONFIG_AWS_SIZE == sizeof(struct aws_signing_config_aws),
    "Invalid size assertion; must update the value of ZIG_AWS_SIGNING_CONFIG_AWS_SIZE"
);

// Wrapper over `aws_signing_config_aws`
// AWS exposes the actual struct with a bitfield embedded,
// which translate-c can't handle. We instead use an opaque
// bag of bytes.
struct zig_aws_signing_config_aws_bytes {
    char bytes[ZIG_AWS_SIGNING_CONFIG_AWS_SIZE];
};

// mirrors the fields of the actual `aws_signing_config_aws`,
// in order to initialise the opaque bag of bytes.
struct zig_aws_signing_config_aws_wrapper {
    enum aws_signing_config_type config_type;
    enum aws_signing_algorithm algorithm;
    enum aws_signature_type signature_type;
    struct aws_byte_cursor region;
    struct aws_byte_cursor service;
    struct aws_date_time date;
    aws_should_sign_header_fn *should_sign_header;
    void *should_sign_header_ud;
    struct {
        bool use_double_uri_encode;
        bool should_normalize_uri_path;
        bool omit_session_token;
    } flags;
    struct aws_byte_cursor signed_body_value;
    enum aws_signed_body_header_type signed_body_header;
    const struct aws_credentials *credentials;
    struct aws_credentials_provider *credentials_provider;
    uint64_t expiration_in_seconds;
};
void zig_aws_s3_init_signing_config(
    struct zig_aws_signing_config_aws_bytes *const sc,
    struct zig_aws_signing_config_aws_wrapper const *const init
);
