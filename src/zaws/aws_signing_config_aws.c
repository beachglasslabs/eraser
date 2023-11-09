#include "aws_signing_config_aws.h"
#include "aws/common/zero.h"
#include <string.h>

typedef struct zig_aws_signing_config_aws_bytes wrapped;
typedef struct aws_signing_config_aws unwrapped;

#define SIGNING_CONFIG_ASSIGN(dst, src) \
    (dst)->config_type                     = (src)->config_type;                     \
    (dst)->algorithm                       = (src)->algorithm;                       \
    (dst)->signature_type                  = (src)->signature_type;                  \
    (dst)->region                          = (src)->region;                          \
    (dst)->service                         = (src)->service;                         \
    (dst)->date                            = (src)->date;                            \
    (dst)->should_sign_header              = (src)->should_sign_header;              \
    (dst)->should_sign_header_ud           = (src)->should_sign_header_ud;           \
                                                                                     \
    (dst)->flags.use_double_uri_encode     = (src)->flags.use_double_uri_encode;     \
    (dst)->flags.should_normalize_uri_path = (src)->flags.should_normalize_uri_path; \
    (dst)->flags.omit_session_token        = (src)->flags.omit_session_token;        \
                                                                                     \
    (dst)->signed_body_value               = (src)->signed_body_value;               \
    (dst)->signed_body_header              = (src)->signed_body_header;              \
    (dst)->credentials                     = (src)->credentials;                     \
    (dst)->credentials_provider            = (src)->credentials_provider;            \
    (dst)->expiration_in_seconds           = (src)->expiration_in_seconds;

void zig_aws_s3_signing_config_wrapper_to_bytes(
    struct zig_aws_signing_config_aws_bytes *const sc_w,
    struct zig_aws_signing_config_aws_wrapper const *const wrapper
) {
    unwrapped *const sc = (unwrapped *)sc_w->bytes;
    AWS_ZERO_STRUCT(*sc);
    SIGNING_CONFIG_ASSIGN(sc, wrapper);
}

void zig_aws_s3_signing_config_bytes_to_wrapper(
    struct zig_aws_signing_config_aws_wrapper *const wrapper,
    struct zig_aws_signing_config_aws_bytes const *const sc_w
) {
    unwrapped const *const sc = (unwrapped *)sc_w->bytes;
    AWS_ZERO_STRUCT(*wrapper);
    SIGNING_CONFIG_ASSIGN(wrapper, sc);
}

