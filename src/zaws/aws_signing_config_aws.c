#include "aws_signing_config_aws.h"
#include "aws/common/zero.h"
#include <string.h>

typedef struct zig_aws_signing_config_aws_bytes wrapped;
typedef struct aws_signing_config_aws unwrapped;

// initialisation
void zig_aws_s3_init_signing_config(
    struct zig_aws_signing_config_aws_bytes *const sc_w,
    struct zig_aws_signing_config_aws_wrapper const *const init
) {
    unwrapped *const sc = (unwrapped *)sc_w->bytes;
    AWS_ZERO_STRUCT(*sc);
    sc->config_type = init->config_type;
    sc->algorithm = init->algorithm;
    sc->signature_type = init->signature_type;
    sc->region = init->region;
    sc->service = init->service;
    sc->date = init->date;
    sc->should_sign_header = init->should_sign_header;
    sc->should_sign_header_ud = init->should_sign_header_ud;

    sc->flags.use_double_uri_encode = init->flags.use_double_uri_encode;
    sc->flags.should_normalize_uri_path = init->flags.should_normalize_uri_path;
    sc->flags.omit_session_token = init->flags.omit_session_token;

    sc->signed_body_value = init->signed_body_value;
    sc->signed_body_header = init->signed_body_header;
    sc->credentials = init->credentials;
    sc->credentials_provider = init->credentials_provider;
    sc->expiration_in_seconds = init->expiration_in_seconds;
}
