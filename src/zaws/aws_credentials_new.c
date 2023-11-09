#include "aws_credentials_new.h"

struct aws_credentials *zig_aws_credentials_new(
    struct aws_allocator *allocator,
   struct aws_byte_cursor const *access_key_id_cursor,
   struct aws_byte_cursor const *secret_access_key_cursor,
   struct aws_byte_cursor const *session_token_cursor,
   uint64_t expiration_timepoint_seconds
) {
    return aws_credentials_new(
        allocator,
        *access_key_id_cursor,
        *secret_access_key_cursor,
        *session_token_cursor,
        expiration_timepoint_seconds
    );
}
