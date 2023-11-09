#pragma once
// THIS EXISTS BECAUSE ZIG HAS PROBLEMS PASSING 16 BYTE STRUCTS BY VALUE TO C

#include <aws/auth/credentials.h>
#include <aws/common/allocator.h>

struct aws_credentials *zig_aws_credentials_new(
    struct aws_allocator *allocator,
   struct aws_byte_cursor const *access_key_id_cursor,
   struct aws_byte_cursor const *secret_access_key_cursor,
   struct aws_byte_cursor const *session_token_cursor,
   uint64_t expiration_timepoint_seconds
);
