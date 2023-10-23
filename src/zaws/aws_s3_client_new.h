#pragma once
#include "aws_signing_config_aws.h"
#include <aws/s3/s3_client.h>

// same as the original, except the signing_config
// field is replaced with our wrapper
struct zig_aws_s3_client_config_aws_wrapper {
  uint32_t max_active_connections_override;
  struct aws_byte_cursor region;
  struct aws_client_bootstrap *client_bootstrap;
  enum aws_s3_meta_request_tls_mode tls_mode;
  struct aws_tls_connection_options *tls_connection_options;
  struct zig_aws_signing_config_aws_bytes *signing_config;
  uint64_t part_size;
  uint64_t max_part_size;
  uint64_t multipart_upload_threshold;
  double throughput_target_gbps;
  struct aws_retry_strategy *retry_strategy;
  enum aws_s3_meta_request_compute_content_md5 compute_content_md5;
  struct aws_http_proxy_options *proxy_options;
  struct proxy_env_var_settings *proxy_ev_settings;
  uint32_t connect_timeout_ms;
  struct aws_s3_tcp_keep_alive_options *tcp_keep_alive_options;
  struct aws_http_connection_monitoring_options *monitoring_options;
  bool enable_read_backpressure;
  size_t initial_read_window;
};

struct aws_s3_client *zig_aws_s3_client_new_wrapper(
    struct aws_allocator *allocator,
    struct zig_aws_s3_client_config_aws_wrapper const *ccw);
