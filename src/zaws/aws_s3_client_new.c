#include "aws_s3_client_new.h"

struct aws_s3_client *zig_aws_s3_client_new_wrapper(
    struct aws_allocator *allocator,
    struct zig_aws_s3_client_config_aws_wrapper const *ccw) {

  struct aws_s3_client_config client_config = {
      .max_active_connections_override = ccw->max_active_connections_override,
      .region = ccw->region,
      .client_bootstrap = ccw->client_bootstrap,
      .tls_mode = ccw->tls_mode,
      .tls_connection_options = ccw->tls_connection_options,

      .signing_config = (struct aws_signing_config_aws *)ccw->signing_config->bytes,

      .part_size = ccw->part_size,
      .max_part_size = ccw->max_part_size,
      .multipart_upload_threshold = ccw->multipart_upload_threshold,
      .throughput_target_gbps = ccw->throughput_target_gbps,
      .retry_strategy = ccw->retry_strategy,
      .compute_content_md5 = ccw->compute_content_md5,
      .proxy_options = ccw->proxy_options,
      .proxy_ev_settings = ccw->proxy_ev_settings,
      .connect_timeout_ms = ccw->connect_timeout_ms,
      .tcp_keep_alive_options = ccw->tcp_keep_alive_options,
      .monitoring_options = ccw->monitoring_options,
      .enable_read_backpressure = ccw->enable_read_backpressure,
      .initial_read_window = ccw->initial_read_window,
  };

  return aws_s3_client_new(allocator, &client_config);
}