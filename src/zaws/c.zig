pub usingnamespace @cImport({
    @cInclude("aws/auth/credentials.h");
    @cInclude("aws/common/condition_variable.h");
    @cInclude("aws/common/mutex.h");
    @cInclude("aws/io/channel_bootstrap.h");
    @cInclude("aws/io/event_loop.h");
    @cInclude("aws/io/logging.h");
    @cInclude("aws/io/uri.h");
    @cInclude("aws/io/stream.h");
    @cInclude("aws/io/async_stream.h");
    @cInclude("aws/http/request_response.h");
    @cInclude("aws/s3/s3_client.h");
    @cInclude("aws/s3/s3.h");

    // implemented by us to get around the API's use of bitfields and other things
    @cInclude("zaws/zaws.h");
});
