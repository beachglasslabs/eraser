//! Documentation used for reference:
//! https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

const eraser = @import("../../pipelines.zig");
const digestBytesToString = eraser.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util");
pub const zaws = @import("zaws");

const Aws = @This();
region: Region,
buckets: []const Bucket,

pub const Bucket = struct { region: Region, name: []const u8 };

pub const access_key_id_len = 20;
pub const secret_access_key_len = 40;
pub const session_token_len = 912;

pub const CredentialsInit = struct {
    access_key_id: SensitiveBytes.Fixed(access_key_id_len),
    secret_access_key: SensitiveBytes.Fixed(secret_access_key_len),
    session_token: SensitiveBytes.Fixed(session_token_len),
};

pub const Ctx = struct {
    /// needs to be a stable pointer.
    zig_ally: std.mem.Allocator,
    /// points to `zig_ally`.
    aws_ally: zaws.Allocator,

    logger: zaws.Logger,

    cond_var: zaws.ConditionVariable,
    mutex: zaws.Mutex,
    event_loop_group: zaws.EventLoopGroup,
    resolver: zaws.HostResolver,
    client_bootstrap: zaws.ClientBootstrap,

    credentials_provider: zaws.CredentialsProvider,
    credentials_provider_delegate: CredentialsProviderDelegate,

    signing_config: zaws.signing_config.Bytes,
    client: zaws.ClientS3,

    const CredentialsProviderDelegate = struct {
        current_creds: ?zaws.Credentials,

        fn getCredentials(delegate_ud: ?*anyopaque, maybe_onGet: ?*const zaws.c.aws_on_get_credentials_callback_fn, on_get_ud: ?*anyopaque) callconv(.C) c_int {
            const delegate: *CredentialsProviderDelegate = @alignCast(@ptrCast(delegate_ud.?));
            const onGet = maybe_onGet.?;

            const is_available = delegate.current_creds != null;
            const err_code = if (is_available) zaws.c.AWS_ERROR_SUCCESS else zaws.c.AWS_ERROR_UNKNOWN;
            const ret_code = if (is_available) zaws.c.AWS_OP_SUCCESS else zaws.c.AWS_ERROR_UNKNOWN;
            onGet(if (delegate.current_creds) |creds| creds.ptr else null, err_code, on_get_ud);

            return ret_code;
        }
    };

    pub const InitAwsError = std.mem.Allocator.Error || zaws.Error || error{
        AwsEventLoopGroupFailedInit,
        AwsHostResolverDefaultFailedInit,
        AwsClientBootstrapFailedInit,
        AwsCredentialsProviderFailedInit,
        AwsS3ClientFailedInit,
    };

    pub fn init(
        aws_ctx: *Ctx,
        allocator: std.mem.Allocator,
        params: struct {
            region: Region,
            log_level: zaws.LogLevel = .warn,
        },
    ) InitAwsError!void {
        aws_ctx.zig_ally = allocator;
        aws_ctx.aws_ally = zaws.stdToAwsAllocator(&aws_ctx.zig_ally);
        const aws_ally = &aws_ctx.aws_ally;

        try aws_ctx.logger.initStandardFile(aws_ally, params.log_level, @ptrCast(zaws.c.stderr));
        errdefer aws_ctx.logger.cleanUp();
        aws_ctx.logger.setCurrent();

        zaws.libraryInit(aws_ally);
        errdefer zaws.libraryCleanUp();

        try zaws.conditionVariableInit(&aws_ctx.cond_var);
        errdefer zaws.conditionVariableCleanUp(&aws_ctx.cond_var);

        try zaws.mutexInit(&aws_ctx.mutex);
        errdefer zaws.mutexCleanUp(&aws_ctx.mutex);

        aws_ctx.event_loop_group = zaws.EventLoopGroup.newDefault(aws_ally, 0, null) orelse
            return error.AwsEventLoopGroupFailedInit;
        errdefer aws_ctx.event_loop_group.release();

        aws_ctx.resolver = zaws.HostResolver.newDefault(aws_ally, .{
            .max_entries = 8,
            .el_group = aws_ctx.event_loop_group.ptr,
        }) orelse return error.AwsHostResolverDefaultFailedInit;
        errdefer aws_ctx.resolver.release();

        aws_ctx.client_bootstrap = zaws.ClientBootstrap.new(aws_ally, .{
            .event_loop_group = aws_ctx.event_loop_group.ptr,
            .host_resolver = aws_ctx.resolver.ptr,
        }) orelse return error.AwsClientBootstrapFailedInit;
        errdefer aws_ctx.client_bootstrap.release();

        aws_ctx.credentials_provider_delegate = .{
            .current_creds = null,
        };
        errdefer if (aws_ctx.credentials_provider_delegate.current_creds) |cur_creds| {
            cur_creds.release();
        };

        aws_ctx.credentials_provider = zaws.CredentialsProvider.newDelegate(aws_ally, .{
            .shutdown_options = .{},
            .get_credentials = CredentialsProviderDelegate.getCredentials,
            .delegate_user_data = &aws_ctx.credentials_provider_delegate,
        }) orelse return error.AwsCredentialsProviderFailedInit;
        errdefer aws_ctx.credentials_provider.release();

        const region_bounded_str = params.region.toBytes();
        const region_str = region_bounded_str.constSlice();

        aws_ctx.signing_config = zaws.signing_config.wrapperToBytes(.{
            .config_type = zaws.c.AWS_SIGNING_CONFIG_AWS,
            .algorithm = zaws.c.AWS_SIGNING_ALGORITHM_V4,
            .signature_type = zaws.c.AWS_ST_HTTP_REQUEST_HEADERS,

            .date = zaws.DateTime.initNow().value,
            .region = zaws.byteCursorFromSlice(@constCast(region_str)), // this should just get read, the C API just doesn't express this constness
            .service = zaws.byteCursorFromSlice(@constCast("s3")), // this should just get read, the C API just doesn't express this constness

            .should_sign_header = null,
            .should_sign_header_ud = null,

            .flags = .{
                .use_double_uri_encode = false,
            },

            .signed_body_header = zaws.c.AWS_SBHT_X_AMZ_CONTENT_SHA256,
            .signed_body_value = zaws.byteCursorFromSlice(null), // leave empty to make AWS calculate it

            .credentials = null,
            .credentials_provider = aws_ctx.credentials_provider.ptr,

            .expiration_in_seconds = 0,
        });

        aws_ctx.client = zaws.ClientS3.new(aws_ally, .{
            .client_bootstrap = aws_ctx.client_bootstrap.ptr,
            .region = zaws.byteCursorFromSlice(@constCast(region_str)), // should just get copied, the C API just doesn't express this
            .signing_config = &aws_ctx.signing_config,
        }) orelse return error.AwsS3ClientFailedInit;
        errdefer aws_ctx.client.release();
    }

    pub fn deinit(aws_ctx: *Ctx) void {
        assert(aws_ctx.aws_ally.impl.? == @as(*anyopaque, &aws_ctx.zig_ally));
        aws_ctx.client.release();
        aws_ctx.credentials_provider.release();
        if (aws_ctx.credentials_provider_delegate.current_creds) |creds| creds.release();
        aws_ctx.client_bootstrap.release();
        aws_ctx.resolver.release();
        aws_ctx.event_loop_group.release();
        zaws.mutexCleanUp(&aws_ctx.mutex);
        zaws.libraryCleanUp();
        aws_ctx.logger.cleanUp();
    }
};

pub const Region = struct {
    /// For example: "us", "af", "ap", "eu"
    geo: [2]u8,
    cardinal: Cardinal,
    number: u16,

    pub const Cardinal = enum {
        central,
        north,
        northeast,
        east,
        southeast,
        south,
        southwest,
        west,
        northwest,
    };

    pub fn toBytes(region: Region) std.BoundedArray(u8, max_len) {
        var result: std.BoundedArray(u8, max_len) = .{};
        result.writer().print(
            "{s}-{s}-{d}",
            .{ region.geo, @tagName(region.cardinal), region.number },
        ) catch unreachable;
        return result;
    }

    pub const max_len = blk: {
        var len = 0;
        for (@typeInfo(Region).Struct.fields) |field| len += switch (@field(std.meta.FieldEnum(Region), field.name)) {
            .geo => add: {
                const info = @typeInfo(field.type).Array;
                break :add info.len * @sizeOf(info.child);
            },
            .cardinal => add: {
                const info = @typeInfo(field.type).Enum;
                const max_tag_name_len = max: {
                    var max = 0;
                    @setEvalBranchQuota(info.fields.len);
                    for (info.fields) |e_field| max = @max(max, e_field.name.len);
                    break :max max;
                };
                break :add max_tag_name_len;
            },
            .number => std.math.maxInt(field.type),
        };
        break :blk len;
    };
};
