const std = @import("std");
const assert = std.debug.assert;
const util = @import("util");
const zaws = @This();

pub const c = @import("zaws/c.zig");

pub const Error = @Type(.{ .ErrorSet = blk: {
    const fields = @typeInfo(ErrorCode).Enum.fields;
    var errs: [fields.len]std.builtin.Type.Error = undefined;
    for (&errs, fields) |*err, field| {
        err.name = "AWS_" ++ field.name;
    }
    break :blk &errs;
} });

pub inline fn lastError() ErrorCode {
    return @enumFromInt(c.aws_last_error());
}
pub const ErrorCode = enum(c_int) {
    SUCCESS = c.AWS_ERROR_SUCCESS,
    OOM = c.AWS_ERROR_OOM,
    NO_SPACE = c.AWS_ERROR_NO_SPACE,
    UNKNOWN = c.AWS_ERROR_UNKNOWN,
    SHORT_BUFFER = c.AWS_ERROR_SHORT_BUFFER,
    OVERFLOW_DETECTED = c.AWS_ERROR_OVERFLOW_DETECTED,
    UNSUPPORTED_OPERATION = c.AWS_ERROR_UNSUPPORTED_OPERATION,
    INVALID_BUFFER_SIZE = c.AWS_ERROR_INVALID_BUFFER_SIZE,
    INVALID_HEX_STR = c.AWS_ERROR_INVALID_HEX_STR,
    INVALID_BASE64_STR = c.AWS_ERROR_INVALID_BASE64_STR,
    INVALID_INDEX = c.AWS_ERROR_INVALID_INDEX,
    THREAD_INVALID_SETTINGS = c.AWS_ERROR_THREAD_INVALID_SETTINGS,
    THREAD_INSUFFICIENT_RESOURCE = c.AWS_ERROR_THREAD_INSUFFICIENT_RESOURCE,
    THREAD_NO_PERMISSIONS = c.AWS_ERROR_THREAD_NO_PERMISSIONS,
    THREAD_NOT_JOINABLE = c.AWS_ERROR_THREAD_NOT_JOINABLE,
    THREAD_NO_SUCH_THREAD_ID = c.AWS_ERROR_THREAD_NO_SUCH_THREAD_ID,
    THREAD_DEADLOCK_DETECTED = c.AWS_ERROR_THREAD_DEADLOCK_DETECTED,
    MUTEX_NOT_INIT = c.AWS_ERROR_MUTEX_NOT_INIT,
    MUTEX_TIMEOUT = c.AWS_ERROR_MUTEX_TIMEOUT,
    MUTEX_CALLER_NOT_OWNER = c.AWS_ERROR_MUTEX_CALLER_NOT_OWNER,
    MUTEX_FAILED = c.AWS_ERROR_MUTEX_FAILED,
    COND_VARIABLE_INIT_FAILED = c.AWS_ERROR_COND_VARIABLE_INIT_FAILED,
    COND_VARIABLE_TIMED_OUT = c.AWS_ERROR_COND_VARIABLE_TIMED_OUT,
    COND_VARIABLE_ERROR_UNKNOWN = c.AWS_ERROR_COND_VARIABLE_ERROR_UNKNOWN,
    CLOCK_FAILURE = c.AWS_ERROR_CLOCK_FAILURE,
    LIST_EMPTY = c.AWS_ERROR_LIST_EMPTY,
    DEST_COPY_TOO_SMALL = c.AWS_ERROR_DEST_COPY_TOO_SMALL,
    LIST_EXCEEDS_MAX_SIZE = c.AWS_ERROR_LIST_EXCEEDS_MAX_SIZE,
    LIST_STATIC_MODE_CANT_SHRINK = c.AWS_ERROR_LIST_STATIC_MODE_CANT_SHRINK,
    PRIORITY_QUEUE_FULL = c.AWS_ERROR_PRIORITY_QUEUE_FULL,
    PRIORITY_QUEUE_EMPTY = c.AWS_ERROR_PRIORITY_QUEUE_EMPTY,
    PRIORITY_QUEUE_BAD_NODE = c.AWS_ERROR_PRIORITY_QUEUE_BAD_NODE,
    HASHTBL_ITEM_NOT_FOUND = c.AWS_ERROR_HASHTBL_ITEM_NOT_FOUND,
    INVALID_DATE_STR = c.AWS_ERROR_INVALID_DATE_STR,
    INVALID_ARGUMENT = c.AWS_ERROR_INVALID_ARGUMENT,
    RANDOM_GEN_FAILED = c.AWS_ERROR_RANDOM_GEN_FAILED,
    MALFORMED_INPUT_STRING = c.AWS_ERROR_MALFORMED_INPUT_STRING,
    UNIMPLEMENTED = c.AWS_ERROR_UNIMPLEMENTED,
    INVALID_STATE = c.AWS_ERROR_INVALID_STATE,
    ENVIRONMENT_GET = c.AWS_ERROR_ENVIRONMENT_GET,
    ENVIRONMENT_SET = c.AWS_ERROR_ENVIRONMENT_SET,
    ENVIRONMENT_UNSET = c.AWS_ERROR_ENVIRONMENT_UNSET,
    STREAM_UNSEEKABLE = c.AWS_ERROR_STREAM_UNSEEKABLE,
    NO_PERMISSION = c.AWS_ERROR_NO_PERMISSION,
    FILE_INVALID_PATH = c.AWS_ERROR_FILE_INVALID_PATH,
    MAX_FDS_EXCEEDED = c.AWS_ERROR_MAX_FDS_EXCEEDED,
    SYS_CALL_FAILURE = c.AWS_ERROR_SYS_CALL_FAILURE,
    C_STRING_BUFFER_NOT_NULL_TERMINATED = c.AWS_ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED,
    STRING_MATCH_NOT_FOUND = c.AWS_ERROR_STRING_MATCH_NOT_FOUND,
    DIVIDE_BY_ZERO = c.AWS_ERROR_DIVIDE_BY_ZERO,
    INVALID_FILE_HANDLE = c.AWS_ERROR_INVALID_FILE_HANDLE,
    OPERATION_INTERUPTED = c.AWS_ERROR_OPERATION_INTERUPTED,
    DIRECTORY_NOT_EMPTY = c.AWS_ERROR_DIRECTORY_NOT_EMPTY,
    PLATFORM_NOT_SUPPORTED = c.AWS_ERROR_PLATFORM_NOT_SUPPORTED,
    INVALID_UTF8 = c.AWS_ERROR_INVALID_UTF8,
    GET_HOME_DIRECTORY_FAILED = c.AWS_ERROR_GET_HOME_DIRECTORY_FAILED,
    INVALID_XML = c.AWS_ERROR_INVALID_XML,
    FILE_OPEN_FAILURE = c.AWS_ERROR_FILE_OPEN_FAILURE,
    FILE_READ_FAILURE = c.AWS_ERROR_FILE_READ_FAILURE,
    FILE_WRITE_FAILURE = c.AWS_ERROR_FILE_WRITE_FAILURE,
    END_COMMON_RANGE = c.AWS_ERROR_END_COMMON_RANGE,

    pub inline fn toError(ec: ErrorCode) !void {
        return switch (ec) {
            .SUCCESS => {},
            inline else => |tag| @field(anyerror, "AWS_" ++ @tagName(tag)),
        };
    }
};

pub inline fn libraryInit(allocator: *zaws.Allocator) void {
    c.aws_s3_library_init(allocator);
}
pub inline fn libraryCleanUp() void {
    c.aws_s3_library_clean_up();
}

pub const ConditionVariable = c.aws_condition_variable;
pub inline fn conditionVariableInit(cond_var: *ConditionVariable) Error!void {
    return switch (c.aws_condition_variable_init(cond_var)) {
        c.AWS_OP_SUCCESS => {},
        c.AWS_OP_ERR => lastError().toError(),
        else => unreachable,
    };
}
pub inline fn conditionVariableCleanUp(cond_var: *ConditionVariable) void {
    c.aws_condition_variable_clean_up(cond_var);
}

pub const Mutex = c.aws_mutex;
pub inline fn mutexInit(mtx: *Mutex) Error!void {
    return switch (c.aws_mutex_init(mtx)) {
        c.AWS_OP_SUCCESS => {},
        c.AWS_OP_ERR => lastError().toError(),
        else => unreachable,
    };
}
pub inline fn mutexCleanUp(mtx: *Mutex) void {
    c.aws_mutex_clean_up(mtx);
}
pub inline fn mutexLock(mtx: *Mutex) Error!void {
    return switch (c.aws_mutex_lock(mtx)) {
        c.AWS_OP_SUCCESS => {},
        c.AWS_OP_ERR => lastError().toError(),
        else => unreachable,
    };
}
pub inline fn mutexTryLock(mtx: *Mutex) Error!void {
    return switch (c.aws_mutex_try_lock(mtx)) {
        c.AWS_OP_SUCCESS => {},
        c.AWS_OP_ERR => lastError().toError(),
        else => unreachable,
    };
}
pub inline fn mutexUnlock(mtx: *Mutex) Error!void {
    return switch (c.aws_mutex_unlock(mtx)) {
        c.AWS_OP_SUCCESS => {},
        c.AWS_OP_ERR => lastError().toError(),
        else => unreachable,
    };
}

pub const ShutdownCallbackOptions = c.aws_shutdown_callback_options;

pub const EventLoopGroup = struct {
    ptr: *c.aws_event_loop_group,

    pub inline fn release(el_group: EventLoopGroup) void {
        return c.aws_event_loop_group_release(el_group.ptr);
    }
    pub inline fn newDefault(allocator: *zaws.Allocator, max_threads: u16, shutdown_opts: ?ShutdownCallbackOptions) ?EventLoopGroup {
        const ptr = c.aws_event_loop_group_new_default(allocator, max_threads, if (shutdown_opts) |*opts| opts else null) orelse return null;
        return .{ .ptr = ptr };
    }
};

pub const HostResolver = struct {
    ptr: *c.aws_host_resolver,

    pub inline fn release(resolver: HostResolver) void {
        return c.aws_host_resolver_release(resolver.ptr);
    }

    pub const DefaultOptions = c.aws_host_resolver_default_options;
    pub inline fn newDefault(allocator: *zaws.Allocator, options: DefaultOptions) ?HostResolver {
        const ptr = c.aws_host_resolver_new_default(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }
};

pub const ClientBootstrap = struct {
    ptr: *c.aws_client_bootstrap,

    pub inline fn release(bootstrap: ClientBootstrap) void {
        return c.aws_client_bootstrap_release(bootstrap.ptr);
    }

    pub const Options = c.aws_client_bootstrap_options;
    pub inline fn new(allocator: *zaws.Allocator, options: Options) ?ClientBootstrap {
        const ptr = c.aws_client_bootstrap_new(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }
};

pub const Credentials = struct {
    ptr: *c.aws_credentials,

    pub inline fn acquire(creds: Credentials) void {
        c.aws_credentials_acquire(creds.ptr);
    }

    pub inline fn release(creds: Credentials) void {
        return c.aws_credentials_release(creds.ptr);
    }

    pub inline fn new(
        allocator: *zaws.Allocator,
        access_key_id: []const u8,
        secret_access_key: []const u8,
        session_token: []const u8,
        expiration_timepoint_seconds: u64,
    ) ?Credentials {
        const ptr = c.zig_aws_credentials_new(
            allocator,
            &byteCursorFromSlice(@constCast(access_key_id)), // should be safe, the immutability just isn't expressed by the C API
            &byteCursorFromSlice(@constCast(secret_access_key)), // should be safe, the immutability just isn't expressed by the C API
            &byteCursorFromSlice(@constCast(session_token)), // should be safe, the immutability just isn't expressed by the C API
            expiration_timepoint_seconds,
        ) orelse return null;
        return .{ .ptr = ptr };
    }

    pub inline fn newAnonymous(allocator: *zaws.Allocator) ?Credentials {
        const ptr = c.aws_credentials_new_anonymous(allocator) orelse return null;
        return .{ .ptr = ptr };
    }
};

pub const CredentialsProvider = struct {
    ptr: *c.aws_credentials_provider,

    pub inline fn acquire(creds_prov: CredentialsProvider) void {
        assert(c.aws_credentials_provider_acquire(creds_prov.ptr) == creds_prov.ptr);
    }
    pub inline fn release(creds_prov: CredentialsProvider) void {
        assert(c.aws_credentials_provider_release(creds_prov.ptr) == null);
    }

    pub const CredentialsProviderStaticOptions = c.aws_credentials_provider_static_options;
    pub inline fn newStatic(allocator: *zaws.Allocator, options: CredentialsProviderStaticOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_static(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }

    pub inline fn newAnonymous(allocator: *zaws.Allocator, shutdown_opts: ?ShutdownCallbackOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_anonymous(allocator, if (shutdown_opts) |*opts| opts else null) orelse return null;
        return .{ .ptr = ptr };
    }

    pub const CredentialsProviderEnvironmentOptions = c.aws_credentials_provider_environment_options;
    pub inline fn newEnvironment(allocator: *zaws.Allocator, options: CredentialsProviderEnvironmentOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_environment(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }

    pub const CredentialsProviderCachedOptions = c.aws_credentials_provider_cached_options;
    pub inline fn newCached(allocator: *zaws.Allocator, options: CredentialsProviderCachedOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_cached(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }
    // aws_credentials_provider_new_profile
    // aws_credentials_provider_new_sts
    pub const CredentialsProviderChainOptions = c.aws_credentials_provider_chain_options;
    pub inline fn newChain(allocator: *zaws.Allocator, options: CredentialsProviderChainOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_chain(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }
    // aws_credentials_provider_new_imds
    // aws_credentials_provider_new_ecs
    // aws_credentials_provider_new_x509
    // aws_credentials_provider_new_sts_web_identity
    // aws_credentials_provider_new_sso
    // aws_credentials_provider_new_process
    pub const CredentialsProviderDelegateOptions = c.aws_credentials_provider_delegate_options;
    pub inline fn newDelegate(allocator: *zaws.Allocator, options: CredentialsProviderDelegateOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_delegate(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }
    // aws_credentials_provider_new_cognito
    // aws_credentials_provider_new_cognito_caching
    pub const CredentialsProviderChainDefaultOptions = c.aws_credentials_provider_chain_default_options;
    pub inline fn newChainDefault(allocator: *zaws.Allocator, options: CredentialsProviderChainDefaultOptions) ?CredentialsProvider {
        const ptr = c.aws_credentials_provider_new_chain_default(allocator, &options) orelse return null;
        return .{ .ptr = ptr };
    }
};

pub const ClientS3 = struct {
    ptr: *c.aws_s3_client,

    pub inline fn acquire(client: ClientS3) void {
        assert(c.aws_s3_client_acquire(client.ptr) == client.ptr);
    }
    pub inline fn release(client: ClientS3) void {
        assert(c.aws_s3_client_release(client.ptr) == null);
    }

    pub const Config = c.zig_aws_s3_client_config_aws_wrapper;
    pub inline fn new(allocator: *zaws.Allocator, config: Config) ?ClientS3 {
        const ptr = c.zig_aws_s3_client_new_wrapper(allocator, &config) orelse return null;
        return .{ .ptr = ptr };
    }

    pub inline fn makeMetaRequest(client: ClientS3, options: MetaRequestS3.Options) ?MetaRequestS3 {
        const ptr = c.zig_aws_s3_client_make_meta_request_wrapper(client.ptr, &options) orelse return null;
        return .{ .ptr = ptr };
    }
};

pub const InputStream = struct {
    ptr: *c.aws_input_stream,

    pub inline fn acquire(in_stream: InputStream) void {
        assert(c.aws_input_stream_acquire(in_stream.ptr) == in_stream.ptr);
    }

    pub inline fn release(in_stream: InputStream) void {
        assert(c.aws_input_stream_release(in_stream.ptr) == null);
    }

    pub inline fn newFromCursor(
        allocator: *zaws.Allocator,
        /// Must have a lifetime greater than or equal to the returned input stream.
        slice: []const u8,
    ) ?InputStream {
        const cursor = byteCursorFromSlice(@constCast(slice)); // this should just be read from, and not written to, the C API just doesn't express this constness
        const ptr = c.aws_input_stream_new_from_cursor(allocator, &cursor) orelse return null;
        return .{ .ptr = ptr };
    }

    // pub extern fn aws_input_stream_new_from_file(allocator: [*c]struct_aws_allocator, file_name: [*c]const u8) [*c]struct_aws_input_stream;
    // pub extern fn aws_input_stream_new_from_open_file(allocator: [*c]struct_aws_allocator, file: [*c]FILE) [*c]struct_aws_input_stream;

    // pub extern fn aws_input_stream_seek(stream: [*c]struct_aws_input_stream, offset: i64, basis: enum_aws_stream_seek_basis) c_int;
    // pub extern fn aws_input_stream_read(stream: [*c]struct_aws_input_stream, dest: [*c]struct_aws_byte_buf) c_int;
    // pub extern fn aws_input_stream_get_status(stream: [*c]struct_aws_input_stream, status: [*c]struct_aws_stream_status) c_int;
    // pub extern fn aws_input_stream_get_length(stream: [*c]struct_aws_input_stream, out_length: [*c]i64) c_int;

};

pub const HttpMessage = struct {
    ptr: *c.aws_http_message,

    pub inline fn acquire(msg: HttpMessage) void {
        assert(c.aws_http_message_acquire(msg.ptr) == msg.ptr);
    }

    pub inline fn release(msg: HttpMessage) void {
        assert(c.aws_http_message_release(msg.ptr) == null);
    }

    pub inline fn newRequest(allocator: *zaws.Allocator) ?HttpMessage {
        const ptr = c.aws_http_message_new_request(allocator) orelse return null;
        return .{ .ptr = ptr };
    }

    pub inline fn newRequestHttp2(allocator: *zaws.Allocator) ?HttpMessage {
        const ptr = c.aws_http2_message_new_request(allocator) orelse return null;
        return .{ .ptr = ptr };
    }

    pub inline fn setRequestMethod(msg: HttpMessage, method: []const u8) Error!void {
        const method_cursor = byteCursorFromSlice(@constCast(method)); // this should just get copied, the C API just doesn't express this
        return switch (c.aws_http_message_set_request_method(msg.ptr, method_cursor)) {
            c.AWS_OP_SUCCESS => {},
            c.AWS_OP_ERR => lastError().toError(),
            else => unreachable,
        };
    }

    pub inline fn setRequestPath(msg: HttpMessage, path: []const u8) Error!void {
        const path_cursor = byteCursorFromSlice(@constCast(path)); // this should just get copied, the C API just doesn't express this
        return switch (c.aws_http_message_set_request_path(msg.ptr, path_cursor)) {
            c.AWS_OP_SUCCESS => {},
            c.AWS_OP_ERR => lastError().toError(),
            else => unreachable,
        };
    }

    pub inline fn setBodyStream(msg: HttpMessage, body_stream: ?InputStream) void {
        return c.aws_http_message_set_body_stream(msg.ptr, if (body_stream) |bs| bs.ptr else null);
    }
};

pub const Uri = struct {
    value: zaws.c.aws_uri,

    pub inline fn cleanUp(uri: *Uri) void {
        c.aws_uri_clean_up(&uri.value);
    }

    pub inline fn initParse(allocator: *zaws.Allocator, str: []const u8) Error!Uri {
        var result: Uri = .{ .value = undefined };
        return switch (c.aws_uri_init_parse(
            &result.value,
            allocator,
            &byteCursorFromSlice(@constCast(str)), // this should only be read and never written to, the C API just doesn't express this constness
        )) {
            c.AWS_OP_SUCCESS => result,
            c.AWS_OP_ERR => if (lastError().toError()) |_| unreachable else |e| e,
            else => unreachable,
        };
    }

    pub const BuilderOptions = c.aws_uri_builder_options;
    pub inline fn initFromBuilderOptions(allocator: *zaws.Allocator, options: BuilderOptions) Error!Uri {
        var result: Uri = .{ .value = undefined };
        return switch (c.aws_uri_init_from_builder_options(
            &result.value,
            allocator,
            @constCast(&options),
        )) {
            c.AWS_OP_SUCCESS => result,
            c.AWS_OP_ERR => if (lastError().toError()) |_| unreachable else |e| e,
            else => unreachable,
        };
    }
};

pub const MetaRequestS3 = struct {
    ptr: *c.aws_s3_meta_request,

    pub const Options = c.zig_aws_s3_meta_request_options_wrapper;

    pub inline fn acquire(req: MetaRequestS3) void {
        assert(c.aws_s3_meta_request_acquire(req.ptr) == req.ptr);
    }

    pub inline fn release(req: MetaRequestS3) void {
        assert(c.aws_s3_meta_request_release(req.ptr) == null);
    }

    pub inline fn cancel(mreq: MetaRequestS3) void {
        return c.aws_s3_meta_request_cancel(mreq.ptr);
    }

    pub const MetaRequestS3ResumeToken = c.aws_s3_meta_request_resume_token;
    pub inline fn pause(mreq: *MetaRequestS3) Error!*MetaRequestS3ResumeToken {
        var req: ?*MetaRequestS3ResumeToken = null;
        return switch (c.aws_s3_meta_request_pause(mreq, &req)) {
            c.AWS_OP_SUCCESS => req.?,
            c.AWS_OP_ERR => try lastError().toError(),
            else => unreachable,
        };
    }
};

pub const ChecksumAlgorithmS3 = enum(c.enum_aws_s3_checksum_algorithm) {
    none = c.AWS_SCA_NONE,
    crc32c = c.AWS_SCA_CRC32C,
    crc32 = c.AWS_SCA_CRC32,
    sha1 = c.AWS_SCA_SHA1,
    sha256 = c.AWS_SCA_SHA256,
};

pub const LogLevel = enum(c.enum_aws_log_level) {
    none = c.AWS_LL_NONE,
    fatal = c.AWS_LL_FATAL,
    @"error" = c.AWS_LL_ERROR,
    warn = c.AWS_LL_WARN,
    info = c.AWS_LL_INFO,
    debug = c.AWS_LL_DEBUG,
    trace = c.AWS_LL_TRACE,
    _,
};

pub const LogSubject = enum(c.aws_log_subject_t) { _ };

pub const Logger = extern struct {
    value: c.aws_logger,
    comptime {
        assert(@sizeOf(Logger) == @sizeOf(c.aws_logger));
    }

    pub inline fn cleanUp(logger: *Logger) void {
        c.aws_logger_clean_up(logger.asCPtr());
    }

    pub inline fn setCurrent(logger: ?*Logger) void {
        c.aws_logger_set(if (logger) |ptr| ptr.asCPtr() else null);
    }

    pub inline fn getCurrent() ?*Logger {
        return Logger.fromCPtr(c.aws_logger_get() orelse return null);
    }

    pub inline fn getCurrentConditional(subject: LogSubject, level: LogLevel) ?*Logger {
        const ptr = c.aws_logger_get_conditional(@intFromEnum(subject), @intFromEnum(level)) orelse return null;
        return Logger.fromCPtr(ptr);
    }

    pub inline fn setLogLevel(logger: *Logger, log_level: LogLevel) Error!void {
        switch (c.aws_logger_set_log_level(logger.asCPtr(), @intFromEnum(log_level))) {
            c.AWS_OP_SUCCESS => {},
            c.AWS_OP_ERR => try lastError().toError(),
            else => unreachable,
        }
    }

    pub inline fn initStandardFile(
        logger: *Logger,
        allocator: *zaws.Allocator,
        log_level: LogLevel,
        file: *std.c.FILE,
    ) Error!void {
        const options = util.initNoDefault(c.aws_logger_standard_options, .{
            .level = @intFromEnum(log_level),
            .file = @alignCast(@ptrCast(file)),
            .filename = null,
        });
        const ret_code = c.aws_logger_init_standard(
            logger.asCPtr(),
            allocator,
            @constCast(&options), // the AWS API declares this as a mutable pointer, however it never actually mutates through it, nor stores it
        );
        switch (ret_code) {
            c.AWS_OP_SUCCESS => {},
            c.AWS_OP_ERR => try lastError().toError(),
            else => unreachable,
        }
    }

    pub inline fn initStandardPath(
        logger: *Logger,
        allocator: *zaws.Allocator,
        log_level: LogLevel,
        path: [:0]const u8,
    ) Error!void {
        const options = util.initNoDefault(c.aws_logger_standard_options, .{
            .level = @intFromEnum(log_level),
            .file = null,
            .filename = path.ptr,
        });
        const ret_code = c.aws_logger_init_standard(
            logger.asCPtr(),
            allocator,
            &options, // the AWS API declares this as a mutable pointer, however it never actually mutates through it, nor stores it
        );
        switch (ret_code) {
            c.AWS_OP_SUCCESS => {},
            c.AWS_OP_ERR => try lastError().toError(),
            else => unreachable,
        }
    }

    inline fn asCPtr(self: *Logger) *c.aws_logger {
        return @ptrCast(self);
    }
    inline fn fromCPtr(c_ptr: *c.aws_logger) *Logger {
        return @ptrCast(c_ptr);
    }
};

pub const DateTime = struct {
    value: c.aws_date_time,

    pub inline fn initNow() DateTime {
        var value: c.aws_date_time = undefined;
        c.aws_date_time_init_now(&value);
        return .{ .value = value };
    }
};

pub const signing_config = struct {
    pub const Wrapper = c.zig_aws_signing_config_aws_wrapper;
    pub const Bytes = c.zig_aws_signing_config_aws_bytes;

    pub inline fn wrapperToBytes(wrapper: signing_config.Wrapper) signing_config.Bytes {
        var sc: signing_config.Bytes = undefined;
        c.zig_aws_s3_signing_config_wrapper_to_bytes(&sc, &wrapper);
        return sc;
    }
    pub inline fn bytesToWrapper(sc: signing_config.Bytes) signing_config.Wrapper {
        var wrapper: signing_config.Wrapper = undefined;
        c.zig_aws_s3_signing_config_bytes_to_wrapper(&wrapper, &sc);
        return wrapper;
    }
};

pub const ByteCursor = c.aws_byte_cursor;
pub inline fn byteCursorToSlice(bc: ByteCursor) ?[]u8 {
    const ptr: [*]u8 = bc.ptr orelse return null;
    return ptr[0..bc.len];
}
pub inline fn byteCursorFromSlice(slice: ?[]u8) ByteCursor {
    return .{
        .len = if (slice) |s| s.len else 0,
        .ptr = if (slice) |s| s.ptr else null,
    };
}

pub const Allocator = c.aws_allocator;

/// Returns an AWS allocator wrapping the given zig allocator.
/// The pointed-to zig allocator must outlive the returned AWS allocator interface.
pub inline fn stdToAwsAllocator(allocator: *const std.mem.Allocator) zaws.Allocator {
    const gen = struct {
        const mbah = util.MetadataBasedAllocHelpers(16);

        fn acquire(aws_allocator: [*c]c.aws_allocator, size: usize) callconv(.C) ?*anyopaque {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));
            const result = mbah.alloc(ally.*, size);
            if (result == null) {
                std.debug.dumpCurrentStackTrace(@returnAddress());
            }
            return result;
        }

        fn release(aws_allocator: [*c]c.aws_allocator, maybe_ptr: ?*anyopaque) callconv(.C) void {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));
            const ptr = maybe_ptr orelse return;
            mbah.free(ally.*, @ptrCast(@alignCast(ptr)));
        }

        fn realloc(aws_allocator: [*c]c.aws_allocator, maybe_ptr: ?*anyopaque, old_size: usize, new_size: usize) callconv(.C) ?*anyopaque {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));
            const ptr: [*]align(mbah.alignment) u8 = if (maybe_ptr) |ptr| @ptrCast(@alignCast(ptr)) else {
                assert(old_size == 0);
                return mbah.alloc(ally.*, new_size);
            };
            assert(mbah.getMetadata(ptr).size == old_size);
            return mbah.realloc(ally.*, ptr, new_size);
        }

        fn calloc(aws_allocator: [*c]c.aws_allocator, num: usize, val_size: usize) callconv(.C) ?*anyopaque {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));
            const size = num * val_size;
            const result = mbah.alloc(ally.*, size) orelse return null;
            @memset(result[0..size], 0);
            return result;
        }
    };

    return c.aws_allocator{
        .mem_acquire = gen.acquire,
        .mem_release = gen.release,
        .mem_realloc = gen.realloc,
        .mem_calloc = gen.calloc,
        .impl = @constCast(allocator),
    };
}
