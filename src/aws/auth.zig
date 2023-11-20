//! AWS Signature Version 4 code based off of the following documentation on 14 November 2023:
//! * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
//! * https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

const std = @import("std");
const assert = std.debug.assert;
const base64 = std.base64;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const util = @import("util");

pub const access_key_id_len = "AKIAIOSFODNN7EXAMPLE".len;
pub const secret_access_key_len = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".len;

pub const signing_key_len = HmacSha256.mac_length;
pub const signature_len = HmacSha256.mac_length;

pub const CanonicalPayloadSign = union(enum) {
    /// The SHA-256 hash digest of the request payload.
    digest: *const [Sha256.digest_length]u8,
    /// Enumeration representing special blessed string literals which aren't  a digest.
    special: Special,
    /// Custom UTF-8 string for anything not supported by this API.
    other: []const u8,

    pub const Special = enum {
        /// Use this when you are uploading the object as a single unsigned chunk.
        unsigned_payload,
        /// Use this when sending an unsigned payload over multiple chunks. In this case you also have a trailing header after the chunk is uploaded.
        streaming_unsigned_payload_trailer,
        /// Use this when sending a payload over multiple chunks, and the chunks are signed using AWS4-HMAC-SHA256. This produces a SigV4 signature.
        streaming_aws4_hmac_sha256_payload,
        /// Use this when sending a payload over multiple chunks, and the chunks are signed using AWS4-HMAC-SHA256. This produces a SigV4 signature. In addition, the digest for the chunks is included as a trailing header.
        streaming_aws4_hmac_sha256_payload_trailer,
        /// Use this when sending a payload over multiple chunks, and the chunks are signed using AWS4-ECDSA-P256-SHA256. This produces a SigV4A signature.
        streaming_aws4_ecdsa_p256_sha256_payload,
        /// Use this when sending a payload over multiple chunks, and the chunks are signed using AWS4-ECDSA-P256-SHA256. This produces a SigV4A signature. In addition, the digest for the chunks is included as a trailing header.
        streaming_aws4_ecdsa_p256_sha256_payload_trailer,

        /// Returns a static string which is associated with the enum value.
        pub inline fn toString(special: Special) []const u8 {
            return switch (special) {
                inline else => |tag| comptime blk: {
                    var string: [@tagName(tag).len]u8 = @tagName(tag)[0..].*;
                    std.mem.replaceScalar(u8, &string, '_', '-');
                    break :blk std.ascii.upperString(&string, &string);
                },
            };
        }
    };

    pub inline fn writeTo(canon_ps: CanonicalPayloadSign, writer: anytype) @TypeOf(writer).Error!void {
        return switch (canon_ps) {
            .digest => |digest| writer.writeAll(&awsHex(digest)),
            .special => |special| writer.writeAll(special.toString()),
            .other => |other| writer.writeAll(other),
        };
    }

    pub inline fn fmt(canon_ps: CanonicalPayloadSign) Fmt {
        return .{ .canon_ps = canon_ps };
    }

    pub const Fmt = struct {
        canon_ps: CanonicalPayloadSign,

        pub fn format(
            self: Fmt,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = options;
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
            try self.canon_ps.writeTo(writer);
        }
    };
};

pub inline fn canonicalRequestBuilder(
    dst_writer: anytype,
) CanonicalRequestBuilder(@TypeOf(dst_writer)) {
    return CanonicalRequestBuilder(@TypeOf(dst_writer)).init(dst_writer);
}

pub fn CanonicalRequestBuilder(comptime DstWriter: type) type {
    return struct {
        dest: DstWriter,
        state: State,
        const Self = @This();

        pub inline fn init(dest: DstWriter) Self {
            return .{
                .dest = dest,
                .state = .begin,
            };
        }

        pub fn setHttpMethod(
            self: *Self,
            /// Should be the HTTP method, for example "PUT", "GET", "DELETE", etc.
            method: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .begin => {},
                else => unreachable,
            }
            try self.dest.print("{s}\n", .{method});
            self.state = .http_verb_set;
        }

        pub fn setCanonicalUri(
            self: *Self,
            /// Should be the absolute path component of the URI, and be URI-encoded.
            uri: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .http_verb_set => {},
                else => unreachable,
            }
            try self.dest.print("{s}\n", .{uri});
            self.state = .canon_uri_set;
        }

        /// Adds a canonical query parameter name. The `setQueryValue` method
        /// can be called after to set the value of this query parameter.
        pub fn addQueryName(
            self: *Self,
            /// Must be URI-encoded. Must be added such that the resulting "list" of
            /// query names would be in lexicographic order.
            name: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .canon_uri_set => {},
                .query_value_set => try self.dest.writeByte('&'),
                else => unreachable,
            }
            try self.dest.print("{s}=", .{name});
            self.state = .query_name_added;
        }

        pub fn setQueryValue(
            self: *Self,
            /// Must be URI-encoded.
            value: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .query_name_added => {},
                else => unreachable,
            }
            try self.dest.writeAll(value);
            self.state = .query_value_set;
        }

        /// Terminates the query string. The `addQueryName` and `setQueryValue` methods
        /// can no longer be called after this, and subsequent methods may now be called.
        pub fn endQueryString(self: *Self) WriteError!void {
            switch (self.state) {
                .canon_uri_set,
                .query_value_set,
                => {},
                else => unreachable,
            }
            try self.dest.writeByte('\n');
            self.state = .query_string_ended;
        }

        /// Adds a canon header name.
        /// At time of writing, the list of canon headers which must be added are:
        /// * The "content-type" header if available.
        /// * The "host" header.
        /// * Any "x-amz-*" headers in the request (for example "x-amz-security-token", "x-amz-content-sha256", etc).
        /// Other headers in the request are not required to sign, but are recommended.
        pub fn addCanonHeaderName(
            self: *Self,
            /// Must be added in an order such that the resulting "list" of header
            /// names would be in case-insensitive lexicographic order, where
            /// upper case ASCII characters are compared as lower case characters.
            name: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .query_string_ended,
                .canon_header_value_set,
                => {},
                else => unreachable,
            }
            for (name) |name_char| try self.dest.writeByte(std.ascii.toLower(name_char));
            try self.dest.writeByte(':');
            self.state = .canon_header_name_added;
        }

        /// Sets the value of the header name added by `addCanonHeaderName`.
        pub fn setCanonHeaderValue(
            self: *Self,
            value: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .canon_header_name_added => {},
                else => unreachable,
            }
            try self.dest.print("{s}\n", .{awsTrim(value)});
            self.state = .canon_header_value_set;
        }

        /// Terminates the canonical headers string. The `addCanonHeaderName` method can no longer
        /// be called after this, and subsequent methods may now be called.
        pub fn endCanonHeaders(self: *Self) WriteError!void {
            switch (self.state) {
                .canon_header_value_set => {},
                else => unreachable,
            }
            try self.dest.writeByte('\n');
            self.state = .canon_headers_ended;
        }

        /// At time of writing, this should be given the same headers passed to `addCanonHeaderName`.
        pub fn addSignedHeader(
            self: *Self,
            /// Must be added in an order such that the resulting "list" of header
            /// names would be in case-insensitive lexicographic order, where
            /// upper case ASCII characters are compared as lower case characters.
            name: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .canon_headers_ended => {},
                .signed_header_added => try self.dest.writeByte(';'),
                else => unreachable,
            }
            for (name) |name_char| try self.dest.writeByte(name_char);
            self.state = .signed_header_added;
        }

        /// Sets the payload hash, completing the canonical request.
        pub fn setPayloadSign(
            self: *Self,
            /// The SHA-256 hash digest of the request payload contents. If there
            /// is no payload, this should be the hash of an empty string.
            payload_sign: CanonicalPayloadSign,
        ) WriteError!void {
            switch (self.state) {
                .signed_header_added => {},
                else => unreachable,
            }
            try self.dest.writeByte('\n');
            switch (payload_sign) {
                .digest => |digest| try self.dest.writeAll(&awsHex(digest)),
                .special => |tag| try self.dest.writeAll(tag.toString()),
                .other => |other| try self.dest.writeAll(other),
            }
            self.state = .payload_sign_set;
        }

        const WriteError = DstWriter.Error;
        const State = enum {
            begin,
            http_verb_set,
            canon_uri_set,

            query_name_added,
            query_value_set,
            query_string_ended,

            canon_header_name_added,
            canon_header_value_set,
            canon_headers_ended,

            signed_header_added,
            payload_sign_set,
        };
    };
}

pub const Scope = struct {
    /// Must be the date in the format "YYYYMMDD"
    date: []const u8,
    region: []const u8,
    service: []const u8,

    pub inline fn writeTo(scope: Scope, writer: anytype) @TypeOf(writer).Error!void {
        return writer.print("{[date]s}/{[region]s}/{[service]s}/aws4_request", scope);
    }

    pub inline fn fmt(scope: Scope) Fmt {
        return .{ .scope = scope };
    }

    pub const Fmt = struct {
        scope: Scope,

        pub fn format(
            self: Fmt,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = options;
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
            return self.scope.writeTo(writer);
        }
    };
};

pub const StringToSign = struct {
    /// Usually "AWS4-HMAC-SHA256"
    algorithm: []const u8,
    /// Current UTC time in ISO 8601 format (for example, "20130524T000000Z")
    date_time: []const u8,
    /// Scope of the request.
    scope: Scope,
    /// Should be the SHA-256 hash digest of the string built by a `CanonicalRequestBuilder`.
    canon_request_digest: *const [Sha256.digest_length]u8,

    pub inline fn writeTo(sts: StringToSign, writer: anytype) !void {
        return writer.print(
            \\{[algorithm]s}
            \\{[date_time]s}
            \\{[scope]}
            \\{[canon_req_hash]s}
        , .{
            .algorithm = sts.algorithm,
            .date_time = sts.date_time,
            .scope = sts.scope.fmt(),
            .canon_req_hash = &awsHex(sts.canon_request_digest),
        });
    }

    pub inline fn fmt(sts: StringToSign) Fmt {
        return .{ .sts = sts };
    }

    pub const Fmt = struct {
        sts: StringToSign,

        pub fn format(
            self: Fmt,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = options;
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
            try self.sts.writeTo(writer);
        }
    };
};

pub inline fn calcSigningKey(
    secret_access_key: *const [secret_access_key_len]u8,
    scope: Scope,
) [signing_key_len]u8 {
    // zig fmt: off
    const date_key                = calcHmacSha256Digest(.{ .key = &"AWS4".* ++ secret_access_key.*, .msg = scope.date    });
    const date_region_key         = calcHmacSha256Digest(.{ .key = &date_key,                        .msg = scope.region  });
    const date_region_service_key = calcHmacSha256Digest(.{ .key = &date_region_key,                 .msg = scope.service });
    const signing_key             = calcHmacSha256Digest(.{ .key = &date_region_service_key,         .msg = "aws4_request"    });
    // zig fmt: on
    return signing_key;
}

pub inline fn calcSignature(
    signing_key: *const [signature_len]u8,
    sts: StringToSign,
) [signature_len]u8 {
    var hasher = HmacSha256.init(signing_key);
    sts.writeTo(hmacSha256Writer(&hasher)) catch |e| switch (e) {};
    var result: [HmacSha256.mac_length]u8 = undefined;
    hasher.final(&result);
    return result;
}

/// Returns a builder for the "Authorization" HTTP header value.
pub inline fn authorizationHeaderBuilder(
    dst_writer: anytype,
) AuthorizationHeaderBuilder(@TypeOf(dst_writer)) {
    return AuthorizationHeaderBuilder(@TypeOf(dst_writer)).init(dst_writer);
}

pub fn AuthorizationHeaderBuilder(comptime DstWriter: type) type {
    return struct {
        dest: DstWriter,
        state: State,
        const Self = @This();

        pub inline fn init(dest: DstWriter) Self {
            return .{
                .dest = dest,
                .state = .begin,
            };
        }

        pub inline fn setAlgorithm(
            self: *Self,
            /// Usually "AWS4-HMAC-SHA256"
            algorithm: []const u8,
        ) !void {
            switch (self.state) {
                .begin => {},
                else => unreachable,
            }
            try self.dest.print("{s} ", .{algorithm});
            self.state = .algorithm_set;
        }

        pub inline fn setCredential(
            self: *Self,
            access_key_id: *const [access_key_id_len]u8,
            scope: Scope,
        ) WriteError!void {
            switch (self.state) {
                .algorithm_set => {},
                else => unreachable,
            }
            try self.dest.print("Credential={s}/{}, ", .{ access_key_id, scope.fmt() });
            try self.dest.writeAll("SignedHeaders=");
            self.state = .credential_set;
        }

        pub inline fn addSignedHeader(
            self: *Self,
            /// Must be added in an order such that the resulting "list" of header
            /// names would be in case-insensitive lexicographic order, where
            /// upper case ASCII characters are compared as lower case characters.
            name: []const u8,
        ) WriteError!void {
            switch (self.state) {
                .credential_set => {},
                .signed_header_added => try self.dest.writeByte(';'),
                else => unreachable,
            }
            for (name) |name_char| try self.dest.writeByte(std.ascii.toLower(name_char));
            self.state = .signed_header_added;
        }

        /// Sets the signature, and finishes the authorization header value.
        pub inline fn setSignature(
            self: *Self,
            /// Must be the result of `calcSignature`.
            signature: *const [signature_len]u8,
        ) WriteError!void {
            switch (self.state) {
                .signed_header_added => {},
                else => unreachable,
            }
            try self.dest.print(", Signature={s}", .{awsHex(signature)});
            self.state = .signature_set;
        }

        const WriteError = DstWriter.Error;
        const State = enum {
            begin,
            algorithm_set,
            credential_set,
            signed_header_added,
            signature_set,
        };
    };
}

inline fn awsTrim(untrimmed: []const u8) []const u8 {
    return std.mem.trim(u8, untrimmed, &[_]u8{ ' ', '\t' });
}
inline fn awsHex(bytes: anytype) [bytes.len * 2]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}
inline fn calcHmacSha256Digest(params: struct { key: []const u8, msg: []const u8 }) [HmacSha256.mac_length]u8 {
    var output: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&output, params.msg, params.key);
    return output;
}

pub inline fn sha256Writer(hasher: *Sha256) Sha256Writer {
    return .{ .context = hasher };
}
pub const Sha256Writer = struct {
    const Writer = std.io.Writer(*Sha256, error{}, @This().write);
    fn write(hasher: *Sha256, bytes: []const u8) error{}!usize {
        hasher.update(bytes);
        return bytes.len;
    }
}.Writer;

inline fn hmacSha256Writer(hasher: *HmacSha256) HmacSha256Writer {
    return .{ .context = hasher };
}
const HmacSha256Writer = struct {
    const Writer = std.io.Writer(*HmacSha256, error{}, @This().write);
    fn write(hasher: *HmacSha256, bytes: []const u8) error{}!usize {
        hasher.update(bytes);
        return bytes.len;
    }
}.Writer;

const TestAuthInputs = struct {
    access_key_id: *const [access_key_id_len]u8,
    secret_access_key: *const [secret_access_key_len]u8,

    date_time: []const u8,
    scope: Scope,

    method: []const u8,
    uri: []const u8,
    queries: []const struct { []const u8, []const u8 },
    headers: []const struct { []const u8, []const u8 },
    hash: CanonicalPayloadSign,
};
const TestAuthOutputs = struct {
    canon_req: []const u8,
    sts: []const u8,
    signature: *const [HmacSha256.mac_length]u8,
    authorization: []const u8,
};
fn testAuth(
    inputs: TestAuthInputs,
    expected: TestAuthOutputs,
) !void {
    var actual_canon_request_hasher = Sha256.init(.{});

    const actual_canon_request_str = sts: {
        var actual_canon_req = std.ArrayList(u8).init(std.testing.allocator);
        defer actual_canon_req.deinit();

        var multi = std.io.multiWriter(.{
            actual_canon_req.writer(),
            sha256Writer(&actual_canon_request_hasher),
        });
        var crb = canonicalRequestBuilder(multi.writer());

        try crb.setHttpMethod(inputs.method);
        try crb.setCanonicalUri(inputs.uri);

        for (inputs.queries) |query| {
            const name, const value = query;
            try crb.addQueryName(name);
            try crb.setQueryValue(value);
        }
        try crb.endQueryString();

        for (inputs.headers) |header| {
            const name, const value = header;
            try crb.addCanonHeaderName(name);
            try crb.setCanonHeaderValue(value);
        }
        try crb.endCanonHeaders();

        for (inputs.headers) |header| {
            const name, _ = header;
            try crb.addSignedHeader(name);
        }

        try crb.setPayloadSign(inputs.hash);
        break :sts try actual_canon_req.toOwnedSlice();
    };
    defer std.testing.allocator.free(actual_canon_request_str);

    const actual_canonical_request_digest = actual_canon_request_hasher.finalResult();
    { // check whether using `Sha256.hash` and `sha256Writer` are equivalent.
        var from_str: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(actual_canon_request_str, &from_str, .{});
        try std.testing.expectEqual(from_str, actual_canonical_request_digest);
    }

    const sts: StringToSign = .{
        .algorithm = "AWS4-HMAC-SHA256",
        .date_time = inputs.date_time,
        .scope = inputs.scope,
        .canon_request_digest = &actual_canonical_request_digest,
    };

    const actual_sts_str: []const u8 = str: {
        var sts_str = std.ArrayList(u8).init(std.testing.allocator);
        defer sts_str.deinit();
        try sts.writeTo(sts_str.writer());
        break :str try sts_str.toOwnedSlice();
    };
    defer std.testing.allocator.free(actual_sts_str);

    const signing_key = calcSigningKey(inputs.secret_access_key, inputs.scope);
    const actual_signature: [signature_len]u8 = calcSignature(&signing_key, sts);

    const actual_authorization: []const u8 = auth: {
        var actual_authorization = std.ArrayList(u8).init(std.testing.allocator);
        defer actual_authorization.deinit();

        var ahb = authorizationHeaderBuilder(actual_authorization.writer());
        try ahb.setAlgorithm(sts.algorithm);
        try ahb.setCredential(inputs.access_key_id, inputs.scope);
        for (inputs.headers) |header| {
            const name, _ = header;
            try ahb.addSignedHeader(name);
        }
        try ahb.setSignature(&actual_signature);

        break :auth try actual_authorization.toOwnedSlice();
    };
    defer std.testing.allocator.free(actual_authorization);

    try std.testing.expectEqualStrings(expected.canon_req, actual_canon_request_str);
    try std.testing.expectEqualStrings(expected.sts, actual_sts_str);
    try std.testing.expectEqualStrings(expected.authorization, actual_authorization);
    try std.testing.expectEqualSlices(u8, expected.signature, &actual_signature);
}

test calcSignature {
    const common = .{
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .scope = Scope{
            .date = "20130524",
            .region = "us-east-1",
            .service = "s3",
        },
    };

    try testAuth(
        .{
            .access_key_id = common.access_key_id,
            .secret_access_key = common.secret_access_key,

            .date_time = "20130524T000000Z",
            .scope = common.scope,

            .method = "GET",
            .uri = "/test.txt",
            .queries = &.{},
            .headers = &.{
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "range", "bytes=0-9" },
                .{ "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                .{ "x-amz-date", "20130524T000000Z" },
            },
            .hash = .{ .digest = &comptime util.hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") catch |e| @compileError(@errorName(e)) },
        },

        .{
            .canon_req =
            \\GET
            \\/test.txt
            \\
            \\host:examplebucket.s3.amazonaws.com
            \\range:bytes=0-9
            \\x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            \\x-amz-date:20130524T000000Z
            \\
            \\host;range;x-amz-content-sha256;x-amz-date
            \\e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            ,
            .sts =
            \\AWS4-HMAC-SHA256
            \\20130524T000000Z
            \\20130524/us-east-1/s3/aws4_request
            \\7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972
            ,
            .signature = &comptime util.hexToBytes("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") catch |e| @compileError(@errorName(e)),
            .authorization = "AWS4-HMAC-SHA256 " ++
                "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " ++
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41" //
            ,
        },
    );
    try testAuth(
        .{
            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",

            .date_time = "20130524T000000Z",
            .scope = common.scope,

            .method = "PUT",
            .uri = "/test%24file.text",
            .queries = &.{},
            .headers = &.{
                .{ "date", "Fri, 24 May 2013 00:00:00 GMT" },
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "x-amz-content-sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" },
                .{ "x-amz-date", "20130524T000000Z" },
                .{ "x-amz-storage-class", "REDUCED_REDUNDANCY" },
            },
            .hash = .{ .digest = &comptime util.hexToBytes("44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072") catch |e| @compileError(@errorName(e)) },
        },
        .{
            .canon_req =
            \\PUT
            \\/test%24file.text
            \\
            \\date:Fri, 24 May 2013 00:00:00 GMT
            \\host:examplebucket.s3.amazonaws.com
            \\x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072
            \\x-amz-date:20130524T000000Z
            \\x-amz-storage-class:REDUCED_REDUNDANCY
            \\
            \\date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class
            \\44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072
            ,
            .sts =
            \\AWS4-HMAC-SHA256
            \\20130524T000000Z
            \\20130524/us-east-1/s3/aws4_request
            \\9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d
            ,
            .signature = &comptime util.hexToBytes("98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd") catch |e| @compileError(@errorName(e)),
            .authorization = "AWS4-HMAC-SHA256 " ++
                "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, " ++
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd" //
            ,
        },
    );
    try testAuth(
        .{
            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",

            .date_time = "20130524T000000Z",
            .scope = common.scope,

            .method = "GET",
            .uri = "/",
            .queries = &.{
                .{ "lifecycle", "" },
            },
            .headers = &.{
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                .{ "x-amz-date", "20130524T000000Z" },
            },
            .hash = .{ .digest = &comptime util.hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") catch |e| @compileError(@errorName(e)) },
        },
        .{
            .canon_req =
            \\GET
            \\/
            \\lifecycle=
            \\host:examplebucket.s3.amazonaws.com
            \\x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            \\x-amz-date:20130524T000000Z
            \\
            \\host;x-amz-content-sha256;x-amz-date
            \\e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            ,
            .sts =
            \\AWS4-HMAC-SHA256
            \\20130524T000000Z
            \\20130524/us-east-1/s3/aws4_request
            \\9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca
            ,
            .signature = &comptime util.hexToBytes("fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543") catch |e| @compileError(@errorName(e)),
            .authorization = "AWS4-HMAC-SHA256 " ++
                "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " ++
                "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543" //
            ,
        },
    );
    try testAuth(
        .{
            .access_key_id = "AKIAIOSFODNN7EXAMPLE",
            .secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",

            .date_time = "20130524T000000Z",
            .scope = common.scope,

            .method = "GET",
            .uri = "/",
            .queries = &.{
                .{ "max-keys", "2" },
                .{ "prefix", "J" },
            },
            .headers = &.{
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                .{ "x-amz-date", "20130524T000000Z" },
            },
            .hash = .{ .digest = &comptime util.hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") catch |e| @compileError(@errorName(e)) },
        },
        .{
            .canon_req =
            \\GET
            \\/
            \\max-keys=2&prefix=J
            \\host:examplebucket.s3.amazonaws.com
            \\x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            \\x-amz-date:20130524T000000Z
            \\
            \\host;x-amz-content-sha256;x-amz-date
            \\e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            ,
            .sts =
            \\AWS4-HMAC-SHA256
            \\20130524T000000Z
            \\20130524/us-east-1/s3/aws4_request
            \\df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7
            ,
            .signature = &comptime util.hexToBytes("34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7") catch |e| @compileError(@errorName(e)),
            .authorization = "AWS4-HMAC-SHA256 " ++
                "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " ++
                "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
        },
    );
}

pub const UriQuery = struct {
    name: []const u8,
    value: ?[]const u8,

    pub inline fn parse(
        /// Must be a substring of an encoded URI query string, not including the delimiters '?' or '&'.
        name_value: []const u8,
    ) UriQuery {
        const eql_idx = std.mem.indexOfScalar(u8, name_value, '=');
        const name_len = eql_idx orelse name_value.len;
        return .{
            .name = name_value[0..name_len],
            .value = if (eql_idx) |idx| name_value[idx + 1 ..] else null,
        };
    }
};

pub inline fn uriQueryStringParser(
    /// Must be the encoded query string of a URI.
    queries: []const u8,
) UriQueryStringParser {
    return .{ .queries = queries, .idx = 0 };
}
pub const UriQueryStringParser = struct {
    queries: []const u8,
    idx: ?usize,

    pub inline fn next(self: *UriQueryStringParser) ?UriQuery {
        const pair_start = self.idx orelse return null;
        const pair_end = std.mem.indexOfScalarPos(u8, self.queries, pair_start, '&');
        const pair_str = self.queries[pair_start .. pair_end orelse self.queries.len];
        self.idx = if (pair_end) |idx| idx + 1 else null;
        return UriQuery.parse(pair_str);
    }
};

fn testUriQueryIterator(
    queries: []const u8,
    expected_name_value_pairs: []const struct { []const u8, ?[]const u8 },
) !void {
    const expected = try std.testing.allocator.alloc(UriQuery, expected_name_value_pairs.len);
    defer std.testing.allocator.free(expected);
    for (expected, expected_name_value_pairs) |*uri_query, tuple| {
        const name, const value = tuple;
        uri_query.* = .{ .name = name, .value = value };
    }

    var actual = try std.ArrayList(UriQuery).initCapacity(std.testing.allocator, expected_name_value_pairs.len);
    defer actual.deinit();

    var iter = uriQueryStringParser(queries);
    while (iter.next()) |query| try actual.append(query);

    try std.testing.expectEqualDeep(expected, actual.items);
}

test UriQueryStringParser {
    try testUriQueryIterator("", &.{
        .{ "", null },
    });
    try testUriQueryIterator("=", &.{
        .{ "", "" },
    });
    try testUriQueryIterator("==", &.{
        .{ "", "=" },
    });
    try testUriQueryIterator("&", &.{
        .{ "", null },
        .{ "", null },
    });
    try testUriQueryIterator("&&", &.{
        .{ "", null },
        .{ "", null },
        .{ "", null },
    });
    try testUriQueryIterator("&=", &.{
        .{ "", null },
        .{ "", "" },
    });
    try testUriQueryIterator("=&", &.{
        .{ "", "" },
        .{ "", null },
    });
    try testUriQueryIterator("=&=", &.{
        .{ "", "" },
        .{ "", "" },
    });
    try testUriQueryIterator("=&=&", &.{
        .{ "", "" },
        .{ "", "" },
        .{ "", null },
    });
    try testUriQueryIterator("&=&=", &.{
        .{ "", null },
        .{ "", "" },
        .{ "", "" },
    });

    try testUriQueryIterator("foo", &.{
        .{ "foo", null },
    });
    try testUriQueryIterator("foo=", &.{
        .{ "foo", "" },
    });
    try testUriQueryIterator("=foo", &.{
        .{ "", "foo" },
    });
    try testUriQueryIterator("foo&", &.{
        .{ "foo", null },
        .{ "", null },
    });
    try testUriQueryIterator("&foo", &.{
        .{ "", null },
        .{ "foo", null },
    });
    try testUriQueryIterator("foo&bar", &.{
        .{ "foo", null },
        .{ "bar", null },
    });
    try testUriQueryIterator("&foo&bar", &.{
        .{ "", null },
        .{ "foo", null },
        .{ "bar", null },
    });
    try testUriQueryIterator("foo&bar&", &.{
        .{ "foo", null },
        .{ "bar", null },
        .{ "", null },
    });
}
