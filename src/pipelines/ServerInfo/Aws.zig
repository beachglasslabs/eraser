//! Documentation used for reference:
//! https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

const eraser = @import("../../pipelines.zig");
const digestBytesToString = eraser.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../../util.zig");

const Aws = @This();
buckets: []const Bucket,
access_key_id: SensitiveBytes.Fixed(access_key_id_len),
secret_access_key: SensitiveBytes.Fixed(secret_access_key_len),

pub const Bucket = struct { []const u8, Region };

pub const object_uri_fmt = "http://s3.{[region]}.amazonaws.com/{[bucket]}/{[object]}";

pub const access_key_id_len = "AKIAIOSFODNN7EXAMPLE".len;
pub const secret_access_key_len = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".len;

pub const authorization_value_fmt =
    "AWS4-HMAC-SHA256 " ++
    "Credential={[access_key]s}/{[date]}/{[region]}/{[service]}/aws4_request," ++
    "SignedHeaders={[signed_headers]}," ++
    "Signature={[signature]s}" //
;

pub inline fn totalObjectUrisByteCount(gc: *const Aws) usize {
    var result: usize = 0;
    for (gc.buckets) |bucket| {
        const name: []const u8 = bucket[0];
        const region: Region = bucket[1];
        result += std.fmt.count(object_uri_fmt, .{
            .region = util.hardCodeFmt("s", region.toBytes().constSlice()),
            .bucket = util.hardCodeFmt("s", name),
            .object = util.hardCodeFmt("s", &comptime eraser.digestBytesToString("F" ** eraser.chunk.name_len)),
        });
    }
    return result;
}

/// Asserts `buffer.len == gc.totalObjectUriBytes()`
pub inline fn objectUriIterator(
    aws: *const Aws,
    object: *const [Sha256.digest_length]u8,
    buffer: []u8,
) ObjectUriIterator {
    assert(aws.totalObjectUrisByteCount() == buffer.len);
    return .{
        .buckets = aws.buckets,
        .bytes = .{ .buffer = buffer },
        .object = object.*,
    };
}

pub const ObjectUriIterator = struct {
    index: usize = 0,
    buckets: []const Bucket,
    bytes: util.BoundedBufferArray(u8),
    object: [Sha256.digest_length]u8,

    pub const NextResult = struct {
        uri: []const u8,
        region: Region,
    };

    /// Each string returned is a unique slice which does not overlap with any previously returned slice.
    pub inline fn next(iter: *ObjectUriIterator) ?NextResult {
        if (iter.index == iter.buckets.len) return null;
        const bucket = iter.buckets[iter.index];
        iter.index += 1;
        const name: []const u8 = bucket[0];
        const region: Region = bucket[1];

        const start = iter.bytes.len;
        iter.bytes.writer().print(object_uri_fmt, .{
            .region = util.hardCodeFmt("s", region.toBytes().constSlice()),
            .bucket = util.hardCodeFmt("s", name),
            .object = util.hardCodeFmt("s", &digestBytesToString(&iter.object)),
        }) catch |err| switch (err) {
            error.Overflow => unreachable,
        };
        return .{
            .uri = iter.bytes.slice()[start..],
            .region = bucket[1],
        };
    }
};

pub inline fn signedHeadersFmt(
    /// Must be sorted
    headers: *const std.http.Headers,
) SignedHeadersFmt {
    return .{ .headers = headers };
}

pub const SignedHeadersFmt = struct {
    headers: *const std.http.Headers,

    pub fn format(
        self: SignedHeadersFmt,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        _ = fmt_str;
        const x_amz_headers_start_idx = for (self.headers.list.items, 0..) |field, i| {
            if (std.mem.startsWith(u8, field.name, "x-amz-")) break i;
        } else null;

        var sep = false;
        if (self.headers.contains("content-type")) {
            if (sep) try writer.writeByte(';');
            sep = true;
            try writer.writeAll("content-type");
        }

        if (sep) try writer.writeByte(';');
        sep = true;
        try writer.writeAll("host");

        if (x_amz_headers_start_idx) |start_idx| {
            for (self.headers.list.items[start_idx..]) |field| {
                if (!std.mem.startsWith(u8, field.name, "x-amz-")) break;

                if (sep) try writer.writeByte(';');
                sep = true;
                try writer.writeAll(field.name);
            }
        }
    }
};

pub const CalcSignatureParams = struct {
    timestamp: *const TimestampIso8601,
    region: Region,
    service: []const u8,
    /// Result of `calcSigningKey`
    sigining_key: *const [HmacSha256.mac_length]u8,
    /// Result of `CanonRequestHasher.getCanonicalRequestHash`
    canon_request: *const [Sha256.digest_length]u8,
};
pub fn calcSignature(params: CalcSignatureParams) [HmacSha256.mac_length]u8 {
    var hasher = HmacSha256.init(params.sigining_key);
    const ihw = util.hasherWriter(&hasher);
    ihw.print(
        \\AWS4-HMAC-SHA256
        \\{[ts]s}
        \\{[scope_ts]s}/{[scope_region]s}/{[scope_service]s}/aws4_request
        \\{[canon_req]s}
    , .{
        .ts = std.mem.asBytes(params.timestamp),
        .scope_ts = std.mem.asBytes(&params.timestamp.date),
        .scope_region = params.region.toBytes().constSlice(),
        .scope_service = params.service,
        .canon_req = &eraser.digestBytesToString(params.canon_request),
        // }) catch |err| switch (err) {};
    }) catch unreachable;

    var result: [HmacSha256.mac_length]u8 = undefined;
    hasher.final(&result);
    return result;
}

pub const CalcSigningKeyParams = struct {
    secret_access_key: *const [secret_access_key_len]u8,
    date: TimestampIso8601.Date,
    region: Region,
    /// For example: "ec2", "s3"
    service: []const u8,
};
pub inline fn calcSigningKey(params: CalcSigningKeyParams) [HmacSha256.mac_length]u8 {
    // zig fmt: off
    // TODO: turn zig fmt back on if/when https://github.com/ziglang/zig/issues/17145 is accepted & implemented
    const k_secret  = "AWS4".* ++ params.secret_access_key.*;
    const k_date    = hmacSha256Result(.{ .key = &k_secret,  .msg = std.mem.asBytes(&params.date) });
    const k_region  = hmacSha256Result(.{ .key = &k_date,    .msg = params.region.toBytes().constSlice() });
    const k_service = hmacSha256Result(.{ .key = &k_region,  .msg = params.service });
    const k_signing = hmacSha256Result(.{ .key = &k_service, .msg = "aws4_request" });
    // zig fmt: on
    return k_signing;
}

pub inline fn canonRequestWriter(inner: anytype) CanonRequestWriter(@TypeOf(inner)) {
    return CanonRequestWriter(@TypeOf(inner)).init(inner);
}
pub fn CanonRequestWriter(comptime Inner: type) type {
    return struct {
        inner: Inner,
        state: State,
        const Self = @This();

        const State = union(enum) {
            start,
            query_string: struct { count: usize = 0 },
            headers,
            signed_headers: struct { count: usize = 0 },
            hashed_payload,
            finished,
        };

        pub fn init(writer: Inner) Self {
            return .{
                .inner = writer,
                .state = .start,
            };
        }

        pub fn start(
            self: *Self,
            params: struct {
                /// The HTTP method used in the request to be signed.
                method: []const u8,
                /// The `.path` component of a `std.Uri`, or equivalent.
                uri_path: []const u8,
            },
        ) Inner.Error!void {
            assert(self.state == .start);
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();
            try writer.print("{s}\n", .{params.method});
            try writer.print("{s}\n", .{params.uri_path});
            try buffered.flush();
            self.state = .{ .query_string = .{} };
        }

        pub fn addQuery(
            self: *Self,
            /// Assumed to be alphabetically sorted after the `name` supplied
            /// in the previous call.
            name: []const u8,
            value: []const u8,
        ) Inner.Error!void {
            const state = &self.state.query_string;
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();

            if (state.count != 0) try writer.writeByte('&');
            state.count += 1;

            try std.Uri.writeEscapedQuery(writer, name);
            try writer.writeByte('=');
            try std.Uri.writeEscapedQuery(writer, value);
            try buffered.flush();
        }

        pub fn endQueryString(self: *Self) Inner.Error!void {
            assert(self.state == .query_string);
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();
            try writer.writeByte('\n');
            try buffered.flush();
            self.state = .headers;
        }

        pub fn addHeader(
            self: *Self,
            /// Assumed to be alphabetically sorted after the `name` supplied
            /// in the previous call.
            name: []const u8,
            value: []const u8,
        ) Inner.Error!void {
            assert(self.state == .headers);
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();
            try util.writeLowerCaseString(writer, name);
            try writer.writeByte(':');
            try writer.writeAll(std.mem.trim(u8, value, &std.ascii.whitespace));
            try writer.writeByte('\n');
            try buffered.flush();
        }

        pub fn endHeaders(self: *Self) Inner.Error!void {
            assert(self.state == .headers);
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();
            try writer.writeByte('\n');
            try buffered.flush();
            self.state = .{ .signed_headers = .{} };
        }

        pub fn addSignedHeader(
            self: *Self,
            name: []const u8,
        ) Inner.Error!void {
            const state = &self.state.signed_headers;
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();

            if (state.count != 0) try writer.writeByte(';');
            state.count += 1;

            try util.writeLowerCaseString(writer, name);
            try buffered.flush();
        }

        pub fn endSignedHeaders(self: *Self) Inner.Error!void {
            assert(self.state == .signed_headers);
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();
            try writer.writeByte('\n');
            try buffered.flush();
            self.state = .hashed_payload;
        }

        pub fn setPayloadHash(
            self: *Self,
            payload_hash: *const [Sha256.digest_length]u8,
        ) Inner.Error!void {
            assert(self.state == .hashed_payload);
            var buffered = std.io.bufferedWriter(self.inner);
            const writer = buffered.writer();
            const hex = eraser.digestBytesToString(payload_hash);
            try writer.writeAll(&hex);
            try buffered.flush();
            self.state = .finished;
        }
    };
}

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

pub const TimestampIso8601 = extern struct {
    date: Date,
    T: enum(u8) { T = 'T' } = .T,
    hour: [2]u8,
    minute: [2]u8,
    second: [2]u8,
    Z: enum(u8) { Z = 'Z' } = .Z,

    pub const Date = extern struct {
        year: [4]u8,
        month: [2]u8,
        day: [2]u8,
    };

    pub inline fn from(
        /// Timestamp in seconds relative to 1970-01-01.
        epoch_ts: u64,
    ) error{NonFourDigitYear}!TimestampIso8601 {
        const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = epoch_ts };
        const year_day = epoch_secs.getEpochDay().calculateYearDay();
        const day_seconds = epoch_secs.getDaySeconds();
        const month_day = year_day.calculateMonthDay();

        const year: [4]u8 = util.fixedLenFmt("{d:0>4}", .{year_day.year}, .{2000}) catch |err| return switch (err) {
            error.Overflow, error.Underflow => error.NonFourDigitYear,
        };
        const month: [2]u8 = util.fixedLenFmt("{d:0>2}", .{month_day.month.numeric()}, .{12}) catch unreachable; // this should be impossible
        const day: [2]u8 = day: {
            const Day = std.math.IntFittingRange(1, 31);
            const day = @as(Day, month_day.day_index) + 1;
            break :day util.fixedLenFmt("{d:0>2}", .{day}, .{31}) catch unreachable; // this should be impossible
        };

        const hour: [2]u8 = util.fixedLenFmt("{d:0>2}", .{day_seconds.getHoursIntoDay()}, .{23}) catch unreachable; // this should be impossible
        const minute: [2]u8 = util.fixedLenFmt("{d:0>2}", .{day_seconds.getMinutesIntoHour()}, .{59}) catch unreachable; // this should be impossible
        const second: [2]u8 = util.fixedLenFmt("{d:0>2}", .{day_seconds.getSecondsIntoMinute()}, .{59}) catch unreachable; // this should be impossible

        return .{
            .date = .{ .year = year, .month = month, .day = day },
            .hour = hour,
            .minute = minute,
            .second = second,
        };
    }
};

test TimestampIso8601 {
    try std.testing.expectEqualStrings("2013" ++ "0124" ++ "T" ++ "224915" ++ "Z", std.mem.asBytes(&TimestampIso8601{
        .date = .{
            .year = "2013".*,
            .month = "01".*,
            .day = "24".*,
        },
        .hour = "22".*,
        .minute = "49".*,
        .second = "15".*,
    }));
    try std.testing.expectEqualStrings("0000" ++ "1203" ++ "T" ++ "235959" ++ "Z", std.mem.asBytes(&TimestampIso8601{
        .date = .{
            .year = "0000".*,
            .month = "12".*,
            .day = "03".*,
        },
        .hour = "23".*,
        .minute = "59".*,
        .second = "59".*,
    }));
}

inline fn hmacSha256Result(params: struct { msg: []const u8, key: []const u8 }) [HmacSha256.mac_length]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, params.msg, params.key);
    return mac;
}

test "Request Signature" {
    const TestCase = struct {
        expected_canon_req_digest: [HmacSha256.mac_length * 2]u8,
        expected_signature: [HmacSha256.mac_length * 2]u8,
        method: []const u8,
        uri: []const u8,
        content_hash: [Sha256.digest_length * 2]u8,
        headers: []const struct { []const u8, []const u8 },
    };

    const test_cases: []const TestCase = &[_]TestCase{
        .{
            .expected_canon_req_digest = "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972".*,
            .expected_signature = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41".*,
            .method = "GET",
            .uri = "https://examplebucket.s3.amazonaws.com/test.txt",
            .content_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".*,
            .headers = &.{
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "range", "bytes=0-9" },
                .{ "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                .{ "x-amz-date", "20130524T000000Z" },
            },
        },
        .{
            .expected_canon_req_digest = "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d".*,
            .expected_signature = "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd".*,
            .method = "PUT",
            .uri = "https://examplebucket.s3.amazonaws.com/test%24file.text",
            .content_hash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072".*,
            .headers = &.{
                .{ "date", "Fri, 24 May 2013 00:00:00 GMT" },
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "x-amz-content-sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" },
                .{ "x-amz-date", "20130524T000000Z" },
                .{ "x-amz-storage-class", "REDUCED_REDUNDANCY" },
            },
        },
        .{
            .expected_canon_req_digest = "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca".*,
            .expected_signature = "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543".*,
            .method = "GET",
            .uri = "https://examplebucket.s3.amazonaws.com/?lifecycle=",
            .content_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".*,
            .headers = &.{
                .{ "host", "examplebucket.s3.amazonaws.com" },
                .{ "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                .{ "x-amz-date", "20130524T000000Z" },
            },
        },
    };

    const service = "s3";
    const secret_access_key: [secret_access_key_len]u8 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".*;
    const timestamp: TimestampIso8601 = @bitCast(@as([16]u8, "20130524T000000Z".*));
    const region: Region = .{
        .geo = "us".*,
        .cardinal = .east,
        .number = 1,
    };

    for (test_cases, 0..) |test_inputs, iteration| {
        errdefer std.log.err("Failed on iteration {d} ('{s}')", .{ iteration, test_inputs.uri });

        const http_verb = test_inputs.method;
        const uri = try std.Uri.parse(test_inputs.uri);

        const expected_canon_request = blk: {
            var expected: [HmacSha256.mac_length]u8 = undefined;
            assert((std.fmt.hexToBytes(&expected, &test_inputs.expected_canon_req_digest) catch unreachable).len == expected.len);
            break :blk expected;
        };
        const expected_signature: [HmacSha256.mac_length]u8 = blk: {
            var expected: [HmacSha256.mac_length]u8 = undefined;
            assert((std.fmt.hexToBytes(&expected, &test_inputs.expected_signature) catch unreachable).len == expected.len);
            break :blk expected;
        };

        const canon_request = blk: {
            var hasher = Sha256.init(.{});
            var crw = canonRequestWriter(util.hasherWriter(&hasher));
            try crw.start(.{
                .method = http_verb,
                .uri_path = uri.path,
            });

            if (uri.query) |queries| {
                var iter = std.mem.splitScalar(u8, queries, '&');
                while (iter.next()) |query| {
                    const name = query[0 .. std.mem.indexOfScalar(u8, query, '=') orelse query.len];
                    const value = query[if (name.len != query.len) name.len + 1 else query.len..];
                    try crw.addQuery(name, value);
                }
            }
            try crw.endQueryString();

            for (test_inputs.headers) |header| try crw.addHeader(header[0], header[1]);
            try crw.endHeaders();

            for (test_inputs.headers) |header| try crw.addSignedHeader(header[0]);
            try crw.endSignedHeaders();

            const content_hash = hash: {
                var content_hash: [Sha256.digest_length]u8 = undefined;
                assert((std.fmt.hexToBytes(&content_hash, &test_inputs.content_hash) catch unreachable).len == content_hash.len);
                break :hash content_hash;
            };

            try crw.setPayloadHash(&content_hash);
            break :blk hasher.finalResult();
        };
        try std.testing.expectEqual(expected_canon_request, canon_request);

        const signing_key = calcSigningKey(.{
            .secret_access_key = &secret_access_key,
            .date = timestamp.date,
            .region = region,
            .service = service,
        });
        const signature = calcSignature(.{
            .timestamp = &timestamp,
            .region = region,
            .service = service,
            .canon_request = &canon_request,
            .sigining_key = &signing_key,
        });
        try std.testing.expectEqual(expected_signature, signature);
    }
}
