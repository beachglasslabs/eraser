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
