const eraser = @import("../../pipelines.zig");
const digestBytesToString = eraser.digestBytesToString;

const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util");
const zaws = @import("zaws");
pub const auth = zaws.auth;
pub const http = zaws.http;
pub const iso8601 = zaws.iso8601;

const Aws = @This();
credentials: ?Credentials,

pub const Credentials = struct {
    access_key_id: AccessKeyId,
    secret_access_key: SecretAccessKey,
    session_token: SessionToken,

    pub const AccessKeyId = struct { string: [auth.access_key_id_len]u8 };
    pub const SecretAccessKey = struct { string: [auth.secret_access_key_len]u8 };
    /// Must contain a non-null string for temporary credentials.
    pub const SessionToken = struct { string: ?[]const u8 };
};

pub const Bucket = struct {
    region: Region,
    name: []const u8,

    pub const WriteUriOptions = struct {
        /// e.g. "http", "https".
        protocol: []const u8,
        style: Style,
        /// If set to a non-null, writes this as the sub-object path of the bucket URI.
        object: ?[]const u8,

        pub const Style = enum { path, virtual_hosted };
    };

    pub inline fn writeUriTo(bucket: Bucket, writer: anytype, options: WriteUriOptions) @TypeOf(writer).Error!void {
        switch (options.style) {
            inline .path, .virtual_hosted => |style| {
                const uri_fmt = switch (style) {
                    // zig fmt: off
                    .path           => "{[protocol]s}://s3.{[region]}.amazonaws.com/{[name]s}",
                    .virtual_hosted => "{[protocol]s}://{[name]s}.s3.{[region]}.amazonaws.com",
                    // zig fmt: on
                };
                try writer.print(uri_fmt, .{
                    .protocol = options.protocol,
                    .region = bucket.region.fmt(),
                    .name = bucket.name,
                });
                if (options.object) |object| {
                    try writer.print("/{s}", .{object});
                }
            },
        }
    }

    pub inline fn fmtUri(bucket: Bucket, options: WriteUriOptions) FmtUri {
        return .{
            .bucket = bucket,
            .options = options,
        };
    }

    pub const FmtUri = struct {
        bucket: Bucket,
        options: WriteUriOptions,

        pub fn format(
            self: FmtUri,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = options;
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
            try self.bucket.writeUriTo(writer, self.options);
        }
    };
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

    pub inline fn writeTo(region: Region, writer: anytype) @TypeOf(writer).Error!void {
        const str_bytes = region.toBytes();
        try writer.writeAll(str_bytes.constSlice());
    }

    pub inline fn fmt(region: Region) Fmt {
        return .{ .region = region };
    }

    pub const Fmt = struct {
        region: Region,

        pub fn format(
            self: Fmt,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = options;
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
            try self.region.writeTo(writer);
        }
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
