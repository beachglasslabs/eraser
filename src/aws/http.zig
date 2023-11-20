const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const aws = @import("../aws.zig");
const iso8601 = @import("../iso-8601.zig");

pub const AddHeadersError = std.mem.Allocator.Error || iso8601.YearMonthDay.ParseError || error{
    MissingTimeInDateTime,
    DateTimeExtendedYear,
    MissingHost,
};

pub const AddHeadersParams = struct {
    /// "GET", "POST", "DELETE", etc.
    request_method: []const u8,
    request_uri: std.Uri,

    /// Must be the Date and Time in ISO 8601 format, ie "20130926T225743Z".
    date_time: []const u8,
    /// The service for which the request should be scoped.
    service: []const u8,
    /// Region for which the request should be scoped.
    region: []const u8,

    access_key_id: *const [aws.auth.access_key_id_len]u8,
    secret_access_key: *const [aws.auth.secret_access_key_len]u8,
    session_token: []const u8,
    payload_sign: aws.auth.CanonicalPayloadSign,
};

pub fn sortAndAddHeaders(
    allocator: std.mem.Allocator,
    headers: *std.http.Headers,
    params: AddHeadersParams,
) AddHeadersError!void {
    assert(headers.owned); // memory management without owning the fields is too complicated

    try headers.append("x-amz-date", params.date_time);
    try headers.append("x-amz-security-token", params.session_token);
    if (!headers.contains("host")) {
        const host = params.request_uri.host orelse return error.MissingHost;
        try headers.append("host", host);
    }
    {
        try headers.append("x-amz-content-sha256", "");

        const payload_sign = try std.fmt.allocPrint(headers.allocator, "{}", .{params.payload_sign.fmt()});
        errdefer headers.allocator.free(payload_sign);

        const indices = headers.getIndices("x-amz-content-sha256").?;
        const idx = indices[indices.len - 1];
        headers.list.items[idx].value = payload_sign;
    }
    headers.sort();

    const date_bounded_array = blk: {
        var date_str: std.BoundedArray(u8, "2000-12-31".len) = .{};

        const time_sep_idx = std.mem.indexOfScalar(u8, params.date_time, 'T') orelse return error.MissingTimeInDateTime;
        const year_month_day = try iso8601.YearMonthDay.parse(params.date_time[0..time_sep_idx]);
        const year = switch (year_month_day.year) {
            .basic => |basic| basic,
            .extended => return error.DateTimeExtendedYear,
        };

        iso8601.writeYearMonthDayTo(
            date_str.writer(),
            year,
            year_month_day.getMonth(),
            year_month_day.getDay(),
            .{ .want_dashes = false },
        ) catch unreachable;
        break :blk date_str;
    };
    const date_str: []const u8 = date_bounded_array.constSlice();

    const canon_request_digest: [Sha256.digest_length]u8 = digest: {
        var canon_request_hasher = Sha256.init(.{});

        var crb = aws.auth.canonicalRequestBuilder(aws.auth.sha256Writer(&canon_request_hasher));
        crb.setHttpMethod(params.request_method) catch |e| switch (e) {};
        crb.setCanonicalUri(params.request_uri.path) catch |e| switch (e) {};

        if (params.request_uri.query) |queries_str| {
            var queries = try std.ArrayList(aws.auth.UriQuery).initCapacity(allocator, cap: {
                var count: usize = 1;
                var start: usize = 0;
                while (std.mem.indexOfScalarPos(u8, queries_str, start, '&')) |idx| {
                    count += 1;
                    start = idx + 1;
                }
                break :cap count;
            });
            defer queries.deinit();

            var query_iter = aws.auth.uriQueryStringParser(queries_str);
            while (query_iter.next()) |query| try queries.append(query);

            std.sort.block(aws.auth.UriQuery, queries.items, {}, struct {
                fn lessThan(
                    _: void,
                    lhs: aws.auth.UriQuery,
                    rhs: aws.auth.UriQuery,
                ) bool {
                    return std.mem.lessThan(u8, lhs.name, rhs.name);
                }
            }.lessThan);

            for (queries.items) |query| {
                crb.addQueryName(query.name) catch |e| switch (e) {};
                crb.setQueryValue(query.value orelse "") catch |e| switch (e) {};
            }
        }
        crb.endQueryString() catch |e| switch (e) {};

        for (headers.list.items) |header| {
            crb.addCanonHeaderName(header.name) catch |e| switch (e) {};
            crb.setCanonHeaderValue(header.value) catch |e| switch (e) {};
        }
        crb.endCanonHeaders() catch |e| switch (e) {};

        for (headers.list.items) |header| {
            crb.addSignedHeader(header.name) catch |e| switch (e) {};
        }
        crb.setPayloadSign(params.payload_sign) catch |e| switch (e) {};

        break :digest canon_request_hasher.finalResult();
    };

    const scope: aws.auth.Scope = .{
        .date = date_str,
        .region = params.region,
        .service = params.service,
    };
    const sts: aws.auth.StringToSign = .{
        .algorithm = "AWS4-HMAC-SHA256",
        .date_time = params.date_time,
        .scope = scope,
        .canon_request_digest = &canon_request_digest,
    };

    const signing_key = aws.auth.calcSigningKey(params.secret_access_key, scope);
    const signature = aws.auth.calcSignature(&signing_key, sts);

    const auth_header_value: []const u8 = blk: {
        var auth_header_value: std.ArrayListUnmanaged(u8) = .{};
        defer auth_header_value.deinit(headers.allocator);

        var ahb = aws.auth.authorizationHeaderBuilder(auth_header_value.writer(headers.allocator));
        try ahb.setAlgorithm(sts.algorithm);
        try ahb.setCredential(params.access_key_id, scope);
        for (headers.list.items) |header| try ahb.addSignedHeader(header.name);
        try ahb.setSignature(&signature);

        break :blk try auth_header_value.toOwnedSlice(headers.allocator);
    };
    errdefer headers.allocator.free(auth_header_value);

    {
        try headers.append("Authorization", "");
        const indices = headers.getIndices("Authorization").?;
        const idx = indices[indices.len - 1];
        headers.list.items[idx].value = auth_header_value;
    }
    headers.sort();
}
