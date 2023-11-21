const std = @import("std");
const assert = std.debug.assert;

pub const DateTimeFormatOptions = struct {
    ymd: YearMonthDay.Dashes,
    hms: HourMinuteSecondTz.WriteOptions.WriteFormat,
};
pub inline fn writeEpochYMDHMS(
    writer: anytype,
    epoch_secs: std.time.epoch.EpochSeconds,
    options: DateTimeFormatOptions,
) @TypeOf(writer).Error!void {
    const year, const month, const day = ymd: {
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        break :ymd .{ year_day.year, month_day.month, month_day.day_index + 1 };
    };
    const hour, const minute, const second = hms: {
        const ds = epoch_secs.getDaySeconds();
        break :hms .{ ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() };
    };

    var year_buf = [_]u8{undefined} ** std.fmt.count("{d:0>4}", .{std.math.maxInt(@TypeOf(year))});
    const ymd: YearMonthDay = .{
        .year = switch (year) {
            0...9999 => blk: {
                var buf: [4]u8 = undefined;
                assert((std.fmt.bufPrint(&buf, "{d:0>4}", .{year}) catch unreachable).len == buf.len);
                break :blk .{ .basic = buf };
            },
            else => .{ .expanded = .{ .plus, std.fmt.bufPrint(&year_buf, "{d:0>4}", .{year}) catch unreachable } },
        },
        .month_day = .{ month, day },
    };
    const hms: HourMinuteSecondTz = .{
        .hour = hour,
        .minute_second = .{ minute, second },
        .decimal = null,
        .timezone = .utc,
    };

    try ymd.writeTo(writer, options.ymd);
    try hms.writeTo(writer, .{
        .time_fmt = switch (options.hms) {
            .dont_want_colons, .want_colons => |tag| tag,
            .want_colons_omit_prefix => .want_colons,
        },
        .utc_offs_colon = undefined, // this will never be referenced
    });
}

fn testWriteEpochYMDHMS(expected: []const u8, epoch_secs: std.time.epoch.EpochSeconds, options: DateTimeFormatOptions) !void {
    var actual = std.ArrayList(u8).init(std.testing.allocator);
    defer actual.deinit();
    try writeEpochYMDHMS(actual.writer(), epoch_secs, options);
    try std.testing.expectEqualStrings(expected, actual.items);
}

test writeEpochYMDHMS {
    try testWriteEpochYMDHMS("19700101T000000Z", .{ .secs = 0 }, .{ .ymd = .dont_want_dashes, .hms = .dont_want_colons });
    try testWriteEpochYMDHMS("1970-01-01T000000Z", .{ .secs = 0 }, .{ .ymd = .want_dashes, .hms = .dont_want_colons });
    try testWriteEpochYMDHMS("19700101T00:00:00Z", .{ .secs = 0 }, .{ .ymd = .dont_want_dashes, .hms = .want_colons });
    try testWriteEpochYMDHMS("1970-01-01T00:00:00Z", .{ .secs = 0 }, .{ .ymd = .want_dashes, .hms = .want_colons });
}

pub const YearMonthDay = struct {
    year: Year,
    month_day: ?struct { Month, ?Day },

    pub inline fn getMonth(ymd: YearMonthDay) ?Month {
        const md = ymd.month_day orelse return null;
        return md[0];
    }

    pub inline fn getDay(ymd: YearMonthDay) ?Day {
        const md = ymd.month_day orelse return null;
        return md[1];
    }

    pub const Expansion = enum(u8) {
        plus = '+',
        sub = '-',
    };

    pub const Year = union(enum) {
        basic: [4]u8,
        expanded: struct { Expansion, []const u8 },
    };
    pub const Month = std.time.epoch.Month;
    /// 1...31
    pub const Day = u5;

    pub const Dashes = enum {
        dont_want_dashes,
        want_dashes,
    };

    pub inline fn writeTo(
        ymd: YearMonthDay,
        writer: anytype,
        dashes: YearMonthDay.Dashes,
    ) @TypeOf(writer).Error!void {
        switch (ymd.year) {
            .basic => |basic| try writer.writeAll(&basic),
            .expanded => |expanded| {
                const expansion, const year = expanded;
                const prefix: u8 = switch (expansion) {
                    .plus => '+',
                    .sub => '-',
                };
                try writer.print("{c}{s:0>4}", .{ prefix, year });
            },
        }

        const month, const maybe_day = ymd.month_day orelse return;

        switch (dashes) {
            .want_dashes => try writer.writeByte('-'),
            .dont_want_dashes => if (maybe_day == null) {
                // need a dash anyway if only month is present,
                // because "YYYY-MM" is valid, but "YYYYMM" isn't.
                try writer.writeByte('-');
            },
        }
        try writer.print("{d:0>2}", .{month.numeric()});

        const day = maybe_day orelse return;
        switch (dashes) {
            .want_dashes => try writer.writeByte('-'),
            .dont_want_dashes => {},
        }
        try writer.print("{d:0>2}", .{day});
    }

    pub const ParseError = error{
        EmptyString,

        AmbiguousExpandedYear,
        TerseYearMonthMissingDay,
        ExtraneousString,

        YearInvalidDigits,
        YearInvalidLength,

        MonthInvalidLength,
        MonthInvalidDigits,
        MonthInvalidValue,

        DayInvalidLength,
        DayInvalidDigits,
        DayInvalidValue,
    };

    pub inline fn parse(string: []const u8) ParseError!YearMonthDay {
        const maybe_expansion: ?Expansion, //
        const year_str: []const u8, //
        const maybe_month_str: ?[]const u8, //
        const maybe_day_str: ?[]const u8 //
        = switch (parseTokens(string)) {
            .empty => return error.EmptyString,
            .expanded_terse => return error.AmbiguousExpandedYear,
            .basic_terse_ym => return error.TerseYearMonthMissingDay,

            inline .basic_terse, .basic_dashed => |basic| eymd: {
                if (basic.extraneous != null) return error.ExtraneousString;
                break :eymd .{ null, basic.ymd.year, basic.ymd.month(), basic.ymd.day() };
            },
            .expanded_dashed => |ed| eymd: {
                if (ed.extraneous != null) return error.ExtraneousString;
                break :eymd .{ ed.expansion, ed.ymd.year, ed.ymd.month(), ed.ymd.day() };
            },
        };
        assert(maybe_month_str != null or maybe_day_str == null);
        assert(year_str.len >= 4);

        const year: Year = yyyy: {
            if (std.mem.indexOfNone(u8, year_str, "0123456789") != null) return error.YearInvalidDigits;
            const expansion = maybe_expansion orelse {
                if (year_str.len != 4) return error.YearInvalidLength;
                break :yyyy .{ .basic = year_str[0..4].* };
            };
            break :yyyy .{ .expanded = .{ expansion, year_str } };
        };

        const month: Month = mm: {
            const month_str = maybe_month_str orelse return .{
                .year = year,
                .month_day = null,
            };

            if (month_str.len != 2) return error.MonthInvalidLength;
            const month_int = std.fmt.parseInt(@typeInfo(Month).Enum.tag_type, month_str, 10) catch |err| return switch (err) {
                error.InvalidCharacter => error.MonthInvalidDigits,
                error.Overflow => error.MonthInvalidValue,
            };
            break :mm std.meta.intToEnum(Month, month_int) catch |err| return switch (err) {
                error.InvalidEnumTag => error.MonthInvalidValue,
            };
        };

        const day: Day = dd: {
            const day_str = maybe_day_str orelse return .{
                .year = year,
                .month_day = .{ month, null },
            };

            if (day_str.len != 2) return error.DayInvalidLength;
            const day_int = std.fmt.parseInt(Day, day_str, 10) catch |err| return switch (err) {
                error.InvalidCharacter => error.DayInvalidDigits,
                error.Overflow => error.DayInvalidValue,
            };
            if (day_int < 1 or 31 < day_int)
                return error.DayInvalidValue;
            break :dd day_int;
        };

        return .{
            .year = year,
            .month_day = .{ month, day },
        };
    }

    pub const ParsedTokens = union(enum) {
        /// The given string was empty.
        empty,

        basic_terse: BasicTerse,
        basic_dashed: BasicDashed,
        expanded_terse: ExpandedTerse,
        expanded_dashed: ExpandedDashed,

        /// This is not a valid format, but is returned as a separate invariant
        /// for the purposes of allowing a more informative error message.
        basic_terse_ym: BaiscTerseYm,

        pub const YmdTerse = struct {
            year: []const u8,
            month_day: ?struct { []const u8, []const u8 },

            pub inline fn month(ymd: YmdTerse) ?[]const u8 {
                const md = ymd.month_day orelse return null;
                return md[0];
            }
            pub inline fn day(ymd: YmdTerse) ?[]const u8 {
                const md = ymd.month_day orelse return null;
                return md[1];
            }
        };
        pub const YmdDashed = struct {
            year: []const u8,
            month_day: ?struct { []const u8, ?[]const u8 },

            pub inline fn month(ymd: YmdDashed) ?[]const u8 {
                const md = ymd.month_day orelse return null;
                return md[0];
            }
            pub inline fn day(ymd: YmdDashed) ?[]const u8 {
                const md = ymd.month_day orelse return null;
                return md[1];
            }
        };

        pub const BasicTerse = struct {
            ymd: YmdTerse,
            /// Is non-null if any trailing string appears after the main date tokens.
            extraneous: ?[]const u8,
        };
        pub const BaiscTerseYm = struct {
            ym: Ym,
            /// Is non-null if there happens to be a single character following the month string.
            /// Only a single digit, because if there were at least one more, it would instead
            /// be interpreted as the day field.
            extraneous: ?u8,

            pub const Ym = struct {
                year: []const u8,
                month: []const u8,
            };
        };
        pub const BasicDashed = struct {
            ymd: YmdDashed,
            /// Is non-null if any trailing string appears after the main date tokens.
            extraneous: ?[]const u8,
        };
        pub const ExpandedTerse = struct {
            expansion: Expansion,
            ymd: []const u8,
        };
        pub const ExpandedDashed = struct {
            expansion: Expansion,
            ymd: YmdDashed,
            /// Is non-null if any trailing string appears after the "day" string.
            extraneous: ?[]const u8,
        };
    };

    pub inline fn parseTokens(string: []const u8) ParsedTokens {
        if (string.len == 0) return .empty;

        const maybe_expansion: ?Expansion, const start_idx: usize = switch (string[0]) {
            '+' => .{ .plus, 1 },
            '-' => .{ .sub, 1 },
            else => .{ null, 0 },
        };

        var splitter = std.mem.splitScalar(u8, string[start_idx..], '-');

        const first_str = splitter.first();
        if (splitter.next()) |second_str| {
            const year = first_str;
            const month = second_str;
            const day, const extraneous = blk: {
                const day = splitter.next() orelse break :blk .{ null, null };
                if (splitter.peek() != null) break :blk .{ day, null };

                var extraneous = splitter.rest();
                extraneous.ptr -= 1;
                extraneous.len += 1;
                assert(extraneous[0] == splitter.delimiter);

                break :blk .{ day, extraneous };
            };

            const ymd: ParsedTokens.YmdDashed = .{
                .year = year,
                .month_day = .{ month, day },
            };
            const expansion = maybe_expansion orelse return .{ .basic_dashed = .{
                .ymd = ymd,
                .extraneous = extraneous,
            } };

            return .{ .expanded_dashed = .{
                .expansion = expansion,
                .ymd = ymd,
                .extraneous = extraneous,
            } };
        } else {
            // there's no general way to tokenize an expanded date, so we
            // simply return the expansion and the rest of the string.
            if (maybe_expansion) |expansion| return .{ .expanded_terse = .{
                .expansion = expansion,
                .ymd = first_str,
            } };

            switch (first_str.len) {
                0...4 => return .{ .basic_terse = .{
                    .ymd = .{
                        .year = first_str,
                        .month_day = null,
                    },
                    .extraneous = null,
                } },
                5 => return .{ .basic_terse = .{
                    .ymd = .{
                        .year = first_str,
                        .month_day = null,
                    },
                    .extraneous = first_str[4..],
                } },

                // invalid lengths, reported as such for utility
                inline 6, 7 => |n| return .{ .basic_terse_ym = .{
                    .ym = .{
                        .year = first_str[0..4],
                        .month = first_str[4..6],
                    },
                    .extraneous = switch (n) {
                        6 => null,
                        7 => first_str[6],
                        else => comptime unreachable,
                    },
                } },

                else => |n| {
                    assert(n >= 8);
                    const year = first_str[0..4];
                    const month = first_str[4..6];
                    const day = first_str[6..8];
                    const extraneous = if (n == 8) null else first_str[8..];
                    return .{ .basic_terse = .{
                        .ymd = .{
                            .year = year,
                            .month_day = .{ month, day },
                        },
                        .extraneous = extraneous,
                    } };
                },
            }
        }
    }
};

fn testYearMonthDayParse(str: []const u8, expected: YearMonthDay.ParseError!YearMonthDay) !void {
    return std.testing.expectEqualDeep(expected, YearMonthDay.parse(str));
}

test YearMonthDay {
    try testYearMonthDayParse("0000" ++ "0", error.ExtraneousString);
    try testYearMonthDayParse("0000" ++ "00", error.TerseYearMonthMissingDay);
    try testYearMonthDayParse("0000" ++ "000", error.TerseYearMonthMissingDay);
    try testYearMonthDayParse("0000" ++ "0a00", error.MonthInvalidDigits);
    try testYearMonthDayParse("0000" ++ "0000", error.MonthInvalidValue);
    try testYearMonthDayParse("0000" ++ "010a", error.DayInvalidDigits);
    try testYearMonthDayParse("0000" ++ "010a" ++ "0", error.ExtraneousString);

    try testYearMonthDayParse("0000" ++ "", .{ .year = .{ .basic = "0000".* }, .month_day = null });
    try testYearMonthDayParse("0000" ++ "0101", .{ .year = .{ .basic = "0000".* }, .month_day = .{ .jan, 1 } });

    try testYearMonthDayParse("+0000" ++ "", error.AmbiguousExpandedYear);
    try testYearMonthDayParse("+0000" ++ "0101", error.AmbiguousExpandedYear);

    try testYearMonthDayParse("0000" ++ "", .{ .year = .{ .basic = "0000".* }, .month_day = null });
    try testYearMonthDayParse("0000" ++ "0101", .{ .year = .{ .basic = "0000".* }, .month_day = .{ .jan, 1 } });
}

pub const HourMinuteSecondTz = struct {
    hour: Hour,
    minute_second: ?struct { Minute, ?Second },
    decimal: ?[]const u8,
    timezone: Timezone,

    pub inline fn minute(hms: HourMinuteSecondTz) ?u6 {
        const min, _ = hms.minute_second orelse return null;
        return min;
    }
    pub inline fn second(hms: HourMinuteSecondTz) ?u6 {
        _, const sec = hms.minute_second orelse return null;
        return sec;
    }

    /// 0...24
    pub const Hour = u5;
    /// 0...60
    pub const Minute = u6;
    /// 0...60
    pub const Second = u6;

    pub const Timezone = union(enum) {
        /// Unspecified
        local,
        /// 'Z'.
        utc,
        /// Offset from UTC
        utc_offset: UtcOffset,

        pub inline fn writeTo(
            timezone: Timezone,
            writer: anytype,
            utc_offset_colon: UtcOffset.Colons,
        ) @TypeOf(writer).Error!void {
            try switch (timezone) {
                .local => {},
                .utc => writer.writeByte('Z'),
                .utc_offset => |utc_offset| utc_offset.writeTo(writer, utc_offset_colon),
            };
        }
    };

    pub const UtcOffset = struct {
        direction: Direction,
        hour: [2]u8,
        min: ?[2]u8,

        pub const Direction = enum(u8) {
            pos = '+',
            neg = '-',
        };

        pub const Colons = enum { dont_want_colon, want_colon };
        pub inline fn writeTo(
            utc_offs: UtcOffset,
            writer: anytype,
            colon: Colons,
        ) @TypeOf(writer).Error!void {
            try writer.writeByte(switch (utc_offs.direction) {
                .pos => '+',
                .neg => '-',
            });
            try writer.writeAll(&utc_offs.hour);
            switch (colon) {
                .dont_want_colon => {},
                .want_colon => try writer.writeByte(':'),
            }
            if (utc_offs.min) |*min| try writer.writeAll(min);
        }
    };

    pub const WriteOptions = struct {
        time_fmt: WriteFormat,
        utc_offs_colon: UtcOffset.Colons,

        pub const WriteFormat = enum {
            dont_want_colons,
            want_colons,
            want_colons_omit_prefix,
        };
    };

    pub inline fn writeTo(
        hms: HourMinuteSecondTz,
        writer: anytype,
        options: WriteOptions,
    ) @TypeOf(writer).Error!void {
        switch (options.time_fmt) {
            .dont_want_colons,
            .want_colons,
            => try writer.writeByte('T'),
            .want_colons_omit_prefix => {},
        }
        try writer.print("{d:0>2}", .{hms.hour});

        const min, const maybe_sec = hms.minute_second orelse {
            try hms.writeTrailingTo(writer, options.utc_offs_colon);
            return;
        };
        const want_colons = switch (options.time_fmt) {
            .dont_want_colons => false,
            .want_colons, .want_colons_omit_prefix => true,
        };

        if (want_colons) try writer.writeByte(':');
        try writer.print("{d:0>2}", .{min});

        const sec = maybe_sec orelse {
            try hms.writeTrailingTo(writer, options.utc_offs_colon);
            return;
        };

        if (want_colons) try writer.writeByte(':');
        try writer.print("{d:0>2}", .{sec});

        try hms.writeTrailingTo(writer, options.utc_offs_colon);
    }

    fn writeTrailingTo(
        hms: HourMinuteSecondTz,
        writer: anytype,
        utc_offset_colons: UtcOffset.Colons,
    ) @TypeOf(writer).Error!void {
        if (hms.decimal) |decimal| try writer.print(".{s}", .{decimal});
        try hms.timezone.writeTo(writer, utc_offset_colons);
    }
};
