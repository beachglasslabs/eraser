const std = @import("std");
const assert = std.debug.assert;

pub const WriteYearMonthDayOptions = struct {
    want_dashes: bool,
};
pub inline fn writeYearMonthDayTo(
    writer: anytype,
    year: anytype,
    month: ?std.time.epoch.Month,
    day: ?u5,
    options: WriteYearMonthDayOptions,
) @TypeOf(writer).Error!void {
    assert(month != null or day == null);
    const write_dashes = options.want_dashes or day == null;

    switch (@typeInfo(@TypeOf(year))) {
        .Pointer, .Array => try writer.print("{s:0>4}", .{year}),
        .Int, .ComptimeInt => try writer.print("{d:0>4}", .{year}),
        else => @compileError("Unsupported year type"),
    }

    if (month) |m| {
        if (write_dashes) try writer.writeByte('-');
        try writer.print("{d:0>2}", .{m.numeric()});
    }

    if (day) |d| {
        if (write_dashes) try writer.writeByte('-');
        try writer.print("{d:0>2}", .{d});
        assert(month != null);
    }
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

    pub const Extension = enum {
        /// '+', year is more than 4 digits.
        plus,
        /// '-', year is mor than 4 digits.
        sub,
    };

    pub const Year = union(enum) {
        basic: [4]u8,
        extended: struct { Extension, []const u8 },
    };
    pub const Month = std.time.epoch.Month;
    /// From 1 to 31
    pub const Day = u5;

    pub const ParseError = error{
        EmptyString,
        AmbiguousExtendedYear,
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
        const maybe_extension: ?Extension, //
        const year_str: []const u8, //
        const maybe_month_str: ?[]const u8, //
        const maybe_day_str: ?[]const u8 //
        = switch (parseTokens(string)) {
            .empty => return error.EmptyString,
            .extended_terse => return error.AmbiguousExtendedYear,
            .basic_terse_ym => return error.TerseYearMonthMissingDay,

            inline .basic_terse, .basic_dashed => |basic| eymd: {
                if (basic.extraneous != null) return error.ExtraneousString;
                break :eymd .{ null, basic.ymd.year, basic.ymd.month(), basic.ymd.day() };
            },
            .extended_dashed => |ed| eymd: {
                if (ed.extraneous != null) return error.ExtraneousString;
                break :eymd .{ ed.extension, ed.ymd.year, ed.ymd.month(), ed.ymd.day() };
            },
        };
        assert(maybe_month_str != null or maybe_day_str == null);
        assert(year_str.len >= 4);

        const year: Year = yyyy: {
            if (std.mem.indexOfNone(u8, year_str, "0123456789") != null) return error.YearInvalidDigits;
            const extension = maybe_extension orelse {
                if (year_str.len != 4) return error.YearInvalidLength;
                break :yyyy .{ .basic = year_str[0..4].* };
            };
            break :yyyy .{ .extended = .{ extension, year_str } };
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
        extended_terse: ExtendedTerse,
        extended_dashed: ExtendedDashed,

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
        pub const ExtendedTerse = struct {
            extension: Extension,
            ymd: []const u8,
        };
        pub const ExtendedDashed = struct {
            extension: Extension,
            ymd: YmdDashed,
            /// Is non-null if any trailing string appears after the "day" string.
            extraneous: ?[]const u8,
        };
    };

    pub inline fn parseTokens(string: []const u8) ParsedTokens {
        if (string.len == 0) return .empty;

        const maybe_extension: ?Extension, const start_idx: usize = switch (string[0]) {
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
            const extension = maybe_extension orelse return .{ .basic_dashed = .{
                .ymd = ymd,
                .extraneous = extraneous,
            } };

            return .{ .extended_dashed = .{
                .extension = extension,
                .ymd = ymd,
                .extraneous = extraneous,
            } };
        } else {
            // there's no general way to tokenize an extended date, so we
            // simply return the extension and the rest of the string.
            if (maybe_extension) |extension| return .{ .extended_terse = .{
                .extension = extension,
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

fn testYearMonthDayParse(str: []const u8, expected: YearMonthDay.ParseError!YearMonthDay, options: YearMonthDay.ParseTokensOptions) !void {
    return std.testing.expectEqualDeep(expected, YearMonthDay.parse(str, options));
}

test YearMonthDay {
    inline for (.{ "", "+", "-" }) |extension| {
        try testYearMonthDayParse(extension ++ "0000" ++ "0", error.InvalidLength, .{});
        try testYearMonthDayParse(extension ++ "0000" ++ "00", error.InvalidLength, .{});
        try testYearMonthDayParse(extension ++ "0000" ++ "000", error.InvalidLength, .{});
        try testYearMonthDayParse(extension ++ "0000" ++ "0a00", error.MonthInvalidDigits, .{});
        try testYearMonthDayParse(extension ++ "0000" ++ "0000", error.MonthInvalidValue, .{});
        try testYearMonthDayParse(extension ++ "0000" ++ "010a", error.DayInvalidDigits, .{});
    }

    try testYearMonthDayParse("0000" ++ "", .{ .year = .{ .basic = "0000".* }, .month_day = null }, .{});
    try testYearMonthDayParse("0000" ++ "0101", .{ .year = .{ .basic = "0000".* }, .month_day = .{ .jan, 1 } }, .{});

    try testYearMonthDayParse("+0000" ++ "", .{ .year = .{ .plus = "0000" }, .month_day = null }, .{});
    try testYearMonthDayParse("+0000" ++ "0101", .{ .year = .{ .plus = "0000" }, .month_day = .{ .jan, 1 } }, .{});

    try testYearMonthDayParse("-0000" ++ "", .{ .year = .{ .sub = "0000".* }, .month_day = null }, .{});
    try testYearMonthDayParse("-0000" ++ "0", error.InvalidLength, .{});
    try testYearMonthDayParse("-0000" ++ "00", error.InvalidLength, .{});
    try testYearMonthDayParse("-0000" ++ "000", error.InvalidLength, .{});
    try testYearMonthDayParse("-0000" ++ "0a00", error.MonthInvalidDigits, .{});
    try testYearMonthDayParse("-0000" ++ "0000", error.MonthInvalidValue, .{});
    try testYearMonthDayParse("-0000" ++ "010a", error.DayInvalidDigits, .{});
    try testYearMonthDayParse("-0000" ++ "0101", .{ .year = .{ .sub = "0000" }, .month_day = .{ .jan, 1 } }, .{});
}
