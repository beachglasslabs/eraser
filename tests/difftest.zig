const std = @import("std");
const paths = @import("paths");

test {
    const input_path = paths.input;
    const output_path = paths.output;

    try std.testing.expect(!std.mem.eql(u8, input_path, output_path));

    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const output_file = try std.fs.cwd().openFile(output_path, .{});
    defer output_file.close();

    const expected: []const u8 = try input_file.readToEndAlloc(std.testing.allocator, 1 << 26);
    defer std.testing.allocator.free(expected);

    const actual: []const u8 = try output_file.readToEndAlloc(std.testing.allocator, 1 << 26);
    defer std.testing.allocator.free(actual);

    try std.testing.expectEqualStrings(expected, actual);
}
