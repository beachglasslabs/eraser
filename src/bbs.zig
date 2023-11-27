//! Buffer backed slices
const std = @import("std");
const assert = std.debug.assert;

pub fn SliceLengths(comptime S: type) type {
    return Impl(S).Lengths;
}
pub fn bufferAlignment(comptime S: type) comptime_int {
    return Impl(S).max_align;
}
pub fn bufferLength(comptime S: type, lengths: Impl(S).Lengths) usize {
    return Impl(S).calcBufferOffsetsAndSize(lengths)[1];
}

pub inline fn fromBuffer(
    comptime S: type,
    buf: []align(bufferAlignment(S)) u8,
    lengths: SliceLengths(S),
) S {
    const I = Impl(S);
    const offsets, const buffer_size = I.calcBufferOffsetsAndSize(lengths);
    assert(buf.len == buffer_size);
    return I.fromBufferImpl(buf, lengths, offsets);
}

/// Appends the backing buffer to the array list, and returns the buffer struct.
pub inline fn fromArrayList(
    comptime S: type,
    array_list: *std.ArrayListAligned(u8, bufferAlignment(S)),
    lengths: SliceLengths(S),
) std.mem.Allocator.Error!S {
    const I = Impl(S);
    const offsets, const buffer_size = I.calcBufferOffsetsAndSize(lengths);
    try array_list.resize(buffer_size);
    return I.fromBufferImpl(array_list.items, lengths, offsets);
}

pub inline fn fromAlloc(
    comptime S: type,
    allocator: std.mem.Allocator,
    lengths: SliceLengths(S),
) std.mem.Allocator.Error!struct { S, []align(bufferAlignment(S)) u8 } {
    const I = Impl(S);

    const offsets, const buffer_size = I.calcBufferOffsetsAndSize(lengths);

    const alloc = try allocator.alignedAlloc(u8, I.max_align, buffer_size);
    errdefer allocator.free(alloc);

    const result = I.fromBufferImpl(alloc, lengths, offsets);
    return .{ result, alloc };
}

fn Impl(comptime S: type) type {
    return struct {
        /// Returns the offsets struct and the exact required buffer length.
        inline fn calcBufferOffsetsAndSize(lengths: Lengths) struct { Offsets, usize } {
            var offsets: Offsets = undefined;

            var offset: usize = 0;
            inline for (ordered_ids) |id| {
                const field_info = fields[@intFromEnum(id)];
                const pointer = @typeInfo(field_info.type).Pointer;
                offset = std.mem.alignForward(usize, offset, pointer.alignment);
                @field(offsets, field_info.name) = offset;
                offset += @sizeOf(pointer.child) * @field(lengths, field_info.name);
            }

            return .{ offsets, offset };
        }

        fn fromBufferImpl(
            /// asserts `buf.len == bufferLength(S, lengths)`
            buf: []align(bufferAlignment(S)) u8,
            lengths: SliceLengths(S),
            offsets: Offsets,
        ) S {
            var result: S = undefined;
            inline for (Impl(S).fields) |field| {
                const pointer = @typeInfo(field.type).Pointer;
                const offset = @field(offsets, field.name);
                const byte_len = @field(lengths, field.name) * @sizeOf(pointer.child);
                @field(result, field.name) = @alignCast(switch (pointer.size) {
                    .Slice => std.mem.bytesAsSlice(pointer.child, buf[offset..][0..byte_len]),
                    .Many => std.mem.bytesAsSlice(pointer.child, buf[offset..][0..byte_len]).ptr,
                    .One => std.mem.bytesAsValue(pointer.child, buf[offset..][0..byte_len]),
                    else => comptime unreachable,
                });
            }

            return result;
        }

        const info = @typeInfo(S).Struct;
        const fields = info.fields;
        const FieldId = std.meta.FieldEnum(S);

        const Offsets = std.enums.EnumFieldStruct(FieldId, usize, null);
        const Lengths = @Type(.{ .Struct = blk: {
            var new_fields = fields[0..].*;
            for (&new_fields) |*field| {
                const pointer = @typeInfo(field.type).Pointer;
                switch (pointer.size) {
                    .Slice, .Many => field.* = .{
                        .name = field.name,
                        .type = usize,
                        .alignment = 0,
                        .is_comptime = false,
                        .default_value = null,
                    },
                    .One => field.* = .{
                        .name = field.name,
                        .type = comptime_int,
                        .alignment = 0,
                        .is_comptime = true,
                        .default_value = @typeInfo(struct {
                            comptime comptime_int = 1,
                        }).Struct.fields[0].default_value,
                    },
                    else => @compileError("Other pointer sizes not supported"),
                }
            }
            break :blk .{
                .layout = .Auto,
                .is_tuple = info.is_tuple,
                .backing_integer = null,
                .decls = &.{},
                .fields = &new_fields,
            };
        } });

        const max_align = blk: {
            var max = 1;
            for (fields) |field| {
                max = @max(max, @typeInfo(field.type).Pointer.alignment);
            }
            break :blk max;
        };
        const ordered_ids = &blk: {
            var ids: [fields.len]FieldId = std.enums.values(FieldId)[0..].*;

            @setEvalBranchQuota(ids.len * ids.len + 10);
            std.sort.insertionContext(0, ids.len, struct {
                pub fn lessThan(a: usize, b: usize) bool {
                    const align_a = @typeInfo(fields[@intFromEnum(ids[a])].type).Pointer.alignment;
                    const align_b = @typeInfo(fields[@intFromEnum(ids[b])].type).Pointer.alignment;
                    return align_a > align_b;
                }
                pub fn swap(a: usize, b: usize) void {
                    std.mem.swap(&ids[a], &ids[b]);
                }
            });

            break :blk ids;
        };
    };
}
