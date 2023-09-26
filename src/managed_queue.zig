const std = @import("std");
const assert = std.debug.assert;

pub fn ManagedQueue(comptime T: type) type {
    return struct {
        tail_queue: TailQueue = .{},
        node_store: NodeList = .{},
        unused_nodes: UnusedNodeList = .{},
        const Self = @This();

        pub const TailQueue = std.TailQueue(T);
        pub const Node = TailQueue.Node;
        pub const NodeList = std.SegmentedList(Node, 0); // uses 0 preallocated items, making it safe to copy by value
        pub const UnusedNodeList = std.ArrayListUnmanaged(*Node);

        pub fn initCapacity(
            allocator: std.mem.Allocator,
            capacity: usize,
        ) std.mem.Allocator.Error!Self {
            var self: Self = .{};
            errdefer self.deinit(allocator);
            try self.ensureUnusedCapacity(allocator, capacity);
            return self;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.unused_nodes.deinit(allocator);
            self.node_store.deinit(allocator);
            self.* = .{};
        }

        pub fn ensureUnusedCapacity(self: *Self, allocator: std.mem.Allocator, additional_count: usize) std.mem.Allocator.Error!void {
            const unused_count = self.unused_nodes.items.len;
            if (unused_count >= additional_count) return;
            const num_added = additional_count - unused_count;

            try self.unused_nodes.ensureUnusedCapacity(allocator, num_added);
            try self.node_store.setCapacity(allocator, self.node_store.len + num_added);
            for (0..num_added) |_| {
                self.unused_nodes.appendAssumeCapacity(self.node_store.addOne(undefined) catch unreachable);
            }
        }

        pub fn clearItems(self: *Self) void {
            self.tail_queue = .{};
        }

        /// Push a node value directly to the queue.
        pub fn pushValue(self: *Self, allocator: std.mem.Allocator, value: T) std.mem.Allocator.Error!void {
            try self.ensureUnusedCapacity(allocator, 1);
            self.pushValueAssumeCapacity(value);
        }

        /// Same as `pushValue`, assuming capacity.
        pub fn pushValueAssumeCapacity(self: *Self, value: T) void {
            const node = self.newPtr();
            node.data = value;
            self.pushPtr(node);
        }

        /// Create a node which can be pushed to the queue.
        pub fn createNode(self: *Self, allocator: std.mem.Allocator) std.mem.Allocator.Error!*T {
            try self.ensureUnusedCapacity(allocator, 1);
            return self.createNodeAssumeCapacity();
        }

        /// Same as `createNode`, assuming capacity.
        pub fn createNodeAssumeCapacity(self: *Self) *T {
            return &self.newPtr().data;
        }

        /// Pushes a node to the queue.
        pub fn pushNode(
            self: *Self,
            /// Must be the result of a call to `self.createNode` or `self.createNodeAssumeCapacity`,
            /// or `popNode`, and must not have been passed to `pushNode` or `destroyNode` beforehand.
            ptr: *T,
        ) void {
            const node = @fieldParentPtr(Node, "data", ptr);
            self.pushPtr(node);
        }

        /// Discards a node not in the queue.
        pub fn destroyNode(
            self: *Self,
            /// Must be the result of a call to `self.createNode` or `self.createNodeAssumeCapacity`,
            /// and must not have been passed to `pushNode` or `destroyNode` before.
            ptr: *T,
        ) void {
            const node = @fieldParentPtr(Node, "data", ptr);
            self.cachePtr(node);
        }

        /// Pops a value from the queue, without retaining the associated node.
        pub fn popValue(self: *Self) ?T {
            const node = self.popPtr() orelse return null;
            defer self.cachePtr(node);
            return node.data;
        }

        /// Pops a node from the queue, retaining the associated node.
        pub fn popNode(self: *Self) ?*T {
            const node = self.popPtr() orelse return null;
            return &node.data;
        }

        /// Creates a new node, assuming capacity for 1 new node.
        inline fn newPtr(self: *Self) *Node {
            const result = self.unused_nodes.pop();
            result.* = .{
                .prev = null,
                .next = null,
                .data = undefined,
            };
            return result;
        }

        /// `node` must have been returned by `popPtr` or `newPtr`, and not have been passed to `cachePtr`.
        /// Puts `node` into the queue.
        inline fn pushPtr(self: *Self, node: *Node) void {
            self.tail_queue.prepend(node);
        }

        /// Removes a node from the queue and returns it.
        inline fn popPtr(self: *Self) ?*Node {
            return self.tail_queue.pop();
        }

        /// `node` must have been returned by `popPtr` or `newPtr`, and not have been passed to `pushPtr`.
        inline fn cachePtr(self: *Self, node: *Node) void {
            // this is correct because `newNode` ensures capacity for 1 more node
            // each time a new one is allocated, meaning there is always capacity
            // for the total number of nodes created.
            self.unused_nodes.appendAssumeCapacity(node);
            node.* = undefined;
        }
    };
}

test ManagedQueue {
    var queue: ManagedQueue(u8) = .{};
    defer queue.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?u8, null), queue.popValue());
    try queue.pushValue(std.testing.allocator, 1);
    try std.testing.expectEqual(@as(?u8, 1), queue.popValue());
    try std.testing.expectEqual(@as(?u8, null), queue.popValue());

    { // can create nodes and destroy them without pushing to queue
        const new_node = try queue.createNode(std.testing.allocator);
        try std.testing.expectEqual(@as(?u8, null), queue.popValue());
        queue.destroyNode(new_node); // `new_node` is no longer valid
        try std.testing.expectEqual(@as(?u8, null), queue.popValue());
    }

    const ptr = try queue.createNode(std.testing.allocator);
    ptr.* = 3;
    queue.pushNode(ptr);

    const ptr_2 = queue.popNode() orelse
        return error.TestExpectedNonNull;
    try std.testing.expectEqual(ptr, ptr_2);
    ptr_2.* += 1;

    const value = ptr.*;

    queue.destroyNode(ptr_2); // `ptr` and `ptr_2` are no longer valid

    try std.testing.expectEqual(@as(u8, value), 4);
}
