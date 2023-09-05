const std = @import("std");
const assert = std.debug.assert;

pub fn SharedQueue(comptime T: type) type {
    return struct {
        /// Used to lock the queue
        mutex: *std.Thread.Mutex,

        tail_queue: TailQueue = .{},
        node_store: NodeList = .{},
        unused_nodes: UnusedNodeList = .{},
        const Self = @This();

        pub const TailQueue = std.DoublyLinkedList(T);
        pub const Node = TailQueue.Node;
        pub const NodeList = std.SegmentedList(Node, 0);
        pub const UnusedNodeList = std.ArrayListUnmanaged(*Node);

        pub fn initCapacity(
            mutex: *std.Thread.Mutex,
            allocator: std.mem.Allocator,
            capacity: usize,
        ) std.mem.Allocator.Error!Self {
            var self: Self = .{ .mutex = mutex };
            errdefer self.deinit(allocator);
            try self.ensureUnusedCapacityLocked(allocator, capacity);
            return self;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            const mtx = self.mutex;
            mtx.lock();
            defer mtx.unlock();

            self.unused_nodes.deinit(allocator);
            self.node_store.deinit(allocator);
            self.* = .{ .mutex = mtx };
        }

        pub fn ensureUnusedCapacity(self: *Self, allocator: std.mem.Allocator, additional_count: usize) std.mem.Allocator.Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.ensureUnusedCapacityLocked(allocator, additional_count);
        }

        /// Similar to `ensureUnusedCapacity`, but assumes `self.mutex` is locked
        pub fn ensureUnusedCapacityLocked(self: *Self, allocator: std.mem.Allocator, additional_count: usize) std.mem.Allocator.Error!void {
            const unused_count = self.unused_nodes.items.len;
            if (unused_count >= additional_count) return;
            const num_added = additional_count - unused_count;

            try self.unused_nodes.ensureUnusedCapacity(allocator, num_added);
            try self.node_store.setCapacity(allocator, self.node_store.len + num_added);
            for (0..num_added) |_| {
                self.unused_nodes.appendAssumeCapacity(self.node_store.addOne(undefined) catch unreachable);
            }
        }

        /// Clears all items from the queue without reallocating.
        /// All pointers returned from `pushStart` and passed to `pushFinish`
        /// become un-bound from `self.mutex`, as though they had been
        /// returned from `popBorrowed`, and may be safely passed to `destroyBorrowed`.
        pub fn clearItems(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.clearItemsLocked();
        }

        /// Similar to `clearItems`, but assumes `self.mutex` is locked.
        pub fn clearItemsLocked(self: *Self) void {
            self.tail_queue = .{};
        }

        /// Equivalent to:
        /// ```
        /// const ptr = try self.pushStart();
        /// ptr.* = value;
        /// self.pushFinish(ptr);
        /// ```
        /// This is useful for when the item to be pushed is a
        /// simple value, whose address isn't relevant to its initialisation.
        pub fn pushValue(self: *Self, allocator: std.mem.Allocator, value: T) std.mem.Allocator.Error!*T {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.ensureUnusedCapacityLocked(allocator, 1);
            return self.pushValueAssumeCapacityLocked(value);
        }

        /// Same as `pushValue`, assuming capacity.
        pub fn pushValueAssumeCapacity(self: *Self, value: T) *T {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.pushValueAssumeCapacityLocked(value);
        }

        /// Similar to `pushValueAssumeCapacity`, but assumes `self.mutex`
        /// is already locked. Useful for adding a number of items
        /// one immediately after the other.
        pub fn pushValueAssumeCapacityLocked(self: *Self, value: T) *T {
            const ptr = @call(.always_inline, Self.pushStartAssumeCapacityLocked, .{self});
            ptr.* = value;
            @call(.always_inline, Self.pushFinishLocked, .{ self, ptr });
            return ptr;
        }

        /// Lock the queue and allocate a new item.
        /// A pointer to the item is returned. The item should
        /// be initialised, and then the pointer should be
        /// passed to one of `pushFinish` and `pushCancel`
        /// exactly one time, in order to unlock the queue
        /// and either complete or cancel the pushing of the
        /// item to the queue.
        /// Must never be called after a `pushStart` which
        /// doesn't have a corresponding `pushFinish`
        /// or `pushCancel`.
        ///
        /// This is mainly useful for when the caller has to
        /// be able to reference the node's final address
        /// while initialising it.
        pub fn pushStart(self: *Self, allocator: std.mem.Allocator) std.mem.Allocator.Error!*T {
            self.mutex.lock();
            errdefer self.mutex.unlock();
            try self.ensureUnusedCapacityLocked(allocator, 1);
            return self.pushStartAssumeCapacityLocked();
        }

        /// Same as `pushStart`, assuming capacity.
        pub fn pushStartAssumeCapacity(self: *Self) *T {
            self.mutex.lock();
            return self.pushStartAssumeCapacityLocked();
        }

        /// Similar to `pushStartAssumeCapacity`, but assumes `self.mutex`
        /// is already locked. Can be called multiple times before calling
        /// calling `pushFinishAssumeMutex` an equivalent number of times.
        pub fn pushStartAssumeCapacityLocked(self: *Self) *T {
            return &self.newNodeAssumeCapacity().data;
        }

        /// Complete the process of pushing the item to the queue,
        /// thus unlocking the queue.
        /// Can only be called once after a matching `pushStart`,
        /// and must never be called after `pushCancel`.
        ///
        /// Concurrent access by the thread holding this pointer
        /// and whichever other thread receives the pointer by
        /// calling `popBorrowed`.
        pub fn pushFinish(self: *Self, data: *T) void {
            self.pushFinishLocked(data);
            self.mutex.unlock();
        }

        /// Similar to `pushFinish`, but doesn't unlock `self.mutex`.
        pub fn pushFinishLocked(self: *Self, data: *T) void {
            const node = @fieldParentPtr(Node, "data", data);
            self.pushNode(node);
        }

        /// Cancel the process of pushing the item to the queue,
        /// thus unlocking the queue.
        /// Can only be called once after a matching `pushStart`,
        /// and must never be called after `pushCancel`.
        ///
        /// This is mainly useful when the construction of a node
        /// could fail between `pushStart` and `pushFinish`.
        /// This will invalidate the `data` pointer.
        pub fn pushCancel(self: *Self, data: *T) void {
            self.pushCancelLocked(data);
            self.mutex.unlock();
        }

        /// Similar to `pushCancel`, but doesn't unlock `self.mutex`.
        pub fn pushCancelLocked(self: *Self, data: *T) void {
            const node = @fieldParentPtr(Node, "data", data);
            self.cacheNode(node);
        }

        /// Equivalent to:
        /// ```
        /// const ptr = try self.popBorrowed();
        /// const value = ptr.*;
        /// self.destroyBorrowed(ptr);
        /// ```
        /// This is useful for when the item to be popped is a
        /// simple value, whose address isn't relevant to its initialisation.
        pub fn popValue(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            const node = self.popNode() orelse return null;
            defer self.cacheNode(node);

            return node.data;
        }

        /// If the queue is empty, returns `null`. Otherwise, pop an item
        /// from the queue, without moving it from its stable address.
        /// After the item is done being used, it should be freed
        /// using `self.destroyBorrowed(borrowed)`.
        ///
        /// This allows a situation where an item which contains some form
        /// of synchronisation primitive can inform the thread holding the
        /// return value from `pushStart` of updates to the item.
        pub fn popBorrowed(self: *Self) ?*T {
            self.mutex.lock();
            defer self.mutex.unlock();

            const node = self.popNode() orelse return null;
            return &node.data;
        }
        pub fn destroyBorrowed(self: *Self, borrowed: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            const node = @fieldParentPtr(Node, "data", borrowed);
            self.cacheNode(node);
        }

        /// Assumes `self.mutex` is locked.
        inline fn pushNode(self: *Self, node: *Node) void {
            self.tail_queue.prepend(node);
        }

        /// Assumes `self.mutex` is locked.
        inline fn popNode(self: *Self) ?*Node {
            return self.tail_queue.pop();
        }

        /// Assumes `self.mutex` is locked.
        inline fn newNode(self: *Self, allocator: std.mem.Allocator) std.mem.Allocator.Error!*Node {
            try self.ensureUnusedCapacityLocked(allocator, 1);
            return self.newNodeAssumeCapacity();
        }

        /// Assumes `self.mutex` is locked.
        inline fn newNodeAssumeCapacity(self: *Self) *Node {
            const result = self.unused_nodes.pop();
            result.* = .{
                .prev = null,
                .next = null,
                .data = undefined,
            };
            return result;
        }

        /// Assumes `self.mutex` is locked.
        /// `node` must be the result of a call to `newNode` or `newNodeAssumeCapacity`.
        inline fn cacheNode(self: *Self, node: *Node) void {
            // this is correct because `newNode` ensures capacity for 1 more node
            // each time a new one is allocated, meaning there is always capacity
            // for the total number of nodes created.
            self.unused_nodes.appendAssumeCapacity(node);
            node.* = undefined;
        }
    };
}

test "SharedQueue smoke test" {
    var sq_mtx = std.Thread.Mutex{};
    var sq: SharedQueue(u8) = .{ .mutex = &sq_mtx };
    defer sq.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?u8, null), sq.popValue());
    _ = try sq.pushValue(std.testing.allocator, 1);
    try std.testing.expectEqual(@as(?u8, 1), sq.popValue());
    try std.testing.expectEqual(@as(?u8, null), sq.popValue());

    const ptr = try sq.pushStart(std.testing.allocator);
    ptr.* = 3;
    sq.pushFinish(ptr); // `ptr` is now also locked technically

    const ptr_borrowed = sq.popBorrowed() orelse // `ptr` is now no longer locked by the queue
        return error.TestExpectedNonNull;
    try std.testing.expectEqual(ptr, ptr_borrowed);
    ptr_borrowed.* += 1;

    // update sync primitive to tell `ptr` it can be accessed

    const value = ptr.*;

    // update sync primitive to tell `ptr_borrowed` it can be destroyed

    sq.destroyBorrowed(ptr_borrowed); // `ptr` is no longer valid

    try std.testing.expectEqual(@as(u8, value), 4);
}
