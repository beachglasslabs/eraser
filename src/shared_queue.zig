const std = @import("std");

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
            if (capacity == 0) return self;

            try self.unused_nodes.ensureTotalCapacityPrecise(allocator, capacity);
            try self.node_store.setCapacity(allocator, capacity);

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

        /// Clears all items from the queue without reallocating.
        /// All pointers returned from `pushStart` and passed to `pushFinish`
        /// become un-bound from `self.mutex`, as though they had been
        /// returned from `popBorrowed`, and may be safely passed to `destroyBorrowed`.
        pub fn clearItems(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
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
            const ptr = try @call(.always_inline, Self.pushStart, .{ self, allocator });
            errdefer @call(.always_inline, Self.pushCancel, .{ self, value });
            ptr.* = value;
            @call(.always_inline, Self.pushFinish, .{ self, ptr });
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

            const node = try self.newNode(allocator);
            errdefer self.cacheNode(node);

            node.* = .{
                .prev = null,
                .next = null,
                .data = undefined,
            };

            return &node.data;
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
            const node = @fieldParentPtr(Node, "data", data);
            self.tail_queue.prepend(node);
            self.mutex.unlock();
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
            const node = @fieldParentPtr(Node, "data", data);
            self.cacheNode(node);
            self.mutex.unlock();
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

            const node = self.tail_queue.pop() orelse return null;
            return &node.data;
        }
        pub fn destroyBorrowed(self: *Self, borrowed: *T) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            const node = @fieldParentPtr(Node, "data", borrowed);
            self.cacheNode(node);
        }

        /// Assumes `self.mutex` is locked.
        inline fn newNode(self: *Self, allocator: std.mem.Allocator) std.mem.Allocator.Error!*Node {
            if (self.unused_nodes.popOrNull()) |node| return node;
            try self.unused_nodes.ensureTotalCapacity(allocator, self.node_store.len + 1);
            return try self.node_store.addOne(allocator);
        }

        /// Assumes `self.mutex` is locked.
        /// `node` must be the result of a call to `newNode`.
        inline fn cacheNode(self: *Self, node: *Node) void {
            // this is correct because `newNode` ensures capacity for 1 more node
            // each time a new one is allocated, meaning there is always capacity
            // for the total number of nodes created.
            self.unused_nodes.appendAssumeCapacity(node);
            node.* = undefined;
        }
    };
}

test SharedQueue {
    var sq_mtx = std.Thread.Mutex{};
    var sq: SharedQueue(u8) = .{ .mutex = &sq_mtx };
    defer sq.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(?u8, null), sq.popValue());
    try sq.pushValue(std.testing.allocator, 1);
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
