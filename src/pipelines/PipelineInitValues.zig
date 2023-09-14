const ServerInfo = @import("ServerInfo.zig");

chunk_buffer: usize = 150_000,
queue_capacity: usize,
server_info: ServerInfo,
