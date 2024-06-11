const std = @import("std");
const Transport = @import("../transport.zig");

pub const libusb = @import("libusb");

stream: std.net.Stream,

transport: Transport = .{
    .vtable = .{
        .reader_fn = readerFn,
        .writer_fn = writerFn,
        .readv_fn = readvFn,
        .writev_fn = writevFn,
        .writev_all_fn = writevAllFn,
    },
},

const Self = @This();

fn closeFn(context: *const Transport) void {
    return @as(*const Self, @fieldParentPtr("transport", context)).close();
}

pub fn close(self: Self) void {
    self.stream.close();
}

fn readerFn(context: *const Transport) std.io.AnyReader {
    return @as(*const Self, @fieldParentPtr("transport", context)).reader();
}

fn readFn(context: *const anyopaque, buffer: []u8) !usize {
    const self: *const Self = @alignCast(@ptrCast(context));
    return self.stream.read(buffer);
}

fn readvFn(context: *const Transport, iovecs: []std.posix.iovec) !usize {
    return try @as(*const Self, @fieldParentPtr("transport", context)).stream.readv(iovecs);
}

pub fn reader(self: *const Self) std.io.AnyReader {
    return .{
        .context = self,
        .readFn = readFn,
    };
}

fn writerFn(context: *const Transport) std.io.AnyWriter {
    return @as(*const Self, @fieldParentPtr("transport", context)).writer();
}

fn writeFn(context: *const anyopaque, bytes: []const u8) !usize {
    const self: *const Self = @alignCast(@ptrCast(context));
    return self.stream.write(bytes);
}

fn writevFn(context: *const Transport, iovecs: []const std.posix.iovec_const) !usize {
    return try @as(*const Self, @fieldParentPtr("transport", context)).stream.writev(iovecs);
}

fn writevAllFn(context: *const Transport, iovecs: []std.posix.iovec_const) !void {
    return try @as(*const Self, @fieldParentPtr("transport", context)).stream.writevAll(iovecs);
}

pub fn writer(self: *const Self) std.io.AnyWriter {
    return .{
        .context = self,
        .writeFn = writeFn,
    };
}

pub fn connect(address: std.net.Address) !Self {
    return .{ .stream = try std.net.tcpConnectToAddress(address) };
}
