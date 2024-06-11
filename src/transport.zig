const std = @import("std");

const protocol = @import("./protocol.zig");
const Packet = protocol.Packet;

pub const libusb = @import("./transport/libusb.zig");
pub const tcp = @import("./transport/tcp.zig");

vtable: VTable,

remote_protocol_version: u32 = protocol.Version.min,
max_payload_size: u32 = protocol.Packet.max_payload_size_v1,
tls_client: ?std.crypto.tls.Client = null,

pub const VTable = struct {
    reader_fn: *const fn (*Self) std.io.AnyReader,
    writer_fn: *const fn (*Self) std.io.AnyWriter,
    readv_fn: ?*const fn (*Self, []std.posix.iovec) anyerror!usize = null,
    writev_fn: ?*const fn (*Self, []const std.posix.iovec_const) anyerror!usize = null,
    writev_all_fn: ?*const fn (*Self, []std.posix.iovec_const) anyerror!void = null,
};

const Self = @This();

pub fn reader(self: *Self) std.io.AnyReader {
    return self.vtable.reader_fn(self);
}

pub fn writer(self: *Self) std.io.AnyWriter {
    return self.vtable.writer_fn(self);
}

pub fn sendConnect(self: *Self, max_data_len: u32, system_identity: []const u8) !void {
    try self.writePacket(Packet.initConnect(max_data_len, system_identity));
}

pub fn sendAuthSignatureResponse(self: *Self, signature: []const u8) !void {
    try self.writePacket(Packet.initAuthSignatureResponse(signature));
}

pub fn sendAuthPublicKeyResponse(self: *Self, public_key: []const u8) !void {
    try self.writePacket(Packet.initAuthPublicKeyResponse(public_key));
}

pub fn sendOpen(self: *Self, socket_id: u32, delayed_ack_bytes: u32, destination: []const u8) !void {
    try self.writePacket(Packet.initOpen(socket_id, delayed_ack_bytes, destination));
}

pub fn sendOkay(self: *Self, local_socket_id: u32, remote_socket_id: u32) !void {
    try self.writePacket(Packet.initOkay(local_socket_id, remote_socket_id));
}

pub fn sendWrite(self: *Self, local_socket_id: u32, remote_socket_id: u32, data: []const u8) !void {
    try self.writePacket(Packet.initWrite(local_socket_id, remote_socket_id, data));
}

pub fn sendClose(self: *Self, local_socket_id: u32, remote_socket_id: u32) !void {
    try self.writePacket(Packet.initClose(local_socket_id, remote_socket_id));
}

pub fn sendTlsRequest(self: *Self) !void {
    try self.writePacket(Packet.initTlsRequest());
}

fn shouldSkipChecksum(self: *Self) bool {
    return protocol.Version.shouldSkipChecksum(self.remote_protocol_version);
}

fn writeAll(self: *Self, bytes: []const u8) !void {
    if (self.tls_client) |*client| {
        try client.writeAll(self.stream(), bytes);
    } else {
        try self.writer().writeAll(bytes);
    }
}

pub fn writePacket(self: *Self, packet: Packet) !void {
    const header, const payload = packet.seal(false);

    try self.writeAll(&header);
    try self.writeAll(payload);

    std.log.scoped(.packet).debug("written : {any}", .{packet});
}

fn readAtLeast(self: *Self, buf: []u8, len: usize) !usize {
    if (self.tls_client) |*client| {
        return try client.readAtLeast(self.stream(), buf, len);
    }

    return try self.reader().readAtLeast(buf, len);
}

fn readAll(self: *Self, buf: []u8) !usize {
    if (self.tls_client) |*client| {
        return try client.readAll(self.stream(), buf);
    }

    return try self.reader().readAll(buf);
}

pub fn readPacket(self: *Self, buf: []u8) !Packet {
    std.debug.assert(buf.len >= self.max_payload_size + @sizeOf(Packet.Header));

    var n = try self.readAtLeast(buf, @sizeOf(Packet.Header));
    const header = std.mem.bytesToValue(Packet.Header, buf[0..@sizeOf(Packet.Header)]);
    if (n < @sizeOf(Packet.Header) + header.len) {
        n += try self.readAll(buf[n .. @sizeOf(Packet.Header) + header.len]);
    }

    std.debug.assert(n == @sizeOf(Packet.Header) + header.len);

    const packet = header.toPacket(buf[@sizeOf(Packet.Header)..][0..@intCast(header.len)]);

    std.log.scoped(.packet).debug("received: {any}", .{packet});

    return packet;
}

const Stream = struct {
    transport: *Self,

    pub const WriteError = anyerror;
    pub const ReadError = anyerror;

    pub fn readv(self: Stream, iovecs: []std.posix.iovec) !usize {
        return try self.transport.vtable.readv_fn.?(self.transport, iovecs);
    }

    pub fn readAtLeast(self: Stream, buffer: []u8, len: usize) !usize {
        return try self.transport.reader().readAtLeast(buffer, len);
    }

    pub fn writev(self: Stream, iovecs: []const std.posix.iovec_const) !usize {
        return try self.transport.vtable.writev_fn.?(self.transport, iovecs);
    }

    pub fn writevAll(self: Stream, iovecs: []std.posix.iovec_const) !void {
        return try self.transport.vtable.writev_all_fn.?(self.transport, iovecs);
    }
};

fn stream(self: *Self) Stream {
    return .{ .transport = self };
}

pub fn configureTLS(self: *Self, ca_bundle: std.crypto.Certificate.Bundle, host: []const u8) !void {
    self.tls_client = try std.crypto.tls.Client.init(self.stream(), ca_bundle, host);
}
