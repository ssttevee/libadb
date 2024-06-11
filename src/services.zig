const std = @import("std");
const Packet = @import("./protocol.zig").Packet;
const Transport = @import("./transport.zig");
const host = @import("./host.zig");
const builtin = @import("builtin");

fn readAll(read_buf: []u8, transport: *Transport, lsid: u32, rsid: u32, writer: anytype) !void {
    const start = std.time.milliTimestamp();
    defer std.log.info("reading all bytes took {d}ms", .{std.time.milliTimestamp() - start});

    while (true) {
        const packet = try transport.readPacket(read_buf);
        if (packet.command == .clse) {
            break;
        }

        std.debug.assert(packet.command == .wrte);

        try writer.writeAll(packet.data);

        try transport.sendOkay(lsid, rsid);
    }
}

pub fn execOut(transport: *Transport, command: []const u8, writer: anytype) !void {
    var read_buf: [Packet.read_buf_size]u8 = undefined;

    const local_socket_id = 1; // this is arbitrary
    const socket_ack_packet = try host.openSocket(&read_buf, transport, try std.fmt.bufPrint(&read_buf, "exec:{s}", .{command}), local_socket_id);
    const remote_socket_id = socket_ack_packet.args[0];

    try readAll(&read_buf, transport, local_socket_id, remote_socket_id, writer);
}

pub fn execOutAlloc(transport: *Transport, command: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();

    try execOut(transport, command, data.writer());

    return data.toOwnedSlice();
}

const FramebufferIterator = struct {
    transport: *Transport,
    local_socket_id: u32,
    remote_socket_id: u32,
    size: usize,

    const Info = extern struct {
        version: u32,
        bpp: u32,
        colorSpace: u32,
        size: u32,
        width: u32,
        height: u32,
        red_offset: u32,
        red_length: u32,
        blue_offset: u32,
        blue_length: u32,
        green_offset: u32,
        green_length: u32,
        alpha_offset: u32,
        alpha_length: u32,
    };

    pub fn open(transport: *Transport) !FramebufferIterator {
        var read_buf: [@sizeOf(Packet.Header) + @sizeOf(Info)]u8 = undefined;

        const local_socket_id = 1; // this is arbitrary
        const socket_ack_packet = try host.openSocket(&read_buf, transport, "framebuffer:", local_socket_id);
        const remote_socket_id = socket_ack_packet.args[0];

        const info_packet = try transport.readPacket(&read_buf);

        var fbinfo = std.mem.bytesToValue(Info, info_packet.data);
        if (builtin.target.cpu.arch.endian() == .big) {
            std.mem.byteSwapAllFields(Info, &fbinfo);
        }

        return .{
            .local_socket_id = local_socket_id,
            .remote_socket_id = remote_socket_id,
            .size = fbinfo.size,
        };
    }

    pub fn next(self: FramebufferIterator, allocator: std.mem.Allocator) ![]u8 {
        var read_buf: [Packet.read_buf_size]u8 = undefined;
        var arr = try std.ArrayList(u8).initCapacity(allocator, self.size);

        readAll(&read_buf, self.transport, self.local_socket_id, self.remote_socket_id, arr.writer());
    }
};
