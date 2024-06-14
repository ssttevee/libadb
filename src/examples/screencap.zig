const std = @import("std");
const adb = @import("adb");

const libusb = adb.Transport.libusb.libusb;

fn logCallback(ctx: ?*libusb.Context, log_level: libusb.LogLevel, msg: [*c]const u8) callconv(.C) void {
    switch (log_level) {
        .err => std.log.scoped(.libusb).err("{?p} {s}", .{ ctx, msg }),
        .warn => std.log.scoped(.libusb).warn("{?p} {s}", .{ ctx, msg }),
        .info => std.log.scoped(.libusb).info("{?p} {s}", .{ ctx, msg }),
        .debug => std.log.scoped(.libusb).debug("{?p} {s}", .{ ctx, msg }),
    }
}

const Connection = union(enum) {
    libusb: adb.Transport.libusb,
    tcp: adb.Transport.tcp,

    pub fn transport(self: *Connection) *adb.Transport {
        return switch (self.*) {
            .libusb => |*c| &c.transport,
            .tcp => |*c| &c.transport,
        };
    }

    pub fn close(self: Connection) void {
        switch (self) {
            .libusb => |c| c.close(),
            .tcp => |c| c.close(),
        }
    }
};

fn connect(addr: ?std.net.Address) !?Connection {
    if (addr) |a| {
        return .{ .tcp = try adb.Transport.tcp.connect(a) };
    }

    var device_it = try adb.Transport.libusb.iterateDevices();
    defer device_it.deinit();

    if (device_it.next()) |device| {
        defer device.deinit();

        return .{ .libusb = try device.open(.{}) };
    }

    std.log.info("no adb interfaces found", .{});
    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const addr: ?std.net.Address = blk: {
        if (std.os.argv.len > 1) {
            var parts = std.mem.split(u8, std.os.argv[1][0..std.mem.len(std.os.argv[1])], ":");
            break :blk try std.net.Address.parseIp(
                parts.next().?,
                if (parts.next()) |s| try std.fmt.parseInt(u16, s, 10) else 5555,
            );
        }

        break :blk null;
    };

    const key = try adb.auth.loadUserKey(allocator) orelse return;
    defer key.deinit();

    if (addr == null) {
        try libusb.init(.{
            .log_level = .info,
            .log_cb = logCallback,
        });
    }

    defer if (addr == null) libusb.deinit();

    var conn = try connect(addr) orelse return;
    defer conn.close();

    const transport = conn.transport();

    var ca_bundle = std.crypto.Certificate.Bundle{};
    defer ca_bundle.deinit(allocator);

    // try ca_bundle.rescan(allocator);

    var buf: [adb.host.Packet.read_buf_size]u8 = undefined;
    const welcome_packet = try adb.host.handshake(&buf, transport, &.{key}, ca_bundle);

    const banner = adb.SystemBanner.parse(welcome_packet.data);

    std.debug.assert(std.mem.eql(u8, banner.type, "device"));

    std.log.info("device properties:", .{});
    std.log.info("  ro.product.name={s}", .{banner.product_name});
    std.log.info("  ro.product.model={s}", .{banner.product_model});
    std.log.info("  ro.product.device={s}", .{banner.product_device});

    std.log.info("interface features:", .{});
    var features = banner.iterateFeatures();
    while (features.next()) |feature| {
        std.log.info("  {s}", .{feature});
    }

    // try simulating adb exec-out screencap -p

    try adb.services.execOut(transport, "screencap -p", std.io.getStdOut());
}
