const std = @import("std");
const Transport = @import("../transport.zig");

pub const libusb = @import("libusb");

interface: libusb.ClaimedInterface,
read_endpoint: u8,
read_timeout: c_uint,
write_endpoint: u8,
write_timeout: c_uint,

transport: Transport = .{
    .vtable = .{
        .reader_fn = readerFn,
        .writer_fn = writerFn,
    },
},

const Self = @This();

fn closeFn(context: *const Transport) void {
    return @as(*const Self, @fieldParentPtr("transport", context)).close();
}

pub fn close(self: Self) void {
    self.interface.release();
    self.interface.device_handle.reset() catch {};
    self.interface.device_handle.close();
}

fn readerFn(context: *const Transport) std.io.AnyReader {
    return @as(*const Self, @fieldParentPtr("transport", context)).reader();
}

fn readFn(context: *const anyopaque, buffer: []u8) libusb.Error!usize {
    const self: *const Self = @alignCast(@ptrCast(context));
    var read: c_int = 0;
    libusb.c.libusb_bulk_transfer(self.interface.device_handle, self.read_endpoint, buffer.ptr, @intCast(buffer.len), &read, self.read_timeout).result() catch |err| {
        if (err != error.OperationTimedOut) {
            return err;
        }
    };

    return @intCast(read);
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

fn writeFn(context: *const anyopaque, bytes: []const u8) libusb.Error!usize {
    const self: *const Self = @alignCast(@ptrCast(context));
    var written: c_int = 0;
    libusb.c.libusb_bulk_transfer(self.interface.device_handle, self.write_endpoint, @constCast(bytes.ptr), @intCast(bytes.len), &written, self.write_timeout).result() catch |err| {
        if (err != error.OperationTimedOut) {
            return err;
        }
    };

    return @intCast(written);
}

pub fn writer(self: *const Self) std.io.AnyWriter {
    return .{
        .context = self,
        .writeFn = writeFn,
    };
}

fn isAdbInterface(desc: libusb.InterfaceDescriptor) bool {
    return desc.bInterfaceClass == .vendor_specific and desc.bInterfaceSubClass == 0x42 and desc.bInterfaceProtocol == 0x1;
}

fn formatDeviceAddress(device: *libusb.Device) [32:0]u8 {
    var buf = [_:0]u8{0} ** 32;
    const ports, const port_count = device.getPortNumbers() catch return buf;
    var n = (std.fmt.bufPrint(&buf, "{d}-{d}", .{ device.getBusNumber(), ports[0] }) catch unreachable).len;
    for (ports[1..port_count]) |port| {
        n += (std.fmt.bufPrint(buf[n..], ".{d}", .{port}) catch unreachable).len;
    }

    return buf;
}

const AdbInterface = struct {
    interface_num: u8,
    write_endpoint: libusb.Endpoint,
    read_endpoint: libusb.Endpoint,
    max_packet_size: u16,
};

fn testAdbInterface(interface: libusb.InterfaceDescriptor) ?AdbInterface {
    if (!isAdbInterface(interface)) {
        return null;
    }

    var bulk_out: ?libusb.Endpoint = null;
    var bulk_in: ?libusb.Endpoint = null;
    var packet_size: ?u16 = null;
    for (interface.endpointsSlice()) |endpoint| {
        if (endpoint.bmAttributes.transfer_type != .bulk) {
            continue;
        }

        switch (endpoint.bEndpointAddress.direction) {
            .input => if (bulk_in == null) {
                bulk_in = endpoint.bEndpointAddress;
            },
            .output => if (bulk_out == null) {
                bulk_out = endpoint.bEndpointAddress;
            },
        }

        std.debug.assert(endpoint.wMaxPacketSize != 0);
        if (packet_size) |other_packet_size| {
            std.debug.assert(other_packet_size == endpoint.wMaxPacketSize);
        } else {
            packet_size = endpoint.wMaxPacketSize;
        }
    }

    if (bulk_in == null or bulk_out == null) {
        return null;
    }

    return .{
        .interface_num = interface.bInterfaceNumber,
        .write_endpoint = bulk_out.?,
        .read_endpoint = bulk_in.?,
        .max_packet_size = packet_size.?,
    };
}

fn findAdbInterface(device: *libusb.Device) ?AdbInterface {
    const desc = device.getDescriptor() catch return null;
    if (desc.bDeviceClass != .per_interface) {
        // std.log.debug("skipping device with incorrect class", .{});
        return null;
    }

    var config_desc = device.getActiveConfigDescriptor() catch |err| {
        std.log.warn("failed to get active config descriptor for device at {s}: {any}\n", .{ formatDeviceAddress(device), err });
        return null;
    };

    defer config_desc.deinit();

    for (config_desc.interfacesSlice()) |interface| {
        for (interface.toSlice()) |interface_desc| {
            if (testAdbInterface(interface_desc)) |adb_interface| {
                return adb_interface;
            }
        }
    }

    return null;
}

pub const Device = struct {
    libusb_device: *libusb.Device,
    interface: AdbInterface,

    pub const OpenOptions = struct {
        read_timeout: u32 = 0,
        write_timeout: u32 = 0,
    };

    pub fn open(self: Device, options: OpenOptions) !Self {
        const dh = try self.libusb_device.open();
        errdefer dh.close();
        errdefer dh.reset() catch {};

        const adb_interface = try dh.claimInterface(self.interface.interface_num);
        errdefer adb_interface.release();

        try dh.clearHalt(self.interface.read_endpoint);
        try dh.clearHalt(self.interface.write_endpoint);

        return .{
            .interface = adb_interface,
            .read_endpoint = self.interface.read_endpoint.toU8(),
            .read_timeout = options.read_timeout,
            .write_endpoint = self.interface.write_endpoint.toU8(),
            .write_timeout = options.write_timeout,
        };
    }

    pub fn deinit(self: Device) void {
        return self.libusb_device.unref();
    }
};

pub const DeviceIterator = struct {
    libusb_devices: []*libusb.Device,
    position: usize = 0,

    pub fn deinit(self: DeviceIterator) void {
        libusb.freeDeviceList(self.libusb_devices, true);
    }

    pub fn next(self: *DeviceIterator) ?Device {
        while (self.position < self.libusb_devices.len) : (self.position += 1) {
            const device = self.libusb_devices[self.position];
            if (findAdbInterface(device)) |interface| {
                return .{
                    .libusb_device = device.ref(),
                    .interface = interface,
                };
            }
        }

        return null;
    }
};

pub fn iterateDevices() !DeviceIterator {
    return .{ .libusb_devices = try libusb.getDeviceList() };
}
