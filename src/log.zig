const std = @import("std");

pub const Level = enum {
    None,
    Error,
    Warning,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
    Debug4,
    Debug5,
};

var log_level = Level.None;
var log_io: std.Io = undefined;
var log_buffer: [8192]u8 = undefined;
var log_writer: std.Io.File.Writer = undefined;
var log_mutex: std.Io.Mutex = .init;

pub fn init(io: std.Io, level: Level) void {
    // Initialize logging system if needed
    log_level = level;
    log_writer = std.Io.File.stdout().writerStreaming(io, &log_buffer);
    log_io = io;
}

pub fn E(comptime format: []const u8, args: anytype) void {
    log(Level.Error, "error: ", format, args);
}

pub fn W(comptime format: []const u8, args: anytype) void {
    log(Level.Warning, "warn: ", format, args);
}

pub fn I(comptime format: []const u8, args: anytype) void {
    log(Level.Info, "", format, args);
}

pub fn V(comptime format: []const u8, args: anytype) void {
    log(Level.Verbose, "", format, args);
}

pub fn D1(comptime format: []const u8, args: anytype) void {
    log(Level.Debug1, "debug1: ", format, args);
}

pub fn D2(comptime format: []const u8, args: anytype) void {
    log(Level.Debug2, "debug2: ", format, args);
}

pub fn D3(comptime format: []const u8, args: anytype) void {
    log(Level.Debug3, "debug3: ", format, args);
}

pub fn D4(comptime format: []const u8, args: anytype) void {
    log(Level.Debug4, "debug4: ", format, args);
}

pub fn D5(comptime format: []const u8, args: anytype) void {
    log(Level.Debug5, "debug5: ", format, args);
}

// Debug logging with an artificially high level, so it can
// be seen without -v. Can later easily be changed by searching
// for "log.T"
pub fn T(comptime format: []const u8, args: anytype) void {
    log(Level.Error, "TEMP: ", format, args);
}

fn log(comptime level: Level, comptime prefix: []const u8,
    comptime format: []const u8, args: anytype) void
{
    if (@intFromEnum(log_level) < @intFromEnum(level)) {
        return;
    }
    log_mutex.lock(log_io) catch
        @panic("Failed to acquire log mutex\n");
    defer log_mutex.unlock(log_io);
    log_writer.interface.print(prefix ++ format ++ "\n", args) catch {
        std.log.err("Failed to write log message\n", .{});
        return;
    };
    log_writer.interface.flush() catch {
        std.log.err("Failed to flush log message\n", .{});
        return;
    };
}
