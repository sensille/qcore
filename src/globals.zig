const std = @import("std");

pub var interrupted = std.atomic.Value(bool).init(false);
