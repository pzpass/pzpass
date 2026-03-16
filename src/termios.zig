const std = @import("std");

pub fn set_terminal(original_termios: *std.os.linux.termios) !void {
    if (std.os.linux.tcgetattr(std.fs.File.stdout().handle, original_termios) != 0) {
        std.debug.print("Cannot save original terminal settings.\n", .{});
        return error.TerminalNotSet;
    }
    var raw = original_termios.*;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    if (std.os.linux.tcsetattr(std.fs.File.stdout().handle, .NOW, &raw) != 0) {
        std.debug.print("Cannot set terminal no echo settings.\n", .{});
        return error.TerminalNotSet;
    }
}

pub fn reset_terminal(original_termios: *std.os.linux.termios) void {
    if (std.os.linux.tcsetattr(std.fs.File.stdout().handle, .NOW, original_termios) != 0) {
        std.debug.print("Cannot reset terminal to original settings.\n", .{});
    }
}
