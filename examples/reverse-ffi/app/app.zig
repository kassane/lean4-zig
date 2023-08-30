const std = @import("std");
const lean4 = @import("lean4");

pub fn main() !void {
    lean4.lean_initialize_runtime_module();
    // use same default as for Lean executables
    var builtin: u8 = 1;
    var res = lean4.initialize_RFFI(builtin, lean4.lean_io_mk_world());
    if (lean4.lean_io_result_is_ok(res)) {
        lean4.lean_dec_ref(res);
    } else {
        lean4.lean_io_result_show_error(res);
        lean4.lean_dec(res);
        // do not access Lean declarations if initialization failed
        @panic("lean: initialization failed!");
    }
    lean4.lean_io_mark_end_initialization();

    // actual program
    var s: lean4.LeanPtr = lean4.lean_mk_string("hello!");
    var l: u64 = lean4.my_length(s);
    std.debug.print("output: {}\n", .{l});
}
