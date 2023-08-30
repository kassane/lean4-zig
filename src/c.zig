//  (lean_object) align error
// const c = @cImport(@cInclude("lean.h"));
// manual fix
const c = @import("lean.zig");

pub usingnamespace c;

pub extern fn my_length(c.lean_obj_arg) u64;
pub extern fn lean_initialize_runtime_module() void;
pub extern fn lean_initialize() void;
pub extern fn initialize_RFFI(builtin: u8, c.LeanPtr) c.LeanPtr;
