pub const __builtin_bswap16 = std.zig.c_builtins.__builtin_bswap16;
pub const __builtin_bswap32 = std.zig.c_builtins.__builtin_bswap32;
pub const __builtin_bswap64 = std.zig.c_builtins.__builtin_bswap64;
pub const __builtin_signbit = std.zig.c_builtins.__builtin_signbit;
pub const __builtin_signbitf = std.zig.c_builtins.__builtin_signbitf;
pub const __builtin_popcount = std.zig.c_builtins.__builtin_popcount;
pub const __builtin_ctz = std.zig.c_builtins.__builtin_ctz;
pub const __builtin_clz = std.zig.c_builtins.__builtin_clz;
pub const __builtin_sqrt = std.zig.c_builtins.__builtin_sqrt;
pub const __builtin_sqrtf = std.zig.c_builtins.__builtin_sqrtf;
pub const __builtin_sin = std.zig.c_builtins.__builtin_sin;
pub const __builtin_sinf = std.zig.c_builtins.__builtin_sinf;
pub const __builtin_cos = std.zig.c_builtins.__builtin_cos;
pub const __builtin_cosf = std.zig.c_builtins.__builtin_cosf;
pub const __builtin_exp = std.zig.c_builtins.__builtin_exp;
pub const __builtin_expf = std.zig.c_builtins.__builtin_expf;
pub const __builtin_exp2 = std.zig.c_builtins.__builtin_exp2;
pub const __builtin_exp2f = std.zig.c_builtins.__builtin_exp2f;
pub const __builtin_log = std.zig.c_builtins.__builtin_log;
pub const __builtin_logf = std.zig.c_builtins.__builtin_logf;
pub const __builtin_log2 = std.zig.c_builtins.__builtin_log2;
pub const __builtin_log2f = std.zig.c_builtins.__builtin_log2f;
pub const __builtin_log10 = std.zig.c_builtins.__builtin_log10;
pub const __builtin_log10f = std.zig.c_builtins.__builtin_log10f;
pub const __builtin_abs = std.zig.c_builtins.__builtin_abs;
pub const __builtin_fabs = std.zig.c_builtins.__builtin_fabs;
pub const __builtin_fabsf = std.zig.c_builtins.__builtin_fabsf;
pub const __builtin_floor = std.zig.c_builtins.__builtin_floor;
pub const __builtin_floorf = std.zig.c_builtins.__builtin_floorf;
pub const __builtin_ceil = std.zig.c_builtins.__builtin_ceil;
pub const __builtin_ceilf = std.zig.c_builtins.__builtin_ceilf;
pub const __builtin_trunc = std.zig.c_builtins.__builtin_trunc;
pub const __builtin_truncf = std.zig.c_builtins.__builtin_truncf;
pub const __builtin_round = std.zig.c_builtins.__builtin_round;
pub const __builtin_roundf = std.zig.c_builtins.__builtin_roundf;
pub const __builtin_strlen = std.zig.c_builtins.__builtin_strlen;
pub const __builtin_strcmp = std.zig.c_builtins.__builtin_strcmp;
pub const __builtin_object_size = std.zig.c_builtins.__builtin_object_size;
pub const __builtin___memset_chk = std.zig.c_builtins.__builtin___memset_chk;
pub const __builtin_memset = std.zig.c_builtins.__builtin_memset;
pub const __builtin___memcpy_chk = std.zig.c_builtins.__builtin___memcpy_chk;
pub const __builtin_memcpy = std.zig.c_builtins.__builtin_memcpy;
pub const __builtin_expect = std.zig.c_builtins.__builtin_expect;
pub const __builtin_nanf = std.zig.c_builtins.__builtin_nanf;
pub const __builtin_huge_valf = std.zig.c_builtins.__builtin_huge_valf;
pub const __builtin_inff = std.zig.c_builtins.__builtin_inff;
pub const __builtin_isnan = std.zig.c_builtins.__builtin_isnan;
pub const __builtin_isinf = std.zig.c_builtins.__builtin_isinf;
pub const __builtin_isinf_sign = std.zig.c_builtins.__builtin_isinf_sign;
pub const __has_builtin = std.zig.c_builtins.__has_builtin;
pub const __builtin_assume = std.zig.c_builtins.__builtin_assume;
pub const __builtin_unreachable = std.zig.c_builtins.__builtin_unreachable;
pub const __builtin_constant_p = std.zig.c_builtins.__builtin_constant_p;
pub const __builtin_mul_overflow = std.zig.c_builtins.__builtin_mul_overflow;

pub extern fn lean_notify_assert(fileName: [*:0]const u8, line: c_int, condition: [*:0]const u8) void;
pub fn lean_is_big_object_tag(arg_tag: u8) callconv(.C) bool {
    var tag = arg_tag;
    return (((@as(c_int, @bitCast(@as(c_uint, tag))) == @as(c_int, 246)) or (@as(c_int, @bitCast(@as(c_uint, tag))) == @as(c_int, 247))) or (@as(c_int, @bitCast(@as(c_uint, tag))) == @as(c_int, 248))) or (@as(c_int, @bitCast(@as(c_uint, tag))) == @as(c_int, 249));
}
// vendor/lean.h:114:14: warning: struct demoted to opaque type - has bitfield
// pub const lean_object = opaque{};

// manual fix
pub const lean_object = extern struct {
    m_rc: c_int,
    m_cs_sz: u16,
    m_other: u8,
    m_tag: u8,
};
pub const lean_obj_arg = ?*lean_object;
pub const b_lean_obj_arg = ?*lean_object;
pub const u_lean_obj_arg = ?*lean_object;
pub const lean_obj_res = ?*lean_object;
pub const b_lean_obj_res = ?*lean_object;
pub const lean_ctor_object = extern struct {
    m_header: lean_object align(8),
    pub fn m_objs(self: anytype) std.zig.c_translation.FlexibleArrayType(@TypeOf(self), ?*lean_object) {
        const Intermediate = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), ?*lean_object);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 8)));
    }
};
pub const lean_array_object = extern struct {
    m_header: lean_object align(8),
    m_size: usize,
    m_capacity: usize,
    pub fn m_data(self: anytype) std.zig.c_translation.FlexibleArrayType(@TypeOf(self), ?*lean_object) {
        const Intermediate = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), ?*lean_object);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 24)));
    }
};
pub const lean_sarray_object = extern struct {
    m_header: lean_object align(8),
    m_size: usize,
    m_capacity: usize,
    pub fn m_data(self: anytype) std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 24)));
    }
};
pub const lean_string_object = extern struct {
    m_header: lean_object align(8),
    m_size: usize,
    m_capacity: usize,
    m_length: usize,
    pub fn m_data(self: anytype) std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 32)));
    }
};
pub const lean_closure_object = extern struct {
    m_header: lean_object align(8),
    m_fun: ?*anyopaque,
    m_arity: u16,
    m_num_fixed: u16,
    pub fn m_objs(self: anytype) std.zig.c_translation.FlexibleArrayType(@TypeOf(self), ?*lean_object) {
        const Intermediate = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = std.zig.c_translation.FlexibleArrayType(@TypeOf(self), ?*lean_object);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 24)));
    }
};
pub const lean_ref_object = extern struct {
    m_header: lean_object,
    m_value: ?*lean_object,
};
pub const lean_thunk_object = extern struct {
    m_header: lean_object,
    m_value: ?*lean_object,
    m_closure: ?*lean_object,
};
pub const struct_lean_task = extern struct {
    m_header: lean_object,
    m_value: ?*lean_object,
    m_imp: [*c]lean_task_imp,
};
pub const lean_task_imp = extern struct {
    m_closure: ?*lean_object,
    m_head_dep: ?*struct_lean_task,
    m_next_dep: ?*struct_lean_task,
    m_prio: c_uint,
    m_canceled: u8,
    m_keep_alive: u8,
    m_deleted: u8,
};
pub const lean_task_object = struct_lean_task;
pub const lean_external_finalize_proc = ?*const fn (?*anyopaque) callconv(.C) void;
pub const lean_external_foreach_proc = ?*const fn (?*anyopaque, b_lean_obj_arg) callconv(.C) void;
pub const lean_external_class = extern struct {
    m_finalize: lean_external_finalize_proc,
    m_foreach: lean_external_foreach_proc,
};
pub extern fn lean_register_external_class(lean_external_finalize_proc, lean_external_foreach_proc) [*c]lean_external_class;
pub const lean_external_object = extern struct {
    m_header: lean_object,
    m_class: [*c]lean_external_class,
    m_data: ?*anyopaque,
};
pub fn lean_is_scalar(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return (@as(usize, @intCast(@intFromPtr(o))) & @as(usize, @intCast(1))) == @as(usize, @intCast(1));
}
pub fn lean_box(arg_n: usize) callconv(.C) ?*lean_object {
    var n = arg_n;

    // manual fix
    var value = (n << @as(usize, 1)) | @as(usize, 1);
    return @as(?*lean_object, @ptrCast(&value));
}
pub fn lean_unbox(arg_o: ?*lean_object) callconv(.C) usize {
    var o = arg_o;
    return @as(usize, @intCast(@intFromPtr(o))) >> @intCast(1);
}
pub extern fn lean_set_exit_on_panic(flag: bool) void;
pub extern fn lean_set_panic_messages(flag: bool) void;
pub extern fn lean_panic_fn(default_val: ?*lean_object, msg: ?*lean_object) ?*lean_object;
pub extern fn lean_internal_panic(msg: [*c]const u8) noreturn;
pub extern fn lean_internal_panic_out_of_memory(...) noreturn;
pub extern fn lean_internal_panic_unreachable(...) noreturn;
pub extern fn lean_internal_panic_rc_overflow(...) noreturn;
pub fn lean_align(arg_v: usize, arg_a: usize) callconv(.C) usize {
    var v = arg_v;
    var a = arg_a;
    return ((v / a) *% a) +% (a *% @as(usize, @intFromBool((v % a) != @as(usize, @bitCast(@as(c_long, @as(c_int, 0)))))));
}
pub fn lean_get_slot_idx(arg_sz: c_uint) callconv(.C) c_uint {
    var sz = arg_sz;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(sz > @as(c_uint, @bitCast(@as(c_int, 0)))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 308), "sz > 0");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(lean_align(@as(usize, @bitCast(@as(c_ulong, sz))), @as(usize, @bitCast(@as(c_long, @as(c_int, 8))))) == @as(usize, @bitCast(@as(c_ulong, sz)))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 309), "lean_align(sz, LEAN_OBJECT_SIZE_DELTA) == sz");
        }
    }
    return (sz / @as(c_uint, @bitCast(@as(c_int, 8)))) -% @as(c_uint, @bitCast(@as(c_int, 1)));
}
pub extern fn lean_alloc_small(sz: c_uint, slot_idx: c_uint) ?*anyopaque;
pub extern fn lean_free_small(p: ?*anyopaque) void;
pub extern fn lean_small_mem_size(p: ?*anyopaque) c_uint;
pub extern fn lean_inc_heartbeat(...) void;
pub extern fn malloc(c_ulong) ?*anyopaque;
pub fn lean_alloc_small_object(arg_sz: c_uint) callconv(.C) ?*lean_object {
    var sz = arg_sz;
    sz = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_align(@as(usize, @bitCast(@as(c_ulong, sz))), @as(usize, @bitCast(@as(c_long, @as(c_int, 8)))))))));
    var slot_idx: c_uint = lean_get_slot_idx(sz);
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(sz <= @as(c_uint, @bitCast(@as(c_int, 4096)))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 326), "sz <= LEAN_MAX_SMALL_OBJECT_SIZE");
        }
    }
    return @as(?*lean_object, @ptrCast(@alignCast(lean_alloc_small(sz, slot_idx))));
}
pub fn lean_alloc_ctor_memory(arg_sz: c_uint) callconv(.C) ?*lean_object {
    var sz = arg_sz;
    var sz1: c_uint = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_align(@as(usize, @bitCast(@as(c_ulong, sz))), @as(usize, @bitCast(@as(c_long, @as(c_int, 8)))))))));
    var slot_idx: c_uint = lean_get_slot_idx(sz1);
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(sz1 <= @as(c_uint, @bitCast(@as(c_int, 4096)))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 341), "sz1 <= LEAN_MAX_SMALL_OBJECT_SIZE");
        }
    }
    // translate-c: ?*anyopaque is align(1)
    //var r: ?*lean_object = @as(?*lean_object, @ptrCast(lean_alloc_small(sz1, slot_idx)));
    var r: ?*lean_object = @as(?*lean_object, @ptrCast(@alignCast(lean_alloc_small(sz1, slot_idx))));
    if (sz1 > sz) {
        var end: [*c]usize = @as([*c]usize, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(r))) + sz1)));
        (blk: {
            const tmp = -@as(c_int, 1);
            if (tmp >= 0) break :blk end + @as(usize, @intCast(tmp)) else break :blk end - ~@as(usize, @bitCast(@as(isize, @intCast(tmp)) +% -1));
        }).* = 0;
    }
    return r;
}
pub fn lean_small_object_size(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    return lean_small_mem_size(@as(?*anyopaque, @ptrCast(o)));
}
pub extern fn free(?*anyopaque) void;
pub fn lean_free_small_object(arg_o: ?*lean_object) callconv(.C) void {
    var o = arg_o;
    lean_free_small(@as(?*anyopaque, @ptrCast(o)));
}
pub extern fn lean_alloc_object(sz: usize) ?*lean_object;
pub extern fn lean_free_object(o: ?*lean_object) void;
pub fn lean_ptr_tag(arg_o: ?*lean_object) callconv(.C) u8 {
    var o = arg_o;
    return @as(u8, @bitCast(@as(u8, @truncate(o.?.*.m_tag))));
}
pub fn lean_ptr_other(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    return o.?.*.m_other;
}
pub extern fn lean_object_byte_size(o: ?*lean_object) usize;
pub fn lean_is_mt(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return o.?.*.m_rc < @as(c_int, 0);
}
pub fn lean_is_st(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return o.?.*.m_rc > @as(c_int, 0);
}
pub fn lean_is_persistent(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return o.?.*.m_rc == @as(c_int, 0);
}
pub fn lean_has_rc(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return o.?.*.m_rc != @as(c_int, 0);
}
pub fn lean_get_rc_mt_addr(arg_o: ?*lean_object) callconv(.C) [*c]c_int {
    var o = arg_o;
    return &o.?.*.m_rc;
}
pub extern fn lean_inc_ref_cold(o: ?*lean_object) void;
pub extern fn lean_inc_ref_n_cold(o: ?*lean_object, n: c_uint) void;
pub fn lean_inc_ref(arg_o: ?*lean_object) callconv(.C) void {
    var o = arg_o;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_st(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        o.?.*.m_rc += 1;
    } else if (o.?.*.m_rc != @as(c_int, 0)) {
        lean_inc_ref_cold(o);
    }
}
pub fn lean_inc_ref_n(arg_o: ?*lean_object, arg_n: usize) callconv(.C) void {
    var o = arg_o;
    var n = arg_n;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_st(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        o.?.*.m_rc += @as(c_int, @bitCast(@as(c_uint, @truncate(n))));
    } else if (o.?.*.m_rc != @as(c_int, 0)) {
        lean_inc_ref_n_cold(o, @as(c_uint, @bitCast(@as(c_uint, @truncate(n)))));
    }
}
pub extern fn lean_dec_ref_cold(o: ?*lean_object) void;
pub fn lean_dec_ref(arg_o: ?*lean_object) callconv(.C) void {
    var o = arg_o;
    if (__builtin_expect(@as(c_long, @intFromBool(o.?.*.m_rc > @as(c_int, 1))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        o.?.*.m_rc -= 1;
    } else if (o.?.*.m_rc != @as(c_int, 0)) {
        lean_dec_ref_cold(o);
    }
}
pub fn lean_inc(arg_o: ?*lean_object) callconv(.C) void {
    var o = arg_o;
    if (!lean_is_scalar(o)) {
        lean_inc_ref(o);
    }
}
pub fn lean_inc_n(arg_o: ?*lean_object, arg_n: usize) callconv(.C) void {
    var o = arg_o;
    var n = arg_n;
    if (!lean_is_scalar(o)) {
        lean_inc_ref_n(o, n);
    }
}
pub fn lean_dec(arg_o: ?*lean_object) callconv(.C) void {
    var o = arg_o;
    if (!lean_is_scalar(o)) {
        lean_dec_ref(o);
    }
}
pub extern fn lean_dealloc(o: ?*lean_object) void;
pub fn lean_is_ctor(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) <= @as(c_int, 244);
}
pub fn lean_is_closure(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 245);
}
pub fn lean_is_array(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 246);
}
pub fn lean_is_sarray(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 248);
}
pub fn lean_is_string(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 249);
}
pub fn lean_is_mpz(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 250);
}
pub fn lean_is_thunk(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 251);
}
pub fn lean_is_task(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 252);
}
pub fn lean_is_external(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 254);
}
pub fn lean_is_ref(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(o)))) == @as(c_int, 253);
}
pub fn lean_obj_tag(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    if (lean_is_scalar(o)) return @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(o))))) else return @as(c_uint, @bitCast(@as(c_uint, lean_ptr_tag(o))));
    return 0;
}
pub fn lean_to_ctor(arg_o: ?*lean_object) callconv(.C) ?*lean_ctor_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_ctor(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 471), "lean_is_ctor(o)");
        }
    }
    return @as(?*lean_ctor_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_closure(arg_o: ?*lean_object) callconv(.C) ?*lean_closure_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_closure(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 472), "lean_is_closure(o)");
        }
    }
    return @as(?*lean_closure_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_array(arg_o: ?*lean_object) callconv(.C) ?*lean_array_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_array(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 473), "lean_is_array(o)");
        }
    }
    return @as(?*lean_array_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_sarray(arg_o: ?*lean_object) callconv(.C) ?*lean_sarray_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_sarray(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 474), "lean_is_sarray(o)");
        }
    }
    return @as(?*lean_sarray_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_string(arg_o: ?*lean_object) callconv(.C) ?*lean_string_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_string(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 475), "lean_is_string(o)");
        }
    }
    return @as(?*lean_string_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_thunk(arg_o: ?*lean_object) callconv(.C) ?*lean_thunk_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_thunk(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 476), "lean_is_thunk(o)");
        }
    }
    return @as(?*lean_thunk_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_task(arg_o: ?*lean_object) callconv(.C) ?*lean_task_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_task(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 477), "lean_is_task(o)");
        }
    }
    return @as(?*lean_task_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_ref(arg_o: ?*lean_object) callconv(.C) ?*lean_ref_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_ref(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 478), "lean_is_ref(o)");
        }
    }
    return @as(?*lean_ref_object, @ptrCast(@alignCast(o)));
}
pub fn lean_to_external(arg_o: ?*lean_object) callconv(.C) ?*lean_external_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_external(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 479), "lean_is_external(o)");
        }
    }
    return @as(?*lean_external_object, @ptrCast(@alignCast(o)));
}
pub fn lean_is_exclusive(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_st(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return o.?.*.m_rc == @as(c_int, 1);
    } else {
        return @as(c_int, 0) != 0;
    }
    return false;
}
pub fn lean_is_shared(arg_o: ?*lean_object) callconv(.C) bool {
    var o = arg_o;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_st(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return o.?.*.m_rc > @as(c_int, 1);
    } else {
        return @as(c_int, 0) != 0;
    }
    return false;
}
pub extern fn lean_mark_mt(o: ?*lean_object) void;
pub extern fn lean_mark_persistent(o: ?*lean_object) void;
pub fn lean_set_st_header(arg_o: ?*lean_object, arg_tag: c_uint, arg_other: c_uint) callconv(.C) void {
    var o = arg_o;
    var tag = arg_tag;
    var other = arg_other;
    o.?.*.m_rc = 1;
    o.?.*.m_tag = @intCast(tag);
    o.?.*.m_other = @intCast(other);
    o.?.*.m_cs_sz = 0;
}
pub fn lean_set_non_heap_header(arg_o: ?*lean_object, arg_sz: usize, arg_tag: c_uint, arg_other: c_uint) callconv(.C) void {
    var o = arg_o;
    var sz = arg_sz;
    var tag = arg_tag;
    var other = arg_other;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(sz > @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 510), "sz > 0");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulonglong, @bitCast(@as(c_ulonglong, sz))) < (@as(c_ulonglong, 1) << @intCast(16))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 511), "sz < (1ull << 16)");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!((sz == @as(usize, @bitCast(@as(c_long, @as(c_int, 1))))) or !lean_is_big_object_tag(@as(u8, @bitCast(@as(u8, @truncate(tag)))))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 512), "sz == 1 || !lean_is_big_object_tag(tag)");
        }
    }
    o.?.*.m_rc = 0;
    o.?.*.m_tag = @intCast(tag);
    o.?.*.m_other = @intCast(other);
    o.?.*.m_cs_sz = @intCast(sz);
}
pub fn lean_set_non_heap_header_for_big(arg_o: ?*lean_object, arg_tag: c_uint, arg_other: c_uint) callconv(.C) void {
    var o = arg_o;
    var tag = arg_tag;
    var other = arg_other;
    lean_set_non_heap_header(o, @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))), tag, other);
}
pub fn lean_ctor_num_objs(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_ctor(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 527), "lean_is_ctor(o)");
        }
    }
    return lean_ptr_other(o);
}
pub fn lean_ctor_obj_cptr(arg_o: ?*lean_object) callconv(.C) [*c]?*lean_object {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_ctor(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 532), "lean_is_ctor(o)");
        }
    }
    return lean_to_ctor(o).?.*.m_objs();
}
pub fn lean_ctor_scalar_cptr(arg_o: ?*lean_object) callconv(.C) [*c]u8 {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_ctor(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 537), "lean_is_ctor(o)");
        }
    }
    return @as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o) + lean_ctor_num_objs(o))));
}
pub fn lean_alloc_ctor(arg_tag: c_uint, arg_num_objs: c_uint, arg_scalar_sz: c_uint) callconv(.C) ?*lean_object {
    var tag = arg_tag;
    var num_objs = arg_num_objs;
    var scalar_sz = arg_scalar_sz;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(((tag <= @as(c_uint, @bitCast(@as(c_int, 244)))) and (num_objs < @as(c_uint, @bitCast(@as(c_int, 256))))) and (scalar_sz < @as(c_uint, @bitCast(@as(c_int, 1024))))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 542), "tag <= LeanMaxCtorTag && num_objs < LEAN_MAX_CTOR_FIELDS && scalar_sz < LEAN_MAX_CTOR_SCALARS_SIZE");
        }
    }
    var o: ?*lean_object = lean_alloc_ctor_memory(@as(c_uint, @bitCast(@as(c_uint, @truncate((@sizeOf(lean_ctor_object) +% (@sizeOf(?*anyopaque) *% @as(c_ulong, @bitCast(@as(c_ulong, num_objs))))) +% @as(c_ulong, @bitCast(@as(c_ulong, scalar_sz))))))));
    lean_set_st_header(o, tag, num_objs);
    return o;
}
pub fn lean_ctor_get(arg_o: b_lean_obj_arg, arg_i: c_uint) callconv(.C) b_lean_obj_res {
    var o = arg_o;
    var i = arg_i;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_ctor_num_objs(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 549), "i < lean_ctor_num_objs(o)");
        }
    }
    return lean_ctor_obj_cptr(o)[i];
}
pub fn lean_ctor_set(arg_o: b_lean_obj_arg, arg_i: c_uint, arg_v: lean_obj_arg) callconv(.C) void {
    var o = arg_o;
    var i = arg_i;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_ctor_num_objs(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 554), "i < lean_ctor_num_objs(o)");
        }
    }
    lean_ctor_obj_cptr(o)[i] = v;
}
pub fn lean_ctor_set_tag(arg_o: b_lean_obj_arg, arg_new_tag: u8) callconv(.C) void {
    var o = arg_o;
    var new_tag = arg_new_tag;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_int, @bitCast(@as(c_uint, new_tag))) <= @as(c_int, 244)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 559), "new_tag <= LeanMaxCtorTag");
        }
    }
    o.?.*.m_tag = @intCast(new_tag);
}
pub fn lean_ctor_release(arg_o: b_lean_obj_arg, arg_i: c_uint) callconv(.C) void {
    var o = arg_o;
    var i = arg_i;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_ctor_num_objs(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 564), "i < lean_ctor_num_objs(o)");
        }
    }
    var objs: [*c]?*lean_object = lean_ctor_obj_cptr(o);
    lean_dec(objs[i]);
    objs[i] = lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))));
}
pub fn lean_ctor_get_usize(arg_o: b_lean_obj_arg, arg_i: c_uint) callconv(.C) usize {
    var o = arg_o;
    var i = arg_i;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i >= lean_ctor_num_objs(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 571), "i >= lean_ctor_num_objs(o)");
        }
    }
    return @as([*c]usize, @ptrCast(@alignCast(lean_ctor_obj_cptr(o) + i))).*;
}
pub fn lean_ctor_get_uint8(arg_o: b_lean_obj_arg, arg_offset: c_uint) callconv(.C) u8 {
    var o = arg_o;
    var offset = arg_offset;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 576), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    return (@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset).*;
}
pub fn lean_ctor_get_uint16(arg_o: b_lean_obj_arg, arg_offset: c_uint) callconv(.C) u16 {
    var o = arg_o;
    var offset = arg_offset;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 581), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    return @as([*c]u16, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_get_uint32(arg_o: b_lean_obj_arg, arg_offset: c_uint) callconv(.C) u32 {
    var o = arg_o;
    var offset = arg_offset;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 586), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    return @as([*c]u32, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_get_uint64(arg_o: b_lean_obj_arg, arg_offset: c_uint) callconv(.C) u64 {
    var o = arg_o;
    var offset = arg_offset;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 591), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    return @as([*c]u64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_get_float(arg_o: b_lean_obj_arg, arg_offset: c_uint) callconv(.C) f64 {
    var o = arg_o;
    var offset = arg_offset;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 596), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    return @as([*c]f64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).*;
}
pub fn lean_ctor_set_usize(arg_o: b_lean_obj_arg, arg_i: c_uint, arg_v: usize) callconv(.C) void {
    var o = arg_o;
    var i = arg_i;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i >= lean_ctor_num_objs(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 601), "i >= lean_ctor_num_objs(o)");
        }
    }
    @as([*c]usize, @ptrCast(@alignCast(lean_ctor_obj_cptr(o) + i))).* = v;
}
pub fn lean_ctor_set_uint8(arg_o: b_lean_obj_arg, arg_offset: c_uint, arg_v: u8) callconv(.C) void {
    var o = arg_o;
    var offset = arg_offset;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 606), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    (@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset).* = v;
}
pub fn lean_ctor_set_uint16(arg_o: b_lean_obj_arg, arg_offset: c_uint, arg_v: u16) callconv(.C) void {
    var o = arg_o;
    var offset = arg_offset;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 611), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    @as([*c]u16, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_ctor_set_uint32(arg_o: b_lean_obj_arg, arg_offset: c_uint, arg_v: u32) callconv(.C) void {
    var o = arg_o;
    var offset = arg_offset;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 616), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    @as([*c]u32, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_ctor_set_uint64(arg_o: b_lean_obj_arg, arg_offset: c_uint, arg_v: u64) callconv(.C) void {
    var o = arg_o;
    var offset = arg_offset;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 621), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    @as([*c]u64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_ctor_set_float(arg_o: b_lean_obj_arg, arg_offset: c_uint, arg_v: f64) callconv(.C) void {
    var o = arg_o;
    var offset = arg_offset;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(@as(c_ulong, @bitCast(@as(c_ulong, offset))) >= (@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(o)))) *% @sizeOf(?*anyopaque))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 626), "offset >= lean_ctor_num_objs(o) * sizeof(void*)");
        }
    }
    @as([*c]f64, @ptrCast(@alignCast(@as([*c]u8, @ptrCast(@alignCast(lean_ctor_obj_cptr(o)))) + offset))).* = v;
}
pub fn lean_closure_fun(arg_o: ?*lean_object) callconv(.C) ?*anyopaque {
    var o = arg_o;
    return lean_to_closure(o).?.*.m_fun;
}
pub fn lean_closure_arity(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    return @as(c_uint, @bitCast(@as(c_uint, lean_to_closure(o).?.*.m_arity)));
}
pub fn lean_closure_num_fixed(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    return @as(c_uint, @bitCast(@as(c_uint, lean_to_closure(o).?.*.m_num_fixed)));
}
pub fn lean_closure_arg_cptr(arg_o: ?*lean_object) callconv(.C) [*c]?*lean_object {
    var o = arg_o;
    return lean_to_closure(o).?.*.m_objs();
}
pub fn lean_alloc_closure(arg_fun: ?*anyopaque, arg_arity: c_uint, arg_num_fixed: c_uint) callconv(.C) lean_obj_res {
    var fun = arg_fun;
    var arity = arg_arity;
    var num_fixed = arg_num_fixed;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(arity > @as(c_uint, @bitCast(@as(c_int, 0)))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 637), "arity > 0");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(num_fixed < arity))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 638), "num_fixed < arity");
        }
    }
    var o: ?*lean_closure_object = @as(?*lean_closure_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_closure_object) +% (@sizeOf(?*anyopaque) *% @as(c_ulong, @bitCast(@as(c_ulong, num_fixed))))))))))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 245))), @as(c_uint, @bitCast(@as(c_int, 0))));
    o.?.*.m_fun = fun;
    o.?.*.m_arity = @as(u16, @bitCast(@as(c_ushort, @truncate(arity))));
    o.?.*.m_num_fixed = @as(u16, @bitCast(@as(c_ushort, @truncate(num_fixed))));
    return @as(?*lean_object, @ptrCast(o));
}
pub fn lean_closure_get(arg_o: b_lean_obj_arg, arg_i: c_uint) callconv(.C) b_lean_obj_res {
    var o = arg_o;
    var i = arg_i;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_closure_num_fixed(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 647), "i < lean_closure_num_fixed(o)");
        }
    }
    return lean_to_closure(o).?.*.m_objs()[i];
}
pub fn lean_closure_set(arg_o: u_lean_obj_arg, arg_i: c_uint, arg_a: lean_obj_arg) callconv(.C) void {
    var o = arg_o;
    var i = arg_i;
    var a = arg_a;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_closure_num_fixed(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 651), "i < lean_closure_num_fixed(o)");
        }
    }
    lean_to_closure(o).?.*.m_objs()[i] = a;
}
pub extern fn lean_apply_1(f: ?*lean_object, a1: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_2(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_3(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_4(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_5(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_6(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_7(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_8(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_9(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_10(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_11(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object, a11: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_12(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object, a11: ?*lean_object, a12: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_13(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object, a11: ?*lean_object, a12: ?*lean_object, a13: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_14(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object, a11: ?*lean_object, a12: ?*lean_object, a13: ?*lean_object, a14: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_15(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object, a11: ?*lean_object, a12: ?*lean_object, a13: ?*lean_object, a14: ?*lean_object, a15: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_16(f: ?*lean_object, a1: ?*lean_object, a2: ?*lean_object, a3: ?*lean_object, a4: ?*lean_object, a5: ?*lean_object, a6: ?*lean_object, a7: ?*lean_object, a8: ?*lean_object, a9: ?*lean_object, a10: ?*lean_object, a11: ?*lean_object, a12: ?*lean_object, a13: ?*lean_object, a14: ?*lean_object, a15: ?*lean_object, a16: ?*lean_object) ?*lean_object;
pub extern fn lean_apply_n(f: ?*lean_object, n: c_uint, args: [*c]?*lean_object) ?*lean_object;
pub extern fn lean_apply_m(f: ?*lean_object, n: c_uint, args: [*c]?*lean_object) ?*lean_object;
pub fn lean_alloc_array(arg_size: usize, arg_capacity: usize) callconv(.C) lean_obj_res {
    var size = arg_size;
    var capacity = arg_capacity;
    var o: ?*lean_array_object = @as(?*lean_array_object, @ptrCast(@alignCast(lean_alloc_object(@sizeOf(lean_array_object) +% (@sizeOf(?*anyopaque) *% capacity)))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 246))), @as(c_uint, @bitCast(@as(c_int, 0))));
    o.?.*.m_size = size;
    o.?.*.m_capacity = capacity;
    return @as(?*lean_object, @ptrCast(o));
}
pub fn lean_array_size(arg_o: b_lean_obj_arg) callconv(.C) usize {
    var o = arg_o;
    return lean_to_array(o).?.*.m_size;
}
pub fn lean_array_capacity(arg_o: b_lean_obj_arg) callconv(.C) usize {
    var o = arg_o;
    return lean_to_array(o).?.*.m_capacity;
}
pub fn lean_array_byte_size(arg_o: ?*lean_object) callconv(.C) usize {
    var o = arg_o;
    return @sizeOf(lean_array_object) +% (@sizeOf(?*anyopaque) *% lean_array_capacity(o));
}
pub fn lean_array_cptr(arg_o: ?*lean_object) callconv(.C) [*c]?*lean_object {
    var o = arg_o;
    return lean_to_array(o).?.*.m_data();
}
pub fn lean_array_set_size(arg_o: u_lean_obj_arg, arg_sz: usize) callconv(.C) void {
    var o = arg_o;
    var sz = arg_sz;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_array(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 690), "lean_is_array(o)");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_exclusive(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 691), "lean_is_exclusive(o)");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(sz <= lean_array_capacity(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 692), "sz <= lean_array_capacity(o)");
        }
    }
    lean_to_array(o).?.*.m_size = sz;
}
pub fn lean_array_get_core(arg_o: b_lean_obj_arg, arg_i: usize) callconv(.C) b_lean_obj_res {
    var o = arg_o;
    var i = arg_i;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_array_size(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 696), "i < lean_array_size(o)");
        }
    }
    return lean_to_array(o).?.*.m_data()[i];
}
pub fn lean_array_set_core(arg_o: u_lean_obj_arg, arg_i: usize, arg_v: lean_obj_arg) callconv(.C) void {
    var o = arg_o;
    var i = arg_i;
    var v = arg_v;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(!lean_has_rc(o) or (@as(c_int, @intFromBool(lean_is_exclusive(o))) != 0)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 702), "!lean_has_rc(o) || lean_is_exclusive(o)");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_array_size(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 703), "i < lean_array_size(o)");
        }
    }
    lean_to_array(o).?.*.m_data()[i] = v;
}
pub extern fn lean_array_mk(l: lean_obj_arg) ?*lean_object;
pub extern fn lean_array_data(a: lean_obj_arg) ?*lean_object;
pub fn lean_array_sz(arg_a: lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var r: ?*lean_object = lean_box(lean_array_size(a));
    lean_dec(a);
    return r;
}
pub fn lean_array_get_size(arg_a: b_lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    return lean_box(lean_array_size(a));
}
pub fn lean_mk_empty_array() callconv(.C) ?*lean_object {
    return lean_alloc_array(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))), @as(usize, @bitCast(@as(c_long, @as(c_int, 0)))));
}
pub fn lean_mk_empty_array_with_capacity(arg_capacity: b_lean_obj_arg) callconv(.C) ?*lean_object {
    var capacity = arg_capacity;
    if (!lean_is_scalar(capacity)) {
        lean_internal_panic_out_of_memory();
    }
    return lean_alloc_array(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))), lean_unbox(capacity));
}
pub fn lean_array_uget(arg_a: b_lean_obj_arg, arg_i: usize) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var r: ?*lean_object = lean_array_get_core(a, i);
    lean_inc(r);
    return r;
}
pub fn lean_array_fget(arg_a: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    var i = arg_i;
    return lean_array_uget(a, lean_unbox(i));
}
pub extern fn lean_array_get_panic(def_val: lean_obj_arg) lean_obj_res;
pub fn lean_array_get(arg_def_val: lean_obj_arg, arg_a: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) ?*lean_object {
    var def_val = arg_def_val;
    var a = arg_a;
    var i = arg_i;
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        if (idx < lean_array_size(a)) {
            lean_dec(def_val);
            return lean_array_uget(a, idx);
        }
    }
    return lean_array_get_panic(def_val);
}
pub extern fn lean_copy_expand_array(a: lean_obj_arg, expand: bool) lean_obj_res;
pub fn lean_copy_array(arg_a: lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    return lean_copy_expand_array(a, @as(c_int, 0) != 0);
}
pub fn lean_ensure_exclusive_array(arg_a: lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    if (lean_is_exclusive(a)) return a;
    return lean_copy_array(a);
}
pub fn lean_array_uset(arg_a: lean_obj_arg, arg_i: usize, arg_v: lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var v = arg_v;
    var r: ?*lean_object = lean_ensure_exclusive_array(a);
    var it: [*c]?*lean_object = lean_array_cptr(r) + i;
    lean_dec(it.*);
    it.* = v;
    return r;
}
pub fn lean_array_fset(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_v: lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var v = arg_v;
    return lean_array_uset(a, lean_unbox(i), v);
}
pub extern fn lean_array_set_panic(a: lean_obj_arg, v: lean_obj_arg) lean_obj_res;
pub fn lean_array_set(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_v: lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var v = arg_v;
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        if (idx < lean_array_size(a)) return lean_array_uset(a, idx, v);
    }
    return lean_array_set_panic(a, v);
}
pub fn lean_array_pop(arg_a: lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var r: ?*lean_object = lean_ensure_exclusive_array(a);
    var sz: usize = lean_to_array(r).?.*.m_size;
    var last: [*c]?*lean_object = undefined;
    if (sz == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) return r;
    sz -%= 1;
    last = lean_array_cptr(r) + sz;
    lean_to_array(r).?.*.m_size = sz;
    lean_dec(last.*);
    return r;
}
pub fn lean_array_uswap(arg_a: lean_obj_arg, arg_i: usize, arg_j: usize) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var j = arg_j;
    var r: ?*lean_object = lean_ensure_exclusive_array(a);
    var it: [*c]?*lean_object = lean_array_cptr(r);
    var v1: ?*lean_object = it[i];
    it[i] = it[j];
    it[j] = v1;
    return r;
}
pub fn lean_array_fswap(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_j: b_lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var j = arg_j;
    return lean_array_uswap(a, lean_unbox(i), lean_unbox(j));
}
pub fn lean_array_swap(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_j: b_lean_obj_arg) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var j = arg_j;
    if (!lean_is_scalar(i) or !lean_is_scalar(j)) return a;
    var ui: usize = lean_unbox(i);
    var uj: usize = lean_unbox(j);
    var sz: usize = lean_to_array(a).?.*.m_size;
    if ((ui >= sz) or (uj >= sz)) return a;
    return lean_array_uswap(a, ui, uj);
}
pub extern fn lean_array_push(a: lean_obj_arg, v: lean_obj_arg) ?*lean_object;
pub extern fn lean_mk_array(n: lean_obj_arg, v: lean_obj_arg) ?*lean_object;
pub fn lean_alloc_sarray(arg_elem_size: c_uint, arg_size: usize, arg_capacity: usize) callconv(.C) lean_obj_res {
    var elem_size = arg_elem_size;
    var size = arg_size;
    var capacity = arg_capacity;
    var o: ?*lean_sarray_object = @as(?*lean_sarray_object, @ptrCast(@alignCast(lean_alloc_object(@sizeOf(lean_sarray_object) +% (@as(usize, @bitCast(@as(c_ulong, elem_size))) *% capacity)))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 248))), elem_size);
    o.?.*.m_size = size;
    o.?.*.m_capacity = capacity;
    return @as(?*lean_object, @ptrCast(o));
}
pub fn lean_sarray_elem_size(arg_o: ?*lean_object) callconv(.C) c_uint {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_sarray(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 837), "lean_is_sarray(o)");
        }
    }
    return lean_ptr_other(o);
}
pub fn lean_sarray_capacity(arg_o: ?*lean_object) callconv(.C) usize {
    var o = arg_o;
    return lean_to_sarray(o).?.*.m_capacity;
}
pub fn lean_sarray_byte_size(arg_o: ?*lean_object) callconv(.C) usize {
    var o = arg_o;
    return @sizeOf(lean_sarray_object) +% (@as(usize, @bitCast(@as(c_ulong, lean_sarray_elem_size(o)))) *% lean_sarray_capacity(o));
}
pub fn lean_sarray_size(arg_o: b_lean_obj_arg) callconv(.C) usize {
    var o = arg_o;
    return lean_to_sarray(o).?.*.m_size;
}
pub fn lean_sarray_set_size(arg_o: u_lean_obj_arg, arg_sz: usize) callconv(.C) void {
    var o = arg_o;
    var sz = arg_sz;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_exclusive(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 846), "lean_is_exclusive(o)");
        }
    }
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(sz <= lean_sarray_capacity(o)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 847), "sz <= lean_sarray_capacity(o)");
        }
    }
    lean_to_sarray(o).?.*.m_size = sz;
}
pub fn lean_sarray_cptr(arg_o: ?*lean_object) callconv(.C) [*c]u8 {
    var o = arg_o;
    return lean_to_sarray(o).?.*.m_data();
}
pub extern fn lean_byte_array_mk(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_byte_array_data(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_copy_byte_array(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_byte_array_hash(a: b_lean_obj_arg) u64;
pub fn lean_mk_empty_byte_array(arg_capacity: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var capacity = arg_capacity;
    if (!lean_is_scalar(capacity)) {
        lean_internal_panic_out_of_memory();
    }
    return lean_alloc_sarray(@as(c_uint, @bitCast(@as(c_int, 1))), @as(usize, @bitCast(@as(c_long, @as(c_int, 0)))), lean_unbox(capacity));
}
pub fn lean_byte_array_size(arg_a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    return lean_box(lean_sarray_size(a));
}
pub fn lean_byte_array_uget(arg_a: b_lean_obj_arg, arg_i: usize) callconv(.C) u8 {
    var a = arg_a;
    var i = arg_i;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!(i < lean_sarray_size(a)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 870), "i < lean_sarray_size(a)");
        }
    }
    return lean_sarray_cptr(a)[i];
}
pub fn lean_byte_array_get(arg_a: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) u8 {
    var a = arg_a;
    var i = arg_i;
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        return @as(u8, @bitCast(@as(i8, @truncate(if (idx < lean_sarray_size(a)) @as(c_int, @bitCast(@as(c_uint, lean_byte_array_uget(a, idx)))) else @as(c_int, 0)))));
    } else {
        return 0;
    }
    return std.mem.zeroes(u8);
}
pub fn lean_byte_array_fget(arg_a: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) u8 {
    var a = arg_a;
    var i = arg_i;
    return lean_byte_array_uget(a, lean_unbox(i));
}
pub extern fn lean_byte_array_push(a: lean_obj_arg, b: u8) lean_obj_res;
pub fn lean_byte_array_uset(arg_a: lean_obj_arg, arg_i: usize, arg_v: u8) callconv(.C) ?*lean_object {
    var a = arg_a;
    var i = arg_i;
    var v = arg_v;
    var r: lean_obj_res = undefined;
    if (lean_is_exclusive(a)) {
        r = a;
    } else {
        r = lean_copy_byte_array(a);
    }
    var it: [*c]u8 = lean_sarray_cptr(r) + i;
    it.* = v;
    return r;
}
pub fn lean_byte_array_set(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_b: u8) callconv(.C) lean_obj_res {
    var a = arg_a;
    var i = arg_i;
    var b = arg_b;
    if (!lean_is_scalar(i)) {
        return a;
    } else {
        var idx: usize = lean_unbox(i);
        if (idx >= lean_sarray_size(a)) {
            return a;
        } else {
            return lean_byte_array_uset(a, idx, b);
        }
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_byte_array_fset(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_b: u8) callconv(.C) lean_obj_res {
    var a = arg_a;
    var i = arg_i;
    var b = arg_b;
    return lean_byte_array_uset(a, lean_unbox(i), b);
}
pub extern fn lean_float_array_mk(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_float_array_data(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_copy_float_array(a: lean_obj_arg) lean_obj_res;
pub fn lean_mk_empty_float_array(arg_capacity: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var capacity = arg_capacity;
    if (!lean_is_scalar(capacity)) {
        lean_internal_panic_out_of_memory();
    }
    return lean_alloc_sarray(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(f64))))), @as(usize, @bitCast(@as(c_long, @as(c_int, 0)))), lean_unbox(capacity));
}
pub fn lean_float_array_size(arg_a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    return lean_box(lean_sarray_size(a));
}
pub fn lean_float_array_cptr(arg_a: b_lean_obj_arg) callconv(.C) [*c]f64 {
    var a = arg_a;
    return @as([*c]f64, @ptrCast(@alignCast(lean_sarray_cptr(a))));
}
pub fn lean_float_array_uget(arg_a: b_lean_obj_arg, arg_i: usize) callconv(.C) f64 {
    var a = arg_a;
    var i = arg_i;
    return lean_float_array_cptr(a)[i];
}
pub fn lean_float_array_fget(arg_a: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) f64 {
    var a = arg_a;
    var i = arg_i;
    return lean_float_array_uget(a, lean_unbox(i));
}
pub fn lean_float_array_get(arg_a: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) f64 {
    var a = arg_a;
    var i = arg_i;
    if (lean_is_scalar(i)) {
        var idx: usize = lean_unbox(i);
        return if (idx < lean_sarray_size(a)) lean_float_array_uget(a, idx) else 0.0;
    } else {
        return 0.0;
    }
    return 0;
}
pub extern fn lean_float_array_push(a: lean_obj_arg, d: f64) lean_obj_res;
pub fn lean_float_array_uset(arg_a: lean_obj_arg, arg_i: usize, arg_d: f64) callconv(.C) lean_obj_res {
    var a = arg_a;
    var i = arg_i;
    var d = arg_d;
    var r: lean_obj_res = undefined;
    if (lean_is_exclusive(a)) {
        r = a;
    } else {
        r = lean_copy_float_array(a);
    }
    var it: [*c]f64 = lean_float_array_cptr(r) + i;
    it.* = d;
    return r;
}
pub fn lean_float_array_fset(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_d: f64) callconv(.C) lean_obj_res {
    var a = arg_a;
    var i = arg_i;
    var d = arg_d;
    return lean_float_array_uset(a, lean_unbox(i), d);
}
pub fn lean_float_array_set(arg_a: lean_obj_arg, arg_i: b_lean_obj_arg, arg_d: f64) callconv(.C) lean_obj_res {
    var a = arg_a;
    var i = arg_i;
    var d = arg_d;
    if (!lean_is_scalar(i)) {
        return a;
    } else {
        var idx: usize = lean_unbox(i);
        if (idx >= lean_sarray_size(a)) {
            return a;
        } else {
            return lean_float_array_uset(a, idx, d);
        }
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_alloc_string(arg_size: usize, arg_capacity: usize, arg_len: usize) callconv(.C) lean_obj_res {
    var size = arg_size;
    var capacity = arg_capacity;
    var len = arg_len;
    var o: ?*lean_string_object = @as(?*lean_string_object, @ptrCast(@alignCast(lean_alloc_object(@sizeOf(lean_string_object) +% capacity))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 249))), @as(c_uint, @bitCast(@as(c_int, 0))));
    o.?.*.m_size = size;
    o.?.*.m_capacity = capacity;
    o.?.*.m_length = len;
    return @as(?*lean_object, @ptrCast(o));
}
pub extern fn lean_utf8_strlen(str: [*c]const u8) usize;
pub extern fn lean_utf8_n_strlen(str: [*c]const u8, n: usize) usize;
pub fn lean_string_capacity(arg_o: ?*lean_object) callconv(.C) usize {
    var o = arg_o;
    return lean_to_string(o).?.*.m_capacity;
}
pub fn lean_string_byte_size(arg_o: ?*lean_object) callconv(.C) usize {
    var o = arg_o;
    return @sizeOf(lean_string_object) +% lean_string_capacity(o);
}
pub fn lean_char_default_value() callconv(.C) u32 {
    return 'A';
}
pub extern fn lean_mk_string_from_bytes(s: [*c]const u8, sz: usize) lean_obj_res;
pub extern fn lean_mk_string(s: [*c]const u8) lean_obj_res;
pub fn lean_string_cstr(arg_o: b_lean_obj_arg) callconv(.C) [*c]const u8 {
    var o = arg_o;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_string(o))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 998), "lean_is_string(o)");
        }
    }
    return lean_to_string(o).?.*.m_data();
}
pub fn lean_string_size(arg_o: b_lean_obj_arg) callconv(.C) usize {
    var o = arg_o;
    return lean_to_string(o).?.*.m_size;
}
pub fn lean_string_len(arg_o: b_lean_obj_arg) callconv(.C) usize {
    var o = arg_o;
    return lean_to_string(o).?.*.m_length;
}
pub extern fn lean_string_push(s: lean_obj_arg, c: u32) lean_obj_res;
pub extern fn lean_string_append(s1: lean_obj_arg, s2: b_lean_obj_arg) lean_obj_res;
pub fn lean_string_length(arg_s: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var s = arg_s;
    return lean_box(lean_string_len(s));
}
pub extern fn lean_string_mk(cs: lean_obj_arg) lean_obj_res;
pub extern fn lean_string_data(s: lean_obj_arg) lean_obj_res;
pub extern fn lean_string_utf8_get(s: b_lean_obj_arg, i: b_lean_obj_arg) u32;
pub extern fn lean_string_utf8_get_fast_cold(str: [*c]const u8, i: usize, size: usize, c: u8) u32;
pub fn lean_string_utf8_get_fast(arg_s: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) u32 {
    var s = arg_s;
    var i = arg_i;
    var str: [*c]const u8 = lean_string_cstr(s);
    var idx: usize = lean_unbox(i);
    var c: u8 = @as(u8, @bitCast(str[idx]));
    if ((@as(c_int, @bitCast(@as(c_uint, c))) & @as(c_int, 128)) == @as(c_int, 0)) return @as(u32, @bitCast(@as(c_uint, c)));
    return lean_string_utf8_get_fast_cold(str, idx, lean_string_size(s), c);
}
pub extern fn lean_string_utf8_next(s: b_lean_obj_arg, i: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_string_utf8_next_fast_cold(i: usize, c: u8) lean_obj_res;
pub fn lean_string_utf8_next_fast(arg_s: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var s = arg_s;
    var i = arg_i;
    var str: [*c]const u8 = lean_string_cstr(s);
    var idx: usize = lean_unbox(i);
    var c: u8 = @as(u8, @bitCast(str[idx]));
    if ((@as(c_int, @bitCast(@as(c_uint, c))) & @as(c_int, 128)) == @as(c_int, 0)) return lean_box(idx +% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))));
    return lean_string_utf8_next_fast_cold(idx, c);
}
pub extern fn lean_string_utf8_prev(s: b_lean_obj_arg, i: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_string_utf8_set(s: lean_obj_arg, i: b_lean_obj_arg, c: u32) lean_obj_res;
pub fn lean_string_utf8_at_end(arg_s: b_lean_obj_arg, arg_i: b_lean_obj_arg) callconv(.C) u8 {
    var s = arg_s;
    var i = arg_i;
    return @as(u8, @intFromBool(!lean_is_scalar(i) or (lean_unbox(i) >= (lean_string_size(s) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1))))))));
}
pub extern fn lean_string_utf8_extract(s: b_lean_obj_arg, b: b_lean_obj_arg, e: b_lean_obj_arg) lean_obj_res;
pub fn lean_string_utf8_byte_size(arg_s: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var s = arg_s;
    return lean_box(lean_string_size(s) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))));
}
pub extern fn lean_string_eq_cold(s1: b_lean_obj_arg, s2: b_lean_obj_arg) bool;
pub fn lean_string_eq(arg_s1: b_lean_obj_arg, arg_s2: b_lean_obj_arg) callconv(.C) bool {
    var s1 = arg_s1;
    var s2 = arg_s2;
    return (s1 == s2) or ((lean_string_size(s1) == lean_string_size(s2)) and (@as(c_int, @intFromBool(lean_string_eq_cold(s1, s2))) != 0));
}
pub fn lean_string_ne(arg_s1: b_lean_obj_arg, arg_s2: b_lean_obj_arg) callconv(.C) bool {
    var s1 = arg_s1;
    var s2 = arg_s2;
    return !lean_string_eq(s1, s2);
}
pub extern fn lean_string_lt(s1: b_lean_obj_arg, s2: b_lean_obj_arg) bool;
pub fn lean_string_dec_eq(arg_s1: b_lean_obj_arg, arg_s2: b_lean_obj_arg) callconv(.C) u8 {
    var s1 = arg_s1;
    var s2 = arg_s2;
    return @as(u8, @intFromBool(lean_string_eq(s1, s2)));
}
pub fn lean_string_dec_lt(arg_s1: b_lean_obj_arg, arg_s2: b_lean_obj_arg) callconv(.C) u8 {
    var s1 = arg_s1;
    var s2 = arg_s2;
    return @as(u8, @intFromBool(lean_string_lt(s1, s2)));
}
pub extern fn lean_string_hash(b_lean_obj_arg) u64;
pub fn lean_mk_thunk(arg_c: lean_obj_arg) callconv(.C) lean_obj_res {
    var c = arg_c;
    var o: ?*lean_thunk_object = @as(?*lean_thunk_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_thunk_object)))))))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 251))), @as(c_uint, @bitCast(@as(c_int, 0))));
    o.?.*.m_value = @as(?*lean_object, @ptrFromInt(@as(c_int, 0)));
    o.?.*.m_closure = c;
    return @as(?*lean_object, @ptrCast(o));
}
pub fn lean_thunk_pure(arg_v: lean_obj_arg) callconv(.C) lean_obj_res {
    var v = arg_v;
    var o: ?*lean_thunk_object = @as(?*lean_thunk_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_thunk_object)))))))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 251))), @as(c_uint, @bitCast(@as(c_int, 0))));
    o.?.*.m_value = v;
    o.?.*.m_closure = @as(?*lean_object, @ptrFromInt(@as(c_int, 0)));
    return @as(?*lean_object, @ptrCast(o));
}
pub extern fn lean_thunk_get_core(t: ?*lean_object) ?*lean_object;
pub fn lean_thunk_get(arg_t: b_lean_obj_arg) callconv(.C) b_lean_obj_res {
    var t = arg_t;
    var r: ?*lean_object = lean_to_thunk(t).?.*.m_value;
    if (r != null) return r;
    return lean_thunk_get_core(t);
}
pub fn lean_thunk_get_own(arg_t: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var t = arg_t;
    var r: ?*lean_object = lean_thunk_get(t);
    lean_inc(r);
    return r;
}
pub extern fn lean_init_task_manager(...) void;
pub extern fn lean_init_task_manager_using(num_workers: c_uint) void;
pub extern fn lean_finalize_task_manager(...) void;
pub extern fn lean_task_spawn_core(c: lean_obj_arg, prio: c_uint, keep_alive: bool) lean_obj_res;
pub fn lean_task_spawn(arg_c: lean_obj_arg, arg_prio: lean_obj_arg) callconv(.C) lean_obj_res {
    var c = arg_c;
    var prio = arg_prio;
    return lean_task_spawn_core(c, @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(prio))))), @as(c_int, 0) != 0);
}
pub extern fn lean_task_pure(a: lean_obj_arg) lean_obj_res;
pub extern fn lean_task_bind_core(x: lean_obj_arg, f: lean_obj_arg, prio: c_uint, keep_alive: bool) lean_obj_res;
pub fn lean_task_bind(arg_x: lean_obj_arg, arg_f: lean_obj_arg, arg_prio: lean_obj_arg) callconv(.C) lean_obj_res {
    var x = arg_x;
    var f = arg_f;
    var prio = arg_prio;
    return lean_task_bind_core(x, f, @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(prio))))), @as(c_int, 0) != 0);
}
pub extern fn lean_task_map_core(f: lean_obj_arg, t: lean_obj_arg, prio: c_uint, keep_alive: bool) lean_obj_res;
pub fn lean_task_map(arg_f: lean_obj_arg, arg_t: lean_obj_arg, arg_prio: lean_obj_arg) callconv(.C) lean_obj_res {
    var f = arg_f;
    var t = arg_t;
    var prio = arg_prio;
    return lean_task_map_core(f, t, @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(prio))))), @as(c_int, 0) != 0);
}
pub extern fn lean_task_get(t: b_lean_obj_arg) b_lean_obj_res;
pub fn lean_task_get_own(arg_t: lean_obj_arg) callconv(.C) lean_obj_res {
    var t = arg_t;
    var r: ?*lean_object = lean_task_get(t);
    lean_inc(r);
    lean_dec(t);
    return r;
}
pub extern fn lean_io_check_canceled_core(...) bool;
pub extern fn lean_io_cancel_core(t: b_lean_obj_arg) void;
pub extern fn lean_io_has_finished_core(t: b_lean_obj_arg) bool;
pub extern fn lean_io_wait_any_core(task_list: b_lean_obj_arg) b_lean_obj_res;
pub fn lean_alloc_external(arg_cls: [*c]lean_external_class, arg_data: ?*anyopaque) callconv(.C) ?*lean_object {
    var cls = arg_cls;
    var data = arg_data;
    var o: ?*lean_external_object = @as(?*lean_external_object, @ptrCast(@alignCast(lean_alloc_small_object(@as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(lean_external_object)))))))));
    lean_set_st_header(@as(?*lean_object, @ptrCast(o)), @as(c_uint, @bitCast(@as(c_int, 254))), @as(c_uint, @bitCast(@as(c_int, 0))));
    o.?.*.m_class = cls;
    o.?.*.m_data = data;
    return @as(?*lean_object, @ptrCast(o));
}
pub fn lean_get_external_class(arg_o: ?*lean_object) callconv(.C) [*c]lean_external_class {
    var o = arg_o;
    return lean_to_external(o).?.*.m_class;
}
pub fn lean_get_external_data(arg_o: ?*lean_object) callconv(.C) ?*anyopaque {
    var o = arg_o;
    return lean_to_external(o).?.*.m_data;
}
pub extern fn lean_nat_big_succ(a: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_add(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_sub(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_mul(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_overflow_mul(a1: usize, a2: usize) ?*lean_object;
pub extern fn lean_nat_big_div(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_mod(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_eq(a1: ?*lean_object, a2: ?*lean_object) bool;
pub extern fn lean_nat_big_le(a1: ?*lean_object, a2: ?*lean_object) bool;
pub extern fn lean_nat_big_lt(a1: ?*lean_object, a2: ?*lean_object) bool;
pub extern fn lean_nat_big_land(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_lor(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_nat_big_xor(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_cstr_to_nat(n: [*c]const u8) lean_obj_res;
pub extern fn lean_big_usize_to_nat(n: usize) lean_obj_res;
pub extern fn lean_big_uint64_to_nat(n: u64) lean_obj_res;
pub fn lean_usize_to_nat(arg_n: usize) callconv(.C) lean_obj_res {
    var n = arg_n;
    if (__builtin_expect(@as(c_long, @intFromBool(n <= (@as(c_ulong, 18446744073709551615) >> @intCast(1)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) return lean_box(n) else return lean_big_usize_to_nat(n);
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_unsigned_to_nat(arg_n: c_uint) callconv(.C) lean_obj_res {
    var n = arg_n;
    return lean_usize_to_nat(@as(usize, @bitCast(@as(c_ulong, n))));
}
pub fn lean_uint64_to_nat(arg_n: u64) callconv(.C) lean_obj_res {
    var n = arg_n;
    if (__builtin_expect(@as(c_long, @intFromBool(n <= (@as(c_ulong, 18446744073709551615) >> @intCast(1)))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) return lean_box(n) else return lean_big_uint64_to_nat(n);
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_succ(arg_a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) return lean_usize_to_nat(lean_unbox(a) +% @as(usize, @bitCast(@as(c_long, @as(c_int, 1))))) else return lean_nat_big_succ(a);
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_add(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) return lean_usize_to_nat(lean_unbox(a1) +% lean_unbox(a2)) else return lean_nat_big_add(a1, a2);
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_sub(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n1: usize = lean_unbox(a1);
        var n2: usize = lean_unbox(a2);
        if (n1 < n2) return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) else return lean_box(n1 -% n2);
    } else {
        return lean_nat_big_sub(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_mul(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n1: usize = lean_unbox(a1);
        if (n1 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) return a1;
        var n2: usize = lean_unbox(a2);
        var r: usize = n1 *% n2;
        if ((r <= (@as(c_ulong, 18446744073709551615) >> @intCast(1))) and ((r / n1) == n2)) return lean_box(r) else return lean_nat_overflow_mul(n1, n2);
    } else {
        return lean_nat_big_mul(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_div(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n1: usize = lean_unbox(a1);
        var n2: usize = lean_unbox(a2);
        if (n2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) else return lean_box(n1 / n2);
    } else {
        return lean_nat_big_div(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_mod(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n1: usize = lean_unbox(a1);
        var n2: usize = lean_unbox(a2);
        if (n2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) return lean_box(n1) else return lean_box(n1 % n2);
    } else {
        return lean_nat_big_mod(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_eq(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return a1 == a2;
    } else {
        return lean_nat_big_eq(a1, a2);
    }
    return false;
}
pub fn lean_nat_dec_eq(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(lean_nat_eq(a1, a2)));
}
pub fn lean_nat_ne(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return !lean_nat_eq(a1, a2);
}
pub fn lean_nat_le(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return std.meta.eql(a1, a2);
    } else {
        return lean_nat_big_le(a1, a2);
    }
    return false;
}
pub fn lean_nat_dec_le(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(lean_nat_le(a1, a2)));
}
pub fn lean_nat_lt(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return std.meta.eql(a1, a2);
    } else {
        return lean_nat_big_lt(a1, a2);
    }
    return false;
}
pub fn lean_nat_dec_lt(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(lean_nat_lt(a1, a2)));
}
pub fn lean_nat_land(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return @as(?*lean_object, @ptrFromInt(@as(usize, @intCast(@intFromPtr(a1))) & @as(usize, @intCast(@intFromPtr(a2)))));
    } else {
        return lean_nat_big_land(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_lor(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return @as(?*lean_object, @ptrFromInt(@as(usize, @intCast(@intFromPtr(a1))) | @as(usize, @intCast(@intFromPtr(a2)))));
    } else {
        return lean_nat_big_lor(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_lxor(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_box(lean_unbox(a1) ^ lean_unbox(a2));
    } else {
        return lean_nat_big_xor(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub extern fn lean_nat_shiftl(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_shiftr(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_pow(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_gcd(a1: b_lean_obj_arg, a2: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_nat_log2(a: b_lean_obj_arg) lean_obj_res;
pub extern fn lean_int_big_neg(a: ?*lean_object) ?*lean_object;
pub extern fn lean_int_big_add(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_int_big_sub(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_int_big_mul(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_int_big_div(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_int_big_mod(a1: ?*lean_object, a2: ?*lean_object) ?*lean_object;
pub extern fn lean_int_big_eq(a1: ?*lean_object, a2: ?*lean_object) bool;
pub extern fn lean_int_big_le(a1: ?*lean_object, a2: ?*lean_object) bool;
pub extern fn lean_int_big_lt(a1: ?*lean_object, a2: ?*lean_object) bool;
pub extern fn lean_int_big_nonneg(a: ?*lean_object) bool;
pub extern fn lean_cstr_to_int(n: [*c]const u8) ?*lean_object;
pub extern fn lean_big_int_to_int(n: c_int) ?*lean_object;
pub extern fn lean_big_size_t_to_int(n: usize) ?*lean_object;
pub extern fn lean_big_int64_to_int(n: i64) ?*lean_object;
pub fn lean_int_to_int(arg_n: c_int) callconv(.C) lean_obj_res {
    var n = arg_n;
    if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) return lean_box(@as(usize, @bitCast(@as(c_ulong, @as(c_uint, @bitCast(n)))))) else if (((if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) -@as(c_int, 2147483647) - @as(c_int, 1) else -(@as(c_int, 1) << @intCast(30))) <= n) and (n <= (if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) @as(c_int, 2147483647) else @as(c_int, 1) << @intCast(30)))) return lean_box(@as(usize, @bitCast(@as(c_ulong, @as(c_uint, @bitCast(n)))))) else return lean_big_int_to_int(n);
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int64_to_int(arg_n: i64) callconv(.C) lean_obj_res {
    var n = arg_n;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(i64, @bitCast(@as(c_long, if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) -@as(c_int, 2147483647) - @as(c_int, 1) else -(@as(c_int, 1) << @intCast(30))))) <= n) and (n <= @as(i64, @bitCast(@as(c_long, if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) @as(c_int, 2147483647) else @as(c_int, 1) << @intCast(30))))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) return lean_box(@as(usize, @bitCast(@as(c_ulong, @as(c_uint, @bitCast(@as(c_int, @bitCast(@as(c_int, @truncate(n)))))))))) else return lean_big_int64_to_int(n);
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_scalar_to_int64(arg_a: b_lean_obj_arg) callconv(.C) i64 {
    var a = arg_a;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_scalar(a))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 1345), "lean_is_scalar(a)");
        }
    }
    if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) return @as(i64, @bitCast(@as(c_long, @as(c_int, @bitCast(@as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a)))))))))) else return @as(i64, @bitCast(@as(c_long, @as(c_int, @bitCast(@as(c_uint, @truncate(@as(usize, @intCast(@intFromPtr(a))))))) >> @intCast(1))));
    return std.mem.zeroes(i64);
}
pub fn lean_scalar_to_int(arg_a: b_lean_obj_arg) callconv(.C) c_int {
    var a = arg_a;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_is_scalar(a))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 1353), "lean_is_scalar(a)");
        }
    }
    if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) return @as(c_int, @bitCast(@as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a))))))) else return @as(c_int, @bitCast(@as(c_uint, @truncate(@as(usize, @intCast(@intFromPtr(a))))))) >> @intCast(1);
    return 0;
}
pub fn lean_nat_to_int(arg_a: lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    if (lean_is_scalar(a)) {
        var v: usize = lean_unbox(a);
        if (v <= @as(usize, @bitCast(@as(c_long, if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) @as(c_int, 2147483647) else @as(c_int, 1) << @intCast(30))))) return a else return lean_big_size_t_to_int(v);
    } else {
        return a;
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_neg(arg_a: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_int64_to_int(-lean_scalar_to_int64(a));
    } else {
        return lean_int_big_neg(a);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_neg_succ_of_nat(arg_a: lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    var s: lean_obj_res = lean_nat_succ(a);
    lean_dec(a);
    var i: lean_obj_res = lean_nat_to_int(s);
    var r: lean_obj_res = lean_int_neg(i);
    lean_dec(i);
    return r;
}
pub fn lean_int_add(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_int64_to_int(lean_scalar_to_int64(a1) + lean_scalar_to_int64(a2));
    } else {
        return lean_int_big_add(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_sub(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_int64_to_int(lean_scalar_to_int64(a1) - lean_scalar_to_int64(a2));
    } else {
        return lean_int_big_sub(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_mul(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_int64_to_int(lean_scalar_to_int64(a1) * lean_scalar_to_int64(a2));
    } else {
        return lean_int_big_mul(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_div(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) {
            var v1: i64 = @as(i64, @bitCast(@as(c_long, lean_scalar_to_int(a1))));
            var v2: i64 = @as(i64, @bitCast(@as(c_long, lean_scalar_to_int(a2))));
            if (v2 == @as(i64, @bitCast(@as(c_long, @as(c_int, 0))))) return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) else return lean_int64_to_int(@divTrunc(v1, v2));
        } else {
            var v1: c_int = lean_scalar_to_int(a1);
            var v2: c_int = lean_scalar_to_int(a2);
            if (v2 == @as(c_int, 0)) return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) else return lean_int_to_int(@divTrunc(v1, v2));
        }
    } else {
        return lean_int_big_div(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_mod(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))) {
            var v1: i64 = lean_scalar_to_int64(a1);
            var v2: i64 = lean_scalar_to_int64(a2);
            if (v2 == @as(i64, @bitCast(@as(c_long, @as(c_int, 0))))) return a1 else return lean_int64_to_int(std.zig.c_translation.signedRemainder(v1, v2));
        } else {
            var v1: c_int = lean_scalar_to_int(a1);
            var v2: c_int = lean_scalar_to_int(a2);
            if (v2 == @as(c_int, 0)) return a1 else return lean_int_to_int(std.zig.c_translation.signedRemainder(v1, v2));
        }
    } else {
        return lean_int_big_mod(a1, a2);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_eq(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return a1 == a2;
    } else {
        return lean_int_big_eq(a1, a2);
    }
    return false;
}
pub fn lean_int_ne(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return !lean_int_eq(a1, a2);
}
pub fn lean_int_le(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_scalar_to_int(a1) <= lean_scalar_to_int(a2);
    } else {
        return lean_int_big_le(a1, a2);
    }
    return false;
}
pub fn lean_int_lt(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) bool {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool((@as(c_int, @intFromBool(lean_is_scalar(a1))) != 0) and (@as(c_int, @intFromBool(lean_is_scalar(a2))) != 0))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        return lean_scalar_to_int(a1) < lean_scalar_to_int(a2);
    } else {
        return lean_int_big_lt(a1, a2);
    }
    return false;
}
pub extern fn lean_big_int_to_nat(a: lean_obj_arg) lean_obj_res;
pub fn lean_int_to_nat(arg_a: lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!!lean_int_lt(a, lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))))))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 1489), "!lean_int_lt(a, lean_box(0))");
        }
    }
    if (lean_is_scalar(a)) {
        return a;
    } else {
        return lean_big_int_to_nat(a);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_nat_abs(arg_i: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var i = arg_i;
    if (lean_int_lt(i, lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))))) {
        return lean_int_to_nat(lean_int_neg(i));
    } else {
        lean_inc(i);
        return lean_int_to_nat(i);
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_int_dec_eq(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(lean_int_eq(a1, a2)));
}
pub fn lean_int_dec_le(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(lean_int_le(a1, a2)));
}
pub fn lean_int_dec_lt(arg_a1: b_lean_obj_arg, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(lean_int_lt(a1, a2)));
}
pub fn lean_int_dec_nonneg(arg_a: b_lean_obj_arg) callconv(.C) u8 {
    var a = arg_a;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) return @as(u8, @intFromBool(lean_scalar_to_int(a) >= @as(c_int, 0))) else return @as(u8, @intFromBool(lean_int_big_nonneg(a)));
    return std.mem.zeroes(u8);
}
pub fn lean_bool_to_uint64(arg_a: u8) callconv(.C) u64 {
    var a = arg_a;
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint8_of_big_nat(a: b_lean_obj_arg) u8;
pub fn lean_uint8_of_nat(arg_a: b_lean_obj_arg) callconv(.C) u8 {
    var a = arg_a;
    return @as(u8, @bitCast(@as(i8, @truncate(if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(c_int, @bitCast(@as(c_uint, @as(u8, @bitCast(@as(u8, @truncate(lean_unbox(a)))))))) else @as(c_int, @bitCast(@as(c_uint, lean_uint8_of_big_nat(a))))))));
}
pub fn lean_uint8_of_nat_mk(arg_a: lean_obj_arg) callconv(.C) u8 {
    var a = arg_a;
    var r: u8 = lean_uint8_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint8_to_nat(arg_a: u8) callconv(.C) lean_obj_res {
    var a = arg_a;
    return lean_usize_to_nat(@as(usize, @bitCast(@as(c_ulong, a))));
}
pub fn lean_uint8_add(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) + @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint8_sub(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) - @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint8_mul(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) * @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint8_div(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @bitCast(@as(i8, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == @as(c_int, 0)) @as(c_int, 0) else @divTrunc(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint8_mod(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @bitCast(@as(i8, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == @as(c_int, 0)) @as(c_int, @bitCast(@as(c_uint, a1))) else std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint8_land(arg_a: u8, arg_b: u8) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) & @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint8_lor(arg_a: u8, arg_b: u8) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) | @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint8_xor(arg_a: u8, arg_b: u8) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) ^ @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint8_shift_left(arg_a: u8, arg_b: u8) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) << @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 8)))))));
}
pub fn lean_uint8_shift_right(arg_a: u8, arg_b: u8) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) >> @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 8)))))));
}
pub fn lean_uint8_complement(arg_a: u8) callconv(.C) u8 {
    var a = arg_a;
    return @as(u8, @bitCast(@as(i8, @truncate(~@as(c_int, @bitCast(@as(c_uint, a)))))));
}
pub fn lean_uint8_modn(arg_a1: u8, arg_a2: b_lean_obj_arg) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: c_uint = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a2)))));
        return @as(u8, @bitCast(@as(u8, @truncate(if (n2 == @as(c_uint, @bitCast(@as(c_int, 0)))) @as(c_uint, @bitCast(@as(c_uint, a1))) else @as(c_uint, @bitCast(@as(c_uint, a1))) % n2))));
    } else {
        return a1;
    }
    return std.mem.zeroes(u8);
}
pub fn lean_uint8_log2(arg_a: u8) callconv(.C) u8 {
    var a = arg_a;
    var res: u8 = 0;
    while (@as(c_int, @bitCast(@as(c_uint, a))) >= @as(c_int, 2)) {
        res +%= 1;
        a /= @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, 2)))));
    }
    return res;
}
pub fn lean_uint8_dec_eq(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) == @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint8_dec_lt(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) < @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint8_dec_le(arg_a1: u8, arg_a2: u8) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) <= @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint8_to_uint16(arg_a: u8) callconv(.C) u16 {
    var a = arg_a;
    return @as(u16, @bitCast(@as(c_ushort, a)));
}
pub fn lean_uint8_to_uint32(arg_a: u8) callconv(.C) u32 {
    var a = arg_a;
    return @as(u32, @bitCast(@as(c_uint, a)));
}
pub fn lean_uint8_to_uint64(arg_a: u8) callconv(.C) u64 {
    var a = arg_a;
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint16_of_big_nat(a: b_lean_obj_arg) u16;
pub fn lean_uint16_of_nat(arg_a: b_lean_obj_arg) callconv(.C) u16 {
    var a = arg_a;
    return @as(u16, @bitCast(@as(c_short, @truncate(if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(c_int, @bitCast(@as(c_int, @as(i16, @bitCast(@as(c_ushort, @truncate(lean_unbox(a)))))))) else @as(c_int, @bitCast(@as(c_uint, lean_uint16_of_big_nat(a))))))));
}
pub fn lean_uint16_of_nat_mk(arg_a: lean_obj_arg) callconv(.C) u16 {
    var a = arg_a;
    var r: u16 = lean_uint16_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint16_to_nat(arg_a: u16) callconv(.C) lean_obj_res {
    var a = arg_a;
    return lean_usize_to_nat(@as(usize, @bitCast(@as(c_ulong, a))));
}
pub fn lean_uint16_add(arg_a1: u16, arg_a2: u16) callconv(.C) u16 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) + @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint16_sub(arg_a1: u16, arg_a2: u16) callconv(.C) u16 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) - @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint16_mul(arg_a1: u16, arg_a2: u16) callconv(.C) u16 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a1))) * @as(c_int, @bitCast(@as(c_uint, a2)))))));
}
pub fn lean_uint16_div(arg_a1: u16, arg_a2: u16) callconv(.C) u16 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u16, @bitCast(@as(c_short, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == @as(c_int, 0)) @as(c_int, 0) else @divTrunc(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint16_mod(arg_a1: u16, arg_a2: u16) callconv(.C) u16 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u16, @bitCast(@as(c_short, @truncate(if (@as(c_int, @bitCast(@as(c_uint, a2))) == @as(c_int, 0)) @as(c_int, @bitCast(@as(c_uint, a1))) else std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, a1))), @as(c_int, @bitCast(@as(c_uint, a2))))))));
}
pub fn lean_uint16_land(arg_a: u16, arg_b: u16) callconv(.C) u16 {
    var a = arg_a;
    var b = arg_b;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) & @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint16_lor(arg_a: u16, arg_b: u16) callconv(.C) u16 {
    var a = arg_a;
    var b = arg_b;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) | @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint16_xor(arg_a: u16, arg_b: u16) callconv(.C) u16 {
    var a = arg_a;
    var b = arg_b;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) ^ @as(c_int, @bitCast(@as(c_uint, b)))))));
}
pub fn lean_uint16_shift_left(arg_a: u16, arg_b: u16) callconv(.C) u16 {
    var a = arg_a;
    var b = arg_b;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) << @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 16)))))));
}
pub fn lean_uint16_shift_right(arg_a: u16, arg_b: u16) callconv(.C) u16 {
    var a = arg_a;
    var b = arg_b;
    return @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, @bitCast(@as(c_uint, a))) >> @intCast(std.zig.c_translation.signedRemainder(@as(c_int, @bitCast(@as(c_uint, b))), @as(c_int, 16)))))));
}
pub fn lean_uint16_complement(arg_a: u16) callconv(.C) u16 {
    var a = arg_a;
    return @as(u16, @bitCast(@as(c_short, @truncate(~@as(c_int, @bitCast(@as(c_uint, a)))))));
}
pub fn lean_uint16_modn(arg_a1: u16, arg_a2: b_lean_obj_arg) callconv(.C) u16 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: c_uint = @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(a2)))));
        return @as(u16, @bitCast(@as(c_ushort, @truncate(if (n2 == @as(c_uint, @bitCast(@as(c_int, 0)))) @as(c_uint, @bitCast(@as(c_uint, a1))) else @as(c_uint, @bitCast(@as(c_uint, a1))) % n2))));
    } else {
        return a1;
    }
    return std.mem.zeroes(u16);
}
pub fn lean_uint16_log2(arg_a: u16) callconv(.C) u16 {
    var a = arg_a;
    var res: u16 = 0;
    while (@as(c_int, @bitCast(@as(c_uint, a))) >= @as(c_int, 2)) {
        res +%= 1;
        a /= @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 2)))));
    }
    return res;
}
pub fn lean_uint16_dec_eq(arg_a1: u16, arg_a2: u16) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) == @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint16_dec_lt(arg_a1: u16, arg_a2: u16) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) < @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint16_dec_le(arg_a1: u16, arg_a2: u16) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(@as(c_int, @bitCast(@as(c_uint, a1))) <= @as(c_int, @bitCast(@as(c_uint, a2)))));
}
pub fn lean_uint16_to_uint8(arg_a: u16) callconv(.C) u8 {
    var a = arg_a;
    return @as(u8, @bitCast(@as(u8, @truncate(a))));
}
pub fn lean_uint16_to_uint32(arg_a: u16) callconv(.C) u32 {
    var a = arg_a;
    return @as(u32, @bitCast(@as(c_uint, a)));
}
pub fn lean_uint16_to_uint64(arg_a: u16) callconv(.C) u64 {
    var a = arg_a;
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint32_of_big_nat(a: b_lean_obj_arg) u32;
pub fn lean_uint32_of_nat(arg_a: b_lean_obj_arg) callconv(.C) u32 {
    var a = arg_a;
    return if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(u32, @bitCast(@as(c_uint, @truncate(lean_unbox(a))))) else lean_uint32_of_big_nat(a);
}
pub fn lean_uint32_of_nat_mk(arg_a: lean_obj_arg) callconv(.C) u32 {
    var a = arg_a;
    var r: u32 = lean_uint32_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint32_to_nat(arg_a: u32) callconv(.C) lean_obj_res {
    var a = arg_a;
    return lean_usize_to_nat(@as(usize, @bitCast(@as(c_ulong, a))));
}
pub fn lean_uint32_add(arg_a1: u32, arg_a2: u32) callconv(.C) u32 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 +% a2;
}
pub fn lean_uint32_sub(arg_a1: u32, arg_a2: u32) callconv(.C) u32 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 -% a2;
}
pub fn lean_uint32_mul(arg_a1: u32, arg_a2: u32) callconv(.C) u32 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 *% a2;
}
pub fn lean_uint32_div(arg_a1: u32, arg_a2: u32) callconv(.C) u32 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return if (a2 == @as(u32, @bitCast(@as(c_int, 0)))) @as(u32, @bitCast(@as(c_int, 0))) else a1 / a2;
}
pub fn lean_uint32_mod(arg_a1: u32, arg_a2: u32) callconv(.C) u32 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return if (a2 == @as(u32, @bitCast(@as(c_int, 0)))) a1 else a1 % a2;
}
pub fn lean_uint32_land(arg_a: u32, arg_b: u32) callconv(.C) u32 {
    var a = arg_a;
    var b = arg_b;
    return a & b;
}
pub fn lean_uint32_lor(arg_a: u32, arg_b: u32) callconv(.C) u32 {
    var a = arg_a;
    var b = arg_b;
    return a | b;
}
pub fn lean_uint32_xor(arg_a: u32, arg_b: u32) callconv(.C) u32 {
    var a = arg_a;
    var b = arg_b;
    return a ^ b;
}
pub fn lean_uint32_shift_left(arg_a: u32, arg_b: u32) callconv(.C) u32 {
    var a = arg_a;
    var b = arg_b;
    return a << @intCast(b % @as(u32, @bitCast(@as(c_int, 32))));
}
pub fn lean_uint32_shift_right(arg_a: u32, arg_b: u32) callconv(.C) u32 {
    var a = arg_a;
    var b = arg_b;
    return a >> @intCast(b % @as(u32, @bitCast(@as(c_int, 32))));
}
pub fn lean_uint32_complement(arg_a: u32) callconv(.C) u32 {
    var a = arg_a;
    return ~a;
}
pub extern fn lean_uint32_big_modn(a1: u32, a2: b_lean_obj_arg) u32;
pub fn lean_uint32_modn(arg_a1: u32, arg_a2: b_lean_obj_arg) callconv(.C) u32 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: usize = lean_unbox(a2);
        return @as(u32, @bitCast(@as(c_uint, @truncate(if (n2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) @as(usize, @bitCast(@as(c_ulong, a1))) else @as(usize, @bitCast(@as(c_ulong, a1))) % n2))));
    } else if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 4))))) {
        return lean_uint32_big_modn(a1, a2);
    } else {
        return a1;
    }
    return std.mem.zeroes(u32);
}
pub fn lean_uint32_log2(arg_a: u32) callconv(.C) u32 {
    var a = arg_a;
    var res: u32 = 0;
    while (a >= @as(u32, @bitCast(@as(c_int, 2)))) {
        res +%= 1;
        a /= @as(u32, @bitCast(@as(c_int, 2)));
    }
    return res;
}
pub fn lean_uint32_dec_eq(arg_a1: u32, arg_a2: u32) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 == a2));
}
pub fn lean_uint32_dec_lt(arg_a1: u32, arg_a2: u32) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 < a2));
}
pub fn lean_uint32_dec_le(arg_a1: u32, arg_a2: u32) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 <= a2));
}
pub fn lean_uint32_to_uint8(arg_a: u32) callconv(.C) u8 {
    var a = arg_a;
    return @as(u8, @bitCast(@as(u8, @truncate(a))));
}
pub fn lean_uint32_to_uint16(arg_a: u32) callconv(.C) u16 {
    var a = arg_a;
    return @as(u16, @bitCast(@as(c_ushort, @truncate(a))));
}
pub fn lean_uint32_to_uint64(arg_a: u32) callconv(.C) u64 {
    var a = arg_a;
    return @as(u64, @bitCast(@as(c_ulong, a)));
}
pub fn lean_uint32_to_usize(arg_a: u32) callconv(.C) usize {
    var a = arg_a;
    return @as(usize, @bitCast(@as(c_ulong, a)));
}
pub extern fn lean_uint64_of_big_nat(a: b_lean_obj_arg) u64;
pub fn lean_uint64_of_nat(arg_a: b_lean_obj_arg) callconv(.C) u64 {
    var a = arg_a;
    return if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) @as(u64, @bitCast(lean_unbox(a))) else lean_uint64_of_big_nat(a);
}
pub fn lean_uint64_of_nat_mk(arg_a: lean_obj_arg) callconv(.C) u64 {
    var a = arg_a;
    var r: u64 = lean_uint64_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_uint64_add(arg_a1: u64, arg_a2: u64) callconv(.C) u64 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 +% a2;
}
pub fn lean_uint64_sub(arg_a1: u64, arg_a2: u64) callconv(.C) u64 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 -% a2;
}
pub fn lean_uint64_mul(arg_a1: u64, arg_a2: u64) callconv(.C) u64 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 *% a2;
}
pub fn lean_uint64_div(arg_a1: u64, arg_a2: u64) callconv(.C) u64 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return if (a2 == @as(u64, @bitCast(@as(c_long, @as(c_int, 0))))) @as(u64, @bitCast(@as(c_long, @as(c_int, 0)))) else a1 / a2;
}
pub fn lean_uint64_mod(arg_a1: u64, arg_a2: u64) callconv(.C) u64 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return if (a2 == @as(u64, @bitCast(@as(c_long, @as(c_int, 0))))) a1 else a1 % a2;
}
pub fn lean_uint64_land(arg_a: u64, arg_b: u64) callconv(.C) u64 {
    var a = arg_a;
    var b = arg_b;
    return a & b;
}
pub fn lean_uint64_lor(arg_a: u64, arg_b: u64) callconv(.C) u64 {
    var a = arg_a;
    var b = arg_b;
    return a | b;
}
pub fn lean_uint64_xor(arg_a: u64, arg_b: u64) callconv(.C) u64 {
    var a = arg_a;
    var b = arg_b;
    return a ^ b;
}
pub fn lean_uint64_shift_left(arg_a: u64, arg_b: u64) callconv(.C) u64 {
    var a = arg_a;
    var b = arg_b;
    return a << @intCast(b % @as(u64, @bitCast(@as(c_long, @as(c_int, 64)))));
}
pub fn lean_uint64_shift_right(arg_a: u64, arg_b: u64) callconv(.C) u64 {
    var a = arg_a;
    var b = arg_b;
    return a >> @intCast(b % @as(u64, @bitCast(@as(c_long, @as(c_int, 64)))));
}
pub fn lean_uint64_complement(arg_a: u64) callconv(.C) u64 {
    var a = arg_a;
    return ~a;
}
pub extern fn lean_uint64_big_modn(a1: u64, a2: b_lean_obj_arg) u64;
pub fn lean_uint64_modn(arg_a1: u64, arg_a2: b_lean_obj_arg) callconv(.C) u64 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: usize = lean_unbox(a2);
        return if (n2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) a1 else a1 % n2;
    } else {
        return lean_uint64_big_modn(a1, a2);
    }
    return std.mem.zeroes(u64);
}
pub fn lean_uint64_log2(arg_a: u64) callconv(.C) u64 {
    var a = arg_a;
    var res: u64 = 0;
    while (a >= @as(u64, @intCast(2))) {
        res +%= 1;
        a /= @intCast(2);
    }
    return res;
}
pub fn lean_uint64_dec_eq(arg_a1: u64, arg_a2: u64) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 == a2));
}
pub fn lean_uint64_dec_lt(arg_a1: u64, arg_a2: u64) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 < a2));
}
pub fn lean_uint64_dec_le(arg_a1: u64, arg_a2: u64) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 <= a2));
}
pub extern fn lean_uint64_mix_hash(a1: u64, a2: u64) u64;
pub fn lean_uint64_to_uint8(arg_a: u64) callconv(.C) u8 {
    var a = arg_a;
    return @as(u8, @bitCast(@as(u8, @truncate(a))));
}
pub fn lean_uint64_to_uint16(arg_a: u64) callconv(.C) u16 {
    var a = arg_a;
    return @as(u16, @bitCast(@as(c_ushort, @truncate(a))));
}
pub fn lean_uint64_to_uint32(arg_a: u64) callconv(.C) u32 {
    var a = arg_a;
    return @as(u32, @bitCast(@as(c_uint, @truncate(a))));
}
pub fn lean_uint64_to_usize(arg_a: u64) callconv(.C) usize {
    var a = arg_a;
    return @as(usize, @bitCast(a));
}
pub extern fn lean_usize_of_big_nat(a: b_lean_obj_arg) usize;
pub fn lean_usize_of_nat(arg_a: b_lean_obj_arg) callconv(.C) usize {
    var a = arg_a;
    return if (@as(c_int, @intFromBool(lean_is_scalar(a))) != 0) lean_unbox(a) else lean_usize_of_big_nat(a);
}
pub fn lean_usize_of_nat_mk(arg_a: lean_obj_arg) callconv(.C) usize {
    var a = arg_a;
    var r: usize = lean_usize_of_nat(a);
    lean_dec(a);
    return r;
}
pub fn lean_usize_add(arg_a1: usize, arg_a2: usize) callconv(.C) usize {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 +% a2;
}
pub fn lean_usize_sub(arg_a1: usize, arg_a2: usize) callconv(.C) usize {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 -% a2;
}
pub fn lean_usize_mul(arg_a1: usize, arg_a2: usize) callconv(.C) usize {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return a1 *% a2;
}
pub fn lean_usize_div(arg_a1: usize, arg_a2: usize) callconv(.C) usize {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return if (a2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) @as(usize, @bitCast(@as(c_long, @as(c_int, 0)))) else a1 / a2;
}
pub fn lean_usize_mod(arg_a1: usize, arg_a2: usize) callconv(.C) usize {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return if (a2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) a1 else a1 % a2;
}
pub fn lean_usize_land(arg_a: usize, arg_b: usize) callconv(.C) usize {
    var a = arg_a;
    var b = arg_b;
    return a & b;
}
pub fn lean_usize_lor(arg_a: usize, arg_b: usize) callconv(.C) usize {
    var a = arg_a;
    var b = arg_b;
    return a | b;
}
pub fn lean_usize_xor(arg_a: usize, arg_b: usize) callconv(.C) usize {
    var a = arg_a;
    var b = arg_b;
    return a ^ b;
}
pub fn lean_usize_shift_left(arg_a: usize, arg_b: usize) callconv(.C) usize {
    var a = arg_a;
    var b = arg_b;
    return a << @intCast(b % (@sizeOf(usize) *% @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))));
}
pub fn lean_usize_shift_right(arg_a: usize, arg_b: usize) callconv(.C) usize {
    var a = arg_a;
    var b = arg_b;
    return a >> @intCast(b % (@sizeOf(usize) *% @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 8))))));
}
pub fn lean_usize_complement(arg_a: usize) callconv(.C) usize {
    var a = arg_a;
    return ~a;
}
pub extern fn lean_usize_big_modn(a1: usize, a2: b_lean_obj_arg) usize;
pub fn lean_usize_modn(arg_a1: usize, arg_a2: b_lean_obj_arg) callconv(.C) usize {
    var a1 = arg_a1;
    var a2 = arg_a2;
    if (__builtin_expect(@as(c_long, @intFromBool(lean_is_scalar(a2))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 1))))) != 0) {
        var n2: usize = lean_unbox(a2);
        return if (n2 == @as(usize, @bitCast(@as(c_long, @as(c_int, 0))))) a1 else a1 % n2;
    } else {
        return lean_usize_big_modn(a1, a2);
    }
    return std.mem.zeroes(usize);
}
pub fn lean_usize_log2(arg_a: usize) callconv(.C) usize {
    var a = arg_a;
    var res: usize = 0;
    while (a >= @as(usize, @bitCast(@as(c_long, @as(c_int, 2))))) {
        res +%= 1;
        a /= @as(usize, @bitCast(@as(c_long, @as(c_int, 2))));
    }
    return res;
}
pub fn lean_usize_dec_eq(arg_a1: usize, arg_a2: usize) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 == a2));
}
pub fn lean_usize_dec_lt(arg_a1: usize, arg_a2: usize) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 < a2));
}
pub fn lean_usize_dec_le(arg_a1: usize, arg_a2: usize) callconv(.C) u8 {
    var a1 = arg_a1;
    var a2 = arg_a2;
    return @as(u8, @intFromBool(a1 <= a2));
}
pub fn lean_usize_to_uint32(arg_a: usize) callconv(.C) u32 {
    var a = arg_a;
    return @as(u32, @bitCast(@as(c_uint, @truncate(a))));
}
pub fn lean_usize_to_uint64(arg_a: usize) callconv(.C) u64 {
    var a = arg_a;
    return @as(u64, @bitCast(a));
}
pub extern fn lean_float_to_string(a: f64) lean_obj_res;
pub extern fn lean_float_scaleb(a: f64, b: b_lean_obj_arg) f64;
pub extern fn lean_float_isnan(a: f64) u8;
pub extern fn lean_float_isfinite(a: f64) u8;
pub extern fn lean_float_isinf(a: f64) u8;
pub extern fn lean_float_frexp(a: f64) lean_obj_res;
pub fn lean_box_uint32(arg_v: u32) callconv(.C) lean_obj_res {
    var v = arg_v;
    if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 4))))) {
        var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(u32))))));
        lean_ctor_set_uint32(r, @as(c_uint, @bitCast(@as(c_int, 0))), v);
        return r;
    } else {
        return lean_box(@as(usize, @bitCast(@as(c_ulong, v))));
    }
    return std.mem.zeroes(lean_obj_res);
}
pub fn lean_unbox_uint32(arg_o: b_lean_obj_arg) callconv(.C) c_uint {
    var o = arg_o;
    if (@sizeOf(?*anyopaque) == @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 4))))) {
        return lean_ctor_get_uint32(o, @as(c_uint, @bitCast(@as(c_int, 0))));
    } else {
        return @as(c_uint, @bitCast(@as(c_uint, @truncate(lean_unbox(o)))));
    }
    return 0;
}
pub fn lean_box_uint64(arg_v: u64) callconv(.C) lean_obj_res {
    var v = arg_v;
    var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(u64))))));
    lean_ctor_set_uint64(r, @as(c_uint, @bitCast(@as(c_int, 0))), v);
    return r;
}
pub fn lean_unbox_uint64(arg_o: b_lean_obj_arg) callconv(.C) u64 {
    var o = arg_o;
    return lean_ctor_get_uint64(o, @as(c_uint, @bitCast(@as(c_int, 0))));
}
pub fn lean_box_usize(arg_v: usize) callconv(.C) lean_obj_res {
    var v = arg_v;
    var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(usize))))));
    lean_ctor_set_usize(r, @as(c_uint, @bitCast(@as(c_int, 0))), v);
    return r;
}
pub fn lean_unbox_usize(arg_o: b_lean_obj_arg) callconv(.C) usize {
    var o = arg_o;
    return lean_ctor_get_usize(o, @as(c_uint, @bitCast(@as(c_int, 0))));
}
pub fn lean_box_float(arg_v: f64) callconv(.C) lean_obj_res {
    var v = arg_v;
    var r: lean_obj_res = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(f64))))));
    lean_ctor_set_float(r, @as(c_uint, @bitCast(@as(c_int, 0))), v);
    return r;
}
pub fn lean_unbox_float(arg_o: b_lean_obj_arg) callconv(.C) f64 {
    var o = arg_o;
    return lean_ctor_get_float(o, @as(c_uint, @bitCast(@as(c_int, 0))));
}
pub extern fn lean_dbg_trace(s: lean_obj_arg, @"fn": lean_obj_arg) ?*lean_object;
pub extern fn lean_dbg_sleep(ms: u32, @"fn": lean_obj_arg) ?*lean_object;
pub extern fn lean_dbg_trace_if_shared(s: lean_obj_arg, a: lean_obj_arg) ?*lean_object;
pub extern fn lean_decode_io_error(errnum: c_int, fname: b_lean_obj_arg) lean_obj_res;
pub fn lean_io_mk_world() callconv(.C) lean_obj_res {
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))));
}
pub fn lean_io_result_is_ok(arg_r: b_lean_obj_arg) callconv(.C) bool {
    var r = arg_r;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(r)))) == @as(c_int, 0);
}
pub fn lean_io_result_is_error(arg_r: b_lean_obj_arg) callconv(.C) bool {
    var r = arg_r;
    return @as(c_int, @bitCast(@as(c_uint, lean_ptr_tag(r)))) == @as(c_int, 1);
}
pub fn lean_io_result_get_value(arg_r: b_lean_obj_arg) callconv(.C) b_lean_obj_res {
    var r = arg_r;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_io_result_is_ok(r))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 1827), "lean_io_result_is_ok(r)");
        }
    }
    return lean_ctor_get(r, @as(c_uint, @bitCast(@as(c_int, 0))));
}
pub fn lean_io_result_get_error(arg_r: b_lean_obj_arg) callconv(.C) b_lean_obj_res {
    var r = arg_r;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!lean_io_result_is_error(r))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 1828), "lean_io_result_is_error(r)");
        }
    }
    return lean_ctor_get(r, @as(c_uint, @bitCast(@as(c_int, 0))));
}
pub extern fn lean_io_result_show_error(r: b_lean_obj_arg) void;
pub extern fn lean_io_mark_end_initialization(...) void;
pub fn lean_io_result_mk_ok(arg_a: lean_obj_arg) callconv(.C) lean_obj_res {
    var a = arg_a;
    var r: ?*lean_object = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 0))), @as(c_uint, @bitCast(@as(c_int, 2))), @as(c_uint, @bitCast(@as(c_int, 0))));
    lean_ctor_set(r, @as(c_uint, @bitCast(@as(c_int, 0))), a);
    lean_ctor_set(r, @as(c_uint, @bitCast(@as(c_int, 1))), lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))));
    return r;
}
pub fn lean_io_result_mk_error(arg_e: lean_obj_arg) callconv(.C) lean_obj_res {
    var e = arg_e;
    var r: ?*lean_object = lean_alloc_ctor(@as(c_uint, @bitCast(@as(c_int, 1))), @as(c_uint, @bitCast(@as(c_int, 2))), @as(c_uint, @bitCast(@as(c_int, 0))));
    lean_ctor_set(r, @as(c_uint, @bitCast(@as(c_int, 0))), e);
    lean_ctor_set(r, @as(c_uint, @bitCast(@as(c_int, 1))), lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0))))));
    return r;
}
pub extern fn lean_mk_io_error_already_exists(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_already_exists_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_eof(lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_hardware_fault(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_illegal_operation(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_inappropriate_type(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_inappropriate_type_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_interrupted(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_invalid_argument(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_invalid_argument_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_no_file_or_directory(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_no_such_thing(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_no_such_thing_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_other_error(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_permission_denied(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_permission_denied_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_protocol_error(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_busy(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_exhausted(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_exhausted_file(lean_obj_arg, u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_resource_vanished(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_time_expired(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_unsatisfied_constraints(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_error_unsupported_operation(u32, lean_obj_arg) lean_obj_res;
pub extern fn lean_mk_io_user_error(str: lean_obj_arg) lean_obj_res;
pub extern fn lean_st_mk_ref(lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_get(b_lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_set(b_lean_obj_arg, lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_reset(b_lean_obj_arg, lean_obj_arg) lean_obj_res;
pub extern fn lean_st_ref_swap(b_lean_obj_arg, lean_obj_arg, lean_obj_arg) lean_obj_res;
pub fn lean_ptr_addr(arg_a: b_lean_obj_arg) callconv(.C) usize {
    var a = arg_a;
    return @as(usize, @intCast(@intFromPtr(a)));
}
pub extern fn lean_name_eq(n1: b_lean_obj_arg, n2: b_lean_obj_arg) u8;
pub fn lean_name_hash_ptr(arg_n: b_lean_obj_arg) callconv(.C) u64 {
    var n = arg_n;
    {
        if (__builtin_expect(@as(c_long, @intFromBool(!!lean_is_scalar(n))), @as(c_long, @bitCast(@as(c_long, @as(c_int, 0))))) != 0) {
            lean_notify_assert("src/lean.zig", @as(c_int, 1885), "!lean_is_scalar(n)");
        }
    }
    return lean_ctor_get_uint64(n, @as(c_uint, @bitCast(@as(c_uint, @truncate(@sizeOf(?*lean_object) *% @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 2)))))))));
}
pub fn lean_name_hash(arg_n: b_lean_obj_arg) callconv(.C) u64 {
    var n = arg_n;
    if (lean_is_scalar(n)) return @as(u64, @bitCast(@as(c_long, @as(c_int, 1723)))) else return lean_name_hash_ptr(n);
    return std.mem.zeroes(u64);
}
pub fn lean_float_to_uint8(arg_a: f64) callconv(.C) u8 {
    var a = arg_a;
    return @as(u8, @bitCast(@as(i8, @truncate(if (0.0 <= a) if (a < 256.0) @as(c_int, @bitCast(@as(c_uint, @as(u8, @intFromFloat(a))))) else @as(c_int, 255) else @as(c_int, 0)))));
}
pub fn lean_float_to_uint16(arg_a: f64) callconv(.C) u16 {
    var a = arg_a;
    return @as(u16, @bitCast(@as(c_short, @truncate(if (0.0 <= a) if (a < 65536.0) @as(c_int, @bitCast(@as(c_uint, @as(u16, @intFromFloat(a))))) else @as(c_int, 65535) else @as(c_int, 0)))));
}
pub fn lean_float_to_uint32(arg_a: f64) callconv(.C) u32 {
    var a = arg_a;
    return if (0.0 <= a) if (a < 4294967296.0) @as(u32, @intFromFloat(a)) else @as(c_uint, 4294967295) else @as(c_uint, @bitCast(@as(c_int, 0)));
}
pub fn lean_float_to_uint64(arg_a: f64) callconv(.C) u64 {
    var a = arg_a;
    return if (0.0 <= a) if (a < 18446744073709550000.0) @as(u64, @intFromFloat(a)) else @as(c_ulong, 18446744073709551615) else @as(c_ulong, @bitCast(@as(c_long, @as(c_int, 0))));
}
pub fn lean_float_to_usize(arg_a: f64) callconv(.C) usize {
    var a = arg_a;
    if (@sizeOf(usize) == @sizeOf(u64)) return @as(usize, @bitCast(lean_float_to_uint64(a))) else return @as(usize, @bitCast(@as(c_ulong, lean_float_to_uint32(a))));
    return std.mem.zeroes(usize);
}
pub fn lean_float_add(arg_a: f64, arg_b: f64) callconv(.C) f64 {
    var a = arg_a;
    var b = arg_b;
    return a + b;
}
pub fn lean_float_sub(arg_a: f64, arg_b: f64) callconv(.C) f64 {
    var a = arg_a;
    var b = arg_b;
    return a - b;
}
pub fn lean_float_mul(arg_a: f64, arg_b: f64) callconv(.C) f64 {
    var a = arg_a;
    var b = arg_b;
    return a * b;
}
pub fn lean_float_div(arg_a: f64, arg_b: f64) callconv(.C) f64 {
    var a = arg_a;
    var b = arg_b;
    return a / b;
}
pub fn lean_float_negate(arg_a: f64) callconv(.C) f64 {
    var a = arg_a;
    return -a;
}
pub fn lean_float_beq(arg_a: f64, arg_b: f64) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @intFromBool(a == b));
}
pub fn lean_float_decLe(arg_a: f64, arg_b: f64) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @intFromBool(a <= b));
}
pub fn lean_float_decLt(arg_a: f64, arg_b: f64) callconv(.C) u8 {
    var a = arg_a;
    var b = arg_b;
    return @as(u8, @intFromBool(a < b));
}
pub fn lean_uint64_to_float(arg_a: u64) callconv(.C) f64 {
    var a = arg_a;
    return @as(f64, @floatFromInt(a));
}
pub fn lean_hashmap_mk_idx(arg_sz: lean_obj_arg, arg_hash: u64) callconv(.C) usize {
    var sz = arg_sz;
    var hash = arg_hash;
    return @as(usize, @bitCast(hash & (lean_unbox(sz) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))))));
}
pub fn lean_hashset_mk_idx(arg_sz: lean_obj_arg, arg_hash: u64) callconv(.C) usize {
    var sz = arg_sz;
    var hash = arg_hash;
    return @as(usize, @bitCast(hash & (lean_unbox(sz) -% @as(usize, @bitCast(@as(c_long, @as(c_int, 1)))))));
}
pub fn lean_expr_data(arg_expr: lean_obj_arg) callconv(.C) u64 {
    var expr = arg_expr;
    return lean_ctor_get_uint64(expr, @as(c_uint, @bitCast(@as(c_uint, @truncate(@as(c_ulong, @bitCast(@as(c_ulong, lean_ctor_num_objs(expr)))) *% @sizeOf(?*anyopaque))))));
}
pub fn lean_get_max_ctor_fields(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 256)))));
}
pub fn lean_get_max_ctor_scalars_size(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 1024)))));
}
pub fn lean_get_usize_size(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@sizeOf(usize));
}
pub fn lean_get_max_ctor_tag(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 244)))));
}
pub fn lean_strict_or(arg_b1: u8, arg_b2: u8) callconv(.C) u8 {
    var b1 = arg_b1;
    var b2 = arg_b2;
    return @as(u8, @intFromBool((@as(c_int, @bitCast(@as(c_uint, b1))) != 0) or (@as(c_int, @bitCast(@as(c_uint, b2))) != 0)));
}
pub fn lean_strict_and(arg_b1: u8, arg_b2: u8) callconv(.C) u8 {
    var b1 = arg_b1;
    var b2 = arg_b2;
    return @as(u8, @intFromBool((@as(c_int, @bitCast(@as(c_uint, b1))) != 0) and (@as(c_int, @bitCast(@as(c_uint, b2))) != 0)));
}
pub fn lean_version_get_major(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 4)))));
}
pub fn lean_version_get_minor(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))));
}
pub fn lean_version_get_patch(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 0)))));
}
pub fn lean_version_get_is_release(arg__unit: lean_obj_arg) callconv(.C) u8 {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return 0;
}
pub fn lean_version_get_special_desc(arg__unit: lean_obj_arg) callconv(.C) lean_obj_res {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return lean_mk_string("nightly-2023-08-26");
}
pub fn lean_internal_is_stage0(arg__unit: lean_obj_arg) callconv(.C) u8 {
    var _unit = arg__unit;
    _ = @TypeOf(_unit);
    return 0;
}
pub fn lean_nat_pred(arg_n: b_lean_obj_arg) callconv(.C) lean_obj_res {
    var n = arg_n;
    return lean_nat_sub(n, lean_box(@as(usize, @bitCast(@as(c_long, @as(c_int, 1))))));
}
pub const LEAN_VERSION_MAJOR = @as(c_int, 4);
pub const LEAN_VERSION_MINOR = @as(c_int, 0);
pub const LEAN_VERSION_PATCH = @as(c_int, 0);
pub const LEAN_VERSION_IS_RELEASE = @as(c_int, 0);
pub const LEAN_IS_STAGE0 = @as(c_int, 0);
pub const LEAN_CLOSURE_MAX_ARGS = @as(c_int, 16);
pub const LEAN_OBJECT_SIZE_DELTA = @as(c_int, 8);
pub const LEAN_MAX_SMALL_OBJECT_SIZE = @as(c_int, 4096);
pub inline fn LEAN_UNLIKELY(x: anytype) @TypeOf(__builtin_expect(x, @as(c_int, 0))) {
    return __builtin_expect(x, @as(c_int, 0));
}
pub inline fn LEAN_LIKELY(x: anytype) @TypeOf(__builtin_expect(x, @as(c_int, 1))) {
    return __builtin_expect(x, @as(c_int, 1));
}
pub inline fn LEAN_BYTE(Var: anytype, Index: anytype) @TypeOf((std.zig.c_translation.cast([*c]u8, &Var) + Index).*) {
    return (std.zig.c_translation.cast([*c]u8, &Var) + Index).*;
}
pub const LeanMaxCtorTag = @as(c_int, 244);
pub const LeanClosure = @as(c_int, 245);
pub const LeanArray = @as(c_int, 246);
pub const LeanStructArray = @as(c_int, 247);
pub const LeanScalarArray = @as(c_int, 248);
pub const LeanString = @as(c_int, 249);
pub const LeanMPZ = @as(c_int, 250);
pub const LeanThunk = @as(c_int, 251);
pub const LeanTask = @as(c_int, 252);
pub const LeanRef = @as(c_int, 253);
pub const LeanExternal = @as(c_int, 254);
pub const LeanReserved = @as(c_int, 255);
pub const LEAN_MAX_CTOR_FIELDS = @as(c_int, 256);
pub const LEAN_MAX_CTOR_SCALARS_SIZE = @as(c_int, 1024);
pub const LEAN_MAX_SMALL_NAT = std.math.maxInt(c_int) >> @as(c_int, 1);
pub const LEAN_MAX_SMALL_INT = if (std.zig.c_translation.sizeof(?*anyopaque) == @as(c_int, 8)) std.math.maxInt(c_int) else @as(c_int, 1) << @as(c_int, 30);
pub const LEAN_MIN_SMALL_INT = if (std.zig.c_translation.sizeof(?*anyopaque) == @as(c_int, 8)) std.math.maxInt(c_int) else -(@as(c_int, 1) << @as(c_int, 30));
pub const lean_task = struct_lean_task;
const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
