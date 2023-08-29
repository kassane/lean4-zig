const lean = @import("lean4");

export fn my_add(a: u32, b: u32) u32 {
    //[0] = (a+b), [1] = error (u1)
    const sum = @addWithOverflow(a, b);
    return if (sum[1] != 0) @intCast(sum[1]) else sum[0];
}

export fn my_lean_fun() lean.lean_obj_res {
    return lean.lean_io_result_mk_ok(lean.lean_box(0));
}
