import Lake
open System Lake DSL


package ffi {
  srcDir := "lean"
  precompileModules := true
}

lean_lib FFI

@[default_target] lean_exe test {
  root := `Main
}

target ffi.o pkg : FilePath := do
  let oFile := pkg.buildDir / "c" / "ffi.o"
  let srcJob ← inputFile <| pkg.dir / "c" / "ffi.c"
  let weakArgs := #["-I", (← getLeanIncludeDir).toString]
  buildO "ffi.c" oFile srcJob weakArgs #["-fPIC"] "c" getLeanTrace

extern_lib libffi pkg := do
  proc { cmd := "zig", args := #["build", "-Doptimize=ReleaseFast"], cwd := pkg.dir }
  let name := nameToStaticLib "zffi"
  -- let ffiO ← fetch <| pkg.target ``ffi.o
  -- buildStaticLib (pkg.nativeLibDir / name) #[ffiO]
  let srcPath := pkg.dir / "zig-out" / "lib" / name
  IO.FS.createDirAll pkg.nativeLibDir
  let tgtPath := pkg.nativeLibDir / name
  IO.FS.writeBinFile tgtPath (← IO.FS.readBinFile srcPath)
  return (pure tgtPath)

