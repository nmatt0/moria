cmake_minimum_required(VERSION 3.20)
project(moria VERSION 0.2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Optional sanitizers for debug builds: cmake -DFT_SANITIZE=ON
option(FT_SANITIZE "Build with ASan+UBSan" OFF)
if(FT_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# Embed the signature TOML sets into the binary so it is self-contained (no
# runtime signature directory). tools/embed_sigs is a tiny host codegen tool that
# reads the sets at build time and emits a C++ source; --sigs / $MORIA_SIGDIR
# still override with external TOML on disk.
add_executable(embed_sigs tools/embed_sigs.cpp)
set(EMBED_OUT ${CMAKE_BINARY_DIR}/generated/signatures_embedded.cpp)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/generated)
file(GLOB SIG_TOML CONFIGURE_DEPENDS
  ${CMAKE_SOURCE_DIR}/signatures/*.toml
  ${CMAKE_SOURCE_DIR}/signatures-firmware/*.toml
  ${CMAKE_SOURCE_DIR}/signatures-generated/*.toml)
add_custom_command(
  OUTPUT ${EMBED_OUT}
  COMMAND embed_sigs ${EMBED_OUT}
          ${CMAKE_SOURCE_DIR}/signatures
          ${CMAKE_SOURCE_DIR}/signatures-firmware
          ${CMAKE_SOURCE_DIR}/signatures-generated
  DEPENDS embed_sigs ${SIG_TOML}
  COMMENT "Embedding signature sets into the binary")

add_executable(moria
  ${EMBED_OUT}
  src/main.cpp
  src/scan.cpp
  src/archives.cpp
  src/extract/decompress.cpp
  src/extract/safepath.cpp
  src/extract/manifest.cpp
  src/extract/squashfs.cpp
  src/extract/cpio.cpp
  src/extract/cramfs.cpp
  src/extract/erofs.cpp
  src/extract/f2fs.cpp
  src/extract/hfsplus.cpp
  src/extract/xfs.cpp
  src/extract/btrfs.cpp
  src/extract/zip.cpp
  src/extract/android_boot.cpp
  src/extract/fat.cpp
  src/extract/exfat.cpp
  src/extract/ntfs.cpp
  src/extract/iso9660.cpp
  src/extract/uimage.cpp
  src/extract/uboot_env.cpp
  src/extract/esp32_nvs.cpp
  src/esp32_nvs_parse.cpp
  src/extract/rae_rfp.cpp
  src/extract/lzari.cpp
  src/extract/vbf.cpp
  src/extract/vbmeta.cpp
  src/extract/lzss.cpp
  src/extract/ucl.cpp
  src/extract/upx_filter.cpp
  src/extract/upx.cpp
  src/extract/fit.cpp
  src/extract/compressed.cpp
  src/extract/android_sparse.cpp
  src/extract/ext.cpp
  src/extract/jffs2.cpp
  src/extract/ubifs.cpp
  src/extract/tar.cpp
  src/extract/romfs.cpp
  src/extract/yaffs2.cpp
  src/extract/lzo1x.cpp
  src/ahocorasick.cpp
  src/resolve.cpp
  src/assess.cpp
  src/carve.cpp
  src/deobfuscate/cipher.cpp
  src/deobfuscate/scheme.cpp
  src/extract/descramble.cpp
  src/validators/deobf.cpp
  src/human.cpp
  src/json.cpp
  src/expr.cpp
  src/layout.cpp
  src/sigload.cpp
  src/ubi_info.cpp
  src/walk.cpp
  src/validators/registry.cpp
  src/validators/android_boot.cpp
  src/validators/squashfs.cpp
  src/validators/uimage.cpp
  src/validators/elf.cpp
  src/validators/upx.cpp
  src/validators/cpio.cpp
  src/validators/ihex.cpp
  src/validators/yaffs2.cpp
  src/validators/jffs2.cpp
  src/validators/zip.cpp
  src/validators/jpeg.cpp
  src/validators/rae_rfp.cpp
  src/validators/vbf.cpp
  src/validators/verity.cpp
  src/validators/vbmeta.cpp
  src/validators/uefi_fv.cpp
  src/validators/uboot_env.cpp
  src/validators/tar.cpp
  src/validators/ubi.cpp
  src/validators/dtb.cpp
  src/validators/partition.cpp
  src/validators/esp32_part.cpp
  src/validators/esp32_nvs.cpp
  src/validators/legacy_fs.cpp
  src/validators/luks.cpp
)
target_include_directories(moria PRIVATE src third_party)
target_compile_definitions(moria PRIVATE MORIA_VERSION="${PROJECT_VERSION}")
find_package(Threads REQUIRED)
target_link_libraries(moria PRIVATE Threads::Threads)

# Decompression codecs for --extract. Each is a leaf dependency behind the single
# seam in src/extract/decompress.cpp. All four are REQUIRED by default so a build
# always yields a fully-capable binary and a missing lib fails loudly at configure
# instead of silently dropping a codec. -DMORIA_OPTIONAL_CODECS=ON relaxes that for
# a minimal / identify-only build (a missing codec is then just disabled).
option(MORIA_OPTIONAL_CODECS "Build even if a decompressor is missing (disables that codec)" OFF)

macro(moria_require_codec found_var name pkg)
  if(NOT ${found_var} AND NOT MORIA_OPTIONAL_CODECS)
    message(FATAL_ERROR
      "${name} not found. Install its development package (e.g. ${pkg}), or pass "
      "-DMORIA_OPTIONAL_CODECS=ON to build without it (disables ${name} decoding).")
  endif()
endmacro()

find_package(ZLIB)
moria_require_codec(ZLIB_FOUND "zlib (gzip/DEFLATE)" "zlib1g-dev / zlib-devel")
if(ZLIB_FOUND)
  target_link_libraries(moria PRIVATE ZLIB::ZLIB)
  target_compile_definitions(moria PRIVATE MORIA_HAVE_ZLIB)
endif()

find_package(LibLZMA)
moria_require_codec(LibLZMA_FOUND "liblzma (xz/lzma)" "liblzma-dev / xz-devel")
if(LibLZMA_FOUND)
  target_link_libraries(moria PRIVATE LibLZMA::LibLZMA)
  target_compile_definitions(moria PRIVATE MORIA_HAVE_LZMA)
endif()

find_library(LZ4_LIB lz4)
find_path(LZ4_INC lz4.h)
set(LZ4_FOUND FALSE)
if(LZ4_LIB AND LZ4_INC)
  set(LZ4_FOUND TRUE)
endif()
moria_require_codec(LZ4_FOUND "liblz4" "liblz4-dev / lz4-devel")
if(LZ4_FOUND)
  target_link_libraries(moria PRIVATE ${LZ4_LIB})
  target_include_directories(moria PRIVATE ${LZ4_INC})
  target_compile_definitions(moria PRIVATE MORIA_HAVE_LZ4)
endif()

find_library(ZSTD_LIB zstd)
find_path(ZSTD_INC zstd.h)
set(ZSTD_FOUND FALSE)
if(ZSTD_LIB AND ZSTD_INC)
  set(ZSTD_FOUND TRUE)
endif()
moria_require_codec(ZSTD_FOUND "libzstd" "libzstd-dev / libzstd-devel")
if(ZSTD_FOUND)
  target_link_libraries(moria PRIVATE ${ZSTD_LIB})
  target_include_directories(moria PRIVATE ${ZSTD_INC})
  target_compile_definitions(moria PRIVATE MORIA_HAVE_ZSTD)
endif()

# Component unit tests for the engine primitives.
add_executable(moria_unit
  tests/unit/unit_tests.cpp
  src/expr.cpp
  src/layout.cpp
  src/resolve.cpp
  src/ahocorasick.cpp
  src/extract/lzo1x.cpp
  src/extract/lzari.cpp
  src/extract/ucl.cpp
  src/extract/upx_filter.cpp
  src/deobfuscate/cipher.cpp
  src/validators/upx.cpp
)
target_include_directories(moria_unit PRIVATE src)

enable_testing()
add_test(NAME moria_unit COMMAND moria_unit)

# The Python drivers are the bulk of the regression gate (extraction round-trips
# and per-format identify/extract checks), mirroring tests/run.sh. Each locates
# the built binary relative to its own path and self-skips cleanly (exit 0) when
# an optional maker tool is absent, so they are safe to register unconditionally.
# They need a Python 3 interpreter; without one only moria_unit above is run.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  set(_moria_py_tests
    test_samples
    test_extract
    test_human_tree
    test_partition
    test_legacy_fs
    test_luks
    test_rae_rfp
    test_vbf
    test_uboot_env
    test_vbmeta
    test_fit_signing
    test_upx
    test_upx_extract
    test_carve
    test_deobf
  )
  foreach(_t IN LISTS _moria_py_tests)
    add_test(
      NAME ${_t}
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/${_t}.py
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Install: just the binary and the man page. Every signature set is embedded in
# the binary at build time (self-contained), so a default run needs nothing on
# disk beside it. The on-disk sets are only consulted when the operator opts in
# with --sigs DIR or $MORIA_SIGDIR, and that developer flow already has the
# source/build tree on sig_roots(); installing ~13 MB of TOML that a normal run
# never reads is pure bloat, so it is not installed.
include(GNUInstallDirs)
install(TARGETS moria RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES moria.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 OPTIONAL)
