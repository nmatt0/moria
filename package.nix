{
  lib,
  stdenv,
  cmake,
  ninja,
  pkg-config,
  zlib,
  xz,
  lz4,
  zstd,
}:
stdenv.mkDerivation {
  pname = "moria";
  # Single source of truth: the top-level VERSION file (CMakeLists.txt reads it too).
  version = lib.fileContents ./VERSION;
  src = ./.;

  nativeBuildInputs = [
    cmake
    ninja
    pkg-config
  ];

  buildInputs = [
    zlib
    xz
    lz4
    zstd
  ];

  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    # "-DMORIA_OPTIONAL_CODECS=ON"
  ];

  meta = with lib; {
    description = "IoT firmware identification and extraction (zero external extractors)";
    homepage = "https://github.com/nmatt0/moria";
    license = licenses.mit;
    maintainers = [ ];
    platforms = platforms.unix;
    mainProgram = "moria";
  };
}
