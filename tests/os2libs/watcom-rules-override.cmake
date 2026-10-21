# Loaded *after* CMake detects OpenWatcom and installs its generic rules.
# Generic CMake Watcom rules emit -c/-cc; wcc386 OS/2 uses -fo= instead.
set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER> <DEFINES> <INCLUDES> <FLAGS> -fo=<OBJECT> <SOURCE>")
set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> -q -b <TARGET> +<OBJECTS>")
set(CMAKE_C_ARCHIVE_FINISH "")
set(CMAKE_C_LINK_EXECUTABLE "<CMAKE_LINKER> system os2v2 name <TARGET> file <OBJECTS> <LINK_LIBRARIES>")
