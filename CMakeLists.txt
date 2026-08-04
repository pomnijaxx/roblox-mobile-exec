cmake_minimum_required(VERSION 3.22)
project(robloxexec LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(robloxexec SHARED
  jni_executor/scan.cpp
  jni_executor/hooks.cpp
  jni_executor/unc_api.cpp
  jni_executor/memops.cpp
  jni_executor/roblox_exec.cpp
)

target_include_directories(robloxexec PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/jni_executor
)

target_compile_definitions(robloxexec PRIVATE
  __ANDROID__           # forces jni.h / android/log.h branches
)

target_compile_options(robloxexec PRIVATE
  -fno-strict-aliasing
  -fvisibility=hidden   # keep the export surface minimal (JNIEXPORT re-exports)
  -Wall
)

# g_cur/g_sym are defined AND referenced in the same TU; clang-aarch64 emits
# non-GOT PC-relative access for those, which is only legal in a shared lib
# if the linker binds locally. -Bsymbolic makes the relocation resolvable.
if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Android")
  target_link_options(robloxexec PRIVATE -Wl,-Bsymbolic)
  target_link_libraries(robloxexec PRIVATE log android)
endif()

# Soname match used by patcher.py / System.loadLibrary
set_target_properties(robloxexec PROPERTIES
  OUTPUT_NAME "robloxexec"
  VERSION ""
  SOVERSION ""
)
