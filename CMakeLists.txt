cmake_minimum_required(VERSION 3.16)
project(CryoJS VERSION 1.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(duktape STATIC
    third_party/duktape/duktape.c
)
target_include_directories(duktape PUBLIC third_party/duktape)
if(MSVC)
    target_compile_options(duktape PRIVATE /W0)
else()
    target_compile_options(duktape PRIVATE -w)
endif()

add_library(miniz STATIC
    third_party/miniz/miniz.c
    third_party/miniz/miniz_tdef.c
    third_party/miniz/miniz_tinfl.c
    third_party/miniz/miniz_zip.c
)
target_include_directories(miniz PUBLIC third_party/miniz)
if(MSVC)
    target_compile_options(miniz PRIVATE /W0)
else()
    target_compile_options(miniz PRIVATE -w)
endif()

set(AES_DEFS AES256=1 AES128=0 AES192=0 CBC=1 ECB=0 CTR=0)

add_executable(CryoJS
    src/main.cpp
    third_party/tiny-aes/aes.c
)
target_link_libraries(CryoJS PRIVATE duktape miniz)
target_include_directories(CryoJS PRIVATE third_party/duktape third_party/tiny-aes third_party/miniz src)
target_compile_definitions(CryoJS PRIVATE ${AES_DEFS} CRYOJS_VERSION="${PROJECT_VERSION}")
if(MSVC)
    set_source_files_properties(third_party/tiny-aes/aes.c PROPERTIES COMPILE_FLAGS "/W0")
else()
    set_source_files_properties(third_party/tiny-aes/aes.c PROPERTIES COMPILE_FLAGS "-w")
endif()

add_executable(cryopack
    src/cryopack.cpp
    third_party/tiny-aes/aes.c
)
target_link_libraries(cryopack PRIVATE miniz)
target_include_directories(cryopack PRIVATE third_party/tiny-aes third_party/miniz src)
target_compile_definitions(cryopack PRIVATE ${AES_DEFS})
if(MSVC)
    set_source_files_properties(third_party/tiny-aes/aes.c PROPERTIES COMPILE_FLAGS "/W0")
else()
    set_source_files_properties(third_party/tiny-aes/aes.c PROPERTIES COMPILE_FLAGS "-w")
endif()
