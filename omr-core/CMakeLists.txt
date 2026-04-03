cmake_minimum_required(VERSION 3.13)
project(omr_core)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

set(FW ${CMAKE_CURRENT_SOURCE_DIR}/../b0/hybrid-HE-framework)

# SEAL (built in b0)
set(SEAL_DIR ${FW}/thirdparty/SEAL/build)
find_package(SEAL 4.1 REQUIRED PATHS ${SEAL_DIR})

# Keccak
add_library(keccak STATIC
    ${FW}/util/keccak/KeccakSpongeWidth1600.c
    ${FW}/util/keccak/KeccakHash.c
    ${FW}/util/keccak/opt64/KeccakP-1600-opt64.c
)
target_include_directories(keccak PUBLIC
    ${FW}/util/keccak
    ${FW}/util/keccak/opt64
)

# Common Zp SEAL base
add_library(common_zp STATIC
    ${FW}/ciphers/common_Zp/SEAL_Cipher.cpp
)
target_include_directories(common_zp PUBLIC
    ${FW}/ciphers/common_Zp
    ${FW}/ciphers
)
target_link_libraries(common_zp PUBLIC SEAL::seal keccak)

# Pasta-4 plain
add_library(pasta4_plain STATIC
    ${FW}/ciphers/pasta_4/plain/pasta_4_plain.cpp
)
target_include_directories(pasta4_plain PUBLIC
    ${FW}/ciphers/pasta_4/plain
    ${FW}/ciphers
)
target_link_libraries(pasta4_plain PUBLIC keccak)

# Pasta-4 SEAL (HE evaluation)
add_library(pasta4_seal STATIC
    ${FW}/ciphers/pasta_4/seal/pasta_4_seal.cpp
)
target_include_directories(pasta4_seal PUBLIC
    ${FW}/ciphers/pasta_4/seal
    ${FW}/ciphers
)
target_link_libraries(pasta4_seal PUBLIC common_zp pasta4_plain SEAL::seal)

# OMR core library
add_library(omr_lib STATIC
    src/pvw_he.cpp
)
target_include_directories(omr_lib PUBLIC src)
target_link_libraries(omr_lib PUBLIC SEAL::seal)

# OMR core binary
add_executable(omr-core src/main.cpp)
target_link_libraries(omr-core omr_lib pasta4_seal pasta4_plain common_zp SEAL::seal keccak)
target_include_directories(omr-core PRIVATE
    src
    ${FW}/ciphers
    ${FW}/ciphers/common_Zp
    ${FW}/ciphers/pasta_4/seal
    ${FW}/ciphers/pasta_4/plain
)
