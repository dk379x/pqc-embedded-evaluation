# components/liboqs/CMakeLists.txt

# --- MCU / arch workarounds (ESP32-C6 = RISC-V) ---
set(OQS_PERMIT_UNSUPPORTED_ARCHITECTURE ON CACHE BOOL "" FORCE)
set(OQS_DIST_BUILD ON CACHE BOOL "" FORCE)
set(OQS_USE_CPU_FEATURE_FLAGS OFF CACHE BOOL "" FORCE)

# --- Bez OpenSSL, bez testów, tylko biblioteka ---
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(OQS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)

# --- Zostaw minimalny zestaw algorytmów (zmień wg potrzeb) ---
set(OQS_ALGS_ENABLED "STANDARD" CACHE STRING "" FORCE)
set(OQS_ENABLE_KEM_ML_KEM_512 ON CACHE BOOL "" FORCE)
set(OQS_ENABLE_SIG_ML_DSA_65 ON CACHE BOOL "" FORCE)

# --- WYŁĄCZ generowanie install()/export() w liboqs ---
set(CMAKE_SKIP_INSTALL_RULES ON CACHE BOOL "" FORCE)
set(OQS_INSTALL OFF CACHE BOOL "" FORCE)
set(OQS_USE_CMAKE_CONFIG OFF CACHE BOOL "" FORCE)
set(OQS_SKIP_EXPORT ON CACHE BOOL "" FORCE)  # użyjemy tego w pliku liboqs

# Rejestrujemy nasz komponent (nie podajemy INCLUDE_DIRS ręcznie)
idf_component_register(SRCS "shim.c")

# Dołączamy liboqs jako subprojekt (masz go w components/liboqs/src)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/src
                 ${CMAKE_CURRENT_BINARY_DIR}/_liboqs_build
                 EXCLUDE_FROM_ALL)

# Linkowanie do targetu 'oqs' z liboqs
target_link_libraries(${COMPONENT_LIB} PRIVATE oqs)

# Propaguj include'y liboqs do konsumentów (main)
target_include_directories(${COMPONENT_LIB} INTERFACE
  $<TARGET_PROPERTY:oqs,INTERFACE_INCLUDE_DIRECTORIES>)