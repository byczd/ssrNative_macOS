#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.7)
cmake_policy(SET CMP0048 NEW)
project(json-c VERSION 0.12.99)


include(CheckSymbolExists)

check_symbol_exists(strtoll "stdlib.h" HAVE_STRTOLL)

set(cmake_strtoll "strtoll")
if (NOT HAVE_STRTOLL)
  # Use _strtoi64 if strtoll is not available.
  check_symbol_exists(_strtoi64 stdlib.h have_strtoi64)
  if (have_strtoi64)
    set(HAVE_STRTOLL 1)
    set(cmake_strtoll "_strtoi64")
    # could do the same for strtoull, if needed
  endif ()
endif ()

set(JSON_C_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4100 /wd4996 /wd4244 /wd4706 /wd4702 /wd4127 /wd4701")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4100 /wd4996 /wd4244 /wd4706 /wd4702 /wd4127 /wd4701")
  set(cmake_create_config 1)
elseif(MINGW)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -D_GNU_SOURCE=1")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -D_GNU_SOURCE=1")
  if (MSYS OR CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    execute_process(COMMAND echo ${JSON_C_SOURCE_DIR} WORKING_DIRECTORY ${JSON_C_SOURCE_DIR})
    execute_process(COMMAND sh ${JSON_C_SOURCE_DIR}/autogen.sh WORKING_DIRECTORY ${JSON_C_SOURCE_DIR})
    execute_process(COMMAND sh ${JSON_C_SOURCE_DIR}/configure WORKING_DIRECTORY ${JSON_C_SOURCE_DIR})
    file(COPY ${JSON_C_SOURCE_DIR}/config.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/include/)
    file(COPY ${JSON_C_SOURCE_DIR}/json_config.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/include/)
  else()
    set(cmake_create_config 1)
  endif()
elseif(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -D_GNU_SOURCE")
  execute_process(COMMAND echo ${JSON_C_SOURCE_DIR} WORKING_DIRECTORY ${JSON_C_SOURCE_DIR})
  execute_process(COMMAND sh ${JSON_C_SOURCE_DIR}/autogen.sh WORKING_DIRECTORY ${JSON_C_SOURCE_DIR})
  execute_process(COMMAND ${JSON_C_SOURCE_DIR}/configure WORKING_DIRECTORY ${JSON_C_SOURCE_DIR})
  file(COPY ${JSON_C_SOURCE_DIR}/config.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/include/)
  file(COPY ${JSON_C_SOURCE_DIR}/json_config.h DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/include/)
endif()

if (cmake_create_config)
  file(REMOVE ${JSON_C_SOURCE_DIR}/config.h)  # make sure any stale one is gone
  configure_file(${JSON_C_SOURCE_DIR}/config.h.win32 ${CMAKE_CURRENT_BINARY_DIR}/include/config.h)
  file(COPY ${JSON_C_SOURCE_DIR}/json_config.h.win32 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/include/)
  file(RENAME ${CMAKE_CURRENT_BINARY_DIR}/include/json_config.h.win32 ${CMAKE_CURRENT_BINARY_DIR}/include/json_config.h)
endif ()

include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)
set(LIB_JSON_C_DIR ${JSON_C_SOURCE_DIR} CACHE INTERNAL "json-c library" FORCE)

set(JSON_C_PUBLIC_HEADERS
    ${JSON_C_SOURCE_DIR}/json.h
    ${CMAKE_CURRENT_BINARY_DIR}/include/config.h
    ${CMAKE_CURRENT_BINARY_DIR}/include/json_config.h
    ${JSON_C_SOURCE_DIR}/arraylist.h
    ${JSON_C_SOURCE_DIR}/debug.h
    ${JSON_C_SOURCE_DIR}/json_c_version.h
    ${JSON_C_SOURCE_DIR}/json_inttypes.h
    ${JSON_C_SOURCE_DIR}/json_object.h
    ${JSON_C_SOURCE_DIR}/json_pointer.h
    ${JSON_C_SOURCE_DIR}/json_tokener.h
    ${JSON_C_SOURCE_DIR}/json_util.h
    ${JSON_C_SOURCE_DIR}/linkhash.h
    ${JSON_C_SOURCE_DIR}/printbuf.h
)
set(JSON_C_HEADERS
    ${JSON_C_PUBLIC_HEADERS}
    ${JSON_C_SOURCE_DIR}/json_object_private.h
    ${JSON_C_SOURCE_DIR}/random_seed.h
    ${JSON_C_SOURCE_DIR}/strerror_override.h
    ${JSON_C_SOURCE_DIR}/strerror_override_private.h
    ${JSON_C_SOURCE_DIR}/math_compat.h
    ${JSON_C_SOURCE_DIR}/snprintf_compat.h
    ${JSON_C_SOURCE_DIR}/strdup_compat.h
    ${JSON_C_SOURCE_DIR}/vasprintf_compat.h
)

set(JSON_C_SOURCES
    ${JSON_C_SOURCE_DIR}/arraylist.c
    ${JSON_C_SOURCE_DIR}/debug.c
    ${JSON_C_SOURCE_DIR}/json_c_version.c
    ${JSON_C_SOURCE_DIR}/json_object.c
    ${JSON_C_SOURCE_DIR}/json_object_iterator.c
    ${JSON_C_SOURCE_DIR}/json_pointer.c
    ${JSON_C_SOURCE_DIR}/json_tokener.c
    ${JSON_C_SOURCE_DIR}/json_util.c
    ${JSON_C_SOURCE_DIR}/json_visit.c
    ${JSON_C_SOURCE_DIR}/linkhash.c
    ${JSON_C_SOURCE_DIR}/printbuf.c
    ${JSON_C_SOURCE_DIR}/random_seed.c
    ${JSON_C_SOURCE_DIR}/strerror_override.c
)

add_library(json-c
    STATIC
    ${JSON_C_SOURCES}
    ${JSON_C_HEADERS}
)

set_property(TARGET json-c PROPERTY C_STANDARD 99)


install(TARGETS json-c
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES ${JSON_C_PUBLIC_HEADERS} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/json-c )

if (UNIX)
	set(prefix ${CMAKE_INSTALL_PREFIX})
	set(exec_prefix ${CMAKE_INSTALL_PREFIX}/bin)
	set(libdir ${CMAKE_INSTALL_PREFIX}/lib)
	set(includedir ${CMAKE_INSTALL_PREFIX}/include)
	set(VERSION ${PROJECT_VERSION})
	configure_file(${JSON_C_SOURCE_DIR}/json-c.pc.in ${CMAKE_CURRENT_BINARY_DIR}/json-c.pc @ONLY)
	set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/json-c.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif ()
