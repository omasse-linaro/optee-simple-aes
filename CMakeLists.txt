cmake_minimum_required (VERSION 3.4)
project (optee_simple_aes C)

include(GNUInstallDirs)

# Default cross compile settings
set (CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
