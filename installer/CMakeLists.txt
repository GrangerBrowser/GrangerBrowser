cmake_minimum_required(VERSION 3.24)

set(GRANGER_INSTALLER_VERSION "0.4.4" CACHE STRING "Granger Setup product version")
project(GrangerSetup VERSION ${GRANGER_INSTALLER_VERSION} LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(EMMA_GIF_PATH "" CACHE FILEPATH "Path to the local Emma.gif build asset")
set(GRANGER_PACKAGE_ARCHIVE_PATH "" CACHE FILEPATH "Portable release archive to embed")
set(GRANGER_INSTALLER_MANIFEST_PATH "" CACHE FILEPATH "Offline release manifest to embed")
set(GRANGER_ICON_PATH "${CMAKE_CURRENT_LIST_DIR}/../granger/resources/GrangerBrowser.ico"
    CACHE FILEPATH "Path to the Granger application icon")

if(NOT WIN32)
    message(FATAL_ERROR "GrangerSetup is a Windows-only target")
endif()
if(NOT EXISTS "${EMMA_GIF_PATH}")
    message(FATAL_ERROR "EMMA_GIF_PATH must point to the local Banner_Installer/Emma.gif")
endif()
if(NOT EXISTS "${GRANGER_ICON_PATH}")
    message(FATAL_ERROR "GRANGER_ICON_PATH does not exist")
endif()
if(NOT EXISTS "${GRANGER_PACKAGE_ARCHIVE_PATH}")
    message(FATAL_ERROR "GRANGER_PACKAGE_ARCHIVE_PATH must point to the portable release archive")
endif()
if(NOT EXISTS "${GRANGER_INSTALLER_MANIFEST_PATH}")
    message(FATAL_ERROR "GRANGER_INSTALLER_MANIFEST_PATH must point to the offline release manifest")
endif()

file(TO_CMAKE_PATH "${EMMA_GIF_PATH}" EMMA_GIF_RESOURCE_PATH)
file(TO_CMAKE_PATH "${GRANGER_ICON_PATH}" GRANGER_ICON_RESOURCE_PATH)
file(TO_CMAKE_PATH "${GRANGER_PACKAGE_ARCHIVE_PATH}" GRANGER_PACKAGE_ARCHIVE_RESOURCE_PATH)
file(TO_CMAKE_PATH "${GRANGER_INSTALLER_MANIFEST_PATH}" GRANGER_INSTALLER_MANIFEST_RESOURCE_PATH)
set(GRANGER_RELEASE_RESOURCE_LINES
    "IDR_GRANGER_MANIFEST RCDATA \"${GRANGER_INSTALLER_MANIFEST_RESOURCE_PATH}\"\nIDR_GRANGER_PACKAGE RCDATA \"${GRANGER_PACKAGE_ARCHIVE_RESOURCE_PATH}\"")
configure_file(resources/GrangerSetup.rc.in ${CMAKE_CURRENT_BINARY_DIR}/GrangerSetup.rc @ONLY)

add_executable(GrangerSetup WIN32
    src/main.cpp
    src/resource.h
    ${CMAKE_CURRENT_BINARY_DIR}/GrangerSetup.rc
)

target_include_directories(GrangerSetup PRIVATE src)
target_compile_definitions(GrangerSetup PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    GRANGER_SETUP_VERSION=L"${PROJECT_VERSION}"
    # Do not embed build-machine paths in public WinRT error metadata.
    $<$<CONFIG:Release>:WINRT_NO_SOURCE_LOCATION>
)
target_compile_options(GrangerSetup PRIVATE /W4 /permissive- /EHsc /utf-8)
set_property(TARGET GrangerSetup PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(GrangerSetup PRIVATE
    Advapi32
    Bcrypt
    Comctl32
    Dwmapi
    Gdiplus
    Gdi32
    Ole32
    RuntimeObject
    Shell32
    Shlwapi
    User32
    Version
    WindowsApp
)

set_target_properties(GrangerSetup PROPERTIES
    OUTPUT_NAME "GrangerSetup"
    WIN32_EXECUTABLE TRUE
)
