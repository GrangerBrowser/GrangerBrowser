cmake_minimum_required(VERSION 3.24)

project(GrangerBrowser
    VERSION 0.4.4
    DESCRIPTION "Granger Browser privacy browser with integrated search"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Svg Network Concurrent WebEngineWidgets)

qt_add_executable(granger_browser
    granger/main.cpp
    granger/browser/BrowserPage.cpp
    granger/browser/BrowserPage.h
    granger/browser/BrowserContextMenu.cpp
    granger/browser/BrowserContextMenu.h
    granger/browser/BrowserProfile.cpp
    granger/browser/BrowserProfile.h
    granger/browser/BrowserTab.cpp
    granger/browser/BrowserTab.h
    granger/browser/BrowserManager.cpp
    granger/browser/BrowserManager.h
    granger/browser/BrowserEngine.h
    granger/browser/BrowserTypes.h
    granger/browser/InternalPages.cpp
    granger/browser/InternalPages.h
    granger/browser/QtWebEngineBrowserEngine.cpp
    granger/browser/QtWebEngineBrowserEngine.h
    granger/pamp_lite/core/PampLiteEngine.cpp
    granger/pamp_lite/core/PampLiteEngine.h
    granger/pamp_lite/network/PampRoutedEnricher.cpp
    granger/pamp_lite/network/PampRoutedEnricher.h
    granger/bridges/BridgeManager.cpp
    granger/bridges/BridgeManager.h
    granger/bridges/BridgeProfile.h
    granger/bridges/QrBridgeDecoder.cpp
    granger/bridges/QrBridgeDecoder.h
    granger/core/AppPaths.cpp
    granger/core/AppPaths.h
    granger/core/Brand.cpp
    granger/core/Brand.h
    granger/core/BrandMigration.cpp
    granger/core/BrandMigration.h
    granger/core/BrandMigrationSmokeTests.cpp
    granger/core/BrandMigrationSmokeTests.h
    granger/core/BrandSmokeTests.cpp
    granger/core/BrandSmokeTests.h
    granger/core/EmergencyWipeManager.cpp
    granger/core/EmergencyWipeManager.h
    granger/core/LocalEventLogger.cpp
    granger/core/LocalEventLogger.h
    granger/features/FeatureSmokeTests.cpp
    granger/features/FeatureSmokeTests.h
    granger/containers/ContainerManager.cpp
    granger/containers/ContainerManager.h
    granger/i18n/Localization.cpp
    granger/i18n/Localization.h
    granger/i2p/I2pManager.cpp
    granger/i2p/I2pManager.h
    granger/network/NetworkManager.cpp
    granger/network/NetworkManager.h
    granger/network/GrangerNetworkUrl.cpp
    granger/network/GrangerNetworkUrl.h
    granger/network/GrangerNetworkRuntime.cpp
    granger/network/GrangerNetworkRuntime.h
    granger/network/GrangerHostingManager.cpp
    granger/network/GrangerHostingManager.h
    granger/network/GrangerWanConfigPaths.cpp
    granger/network/GrangerWanConfigPaths.h
    granger/network/GrangerNetworkBrowserSmokeTests.cpp
    granger/network/GrangerNetworkBrowserSmokeTests.h
    granger/network/PrivacyNetworkTypes.cpp
    granger/network/PrivacyNetworkTypes.h
    granger/network/PrivateRouteGateway.cpp
    granger/network/PrivateRouteGateway.h
    granger/network/PrivateRouteSmokeTests.cpp
    granger/network/PrivateRouteSmokeTests.h
    granger/network/PrivacyNetworkManager.cpp
    granger/network/PrivacyNetworkManager.h
    granger/platform/ManagedProcess.cpp
    granger/platform/ManagedProcess.h
    granger/privacy/PrivacyTypes.cpp
    granger/privacy/PrivacyTypes.h
    granger/privacy/PrivacyConfigSerializer.cpp
    granger/privacy/PrivacyConfigSerializer.h
    granger/privacy/ContentBlocker.cpp
    granger/privacy/ContentBlocker.h
    granger/privacy/PrivacyPolicyManager.cpp
    granger/privacy/PrivacyPolicyManager.h
    granger/privacy/PrivacyRequestInterceptor.cpp
    granger/privacy/PrivacyRequestInterceptor.h
    granger/privacy/PrivacySmokeTests.cpp
    granger/privacy/PrivacySmokeTests.h
    granger/privacy/PermissionManager.cpp
    granger/privacy/PermissionManager.h
    granger/search/SearchManager.cpp
    granger/search/SearchManager.h
    granger/security/HttpsFirstPolicy.cpp
    granger/security/HttpsFirstPolicy.h
    granger/settings/SettingsManager.cpp
    granger/settings/SettingsManager.h
    granger/tabs/TabManager.cpp
    granger/tabs/TabManager.h
    granger/tor/TorManager.cpp
    granger/tor/TorManager.h
    granger/tor/ConnectionStrategy.cpp
    granger/tor/ConnectionStrategy.h
    granger/tor/NetworkEnvironmentProbe.cpp
    granger/tor/NetworkEnvironmentProbe.h
    granger/ui/MainWindow.cpp
    granger/ui/MainWindow.h
    granger/ui/AnimationPolicy.cpp
    granger/ui/AnimationPolicy.h
    granger/ui/ConnectionUiState.cpp
    granger/ui/ConnectionUiState.h
    granger/ui/ContainerEditorDialog.cpp
    granger/ui/ContainerEditorDialog.h
    granger/ui/DesignTokens.h
    granger/ui/DownloadUi.cpp
    granger/ui/DownloadUi.h
    granger/ui/NavigationBar.cpp
    granger/ui/NavigationBar.h
    granger/ui/ScrollBarController.cpp
    granger/ui/ScrollBarController.h
    granger/ui/ThemeManager.cpp
    granger/ui/ThemeManager.h
    granger/ui/UiFocusSmokeTests.cpp
    granger/ui/UiFocusSmokeTests.h
    granger/resources/resources.qrc
    third_party/quirc/lib/quirc.c
    third_party/quirc/lib/decode.c
    third_party/quirc/lib/identify.c
    third_party/quirc/lib/version_db.c
)

if(UNIX AND NOT APPLE)
    target_sources(granger_browser PRIVATE
        granger/platform/linux/LinuxSignalHandler.cpp
        granger/platform/linux/LinuxSignalHandler.h
    )
endif()

if(WIN32)
    target_sources(granger_browser PRIVATE granger/resources/GrangerBrowser.rc)
endif()

target_include_directories(granger_browser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quirc/lib
)

target_link_libraries(granger_browser PRIVATE
    Qt6::Widgets
    Qt6::Svg
    Qt6::Network
    Qt6::Concurrent
    Qt6::WebEngineWidgets
)

if(UNIX AND NOT APPLE AND (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    target_compile_options(granger_browser PRIVATE
        "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=."
    )
endif()

set_target_properties(granger_browser PROPERTIES OUTPUT_NAME "GrangerBrowser")

if(WIN32)
    target_link_libraries(granger_browser PRIVATE Advapi32 Iphlpapi Psapi Shell32 User32 Winhttp Ws2_32)
    set_target_properties(granger_browser PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
endif()

include(GNUInstallDirs)
install(TARGETS granger_browser RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(UNIX AND NOT APPLE)
    install(FILES packaging/linux/granger-browser.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
    install(FILES granger/resources/app-icon.png
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/512x512/apps
        RENAME granger-browser.png)
endif()
