@PACKAGE_INIT@

set(simpleio_VERSION "@PROJECT_VERSION@")

include(CMakeFindDependencyMacro)
find_dependency(Boost 1.74 REQUIRED COMPONENTS system log log_setup)
find_dependency(Microsoft.GSL 4 REQUIRED)
find_dependency(nlohmann_json 3.10 REQUIRED)
find_dependency(Poco 1.11 REQUIRED COMPONENTS Net XML)
find_dependency(OpenSSL 3 REQUIRED)

include("${CMAKE_CURRENT_LIST_DIR}/simpleioTargets.cmake")
