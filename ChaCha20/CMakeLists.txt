# CMakeList.txt : CMake project for ChaCha20, include source and define
# project specific logic here.
#

# Add source to this project's executable.
include_directories("cryptopp")
add_executable (cryptopp  "ChaCha20.h" "main.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET cryptopp PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
