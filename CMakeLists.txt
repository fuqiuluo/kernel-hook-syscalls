cmake_minimum_required(VERSION 3.30)
project(trs)

set(CMAKE_CXX_STANDARD 20)

add_executable(trs
        main.cpp
        Commands/TraceLog.cpp
        Client.cpp
        Parser/Parser.h
        Parser/Parser.cpp
        Parser/Syscalls.h
        fnla.cpp
        fnla.h
        Parser/Syscalls.cpp
)

target_include_directories(trs PRIVATE ${CMAKE_SOURCE_DIR}/Lyra/include)
