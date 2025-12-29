add_executable(not_so_fast main.cpp)
set_target_properties(not_so_fast PROPERTIES LINK_SEARCH_START_STATIC ON)
set_target_properties(not_so_fast PROPERTIES LINK_SEARCH_END_STATIC ON)
target_link_libraries(not_so_fast PRIVATE -static-libgcc -static-libstdc++ -static)
