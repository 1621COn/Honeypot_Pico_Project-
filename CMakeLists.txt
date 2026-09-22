cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico_w)

include(pico_sdk_import.cmake)

project(my_pico_w_project C CXX ASM)

pico_sdk_init()

add_executable(my_project
    honeypot.c
)

pico_generate_pio_header(my_project ${CMAKE_CURRENT_LIST_DIR}/alarm.pio)

target_link_libraries(my_project 
    pico_stdlib
   pico_cyw43_arch_lwip_threadsafe_background
    hardware_gpio
    hardware_pio
    hardware_i2c 
)

target_include_directories(my_project PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_LIST_DIR}  
)

target_compile_definitions(my_project PRIVATE
      CYW43_LWIP=1
)

pico_enable_stdio_usb(my_project 1)
pico_enable_stdio_uart(my_project 0)

pico_add_extra_outputs(my_project)
