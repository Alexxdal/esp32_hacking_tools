if(IDF_TARGET STREQUAL "esp32" OR IDF_TARGET STREQUAL "esp32s2" OR IDF_TARGET STREQUAL "esp32s3")
  set(COMPONENT_SRCS
    pcap_file_generator.c
	pcap_file_reader.c
	utils.c
    )

  set(COMPONENT_ADD_INCLUDEDIRS
    ./
    )

  set(COMPONENT_REQUIRES fatfs vfs spi_flash)
	
  register_component()
endif()