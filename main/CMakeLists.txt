idf_component_register(
    SRCS
        "main.c"
        # "bench/mlkem/bench_mlkem.c"
        #"bench/mldsa/bench_mldsa.c"
         "bench/slhdsa/bench_slhdsa.c"
        # "measure/ppk2_trigger.c"
        # "sensor/internal_temp.c"
        # "wireless/bt_le.c"
    INCLUDE_DIRS
        ""
        "bench"
        # "bench/mlkem"
        # "bench/mldsa"
         "bench/slhdsa"
        # "measure"
        # "sensor"
        # "wireless"
    REQUIRES
        # esp_driver_gpio
        # esp_timer
        # liboqs
        # driver
        # bt
        # nvs_flash
    )                    