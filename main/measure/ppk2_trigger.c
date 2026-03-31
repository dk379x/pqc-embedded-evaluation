#include "ppk2_trigger.h"


static gpio_num_t trigger_pin = PPK2_TRIGGER_GPIO;

void ppk2_trigger_init()
{
    gpio_num_t pin = trigger_pin;

    gpio_config_t io_conf = {
        .pin_bit_mask = 1ULL << pin,
        .mode = GPIO_MODE_OUTPUT,
    };

    gpio_config(&io_conf);
    gpio_set_level(trigger_pin, 0);
}

void ppk2_trigger_start(void)
{
    gpio_set_level(trigger_pin, 1);
}

void ppk2_trigger_stop(void)
{
    gpio_set_level(trigger_pin, 0);
}