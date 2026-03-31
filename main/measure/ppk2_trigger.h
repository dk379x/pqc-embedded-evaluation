#pragma once
#include "driver/gpio.h"

// GPIO10 - PIN nr 10 na plytce rozwojowej
#define PPK2_TRIGGER_GPIO GPIO_NUM_10

void ppk2_trigger_init(void);
void ppk2_trigger_start(void);
void ppk2_trigger_stop(void);