#ifndef BT_LE_H
#define BT_LE_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t bt_le_init(void);
void bt_le_update_payload(const char *payload);

#ifdef __cplusplus
}
#endif

#endif // BT_LE_H