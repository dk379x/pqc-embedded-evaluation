/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

 #include <stdio.h>
 #include <inttypes.h>
 #include "sdkconfig.h"
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "esp_log.h"
 #include "esp_timer.h"
 #include "esp_task_wdt.h"
 #include "esp_heap_caps.h"
 
 #include <stdlib.h>
 #include <string.h>

#include <oqs.h>


void app_main(void) {
    printf("ESP32 + liboqs SPHINCS+ test\n");

    // NIST level 5
    //OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256s_simple);

    //NIST level 1
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_128s_simple);
    
    if (sig == NULL) {
        printf("OQS_SIG_new failed\n");
        return;
    }

    printf("Starting memory alocation\n");

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *message = (uint8_t *)"Hello PQ world!";
    uint8_t *signature = malloc(sig->length_signature);

    printf("Key generation...\n");

    // Wygeneruj klucze
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("keypair failed\n");
    } else {
        printf("Generated SPHINCS+ keypair OK\n");
    }

    // Podpisz wiadomość
    size_t sig_len;
    if (OQS_SIG_sign(sig, signature, &sig_len, message, strlen((char *)message), secret_key) != OQS_SUCCESS) {
        printf("sign failed\n");
    } else {
        printf("Signature created (len=%zu)\n", sig_len);
    }

    // Zweryfikuj podpis
    OQS_STATUS verified = OQS_SIG_verify(sig, message, strlen((char *)message),
                                         signature, sig_len, public_key);
    printf("Verify: %s\n", verified == OQS_SUCCESS ? "OK ✅" : "FAIL ❌");

    // Sprzątanie
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);

    // Pętla aby nie zakończyć taska
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

 /*
 void app_main(void) {
     printf("ESP32 SPHINCS+ implementation\n");
     //test_sphincsplus();
     while(1) {
         vTaskDelay(1000 / portTICK_PERIOD_MS);
     }
 }
*/
 