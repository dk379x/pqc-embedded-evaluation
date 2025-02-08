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
 
 #include "api.h"    // SPHINCS+ API
 #include "sign.h"   // SPHINCS+ Signing
 #include "params.h" // Parametry SPHINCS+
 
 static const char *TAG = "SPHINCS_Test";
 
 // 🔥 Funkcja do logowania czasu w formacie "ms,µs"
 void log_time(const char *operation, uint64_t start, uint64_t end) {
     uint64_t elapsed = end - start;
     uint64_t ms = elapsed / 1000;
     uint64_t us = elapsed % 1000;
     ESP_LOGI(TAG, "%s time: %llu,%03llu ms", operation, ms, us);
 }
 
 // 🔥 Funkcja do pomiaru RAM
 void log_ram_usage(const char *operation) {
     multi_heap_info_t heap_info;
     heap_caps_get_info(&heap_info, MALLOC_CAP_INTERNAL);
     ESP_LOGI(TAG, "%s RAM Usage: %d bytes", operation, heap_info.total_allocated_bytes);
 }
 
 // 🔥 Benchmark SPHINCS+
 void test_sphincs(void) {
     uint64_t start, end;
 
     uint8_t pk[CRYPTO_PUBLICKEYBYTES];   // Klucz publiczny
     uint8_t sk[CRYPTO_SECRETKEYBYTES];   // Klucz prywatny
     uint8_t message[] = "Test SPHINCS+ Signature";
     uint8_t signed_message[CRYPTO_BYTES + sizeof(message)];
     uint8_t unsigned_message[sizeof(message)];
     size_t signed_message_len, unsigned_message_len;
 
     ESP_LOGI(TAG, "Starting SPHINCS+ keypair generation...");
     
     log_ram_usage("Before Key Generation");
     start = esp_timer_get_time();
     
     if (crypto_sign_keypair(pk, sk) != 0) {
         ESP_LOGE(TAG, "Keypair generation failed.");
         while (1);
     }
     
     end = esp_timer_get_time();
     log_time("Keypair generation", start, end);
     log_ram_usage("After Key Generation");
 
     // 📝 Podpisanie wiadomości
     ESP_LOGI(TAG, "Signing message...");
     log_ram_usage("Before Signing");
     start = esp_timer_get_time();
 
     if (crypto_sign(signed_message, &signed_message_len, message, sizeof(message), NULL, 0, sk) != 0) {
         ESP_LOGE(TAG, "Message signing failed.");
         while (1);
     }
     
     end = esp_timer_get_time();
     log_time("Message signing", start, end);
     log_ram_usage("After Signing");
 
     // 📝 Weryfikacja podpisu
     ESP_LOGI(TAG, "Verifying signature...");
     log_ram_usage("Before Verification");
     start = esp_timer_get_time();
 
     if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, signed_message_len, NULL, 0, pk) != 0) {
         ESP_LOGE(TAG, "Signature verification failed.");
         while (1);
     }
     
     end = esp_timer_get_time();
     log_time("Signature verification", start, end);
     log_ram_usage("After Verification");
 
     // 📝 Porównanie wiadomości oryginalnej z odtworzoną
     ESP_LOGI(TAG, "Comparing original and unsigned messages...");
     
     if (unsigned_message_len != sizeof(message) || memcmp(message, unsigned_message, sizeof(message)) != 0) {
         ESP_LOGE(TAG, "Message comparison failed.");
         while (1);
     }
     
     ESP_LOGI(TAG, "Message comparison successful. Test passed.");
 }
 
 void app_main(void) {
     printf("ESP32 SPHINCS+ implementation\n");
     test_sphincs();
     while(1) {
         vTaskDelay(1000 / portTICK_PERIOD_MS);
     }
 }
 