#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ta_key_storage.h>
#include <tee_client_api.h>
// Available commands
#define ENCRYPTION 0
#define DECRYPTION 1
#define SIGNATURE 2
#define VERIFICATION 3
#define HASH 4
#define KEYGENERATION 5
#define DHOP 6
#define DHDERIVE 7
#define DHGETPUBLIC 8
#define TESTSETGETKEY 9

#define TEE_TYPE_GENERIC_SECRET 0xA0000000
#define TEE_TYPE_RSA_KEYPAIR 0xA1000030
#define TEE_ALG_RSA_NOPAD 0x60000030
#define TEE_ALG_AES_ECB_NOPAD 0x10000010
#define TEE_ALG_AES_CBC_NOPAD 0x10000110
#define TEE_TYPE_AES 0xA0000010
#define TEE_ALG_SHA256 0x50000004
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 0x70414930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1 0x70212930

typedef enum { RSAALG = 0, AES = 1 } Algorithm_type;

int main() {
  TEEC_UUID uuid = TA_KEY_STORAGE_UUID;
  TEEC_Context context;
  TEEC_Session session;
  TEEC_Operation operation;
  TEEC_SharedMemory in_mem;
  TEEC_SharedMemory out_mem;
  TEEC_Result ret;

  memset(&operation, 0, sizeof(operation));
  printf("-- Initializing context.\n");
  ret = TEEC_InitializeContext(NULL, &context);
  if (ret != TEEC_SUCCESS) {
    printf("!! TEEC_InitializeContext failed: 0x%x\n", ret);
    return 0;
  }

  printf("-- Please select operation:\n-- 1 - Encrypt/Decrypt AES\n-- 2 - "
         "Encrypt/Decrypt RSA\n-- 3 - HASH\n-- 4 - Sign/Verify\n-- 5 - Key "
         "Exchange\n");
  int selection;
  scanf("%d", &selection);
  {
    char c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
  }
  if (selection == 1) {
    /* Clear the TEEC_Operation struct */
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    operation.params[0].value.a = 256;
    operation.params[0].value.b = TEE_TYPE_AES;
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 0;

    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    char *p;
    char *result;

    printf("-- Registering shared memories.\n");

    in_mem.buffer = NULL;
    in_mem.size = 256;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = NULL;
    out_mem.size = 256;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_AllocateSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_AllocateSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[2].memref.parent = &in_mem;
    operation.params[3].memref.parent = &out_mem;
    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    operation.params[2].memref.size = 256;
    operation.params[3].memref.size = 256;

    p = in_mem.buffer;
    result = out_mem.buffer;

    printf("-- Invoking command: Key Generation:\n");
    ret = TEEC_InvokeCommand(&session, KEYGENERATION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error generating key 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    uint32_t key_id = operation.params[0].value.a;
    printf("-- Key generation successful, the key id is: %d\n", key_id);

    printf("++ Enter key to encrypt:\n");

    fgets(p, 256, stdin);
    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    printf("-- Encrypting with generated AES key.\n");
    operation.params[0].value.a = key_id; // id
    operation.params[0].value.b = AES;
    operation.params[1].value.a = TEE_ALG_AES_ECB_NOPAD;
    ret = TEEC_InvokeCommand(&session, ENCRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error encrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Successful encryption\n");

    printf("-- Decrypting with generated AES key.\n");

    char *temp = malloc(256);
    memcpy(temp, result, 256);
    memcpy(result, p, 256);
    memcpy(p, temp, 256);
    free(temp);

    printf("-- The encrypted string is: ");

    for (uint32_t i = 0; i < in_mem.size; i++) {
      printf("%x", p[i]);
    }
    printf("\n");
    printf("-- The IV is: ");
    for (uint32_t i = 0; i < operation.params[1].value.b; i++) {
      printf("%x", result[i]);
    }
    printf("\n");

    ret = TEEC_InvokeCommand(&session, DECRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error decrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- The decrypted string is: ");
    printf("%s\n", result);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 2) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    operation.params[0].value.a = 1024;
    operation.params[0].value.b = TEE_TYPE_RSA_KEYPAIR;
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 0;

    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    char *p;
    char *result;

    printf("-- Registering shared memories.\n");

    in_mem.buffer = NULL;
    in_mem.size = 128;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = NULL;
    out_mem.size = 128;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_AllocateSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_AllocateSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[2].memref.parent = &in_mem;
    operation.params[3].memref.parent = &out_mem;
    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    operation.params[2].memref.size = 128;
    operation.params[3].memref.size = 128;

    p = in_mem.buffer;
    result = out_mem.buffer;

    printf("-- Invoking command: Key Generation:\n");
    ret = TEEC_InvokeCommand(&session, KEYGENERATION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error generating key 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    uint32_t key_id = operation.params[0].value.a;
    printf("-- Key generation successful, the key id is: %d\n", key_id);

    printf("++ Enter key to encrypt:\n");

    fgets(p, 256, stdin);

    printf("-- Encrypting with generated RSA key.\n");
    operation.params[0].value.a = key_id;
    operation.params[0].value.b = RSAALG;
    operation.params[1].value.a = TEE_ALG_RSA_NOPAD;
    ret = TEEC_InvokeCommand(&session, ENCRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error encrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Successful encryption\n");
    printf("-- The encrypted string is: ");
    for (uint32_t i = 0; i < in_mem.size; i++) {
      printf("%x", result[i]);
    }
    printf("\n");

    printf("-- Decrypting with generated RSA key.\n");

    // TEEC_ReleaseSharedMemory(&out_mem);
    // TEEC_ReleaseSharedMemory(&in_mem);
    //
    // in_mem.buffer = result;
    // out_mem.buffer = p;
    //
    // ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    // if (ret != TEEC_SUCCESS) {
    //   printf("!! Error registering output memory 0x%x\n", ret);
    //   TEEC_CloseSession(&session);
    //   TEEC_FinalizeContext(&context);
    //   return 0;
    // }
    //
    // ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    // if (ret != TEEC_SUCCESS) {
    //   printf("!! Error registering input memory 0x%x\n", ret);
    //   TEEC_CloseSession(&session);
    //   TEEC_FinalizeContext(&context);
    //   return 0;
    // }

    memcpy(p, result, 128);
    ret = TEEC_InvokeCommand(&session, DECRYPTION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error decrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- The decrypted string is: %s", (char *)result);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 3) {
    char *p;
    char *result;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    operation.params[0].value.a = TEE_ALG_SHA256;
    operation.params[0].value.b = 0;
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 0;

    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Registering shared memories.\n");

    in_mem.buffer = NULL;
    in_mem.size = 256;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = NULL;
    out_mem.size = 256;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_AllocateSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_AllocateSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    p = in_mem.buffer;
    result = out_mem.buffer;
    memset(p, 'z', 256);
    memset(result, 'z', 256);
    operation.params[2].memref.parent = &in_mem;
    operation.params[3].memref.parent = &out_mem;
    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    operation.params[2].memref.size = 256;
    operation.params[3].memref.size = 256;

    printf("++ Enter text to digest:\n");

    fgets(p, 256, stdin);

    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    printf("-- Invoking command: HASH:\n");
    ret = TEEC_InvokeCommand(&session, HASH, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error at HASH 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Success. The result is: ");
    printf("%d\n", operation.params[0].value.b);
    result = (char *)out_mem.buffer;
    for (uint32_t i = 0; i < operation.params[0].value.b; i++) {
      printf("%x", result[i]);
    }
    printf("\n");
    TEEC_ReleaseSharedMemory(&out_mem);
    TEEC_ReleaseSharedMemory(&in_mem);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 4) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    char *p;
    char *result;

    printf("-- Registering shared memories.\n");

    in_mem.buffer = NULL;
    in_mem.size = 32;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = NULL;
    out_mem.size = 128;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_AllocateSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_AllocateSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    operation.params[2].memref.size = 32;
    operation.params[3].memref.size = 128;

    p = in_mem.buffer;
    result = out_mem.buffer;

    operation.params[2].memref.parent = &in_mem;
    operation.params[3].memref.parent = &out_mem;

    operation.params[0].value.a = 1024;
    operation.params[0].value.b = TEE_TYPE_RSA_KEYPAIR;
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 0;

    printf("befor keygen %d\n", operation.params[2].memref.size);
    printf("-- Invoking command: Key Generation:\n");
    ret = TEEC_InvokeCommand(&session, KEYGENERATION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error generating key 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    uint32_t key_id = operation.params[0].value.a;
    printf("-- Key generation successful, the key id is: %d\n", key_id);

    printf("++ Enter text to digest:\n");

    fgets(p, 32, stdin);

    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    operation.params[0].value.a = TEE_ALG_SHA256;

    // operation.params[2].memref.offset = 0;
    // operation.params[3].memref.offset = 0;
    // printf("befor strlen %d\n", operation.params[2].memref.size);
    // operation.params[2].memref.size = strlen(p);
    // printf("after strlen %d\n", operation.params[2].memref.size);

    printf("-- Invoking command: HASH:\n");
    ret = TEEC_InvokeCommand(&session, HASH, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error at HASH 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    memcpy(p, result, 32);
    printf("-- Success. The result is: ");
    for (uint32_t i = 0; i < 256 / 8; i++) {
      printf("%x", p[i]);
    }
    printf("\n");

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;

    printf("-- Signing with generated RSA key.\n");
    operation.params[0].value.a = key_id;
    operation.params[0].value.b = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
    ret = TEEC_InvokeCommand(&session, SIGNATURE, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error encrypting 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Successful signing\n");
    char *signature = malloc(128);
    memcpy(signature, result, 128);

    printf("-- The signature string is: ");
    for (uint32_t i = 0; i < 128; i++) {
      printf("%x", result[i]);
    }
    printf("\n");

    printf("-- Verification with generated RSA key.\n");

    printf("++ Enter text to digest:\n");
    fgets(p, 32, stdin);

    {
      char *pos;
      if ((pos = strchr(p, '\n')) != NULL) {
        *pos = '\0';
      }
    }

    operation.params[0].value.a = TEE_ALG_SHA256;

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;

    printf("-- Invoking command: HASH:\n");
    ret = TEEC_InvokeCommand(&session, HASH, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error at HASH 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    memcpy(p, result, 32);
    printf("-- Success. The result is: ");
    for (uint32_t i = 0; i < 256 / 8; i++) {
      printf("%x", p[i]);
    }
    printf("\n");

    memcpy(result, signature, 128);

    operation.params[0].value.a = key_id;
    operation.params[0].value.b = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;

    ret = TEEC_InvokeCommand(&session, VERIFICATION, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf(
          "!! Error veryfying 0x%x\n!! The hash did not match the signature\n",
          ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    printf("-- Message verified\n");

    TEEC_ReleaseSharedMemory(&out_mem);
    TEEC_ReleaseSharedMemory(&in_mem);

    printf("-- Test operation ended successfuly\n");
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
  }
  if (selection == 5) {
    const unsigned char dh512_p[] = {
        0xCD, 0xED, 0xF9, 0x6D, 0x4C, 0x65, 0x05, 0xFA, 0x8C, 0x7B, 0xBC,
        0xF8, 0x5D, 0x6E, 0xA8, 0xAB, 0x95, 0x4C, 0x21, 0x55, 0x00, 0xA8,
        0xC6, 0xF8, 0x90, 0x1D, 0xB6, 0x9B, 0x97, 0xC8, 0xFE, 0x57, 0xAD,
        0x56, 0xAA, 0xE2, 0xBE, 0xE8, 0x03, 0xF5, 0xB6, 0x1B, 0x2B, 0x82,
        0xFE, 0x00, 0xBB, 0x76, 0x1F, 0x15, 0x1A, 0x64, 0x89, 0x89, 0x78,
        0x07, 0x4E, 0x0E, 0xF3, 0xEA, 0xC4, 0x0D, 0x25, 0x83,
    };
    const unsigned char dh512_g[] = {
        0x02,
    };

    static unsigned char dh2048_p[] = {
        0xEA, 0x54, 0xE6, 0x37, 0x99, 0x0F, 0xE0, 0x2F, 0xBC, 0x43, 0xC9, 0x2C,
        0x46, 0x8E, 0x9D, 0x9B, 0x1C, 0x76, 0x1E, 0xEC, 0x4C, 0x08, 0xA9, 0x51,
        0x26, 0xED, 0x29, 0x8D, 0x40, 0x38, 0x28, 0x07, 0x55, 0x9F, 0x5E, 0x49,
        0xAC, 0xCD, 0x8C, 0xFF, 0x42, 0xD2, 0xB6, 0x47, 0x88, 0x74, 0x7E, 0xB2,
        0x56, 0xFE, 0x2D, 0xD9, 0xAE, 0xA2, 0x29, 0xD2, 0xE4, 0x41, 0x68, 0x78,
        0x07, 0x6C, 0x4C, 0x4F, 0x49, 0xFF, 0x03, 0x57, 0x7C, 0xCD, 0x8A, 0x20,
        0xC2, 0x88, 0x1D, 0x9B, 0x80, 0xA6, 0x3F, 0x74, 0x61, 0xB9, 0x74, 0x62,
        0x65, 0x0E, 0x29, 0x22, 0xF5, 0x0C, 0xFF, 0x5E, 0xBB, 0x87, 0x56, 0xEE,
        0x20, 0xA3, 0x4A, 0xEA, 0x53, 0x7F, 0xC7, 0x9D, 0x51, 0xD7, 0x35, 0xDB,
        0x1D, 0x53, 0xA3, 0x2F, 0xD6, 0xC2, 0xDF, 0x4A, 0x41, 0xAA, 0x20, 0x5B,
        0x26, 0xB0, 0x11, 0x8F, 0xA9, 0x2E, 0xD0, 0x26, 0xE1, 0xCC, 0xC7, 0x69,
        0x4F, 0x67, 0x9C, 0x2C, 0xE7, 0x4C, 0x16, 0xB5, 0x17, 0x01, 0x5A, 0x1D,
        0x7B, 0xE1, 0x63, 0xC7, 0xF1, 0x69, 0x87, 0x80, 0x0F, 0xDC, 0x78, 0xDA,
        0xEA, 0xC0, 0x08, 0x10, 0x1F, 0xE9, 0x55, 0x77, 0x3B, 0xAD, 0xFD, 0x23,
        0x88, 0x45, 0xF9, 0x8A, 0x5D, 0x6D, 0xBF, 0xB6, 0xC6, 0xAF, 0xE3, 0x39,
        0xD9, 0x80, 0x66, 0xA8, 0x0B, 0x4D, 0x02, 0xB9, 0xAA, 0x0F, 0x25, 0xB2,
        0xDB, 0x88, 0xF4, 0xE0, 0xC0, 0x22, 0xB0, 0x47, 0xC8, 0xB4, 0xB4, 0x9F,
        0x74, 0x31, 0xCD, 0xBC, 0x9B, 0xF6, 0x1B, 0x12, 0x54, 0x81, 0x61, 0x5B,
        0x60, 0x97, 0x39, 0x82, 0x73, 0x88, 0xFF, 0xFA, 0xA2, 0x2F, 0x07, 0xD7,
        0x4B, 0x71, 0x34, 0xB1, 0xCA, 0x08, 0x72, 0x11, 0xC4, 0x6A, 0xB0, 0xBB,
        0xCA, 0xC5, 0x78, 0x77, 0x92, 0x35, 0x87, 0xBB, 0x72, 0x11, 0xBF, 0x24,
        0x0B, 0x1A, 0x49, 0xEB,
    };
    static unsigned char dh2048_g[] = {
        0x05,
    };

    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    char *buffer1;
    char *buffer2;

    printf("-- Registering shared memories.\n");

    in_mem.buffer = NULL;
    in_mem.size = 2048;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = NULL;
    out_mem.size = 2048;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_AllocateSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_AllocateSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[2].memref.parent = &in_mem;
    operation.params[3].memref.parent = &out_mem;
    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    operation.params[2].memref.size = 2048;
    operation.params[3].memref.size = 2048;

    buffer1 = in_mem.buffer;
    buffer2 = out_mem.buffer;
    // BIGNUM *mem1 = BN_bin2bn(dh512_p, (int)sizeof(dh512_p), NULL);
    // BIGNUM *mem2 = BN_bin2bn(dh512_g, (int)sizeof(dh512_g), NULL);
    memcpy(buffer1, dh512_p, sizeof(dh512_p));
    memcpy(buffer2, dh512_g, sizeof(dh512_g));

    operation.params[0].value.a = 0;
    operation.params[0].value.b = 0;
    operation.params[1].value.a = sizeof(dh512_p);
    operation.params[1].value.b = sizeof(dh512_g);

    printf("-- Generating DH keys\n");
    ret = TEEC_InvokeCommand(&session, DHOP, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error generating key1 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    uint32_t id1 = operation.params[0].value.a;
    printf("-- Key 1 id: %d\n", id1);

    ret = TEEC_InvokeCommand(&session, DHOP, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error generating key1 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    uint32_t id2 = operation.params[0].value.a;
    printf("-- Key 2 id: %d\n", id2);

    // in_mem.size = 128;
    // out_mem.size = 128;
    // ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    // if (ret != TEEC_SUCCESS) {
    //   printf("!! Error registering input memory 0x%x\n", ret);
    //   TEEC_CloseSession(&session);
    //   TEEC_FinalizeContext(&context);
    //   return 0;
    // }
    //
    // ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    // if (ret != TEEC_SUCCESS) {
    //   printf("!! Error registering output memory 0x%x\n", ret);
    //   TEEC_CloseSession(&session);
    //   TEEC_FinalizeContext(&context);
    //   return 0;
    // }

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    // operation.params[2].memref.size = 128;
    // operation.params[3].memref.size = 128;

    printf("-- Getting public DH keys\n");
    operation.params[0].value.a = id1;
    ret = TEEC_InvokeCommand(&session, DHGETPUBLIC, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error getting public key 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    uint32_t public1_size = operation.params[0].value.b;
    char *public1 = malloc(public1_size);
    memcpy(public1, buffer1, public1_size);

    operation.params[0].value.a = id2;
    ret = TEEC_InvokeCommand(&session, DHGETPUBLIC, &operation, NULL);
    uint32_t public2_size = operation.params[0].value.b;
    char *public2 = malloc(public2_size);
    memcpy(public2, buffer1, public2_size);

    printf("Public1:\n");
    for (uint32_t i = 0; i < public1_size; i++) {
      printf("%x", public1[i]);
    }
    printf("\nPublic2:\n");
    for (uint32_t i = 0; i < public2_size; i++) {
      printf("%x", public2[i]);
    }
    printf("\n");

    printf("-- Deriving private DH keys\n");

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;

    operation.params[0].value.a = id1;
    operation.params[0].value.b = public2_size;
    memcpy(buffer1, public2, public2_size);
    ret = TEEC_InvokeCommand(&session, DHDERIVE, &operation, NULL);
    uint32_t secret1_size = operation.params[1].value.b;
    char *secret1 = malloc(secret1_size);
    memcpy(secret1, buffer1, secret1_size);

    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;

    operation.params[0].value.a = id2;
    operation.params[0].value.b = public1_size;
    memcpy(buffer1, public1, public1_size);

    ret = TEEC_InvokeCommand(&session, DHDERIVE, &operation, NULL);
    uint32_t secret2_size = operation.params[1].value.b;
    char *secret2 = malloc(secret2_size);
    memcpy(secret2, buffer1, secret2_size);

    printf("Secret1:\n");
    for (uint32_t i = 0; i < secret1_size; i++) {
      printf("%x", secret1[i]);
    }
    printf("\nSecret2:\n");
    for (uint32_t i = 0; i < secret2_size; i++) {
      printf("%x", secret2[i]);
    }
    printf("\n");
    return 0;
  }
  if (selection == 6) {
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE,
                         TEEC_MEMREF_WHOLE);
    printf("-- Opening session.\n");
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL,
                           NULL, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! TEEC_OpenSession failed: 0x%x\n", ret);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    char *buffer1;
    char *buffer2;

    printf("-- Registering shared memories.\n");

    in_mem.buffer = NULL;
    in_mem.size = 2048;
    in_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    out_mem.buffer = NULL;
    out_mem.size = 2048;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_AllocateSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_AllocateSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error allocating output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering input memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error registering output memory 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }

    operation.params[2].memref.parent = &in_mem;
    operation.params[3].memref.parent = &out_mem;
    operation.params[2].memref.offset = 0;
    operation.params[3].memref.offset = 0;
    operation.params[2].memref.size = 2048;
    operation.params[3].memref.size = 2048;

    buffer1 = in_mem.buffer;
    buffer2 = out_mem.buffer;
    
    char * key = "test";
    memcpy(buffer1, key, strlen(key));
    printf("-- Invoking command: Get-Set Key:\n");
    ret = TEEC_InvokeCommand(&session, TESTSETGETKEY, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
      printf("!! Error generating key 0x%x\n", ret);
      TEEC_CloseSession(&session);
      TEEC_FinalizeContext(&context);
      return 0;
    }
    printf("Key id is: %d\n", operation.params[0].value.a);

    printf("Key returned: %s\nWith a size of: %d\n", buffer2, operation.params[1].value.b);

    printf("Program ended succesfully");

   
    
  }
}

