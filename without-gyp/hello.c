#include <assert.h>
#include <stdint.h>
#define NAPI_VERSION 3
#include <node_api.h>
#include <stdio.h>

#define CHECK_STATUS(status)                                                   \
  if (status != napi_ok) {                                                     \
    const napi_extended_error_info *result;                                    \
    assert(napi_get_last_error_info(env, &result) == napi_ok);                 \
    printf("ERROR: %s in file %s at line: %d\n", result->error_message,        \
           __FILE__, __LINE__);                                                \
    return NULL;                                                               \
  }

napi_value Hello(napi_env env, napi_callback_info info) {
  printf("Hello World!\n");
  napi_value ret;
  napi_status status = napi_create_int32(env, 1, &ret);
  CHECK_STATUS(status)
  return ret;
}

napi_value Add(napi_env env, napi_callback_info info) {
  napi_value sum;
  napi_status status;
  size_t argc = 2;
  napi_value argv[2];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  CHECK_STATUS(status)
  printf("TRACE: Add got %zu parameters:\n", argc);

  int32_t a, b;
  status = napi_get_value_int32(env, argv[0], &a);
  CHECK_STATUS(status)

  status = napi_get_value_int32(env, argv[1], &b);
  CHECK_STATUS(status)

  status = napi_create_int32(env, a + b, &sum);
  CHECK_STATUS(status)

  return sum;
}
void print_node_version(napi_env env) {
  napi_status status;
  const napi_node_version *version;
  status = napi_get_node_version(env, &version);
  if (status != napi_ok) {
    const napi_extended_error_info *result;
    assert(napi_get_last_error_info(env, &result) == napi_ok);
    printf("ERROR: %s in file %s at line: %d\n", result->error_message,
           __FILE__, __LINE__);
    return;
  }

  printf("Node release: %s\n", version->release);
  printf("Node Major version: %d\n", version->major);
  printf("Node Minor version: %d\n", version->minor);
  printf("Node Patch version: %d\n", version->patch);
  return;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;

  print_node_version(env);
  napi_property_descriptor desc[2] = {
      {"hello", NULL, Hello, NULL, NULL, NULL,
       napi_writable | napi_enumerable | napi_configurable, NULL},
      {.utf8name = "add",
       .method = Add,
       .attributes = napi_writable | napi_enumerable | napi_configurable}};
  status = napi_define_properties(env, exports, 2, desc);
  CHECK_STATUS(status)

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init);
