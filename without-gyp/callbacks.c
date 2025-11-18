
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "node_api.h"
#include <assert.h>
#include <stddef.h>

napi_value RunCallback(napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value argv[1];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  napi_value cb = argv[0];
  napi_value cb_args[1];
  status = napi_create_string_utf8(env, "hello world from callback",
                                   NAPI_AUTO_LENGTH, cb_args);
  napi_value global;
  napi_value result;
  status = napi_get_global(env, &global);
  assert(status == napi_ok);
  status = napi_call_function(env, global, cb, 1, cb_args, &result);
  assert(status == napi_ok);

  return NULL;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  status = napi_create_function(env, NULL, 0, RunCallback, NULL, &exports);
  assert(status == napi_ok);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
