#include <_stdlib.h>
#include <assert.h>
#include <node_api.h>
#include <stdlib.h>
#include <uv.h>

typedef struct {
  uv_timer_t timer;
  napi_env env;
  napi_ref callback_ref;
  napi_threadsafe_function tsfn;
} addon_state;

void timer_cb(uv_timer_t *handle) {
  addon_state *state = handle->data;
  napi_status status =
      napi_call_threadsafe_function(state->tsfn, NULL, napi_tsfn_nonblocking);
  assert(status == napi_ok);
}

void call_js(napi_env env, napi_value js_callback, void *context, void *data) {
  if (env != NULL) {
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    napi_call_function(env, undefined, js_callback, 0, NULL, NULL);
  }
}

void tsfn_finalize(napi_env env, void *finalize_data, void *finalize_hint) {
  // Cleanup if needed (none here)
}

napi_value start_timer(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  napi_value jsthis;
  void *data;

  napi_get_cb_info(env, info, &argc, args, &jsthis, &data);

  if (argc < 2) {
    napi_throw_type_error(env, NULL, "Expected callback and timeout");
    return NULL;
  }

  napi_valuetype valuetype;
  napi_typeof(env, args[0], &valuetype);
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "First argument must be function");
    return NULL;
  }

  uint32_t timeout;
  napi_get_value_uint32(env, args[1], &timeout);

  addon_state *state;
  state = malloc(sizeof(*state));
  state->env = env;

  napi_create_reference(env, args[0], 1, &state->callback_ref);

  uv_timer_init(uv_default_loop(), &state->timer);
  state->timer.data = state;

  napi_value resource_name;
  napi_create_string_utf8(env, "TimerCallback", NAPI_AUTO_LENGTH,
                          &resource_name);

  napi_create_threadsafe_function(env, args[0], NULL, resource_name, 0, 1, NULL,
                                  tsfn_finalize, NULL, call_js, &state->tsfn);

  uv_timer_start(&state->timer, timer_cb, timeout, timeout);

  napi_value external;
  napi_create_external(env, state, NULL, NULL, &external);

  return external;
}

napi_value stop_timer(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value args[1];
  napi_get_cb_info(env, info, &argc, args, NULL, NULL);

  addon_state *state;
  napi_get_value_external(env, args[0], (void **)&state);

  uv_timer_stop(&state->timer);
  // uv_close((void *)&state->timer, NULL);

  napi_unref_threadsafe_function(env, state->tsfn);
  napi_delete_reference(env, state->callback_ref);

  free(state);

  return NULL;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor desc[] = {
      {"startTimer", 0, start_timer, 0, 0, 0, napi_default, 0},
      {"stopTimer", 0, stop_timer, 0, 0, 0, napi_default, 0}};
  napi_define_properties(env, exports, 2, desc);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODUE_NAME, Init)
