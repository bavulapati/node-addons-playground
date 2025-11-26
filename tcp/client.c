#include "js_native_api.h"
#include "js_native_api_types.h"
#include <assert.h>
#include <node_api.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#ifdef DEBUG
#define debug_log(fmt, ...)                                                    \
  fprintf(stderr, "DEBUG %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__, \
          ##__VA_ARGS__)
#else
#define debug_log(fmt, ...) ((void)0)
#endif

// Error logging function
void log_error(const char *func, const char *file, int line, const char *msg) {
  fprintf(stderr, "Error in function %s at %s:%d - %s\n", func, file, line,
          msg);
}

#ifdef DEBUG
// Macro to automatically pass current function, file, and line to log_error
#define LOG_ERROR(msg) log_error(__func__, __FILE__, __LINE__, msg)
#else
#define LOG_ERROR(msg) ((void)0)
#endif

typedef struct {
  napi_env env;
  uv_connect_t *req;
  napi_ref on_data_ref;
  napi_ref on_connect_ref;
  napi_ref on_end_ref;
  napi_ref on_error_ref;
} addon_state;

addon_state *state_alloc() {
  addon_state *state;

  state = malloc(sizeof(*state));
  if (state == NULL) {
    return state;
  }
  state->env = NULL;
  state->req = NULL;
  state->on_connect_ref = NULL;
  state->on_data_ref = NULL;
  state->on_end_ref = NULL;
  state->on_error_ref = NULL;

  return state;
}

void state_cleanup(addon_state *state) {
  if (state == NULL) {
    return;
  }

  if (state->on_connect_ref != NULL) {
    napi_delete_reference(state->env, state->on_connect_ref);
    state->on_connect_ref = NULL;
  }

  if (state->on_data_ref != NULL) {
    napi_delete_reference(state->env, state->on_data_ref);
    state->on_data_ref = NULL;
  }

  if (state->on_end_ref != NULL) {
    napi_delete_reference(state->env, state->on_end_ref);
    state->on_end_ref = NULL;
  }

  if (state->on_error_ref != NULL) {
    napi_delete_reference(state->env, state->on_error_ref);
    state->on_error_ref = NULL;
  }

  if (state->req != NULL) {
    free(state->req);
    state->req = NULL;
  }

  free(state);
}

/* Helper: call JS callback with existing napi_value */
napi_status call_js_value(addon_state *state, napi_ref cb_ref, napi_value val) {
  napi_status status;

  napi_handle_scope scope;
  status = napi_open_handle_scope(state->env, &scope);
  if (status != napi_ok) {
    LOG_ERROR("Error opening napi handle scope");
    return status;
  }

  napi_value undefined;
  status = napi_get_undefined(state->env, &undefined);
  if (status != napi_ok) {
    LOG_ERROR("Error getting napi undefined value");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  napi_value cb;
  status = napi_get_reference_value(state->env, cb_ref, &cb);
  if (status != napi_ok) {
    LOG_ERROR("Error getting callback reference value");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  status = napi_call_function(state->env, undefined, cb, val != NULL ? 1 : 0,
                              val != NULL ? &val : NULL, NULL);
  if (status != napi_ok) {
    LOG_ERROR("Error calling function");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  status = napi_close_handle_scope(state->env, scope);
  if (status != napi_ok) {
    LOG_ERROR("Error closing napi handle scope");
  }
  return status;
}

/* Helper: call JS callback with C string + length (creates JS string) */
napi_status call_js_string(addon_state *state, napi_ref cb_ref, char *buf,
                           size_t len) {
  napi_status status;

  napi_handle_scope scope;
  status = napi_open_handle_scope(state->env, &scope);
  if (status != napi_ok) {
    LOG_ERROR("Error opening napi handle scope");
    return status;
  }

  napi_value undefined;
  status = napi_get_undefined(state->env, &undefined);
  if (status != napi_ok) {
    LOG_ERROR("Error getting napi undefined value");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  napi_value cb;
  status = napi_get_reference_value(state->env, cb_ref, &cb);
  if (status != napi_ok) {
    LOG_ERROR("Error getting callback reference value");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  napi_value str;
  status = napi_create_string_utf8(state->env, buf, len, &str);
  if (status != napi_ok) {
    LOG_ERROR("Error creating napi string");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  status = napi_call_function(state->env, undefined, cb, 1, &str, NULL);
  if (status != napi_ok) {
    LOG_ERROR("Error calling function");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  status = napi_close_handle_scope(state->env, scope);
  if (status != napi_ok) {
    LOG_ERROR("Error closing napi handle scope");
  }

  return status;
}

void send_error(addon_state *state, char *errstr) {
  napi_status status;
  napi_value msg;
  napi_value err_obj;
  napi_handle_scope scope;

  status = napi_open_handle_scope(state->env, &scope);
  if (status != napi_ok) {
    LOG_ERROR("Error opening napi handle scope");
    return state_cleanup(state);
  }

  status = napi_create_string_utf8(state->env, errstr, NAPI_AUTO_LENGTH, &msg);
  if (status != napi_ok) {
    LOG_ERROR("Error creating napi string");
    napi_close_handle_scope(state->env, scope);
    return state_cleanup(state);
  }

  status = napi_create_error(state->env, NULL, msg, &err_obj);
  if (status != napi_ok) {
    LOG_ERROR("Error creating napi error");
    napi_close_handle_scope(state->env, scope);
    return state_cleanup(state);
  }

  status = call_js_value(state, state->on_error_ref, err_obj);
  if (status != napi_ok) {
    LOG_ERROR("Error calling error callback");
    napi_close_handle_scope(state->env, scope);
    return state_cleanup(state);
  }
  status = napi_close_handle_scope(state->env, scope);
  if (status != napi_ok) {
    LOG_ERROR("Error closing napi handle scope");
  }
  return state_cleanup(state);
}

void send_error_napi(addon_state *state, napi_status status) {
  char errstr[256];
  const napi_extended_error_info *result;
  napi_status local_status;

  local_status = napi_get_last_error_info(state->env, &result);
  if (local_status == napi_ok && result && result->error_message) {
    sprintf(errstr, "napi failure: %s\n", result->error_message);
  } else {
    sprintf(errstr, "napi failure: unknown error\n");
  }
  LOG_ERROR(errstr);
  send_error(state, errstr);
}

void send_error_uv(addon_state *state, int err) {
  char errstr[256];

  sprintf(errstr, "libuv failure: %s\n", uv_strerror(err));
  send_error(state, errstr);
}

void throw_error_uv(napi_env env, int err) {
  char errstr[256];

  sprintf(errstr, "libuv error: %s\n", uv_strerror(err));
  napi_throw_error(env, NULL, errstr);
}

void throw_error_napi(napi_env env, napi_status status) {
  char errstr[256];
  const napi_extended_error_info *result;

  napi_get_last_error_info(env, &result);
  sprintf(errstr, "ERROR: %s\n", result->error_message);
  napi_throw_error(env, NULL, errstr);
}

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  debug_log("allocating %zu Bytes\n", suggested_size);
  buf->base = malloc(suggested_size);
  if (buf->base == NULL) {
    buf->len = 0;
    return;
  }
  buf->len = suggested_size;
}

void close_cb(uv_handle_t *handle) {
  debug_log("-------------Closed connection---------------\n");
  addon_state *state = handle->data;
  state_cleanup(state);
  handle->data = NULL;
  free(handle);
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  if (stream == NULL) {
    return;
  }

  addon_state *state = ((uv_handle_t *)stream)->data;
  if (state == NULL) {
    if (buf && buf->base) {
      free(buf->base);
      return;
    }
  }

  napi_status status;
  if (nread > 0) {
    debug_log("read %zu Bytes\n", nread);

    status = call_js_string(state, state->on_data_ref, buf->base, nread);
    if (status != napi_ok) {
      LOG_ERROR("Error calling data callback");
      send_error_napi(state, status);
    }
  } else {
    if (nread == UV_EOF) {
      debug_log("received EOF\n");
      status = call_js_value(state, state->on_end_ref, NULL);
      if (status != napi_ok) {
        LOG_ERROR("Error calling end callback");
        send_error_napi(state, status);
      }
    } else if (nread < 0) {
      LOG_ERROR("Error while reading socket");
      send_error_uv(state, nread);
    }
    if (buf && buf->base) {
      free(buf->base);
    }
    uv_read_stop(stream);
    uv_close((uv_handle_t *)stream, close_cb);
    return;
  }

  if (buf && buf->base) {
    free(buf->base);
  }
  return;
}

void connect_cb(uv_connect_t *req, int status) {
  uv_stream_t *stream = req->handle;
  addon_state *state = stream->data;

  if (status != 0) {
    LOG_ERROR("tcp connection erro");
    send_error_uv(state, status);
    stream->data = NULL;
    uv_close((void *)stream, close_cb);
    return;
  }

  debug_log("----------Connected-----------\n");
  napi_status ns = call_js_value(state, state->on_connect_ref, NULL);
  if (ns != napi_ok) {
    LOG_ERROR("Error calling connect callback");
    send_error_napi(state, ns);
    stream->data = NULL;
    uv_close((void *)stream, close_cb);
    return;
  }

  status = uv_read_start(stream, alloc_cb, read_cb);
  if (status != 0) {
    LOG_ERROR("Error starting read");
    send_error_uv(state, status);
    stream->data = NULL;
    uv_close((void *)stream, close_cb);
    return;
  }
}

napi_status validate_cb_input(napi_env env, size_t argc, napi_value *args) {
  napi_status status;

  if (argc < 6) {
    status = napi_throw_type_error(env, NULL, "Expected 6 args");
    return napi_invalid_arg;
  }

  napi_valuetype valuetype;
  status = napi_typeof(env, args[0], &valuetype);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving the type of host");
    throw_error_napi(env, status);
    return napi_generic_failure;
  }
  if (valuetype != napi_string) {
    napi_throw_type_error(env, NULL, "First argument must be host string");
    return napi_string_expected;
  }

  status = napi_typeof(env, args[1], &valuetype);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving the type of port");
    throw_error_napi(env, status);
    return napi_generic_failure;
  }
  if (valuetype != napi_number) {
    napi_throw_type_error(env, NULL, "Second argument must be port number");
    return napi_number_expected;
  }

  status = napi_typeof(env, args[2], &valuetype);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving the type of third parameter");
    throw_error_napi(env, status);
    return napi_generic_failure;
  }
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "Third argument must be function");
    return napi_function_expected;
  }

  status = napi_typeof(env, args[3], &valuetype);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving the type of fourth parameter");
    throw_error_napi(env, status);
    return napi_generic_failure;
  }
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "Fourth argument must be function");
    return napi_function_expected;
  }

  status = napi_typeof(env, args[4], &valuetype);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving the type of fifth parameter");
    throw_error_napi(env, status);
    return napi_generic_failure;
  }
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "Fifth argument must be function");
    return napi_function_expected;
  }

  status = napi_typeof(env, args[5], &valuetype);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving the type of sixth parameter");
    throw_error_napi(env, status);
    return napi_generic_failure;
  }
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "Sixth argument must be function");
    return napi_function_expected;
  }

  return napi_ok;
}

napi_value ConnectToTcpSocket(napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 6;
  napi_value args[argc];
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving connect function arguments");
    throw_error_napi(env, status);
    return NULL;
  }

  // validate_cb_input throws error, so we don't rethrow the error here
  status = validate_cb_input(env, argc, args);
  if (status != napi_ok) {
    LOG_ERROR("Invalid input");
    return NULL;
  }

  size_t host_len;
  status = napi_get_value_string_utf8(env, args[0], NULL, 0, &host_len);
  if (status != napi_ok) {
    LOG_ERROR("Error reading host length");
    throw_error_napi(env, status);
    return NULL;
  }

  char *host = malloc(sizeof(host_len + 1));
  status =
      napi_get_value_string_utf8(env, args[0], host, host_len + 1, &host_len);
  if (status != napi_ok) {
    LOG_ERROR("Error reading host value");
    free(host);
    throw_error_napi(env, status);
    return NULL;
  }

  uint32_t port;
  status = napi_get_value_uint32(env, args[1], &port);
  if (status != napi_ok) {
    LOG_ERROR("Error reading port value");
    free(host);
    throw_error_napi(env, status);
    return NULL;
  }

  addon_state *state;
  state = state_alloc();
  if (state == NULL) {
    LOG_ERROR("Error allocating memory for addon state");
    free(host);
    napi_throw_error(env, NULL, "Error allocating memory for addon state");
    return NULL;
  }
  state->env = env;

  status = napi_create_reference(env, args[2], 1, &state->on_connect_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating on_connect reference");
    state_cleanup(state);
    free(host);
    napi_throw_error(env, NULL, "Failed to create reference");
    return NULL;
  }
  status = napi_create_reference(env, args[3], 1, &state->on_data_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating on_data reference");
    state_cleanup(state);
    free(host);
    napi_throw_error(env, NULL, "Failed to create reference");
    return NULL;
  }
  status = napi_create_reference(env, args[4], 1, &state->on_end_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating on_data reference");
    state_cleanup(state);
    free(host);
    napi_throw_error(env, NULL, "Failed to create reference");
    return NULL;
  }
  status = napi_create_reference(env, args[5], 1, &state->on_error_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating on_error reference");
    state_cleanup(state);
    free(host);
    napi_throw_error(env, NULL, "Failed to create reference");
    return NULL;
  }

  uv_tcp_t *socket;
  socket = malloc(sizeof(*socket));
  int err;

  err = uv_tcp_init(uv_default_loop(), socket);
  if (err != 0) {
    LOG_ERROR("Error initiating tcp socket");
    free(socket);
    state_cleanup(state);
    free(host);
    throw_error_uv(env, err);
    return NULL;
  }

  struct sockaddr_in dest;
  err = uv_ip4_addr(host, port, &dest);
  if (err != 0) {
    LOG_ERROR("Error with tcp IP address");
    // cleanup wil free state->req inside state_cleanup
    free(socket);
    state_cleanup(state);
    free(host);
    throw_error_uv(env, err);
    return NULL;
  }

  free(host);
  uv_connect_t *connect;
  connect = malloc(sizeof(*connect));
  err = uv_tcp_connect(connect, socket, (void *)&dest, connect_cb);
  if (err != 0) {
    LOG_ERROR("Error connecting to tcp socket");
    free(socket);
    state_cleanup(state);
    throw_error_uv(env, err);
    return NULL;
  }
  state->req = connect;
  socket->data = state;

  // function returns undefined on success
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  return undefined;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;

  napi_property_descriptor desc[] = {
      {"connect", 0, ConnectToTcpSocket, 0, 0, 0, napi_default, 0}};

  status = napi_define_properties(env, exports, 1, desc);
  if (status != napi_ok) {
    LOG_ERROR("Error preparing addon exports");
    throw_error_napi(env, status);
    return NULL;
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
