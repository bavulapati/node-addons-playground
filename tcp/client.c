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

// Macro to automatically pass current function, file, and line to log_error
#define LOG_ERROR(msg) log_error(__func__, __FILE__, __LINE__, msg)

typedef struct {
  napi_env env;
  uv_connect_t *req;
  napi_ref on_data_ref;
  napi_ref on_connect_ref;
  napi_ref on_end_ref;
  napi_ref on_error_ref;
} addon_state;

void state_cleanup(void *finalize_data) {
  addon_state *state = finalize_data;
  if (state == NULL) {
    return;
  }

  if (state->on_connect_ref != NULL) {
    napi_delete_reference(state->env, state->on_connect_ref);
  }

  if (state->on_data_ref != NULL) {
    napi_delete_reference(state->env, state->on_data_ref);
  }

  if (state->on_end_ref != NULL) {
    napi_delete_reference(state->env, state->on_end_ref);
  }

  if (state->on_error_ref != NULL) {
    napi_delete_reference(state->env, state->on_error_ref);
  }

  free(state->req);
  state->req = NULL;
  free(state);
  state = NULL;
}

napi_status call_js(addon_state *state, napi_ref cb_ref, void *data) {
  napi_status status;

  napi_handle_scope scope;
  status = napi_open_handle_scope(state->env, &scope);
  if (status != napi_ok) {
    LOG_ERROR("Error opening napi handle scope");
    goto failed;
  }

  napi_value undefined;
  status = napi_get_undefined(state->env, &undefined);
  if (status != napi_ok) {
    LOG_ERROR("Error getting napi undefined value");
    goto failed;
  }

  napi_value cb;
  status = napi_get_reference_value(state->env, cb_ref, &cb);
  if (status != napi_ok) {
    LOG_ERROR("Error getting callback reference value");
    goto failed;
  }

  if (data != NULL) {
    bool isError;
    status = napi_is_error(state->env, *(napi_value *)data, &isError);
    if (status != napi_ok) {
      LOG_ERROR("Error checking if parameter is error");
      goto failed;
    }
    if (isError) {
      status = napi_call_function(state->env, undefined, cb, 1, data, NULL);
      if (status != napi_ok) {
        LOG_ERROR("Error calling function");
        goto failed;
      }
      goto free_data;
    }
    napi_value args[1];
    uv_buf_t *buf = data;
    status = napi_create_string_utf8(state->env, buf->base, buf->len, args);
    if (status != napi_ok) {
      LOG_ERROR("Error creating napi string");
      goto failed_data;
    }

    status = napi_call_function(state->env, undefined, cb, 1, args, NULL);
    if (status != napi_ok) {
      LOG_ERROR("Error calling function");
      goto failed_data;
    }
  } else {
    status = napi_call_function(state->env, undefined, cb, 0, NULL, NULL);
    if (status != napi_ok) {
      LOG_ERROR("Error calling function");
      goto failed_data;
    }
  }
  status = napi_close_handle_scope(state->env, scope);
  if (status != napi_ok) {
    LOG_ERROR("Error closing napi handle scope");
    goto failed_data;
  }

free_data:
  return napi_ok;

failed_data:
failed:
  free(data);
  data = NULL;
  const napi_extended_error_info *result;
  napi_status local_status;
  local_status = napi_get_last_error_info(state->env, &result);
  if (local_status != napi_ok) {
    LOG_ERROR("Error getting the last error info");
    status = local_status;
  } else {
    LOG_ERROR(result->error_message);
  }

  state_cleanup(state);
  return status;
}

void send_error(addon_state *state, char *errstr) {
  napi_status status;
  napi_value msg;
  napi_value *error;
  napi_handle_scope scope;

  status = napi_open_handle_scope(state->env, &scope);
  if (status != napi_ok) {
    LOG_ERROR("Error opening napi handle scope");
    return state_cleanup(state);
  }

  status = napi_create_string_utf8(state->env, errstr, NAPI_AUTO_LENGTH, &msg);
  if (status != napi_ok) {
    LOG_ERROR("Error creating napi string");
    return state_cleanup(state);
  }

  error = malloc(sizeof(*error));
  status = napi_create_error(state->env, NULL, msg, error);
  if (status != napi_ok) {
    LOG_ERROR("Error creating napi error");
    free(error);
    error = NULL;
    return state_cleanup(state);
  }

  status = call_js(state, state->on_error_ref, error);
  free(error);
  error = NULL;
  if (status != napi_ok) {
    LOG_ERROR("Error calling error callback");
    return state_cleanup(state);
  }
  status = napi_close_handle_scope(state->env, scope);
  if (status != napi_ok) {
    LOG_ERROR("Error closing napi handle scope");
    return state_cleanup(state);
  }
}

void send_error_napi(addon_state *state, napi_status status) {
  char errstr[124];
  const napi_extended_error_info *result;
  napi_status local_status;

  local_status = napi_get_last_error_info(state->env, &result);
  if (local_status != napi_ok) {
    LOG_ERROR("Error getting the last error info");
    return state_cleanup(state);
  }
  sprintf(errstr, "napi failure: %s\n", result->error_message);
  send_error(state, errstr);
}

void send_error_uv(addon_state *state, int err) {
  char errstr[124];

  sprintf(errstr, "libuv failure: %s\n", uv_strerror(err));
  send_error(state, errstr);
}

void throw_error_uv(napi_env env, int err) {
  char errstr[124];

  sprintf(errstr, "Error with tcp IP address: %s\n", uv_strerror(err));
  napi_throw_error(env, NULL, errstr);
}

void throw_error_napi(napi_env env, napi_status status) {
  char errstr[124];
  const napi_extended_error_info *result;

  napi_get_last_error_info(env, &result);
  sprintf(errstr, "ERROR: %s\n", result->error_message);
  napi_throw_error(env, NULL, errstr);
}

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  debug_log("allocating %zu Bytes\n", suggested_size);
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

void close_cb(uv_handle_t *handle) {
  debug_log("-------------Closed connection---------------\n");
  state_cleanup(handle->data);
  free(handle);
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  if (stream == NULL) {
    return;
  }
  napi_status status;
  addon_state *state = ((uv_handle_t *)stream)->data;
  if (nread > 0) {
    debug_log("read %zu Bytes\n", nread);
    buf->base[nread] = '\0';
    uv_buf_t *msg;
    msg = malloc(sizeof(*msg));
    msg->base = buf->base;
    msg->len = nread;

    debug_log("read %s\n", buf->base);
    status = call_js(state, state->on_data_ref, msg);
    if (status != napi_ok) {
      LOG_ERROR("Error calling data callback");
      send_error_napi(state, status);
      goto failed;
    }
    free(msg);
  } else {
    if (nread == UV_EOF) {
      debug_log("received EOF\n");
      status = call_js(state, state->on_end_ref, NULL);
      if (status != napi_ok) {
        LOG_ERROR("Error calling end callback");
        send_error_napi(state, status);
        goto failed;
      }
    } else {
      LOG_ERROR("Error while reading socket");
      send_error_uv(state, nread);
      goto failed;
    }
    goto failed;
  }

  free(buf->base);
  return;
failed:
  free(buf->base);
  uv_read_stop(stream);
  uv_tcp_close_reset((void *)stream, close_cb);
}

void connect_cb(uv_connect_t *req, int status) {
  uv_stream_t *stream = req->handle;
  addon_state *state = req->data;
  stream->data = state;

  if (status != 0) {
    LOG_ERROR("tcp connection erro");
    send_error_uv(state, status);
    goto failed;
  }

  debug_log("----------Connected-----------\n");

  if (call_js(state, state->on_connect_ref, NULL) != napi_ok) {
    LOG_ERROR("Error calling connect callback");
    goto failed;
  }

  status = uv_read_start(stream, alloc_cb, read_cb);
  if (status != 0) {
    LOG_ERROR("Error reading socket");
    goto failed;
  }
  return;

failed:
  uv_tcp_close_reset((void *)stream, close_cb);
}

napi_status validate_cb_input(napi_env env, size_t argc, napi_value *args) {
  napi_status status;

  if (argc < 5) {
    status = napi_throw_type_error(env, NULL, "Expected 5 args");
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

  return napi_ok;
}

napi_value ConnectToTcpSocket(napi_env env, napi_callback_info info) {
  napi_status status;
  const napi_extended_error_info *result;
  char erstr[124];

  size_t argc = 6;
  napi_value args[argc];
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  if (status != napi_ok) {
    LOG_ERROR("Error retrieving connect function arguments");
    throw_error_napi(env, status);
    return NULL;
  }

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
    goto failed_napi;
  }

  uint32_t port;
  status = napi_get_value_uint32(env, args[1], &port);
  if (status != napi_ok) {
    LOG_ERROR("Error reading port value");
    goto failed_napi;
  }

  addon_state *state;
  state = malloc(sizeof(*state));
  state->env = env;

  status = napi_create_reference(env, args[2], 1, &state->on_connect_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating reference");
    goto failed_napi;
  }
  status = napi_create_reference(env, args[3], 1, &state->on_data_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating reference");
    goto failed_napi;
  }
  status = napi_create_reference(env, args[4], 1, &state->on_end_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating reference");
    goto failed_napi;
  }
  status = napi_create_reference(env, args[5], 1, &state->on_error_ref);
  if (status != napi_ok) {
    LOG_ERROR("Error creating reference");
    goto failed_napi;
  }

  uv_tcp_t *socket;
  socket = malloc(sizeof(*socket));
  int err;

  err = uv_tcp_init(uv_default_loop(), socket);
  if (err != 0) {
    LOG_ERROR("Error initiating tcp socket");
    goto failed_tcp_init;
  }

  uv_connect_t *connect;
  connect = malloc(sizeof(*connect));
  state->req = connect;
  connect->data = state;

  struct sockaddr_in dest;
  err = uv_ip4_addr(host, port, &dest);
  if (err != 0) {
    LOG_ERROR("Error with tcp IP address");
    goto failed_tcp;
  }

  err = uv_tcp_connect(connect, socket, (void *)&dest, connect_cb);
  if (err != 0) {
    LOG_ERROR("Error connecting to tcp socket");
    goto failed_tcp;
  }

  goto free_host;

failed_tcp:
  free(connect);
  connect = NULL;
failed_tcp_init:
  free(socket);
  socket = NULL;
  throw_error_uv(env, err);
  goto free_state;
failed_napi:
  throw_error_napi(env, status);
free_state:
  state_cleanup(state);
free_host:
  free(host);
  host = NULL;

  return NULL;
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
