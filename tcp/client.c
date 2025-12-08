#include <assert.h>
#include <node_api.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

int net_num_of_allocations = 0;
void *debug_mem_malloc(size_t size, const char *func, uint32_t line) {
  printf("allocating memory of size %zu at line:%u in func:%s\n", size, line,
         func);
  net_num_of_allocations += 1;
  return malloc(size);
}

void debug_mem_free(void *memory, const char *func, uint32_t line) {
  printf("freeing memory %p at line:%u in func:%s\n", memory, line, func);
  net_num_of_allocations -= 1;
  return free(memory);
}

#ifdef MEMORY_DEBUG

#define malloc(n)                                                              \
  debug_mem_malloc(n, __func__, __LINE__) /* Replaces malloc.                  \
                                           */
#define realloc(n, m)                                                          \
  debug_mem_realloc(n, m, __func__, __LINE__)         /* Replaces realloc. */
#define free(n) debug_mem_free(n, __func__, __LINE__) /* Replaces free. */

#endif

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
// Info logging function
void log_info(const char *func, const char *file, int line, const char *msg) {
  fprintf(stdout, "[%s at %s:%d - %s]\n", func, file, line, msg);
}

#ifdef DEBUG
// Macro to automatically pass current function, file, and line to log_error
#define LOG_ERROR(msg) log_error(__func__, __FILE__, __LINE__, msg)
#define LOG_INFO(msg) log_info(__func__, __FILE__, __LINE__, msg)
#else
#define LOG_ERROR(msg) ((void)0)
#define LOG_INFO(msg) ((void)0)
#endif

typedef struct {
  napi_env env;
  napi_ref on_data_ref;
  napi_ref on_connect_ref;
  napi_ref on_end_ref;
  napi_ref on_error_ref;
} state_t;

void print_state(state_t *state) {
  if (state == NULL) {
    printf("state is NULL\n");
    return;
  } else {
    printf("state is not NULL\n");
  }

  if (state->on_connect_ref != NULL) {
    printf("state->on_connect_ref is not NULL\n");
  } else {
    printf("state->on_connect_ref is NULL\n");
  }

  if (state->on_data_ref != NULL) {
    printf("state->on_data_ref is not NULL\n");
  } else {
    printf("state->on_data_ref is NULL\n");
  }

  if (state->on_end_ref != NULL) {
    printf("state->on_end_ref is not NULL\n");
  } else {
    printf("state->on_end_ref is NULL\n");
  }

  if (state->on_error_ref != NULL) {
    printf("state->on_error_ref is not NULL\n");
  } else {
    printf("state->on_error_ref is NULL\n");
  }
}

void state_cleanup(state_t *state) {
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

  free(state);
}

/* Helper: call JS callback with existing napi_value */
napi_status call_js_value(state_t *state, napi_ref cb_ref, napi_value val) {
  napi_status status;

  napi_handle_scope scope;
  status = napi_open_handle_scope(state->env, &scope);
  assert(status == napi_ok);

  napi_value undefined;
  status = napi_get_undefined(state->env, &undefined);
  assert(status == napi_ok);

  napi_value cb;
  status = napi_get_reference_value(state->env, cb_ref, &cb);
  assert(status == napi_ok);
  status = napi_call_function(state->env, undefined, cb, val != NULL ? 1 : 0,
                              val != NULL ? &val : NULL, NULL);
  if (status != napi_ok) {
    LOG_ERROR("Error calling function");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  status = napi_close_handle_scope(state->env, scope);
  assert(status == napi_ok);
  return status;
}

/* Helper: call JS callback with C string + length (creates JS string) */
napi_status call_js_string(state_t *state, napi_ref cb_ref, char *buf,
                           size_t len) {
  napi_status status;

  napi_handle_scope scope;
  status = napi_open_handle_scope(state->env, &scope);
  assert(status == napi_ok);

  napi_value undefined;
  status = napi_get_undefined(state->env, &undefined);
  assert(status == napi_ok);

  napi_value cb;
  status = napi_get_reference_value(state->env, cb_ref, &cb);
  assert(status == napi_ok);

  napi_value str;
  status = napi_create_string_utf8(state->env, buf, len, &str);
  assert(status == napi_ok);

  status = napi_call_function(state->env, undefined, cb, 1, &str, NULL);
  if (status != napi_ok) {
    LOG_ERROR("Error calling function");
    napi_close_handle_scope(state->env, scope);
    return status;
  }

  status = napi_close_handle_scope(state->env, scope);
  assert(status == napi_ok);

  return status;
}

void send_error(state_t *state, char *errstr) {
  napi_status status;
  napi_value msg;
  napi_value err_obj;
  napi_handle_scope scope;

  status = napi_open_handle_scope(state->env, &scope);
  assert(status == napi_ok);

  status = napi_create_string_utf8(state->env, errstr, NAPI_AUTO_LENGTH, &msg);
  assert(status == napi_ok);

  status = napi_create_error(state->env, NULL, msg, &err_obj);
  assert(status == napi_ok);

  status = call_js_value(state, state->on_error_ref, err_obj);
  if (status != napi_ok) {
    LOG_ERROR("Error calling error callback");
    napi_close_handle_scope(state->env, scope);
    return;
  }
  status = napi_close_handle_scope(state->env, scope);
  assert(status == napi_ok);
}

void send_error_napi(state_t *state, napi_status status) {
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

void send_error_uv(state_t *state, int err) {
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
  buf->len = suggested_size;
}

void close_cb(uv_handle_t *handle) {
  debug_log("-------------Closed connection---------------\n");
  if (handle != NULL) {
    free(handle);
  }
  // printf("net_num_of_allocations = %d\n", net_num_of_allocations);
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {

  state_t *state = stream->data;

  napi_status status;
  if (nread > 0) {
    debug_log("read %zu Bytes\n", nread);

    status = call_js_string(state, state->on_data_ref, buf->base, nread);
    if (status != napi_ok) {
      LOG_ERROR("Error calling data callback");
      send_error_napi(state, status);
      goto cleanup;
    }
  } else if (nread < 0) {
    if (nread == UV_EOF) {
      debug_log("received EOF\n");
      status = call_js_value(state, state->on_end_ref, NULL);
      if (status != napi_ok) {
        LOG_ERROR("Error calling end callback");
        send_error_napi(state, status);
      }
    }
    goto cleanup;
  }
  if (buf && buf->base) {
    free(buf->base);
  }
  return;

cleanup:
  uv_close((uv_handle_t *)stream, close_cb);
  if (buf && buf->base) {
    free(buf->base);
  }
  state_cleanup(state);
  stream->data = NULL;

  return;
}

void write_cb(uv_write_t *req, int status) {
  uv_stream_t *stream = req->handle;
  state_t *state = stream->data;
  uv_buf_t *buf = req->data;

  if (buf != NULL && buf->base != NULL) {
    free(buf->base);
    buf->base = NULL;
  }
  if (req->data != NULL) {
    free(req->data);
    req->data = NULL;
  }

  if (status != 0) {
    LOG_ERROR("write erro");
    send_error_uv(state, status);
    free(req);
    uv_close((void *)stream, close_cb);
    return;
  }

  free(req);
  debug_log("write success!");
}

void connect_cb(uv_connect_t *req, int status) {
  uv_stream_t *stream = req->handle;
  state_t *state = stream->data;

  if (status != 0) {
    LOG_ERROR("tcp connection erro");
    send_error_uv(state, status);
    goto cleanup;
  }

  debug_log("----------Connected-----------\n");
  napi_status ns = call_js_value(state, state->on_connect_ref, NULL);
  if (ns != napi_ok) {
    LOG_ERROR("Error calling connect callback");
    send_error_napi(state, ns);
    goto cleanup;
  }

  status = uv_read_start(stream, alloc_cb, read_cb);
  if (status != 0) {
    LOG_ERROR("Error starting read");
    send_error_uv(state, status);
    goto cleanup;
  }

  uv_write_t *write_req = malloc(sizeof(*write_req));

  uv_buf_t *buf = req->data;
  write_req->data = buf;
  status = uv_write(write_req, stream, buf, 1, write_cb);
  if (status != 0) {
    LOG_ERROR("Error writing ");
    send_error_uv(state, status);
    goto cleanup;
  }
  free(req);
  return;

cleanup:
  uv_close((void *)stream, close_cb);
  uv_buf_t *rbuf = req->data;
  if (rbuf != NULL && rbuf->base) {
    free(rbuf->base);
    rbuf->base = NULL;
  }
  if (rbuf != NULL) {
    free(rbuf);
    req->data = NULL;
  }
  free(req);
  if (state != NULL) {
    state_cleanup(state);
    stream->data = NULL;
  }
}

napi_status validate_cb_input(napi_env env, size_t argc, napi_value *args) {
  napi_status status;

  if (argc < 7) {
    status = napi_throw_error(env, NULL, "Expected 7 args");
    return napi_invalid_arg;
  }

  napi_valuetype valuetype;
  status = napi_typeof(env, args[0], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_string) {
    napi_throw_type_error(env, NULL, "First argument must be host string");
    return napi_string_expected;
  }

  status = napi_typeof(env, args[1], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_number) {
    napi_throw_type_error(env, NULL, "Second argument must be port number");
    return napi_number_expected;
  }

  status = napi_typeof(env, args[2], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_string) {
    napi_throw_type_error(env, NULL, "Third argument must be host string");
    return napi_string_expected;
  }

  status = napi_typeof(env, args[3], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "connect callback must be a function");
    return napi_function_expected;
  }

  status = napi_typeof(env, args[4], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "data callback must be a function");
    return napi_function_expected;
  }

  status = napi_typeof(env, args[5], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "end callback must be a function");
    return napi_function_expected;
  }

  status = napi_typeof(env, args[6], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    napi_throw_type_error(env, NULL, "Error callback must be a function");
    return napi_function_expected;
  }

  return napi_ok;
}

napi_value ConnectToTcpSocket(napi_env env, napi_callback_info info) {

  napi_status status = napi_ok;
  state_t *state = NULL;
  uv_connect_t *req = NULL;
  char *host = NULL;
  uv_buf_t *buf = NULL;
  uv_tcp_t *handle = NULL;
  // function returns undefined on success
  napi_value undefined;
  status = napi_get_undefined(env, &undefined);
  assert(status == napi_ok);

  size_t argc = 7;
  napi_value args[argc];
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  // validate_cb_input throws error, so we don't rethrow the error here
  status = validate_cb_input(env, argc, args);
  if (status != napi_ok) {
    LOG_ERROR("Invalid input");
    return undefined;
  }

  size_t host_len;
  status = napi_get_value_string_utf8(env, args[0], NULL, 0, &host_len);
  assert(status == napi_ok);

  host = malloc(host_len + 1);
  status = napi_get_value_string_utf8(env, args[0], host, host_len + 1, NULL);
  assert(status == napi_ok);

  uint32_t port;
  status = napi_get_value_uint32(env, args[1], &port);
  assert(status == napi_ok);

  struct sockaddr_in dest;
  int err = 0;
  err = uv_ip4_addr(host, port, &dest);
  if (err != 0) {
    LOG_ERROR("Error with tcp IP address");
    goto uv_cleanup;
  }

  if (host != NULL) {
    free(host);
    host = NULL;
  }

  size_t message_len;
  status = napi_get_value_string_utf8(env, args[2], NULL, 0, &message_len);
  assert(status == napi_ok);

  buf = malloc(sizeof(*buf));
  buf->len = message_len + 1;
  buf->base = malloc(buf->len);
  status = napi_get_value_string_utf8(env, args[2], buf->base, buf->len, NULL);
  assert(status == napi_ok);

  state = malloc(sizeof(*state));
  state->env = env;

  status = napi_create_reference(env, args[3], 1, &state->on_connect_ref);
  assert(status == napi_ok);
  status = napi_create_reference(env, args[4], 1, &state->on_data_ref);
  assert(status == napi_ok);
  status = napi_create_reference(env, args[5], 1, &state->on_end_ref);
  assert(status == napi_ok);
  status = napi_create_reference(env, args[6], 1, &state->on_error_ref);
  assert(status == napi_ok);

  handle = malloc(sizeof(*handle));
  err = uv_tcp_init(uv_default_loop(), handle);
  if (err != 0) {
    LOG_ERROR("Error initiating tcp socket");
    goto uv_cleanup;
  }
  handle->data = state;

  req = malloc(sizeof(*req));

  err = uv_tcp_connect(req, handle, (void *)&dest, connect_cb);
  if (err != 0) {
    LOG_ERROR("Error connecting to tcp socket");
    goto uv_cleanup;
  }
  req->data = buf;

  return undefined;

uv_cleanup:
  if (host != NULL) {
    free(host);
    host = NULL;
  }
  state_cleanup(state);
  if (handle != NULL) {
    handle->data = NULL;
    free(handle);
    handle = NULL;
  }
  if (buf != NULL && buf->base != NULL) {
    free(buf->base);
    buf->base = NULL;
  }
  if (buf != NULL) {
    free(buf);
    req->data = NULL;
  }
  if (req != NULL) {
    free(req);
    req = NULL;
  }

  throw_error_uv(env, err);
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
