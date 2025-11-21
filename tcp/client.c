#include <assert.h>
#include <node_api.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/_pthread/_pthread_t.h>
#include <uv.h>

#ifdef DEBUG
#define debug_log(fmt, ...)                                                    \
  fprintf(stderr, "DEBUG %s:%d:%s(): " fmt "\n", __FILE__, __LINE__, __func__, \
          ##__VA_ARGS__)
#else
#define debug_log(fmt, ...) ((void)0)
#endif

typedef struct {
  napi_env env;
  uv_connect_t *req;
  napi_ref on_data_ref;
  napi_ref on_connect_ref;
  napi_ref on_end_ref;
} addon_state;

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  debug_log("allocating %zu Bytes\n", suggested_size);
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

void close_cb(uv_handle_t *handle) {
  debug_log("-------------Closed connection---------------\n");
  addon_state *state = handle->data;
  assert(napi_delete_reference(state->env, state->on_data_ref) == napi_ok);
  assert(napi_delete_reference(state->env, state->on_connect_ref) == napi_ok);
  assert(napi_delete_reference(state->env, state->on_end_ref) == napi_ok);
  free(state->req);
  free(state);
  free(handle);
}

void call_js(napi_env env, napi_ref cb_ref, void *data) {
  assert(env);

  napi_status status;

  napi_handle_scope scope;
  status = napi_open_handle_scope(env, &scope);
  assert(status == napi_ok);

  napi_value undefined;
  status = napi_get_undefined(env, &undefined);
  assert(status == napi_ok);

  napi_value cb;
  status = napi_get_reference_value(env, cb_ref, &cb);
  assert(status == napi_ok);

  if (data) {
    napi_value args[1];
    uv_buf_t *buf = data;
    status = napi_create_string_utf8(env, buf->base, buf->len, args);
    assert(status == napi_ok);

    status = napi_call_function(env, undefined, cb, 1, args, NULL);
    assert(status == napi_ok);

    free(buf->base);
    free(buf);
  } else {
    status = napi_call_function(env, undefined, cb, 0, NULL, NULL);
    assert(status == napi_ok);
  }

  status = napi_close_handle_scope(env, scope);
  assert(status == napi_ok);
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  if (nread > 0) {
    debug_log("read %zu Bytes\n", nread);
    buf->base[nread] = '\0';
    uv_buf_t *msg;
    msg = malloc(sizeof(*msg));
    msg->base = buf->base;
    msg->len = nread;
    debug_log("read %s\n", buf->base);

    assert(stream);
    addon_state *state = ((uv_handle_t *)stream)->data;
    assert(state);

    call_js(state->env, state->on_data_ref, msg);

  } else {
    if (nread == UV_EOF) {
      debug_log("received EOF\n");
      assert(stream);
      addon_state *state = ((uv_handle_t *)stream)->data;
      assert(state);

      call_js(state->env, state->on_end_ref, NULL);

    } else {
      char erstr[124];
      sprintf(erstr, "ERROR: read_cb %s in file %s at line: %d\n",
              uv_strerror(nread), __FILE__, __LINE__);
      addon_state *state = ((uv_handle_t *)stream)->data;
      assert(napi_throw_error(state->env, NULL, erstr) == napi_ok);
    }
    uv_read_stop(stream);
    assert(uv_tcp_close_reset((void *)stream, close_cb) == 0);
    free(buf->base);
  }
}

void connect_cb(uv_connect_t *req, int status) {
  uv_stream_t *stream = req->handle;
  stream->data = req->data;

  if (status) {
    printf("ERROR: %s in file %s at line: %d\n", uv_strerror(status), __FILE__,
           __LINE__);
    assert(uv_tcp_close_reset((void *)stream, close_cb) == 0);
    return;
  }

  debug_log("----------Connected-----------\n");

  addon_state *state = req->data;

  call_js(state->env, state->on_connect_ref, NULL);

  int err;

  if ((err = uv_read_start(stream, alloc_cb, read_cb)) != 0) {
    printf("ERROR: %s in file %s at line: %d\n", uv_strerror(err), __FILE__,
           __LINE__);
    return;
  }
}

napi_status validate_cb_input(napi_env env, size_t argc, napi_value *args) {
  napi_status status;

  if (argc < 5) {
    status = napi_throw_type_error(env, NULL, "Expected 5 args");
    assert(status == napi_ok);
    return napi_invalid_arg;
  }

  napi_valuetype valuetype;
  status = napi_typeof(env, args[0], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_string) {
    status =
        napi_throw_type_error(env, NULL, "First argument must be host string");
    assert(status == napi_ok);
    return napi_string_expected;
  }

  status = napi_typeof(env, args[1], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_number) {
    status =
        napi_throw_type_error(env, NULL, "Second argument must be port number");
    assert(status == napi_ok);
    return napi_number_expected;
  }

  status = napi_typeof(env, args[2], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    status =
        napi_throw_type_error(env, NULL, "Third argument must be function");
    assert(status == napi_ok);
    return napi_function_expected;
  }

  status = napi_typeof(env, args[3], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    status =
        napi_throw_type_error(env, NULL, "Fourth argument must be function");
    assert(status == napi_ok);
    return napi_function_expected;
  }

  status = napi_typeof(env, args[4], &valuetype);
  assert(status == napi_ok);
  if (valuetype != napi_function) {
    status =
        napi_throw_type_error(env, NULL, "Fifth argument must be function");
    assert(status == napi_ok);
    return napi_function_expected;
  }

  return napi_ok;
}

napi_value ConnectToTcpSocket(napi_env env, napi_callback_info info) {
  napi_status status;
  const napi_extended_error_info *result;
  char erstr[124];

  size_t argc = 5;
  napi_value args[argc];
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  status = validate_cb_input(env, argc, args);
  if (status != napi_ok) {
    return NULL;
  }

  size_t host_len;
  status = napi_get_value_string_utf8(env, args[0], NULL, 0, &host_len);
  assert(status == napi_ok);

  char *host = malloc(sizeof(host_len + 1));
  status =
      napi_get_value_string_utf8(env, args[0], host, host_len + 1, &host_len);
  assert(status == napi_ok);

  uint32_t port;
  status = napi_get_value_uint32(env, args[1], &port);
  assert(status == napi_ok);

  addon_state *state;
  state = malloc(sizeof(*state));
  state->env = env;

  status = napi_create_reference(env, args[2], 1, &state->on_connect_ref);
  assert(status == napi_ok);
  status = napi_create_reference(env, args[3], 1, &state->on_data_ref);
  assert(status == napi_ok);
  status = napi_create_reference(env, args[4], 1, &state->on_end_ref);
  assert(status == napi_ok);

  uv_tcp_t *socket;
  socket = malloc(sizeof(*socket));
  int err;

  err = uv_tcp_init(uv_default_loop(), socket);
  assert(err == 0);

  uv_connect_t *connect;
  connect = malloc(sizeof(*connect));
  state->req = connect;
  connect->data = state;

  struct sockaddr_in dest;
  err = uv_ip4_addr(host, port, &dest);
  assert(err == 0);

  err = uv_tcp_connect(connect, socket, (void *)&dest, connect_cb);
  assert(err == 0);

  free(host);

  return NULL;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  char erstr[124];
  const napi_extended_error_info *result;

  napi_property_descriptor desc[] = {
      {"connect", 0, ConnectToTcpSocket, 0, 0, 0, napi_default, 0}};

  status = napi_define_properties(env, exports, 1, desc);
  assert(status == napi_ok);

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
