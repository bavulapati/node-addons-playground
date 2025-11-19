#include <assert.h>
#include <node_api.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#define UV_CHECK(err)                                                          \
  if ((err) != 0) {                                                            \
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n", uv_strerror(err),     \
            __FILE__, __LINE__);                                               \
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);                     \
    return NULL;                                                               \
  }

#define NAPI_CHECK(status)                                                     \
  if (status != napi_ok) {                                                     \
    assert(napi_get_last_error_info(env, &result) == napi_ok);                 \
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n",                       \
            result->error_message, __FILE__, __LINE__);                        \
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);                     \
    return NULL;                                                               \
  }

typedef struct {
  napi_env env;
  uv_connect_t *req;
  napi_ref callback_ref;
  napi_threadsafe_function tsfn;
} addon_state;

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  printf("TRACE: alloc_cb allocating %zu Bytes\n", suggested_size);
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

void close_cb(uv_handle_t *handle) {
  printf("TRACE: Closed connection\n");
  addon_state *state = handle->data;
  assert(napi_unref_threadsafe_function(state->env, state->tsfn) == napi_ok);
  assert(napi_delete_reference(state->env, state->callback_ref) == napi_ok);
  free(state->req);
  free(state);
  free(handle);
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
  printf("TRACE: read_cb\n");
  if (nread > 0) {
    printf("TRACE: read_cb read %zu Bytes\n", nread);
    buf->base[nread] = '\0';
    uv_buf_t *msg;
    msg = malloc(sizeof(*msg));
    msg->base = buf->base;
    msg->len = nread;
    printf("TRACE: read %s\n", buf->base);

    assert(stream);
    addon_state *state = ((uv_handle_t *)stream)->data;
    assert(state);
    napi_status status = napi_call_threadsafe_function(state->tsfn, (void *)msg,
                                                       napi_tsfn_nonblocking);
    assert(status == napi_ok);
  } else {
    if (nread == UV_EOF) {
      printf("TRACE: read_cb received EOF\n");
    } else {
      printf("ERROR: read_cb %s in file %s at line: %d\n", uv_strerror(nread),
             __FILE__, __LINE__);
      char erstr[124];
      addon_state *state = ((uv_handle_t *)stream)->data;
      assert(napi_throw_error(state->env, NULL, erstr) == napi_ok);
    }
    uv_read_stop(stream);
    assert(uv_tcp_close_reset((void *)stream, close_cb) == 0);
    free(buf->base);
  }
}

void connect_cb(uv_connect_t *req, int status) {
  char erstr[124];
  addon_state *state = req->data;
  if (status) {
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n", uv_strerror(status),
            __FILE__, __LINE__);
    assert(napi_throw_error(state->env, NULL, erstr) == napi_ok);
    uv_close((void *)req, close_cb);
    return;
  }

  printf("TRACE: connect_cb ----------Connected-----------\n");
  int err;

  uv_stream_t *stream = req->handle;
  stream->data = req->data;

  if ((err = uv_read_start(stream, alloc_cb, read_cb)) != 0) {
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n", uv_strerror(err),
            __FILE__, __LINE__);
    assert(napi_throw_error(state->env, NULL, erstr) == napi_ok);
    return;
  }
}

void call_js(napi_env env, napi_value js_callback, void *context, void *data) {
  assert(env);

  napi_status status;
  napi_value global;
  status = napi_get_global(env, &global);
  assert(status == napi_ok);

  napi_value args[1];
  uv_buf_t *buf = data;
  printf("TRACE: call_js buf->len: %zu\n", buf->len);
  status = napi_create_string_utf8(env, buf->base, buf->len, args);
  assert(status == napi_ok);

  status = napi_call_function(env, global, js_callback, 1, args, NULL);
  assert(status == napi_ok);

  free(buf->base);
  free(buf);
}

napi_status validate_cb_input(napi_env env, size_t argc, napi_value *args) {
  napi_status status;

  if (argc < 3) {
    status = napi_throw_type_error(env, NULL, "Expected 3 args");
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

  return napi_ok;
}

napi_value ConnectToTcpSocket(napi_env env, napi_callback_info info) {
  napi_status status;
  const napi_extended_error_info *result;
  char erstr[124];

  size_t argc = 3;
  napi_value args[3];
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  NAPI_CHECK(status)

  status = validate_cb_input(env, argc, args);
  if (status != napi_ok) {
    return NULL;
  }

  size_t host_len;
  status = napi_get_value_string_utf8(env, args[0], NULL, 0, &host_len);
  NAPI_CHECK(status)
  char *host = malloc(sizeof(host_len + 1));
  status =
      napi_get_value_string_utf8(env, args[0], host, host_len + 1, &host_len);
  NAPI_CHECK(status)

  uint32_t port;
  status = napi_get_value_uint32(env, args[1], &port);
  NAPI_CHECK(status)

  addon_state *state;
  state = malloc(sizeof(*state));
  state->env = env;

  status = napi_create_reference(env, args[2], 1, &state->callback_ref);
  NAPI_CHECK(status)

  napi_value resource_name;
  status = napi_create_string_utf8(env, "TcpCallback", NAPI_AUTO_LENGTH,
                                   &resource_name);
  NAPI_CHECK(status)

  status =
      napi_create_threadsafe_function(env, args[2], NULL, resource_name, 0, 1,
                                      NULL, NULL, state, call_js, &state->tsfn);
  NAPI_CHECK(status)

  uv_tcp_t *socket;
  socket = malloc(sizeof(*socket));
  int err;

  err = uv_tcp_init(uv_default_loop(), socket);
  UV_CHECK(err)

  uv_connect_t *connect;
  connect = malloc(sizeof(*connect));
  state->req = connect;
  connect->data = state;

  struct sockaddr_in dest;
  err = uv_ip4_addr(host, port, &dest);
  UV_CHECK(err)

  err = uv_tcp_connect(connect, socket, (void *)&dest, connect_cb);
  UV_CHECK(err)

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
  NAPI_CHECK(status)

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
