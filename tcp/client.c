#include <assert.h>
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

typedef struct {
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
  free(handle);
}

void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
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
  } else if (nread == UV_EOF) {
    printf("TRACE: read_cb received EOF\n");
    assert(uv_tcp_close_reset((void *)stream, close_cb) == 0);
  }
}

void connect_cb(uv_connect_t *req, int status) {
  if (status) {
    printf("ERROR: connect_cb status: %s\n", uv_strerror(status));
    return;
  }
  int err;

  uv_stream_t *stream = req->handle;
  stream->data = req->data;

  if ((err = uv_read_start(stream, alloc_cb, read_cb)) != 0) {
    printf("ERROR: uv_read_start = %s\n", uv_strerror(err));
    return;
  }

  printf("TRACE: ----------Connected-----------\n");
}

void call_js(napi_env env, napi_value js_callback, void *context, void *data) {
  assert(env);

  napi_status status;
  napi_value undefined;
  status = napi_get_undefined(env, &undefined);
  assert(status == napi_ok);

  napi_value args[1];
  uv_buf_t *buf = data;
  printf("TRACE: call_js buf->len: %zu\n", buf->len);
  status = napi_create_string_utf8(env, buf->base, buf->len, args);
  assert(status == napi_ok);

  status = napi_call_function(env, undefined, js_callback, 1, args, NULL);
  assert(status == napi_ok);

  addon_state *state = context;
  free(buf->base);
  free(buf);

  assert(napi_unref_threadsafe_function(env, state->tsfn) == napi_ok);
  assert(napi_delete_reference(env, state->callback_ref) == napi_ok);
  free(state);
}

napi_value ConnectToTcpSocket(napi_env env, napi_callback_info info) {
  napi_status status;
  const napi_extended_error_info *result;
  char erstr[124];

  size_t argc = 1;
  napi_value args[1];
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  if (status != napi_ok) {
    assert(napi_get_last_error_info(env, &result) == napi_ok);
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n", result->error_message,
            __FILE__, __LINE__);
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);
    return NULL;
  }

  if (argc < 1) {
    assert(napi_throw_type_error(env, NULL, "Expected callback") == napi_ok);
    return NULL;
  }

  napi_valuetype valuetype;
  napi_typeof(env, args[0], &valuetype);
  if (valuetype != napi_function) {
    assert(napi_throw_type_error(env, NULL,
                                 "First argument must be function") == napi_ok);
    return NULL;
  }

  addon_state *state;
  state = malloc(sizeof(*state));

  status = napi_create_reference(env, args[0], 1, &state->callback_ref);
  if (status != napi_ok) {
    assert(napi_get_last_error_info(env, &result) == napi_ok);
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n", result->error_message,
            __FILE__, __LINE__);
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);
    return NULL;
  }

  napi_value resource_name;
  status = napi_create_string_utf8(env, "TcpCallback", NAPI_AUTO_LENGTH,
                                   &resource_name);
  assert(status == napi_ok);

  status =
      napi_create_threadsafe_function(env, args[0], NULL, resource_name, 0, 1,
                                      NULL, NULL, state, call_js, &state->tsfn);
  if (status != napi_ok) {
    assert(napi_get_last_error_info(env, &result) == napi_ok);
    sprintf(erstr, "ERROR: %s in file %s at line: %d\n", result->error_message,
            __FILE__, __LINE__);
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);
    return NULL;
  }

  uv_tcp_t *socket;
  socket = malloc(sizeof(*socket));
  int err;
  if ((err = uv_tcp_init(uv_default_loop(), socket)) != 0) {
    sprintf(erstr, "ERROR: uv_tcp_init = %s\n", uv_strerror(err));
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);
    return NULL;
  }

  uv_connect_t *connect;
  connect = malloc(sizeof(*connect));
  connect->data = state;

  struct sockaddr_in dest;
  if ((err = uv_ip4_addr("127.0.0.1", 4242, &dest)) != 0) {
    sprintf(erstr, "ERROR: uv_ip4_addr = %s\n", uv_strerror(err));
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);
    return NULL;
  }
  if ((err = uv_tcp_connect(connect, socket, (void *)&dest, connect_cb)) != 0) {
    sprintf(erstr, "ERROR: uv_tcp_connect = %s\n", uv_strerror(err));
    assert(napi_throw_error(env, NULL, erstr) == napi_ok);
    return NULL;
  }

  return NULL;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;

  napi_property_descriptor desc[] = {
      {"connect", 0, ConnectToTcpSocket, 0, 0, 0, napi_default, 0}};

  status = napi_define_properties(env, exports, 1, desc);
  assert(status == napi_ok);

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
