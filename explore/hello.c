#define NAPI_VERSION 3
#include <node_api.h>
#include <stdio.h>

napi_value Init(napi_env env, napi_value exports) {
  printf("Hello World!\n");
  const napi_node_version *version;
  napi_status status = napi_get_node_version(env, &version);
  printf("Node release: %s\n", version->release);
  printf("Node Major version: %d\n", version->major);
  printf("Node Minor version: %d\n", version->minor);
  printf("Node Patch version: %d\n", version->patch);

  return 0;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init);
