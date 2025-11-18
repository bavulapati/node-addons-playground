#include <iostream>
#include <node.h>

void Initialize(v8::Local<v8::Object> exports) {
  std::cout << "Hello, World!" << std::endl;
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
