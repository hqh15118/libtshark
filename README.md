修改 ``tsharkprocess.json``文件，改变`PacketAnalyzeEngine`行为。

```json
{
  // 开启的所有tshark进程参数
  "args": [
    // 单协议，即一个进程一个协议
    {
      "protocol": ["s7comm"],
      "filterFields": [""]
    },
    // 多协议，即一个进程多个协议
    {
      "protocol": ["modbus","pnio"],
      "filterFields": [""]
    }
  ],
  "undefined": true
}


```