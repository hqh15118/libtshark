> libtshark

+ 实时在线报文分析
+ 可扩展性能
+ Wireshark + Pcap4J

`libtshark`是基于`Wireshark`和`Pcap4J`的实时在线报文分析库，用于在线报文的实时分析或离线报文的重放分析，基于`Wireshark`实现，支持两千多种协议的详细解析。
解析结果和`Wireshark`完全相同，可以方便地将解析数据导入到自己的程序中进行进一步的流量分析。

> Demo

+ 配置运行环境
1. `libtshark`依赖`Wireshark`的`tshark`，所以首先要下载安装[Wireshark](https://www.wireshark.org/download.html).
2. 将`resource`文件夹下的`mywireshark_plugin.lua`脚本拷贝到`Wireshark`的插件目录`/wireshark/plugins`.
3. 配置环境变量，将`Wireshark`目录添加到`path`中，终端输入`tshark`可以正常运行即可。
+ 配置`libtshark`运行文件
参考`config/tsharkprocess.json`定制`libtshark`报文分析行为.具体参数含义见下文，也可以参考[tshark官网](https://www.wireshark.org/docs/man-pages/tshark.html)

+ 运行

```java
// 代码会从tsharkprocess.json中加载相应的配置初始化tshark
public class Main {
    public static void main(String[] args){
        PacketAnalyzeEngine packetAnalyzeEngine = new PacketAnalyzeEngine();
        packetAnalyzeEngine.setDataCallback(new PacketAnalyzeEngine.DataCallback() {
                    @Override
                    public void callback(int processId, String json) {
                        System.out.println(json);
                    }
                });
        packetAnalyzeEngine.start();
    }
}
```

> 配置文件

修改 ``tsharkprocess.json``文件，改变`PacketAnalyzeEngine`行为。

```json
{
  "args": [
    {
      "protocol": ["s7comm"],   // 分析的协议名称，对应wireshark的display filter
      "filterFields": [
        "s7comm.param.userdata.funcgroup",  // 需要输出的字段名1
        "s7comm.param.func"                 // 需要输出的字段名2
      ],
      "showConsole": false                  // 是否将当前协议的解析结果输出到终端
    }
  ],
  "undefined": true,                        // 非指定协议解析
  "iFace": "\\Device\\NPF_{85B3D44A-D5EF-4256-97A3-2002C1D08DB3}",  // 解析网卡
  "restartProcess": 10000,
  "dumpcap": {
    "iFace" : "\\Device\\NPF_{235EDB77-6B88-41E1-8C1E-29DB35754E3D}", // 抓包网卡
    "tmpFile" : "C:\\Users\\zjucsc\\Desktop\\dumpcap_tmp\\tmp",       // 临时文件目录
    "fileSize" : 100000
  }
}
``` 