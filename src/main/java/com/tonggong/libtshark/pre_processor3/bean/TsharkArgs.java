package com.tonggong.libtshark.pre_processor3.bean;

import lombok.Data;

import java.util.List;

@Data
public class TsharkArgs {

    private List<Args> args;
    private boolean undefined = true;
    private String iFace;
    private Dumpcap dumpcap;
    private int restartProcess = 500000;
    private boolean debug;
    private ZooKeeperConfig zk;

    @Data
    public static class Args{
        private List<String> protocol;
        // -e
        // 需要用到的字段名称
        private List<String> filterFields;

        // 是否在console中打印tshark进程json输出
        private boolean showConsole;
    }

    @Data
    public static class Dumpcap{
        private String iFace;
        private String tmpFile;

    }

    @Data
    public static class ZooKeeperConfig{
        private String address;
        private int port;
    }
}
