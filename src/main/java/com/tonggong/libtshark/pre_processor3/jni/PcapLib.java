package com.tonggong.libtshark.pre_processor3.jni;

public class PcapLib {
    static {
        System.load("D:\\JAVA_PROJECTS\\libtshark\\src\\main\\resources\\liblibtshark.dll");
    }

    public native int sendPacket(byte[] packet,int offset,int len);

    public native void showAllIFaceName();
}
