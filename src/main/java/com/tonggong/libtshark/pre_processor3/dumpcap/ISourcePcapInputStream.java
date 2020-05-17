package com.tonggong.libtshark.pre_processor3.dumpcap;


public interface ISourcePcapInputStream {
    int read(byte[] buffer,int offset,int len) throws Exception;
}
