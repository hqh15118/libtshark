package com.tonggong.libtshark.pre_processor3.stream;


import java.io.InputStream;

public class StreamPcapInputStream extends SourcePcapInputStream {

    private InputStream is;
    public StreamPcapInputStream(){}
    public void setIs(InputStream is){
        this.is = is;
    }

    @Override
    public int read(byte[] buffer, int offset, int len) throws Exception {
        return is.read(buffer, offset, len);
    }
}
