package com.tonggong.libtshark.pre_processor3.stream;


import java.io.RandomAccessFile;

public class RandomFilePcapInputStream extends SourcePcapInputStream {
    private RandomAccessFile randomAccessFile;
    public RandomFilePcapInputStream(){
    }

    public void setRandomAccessFile(RandomAccessFile randomAccessFile0){
        randomAccessFile = randomAccessFile0;
    }

    @Override
    public int read(byte[] buffer, int offset, int len) throws Exception {
        return randomAccessFile.read(buffer, offset, len);
    }
}
