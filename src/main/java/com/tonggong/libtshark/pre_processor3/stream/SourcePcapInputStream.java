package com.tonggong.libtshark.pre_processor3.stream;


import com.tonggong.libtshark.pre_processor3.dumpcap.DumpPcapInputStream;
import com.tonggong.libtshark.pre_processor3.dumpcap.ISourcePcapInputStream;

public abstract class SourcePcapInputStream implements ISourcePcapInputStream {
    /**
     * @param buffer buffer
     */
    public void read(byte[] buffer, DumpPcapInputStream.PacketWrapper packetType) throws Exception {
        read(buffer,0,8);
        int frameLen = getInt(buffer);
        int remainLen = frameLen - 8;
        read(buffer, 8, remainLen);
        packetType.packetType = buffer[0];
        packetType.buffer = buffer;
        packetType.validLen = frameLen;
        if (packetType.packetType == 0x06){
            packetType.dataLen = getCapLen(buffer);
            System.arraycopy(buffer,28,packetType.data,0,packetType.dataLen);
        }
    }



    private int getInt(byte[] buffer) {
        int a = Byte.toUnsignedInt(buffer[4]);
        int b = Byte.toUnsignedInt(buffer[5]);
        int c = Byte.toUnsignedInt(buffer[6]);
        int d = Byte.toUnsignedInt(buffer[7]);
        return a + (b << 8) + (c << 16) + (d << 24);
    }

    private int getCapLen(byte[] buffer){
        int a = Byte.toUnsignedInt(buffer[20]);
        int b = Byte.toUnsignedInt(buffer[21]);
        int c = Byte.toUnsignedInt(buffer[22]);
        int d = Byte.toUnsignedInt(buffer[23]);
        return a + (b << 8) + (c << 16) + (d << 24);
    }
}
