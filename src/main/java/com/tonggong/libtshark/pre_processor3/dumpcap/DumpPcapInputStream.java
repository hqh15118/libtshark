package com.tonggong.libtshark.pre_processor3.dumpcap;



import com.tonggong.libtshark.pre_processor3.stream.RandomFilePcapInputStream;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-02-04 - 13:36
 */
public class DumpPcapInputStream implements IPcapInputStream {

    private LinkedBlockingQueue<Object> queue;
    private RandomAccessFile accessFile;
    private PacketWrapper packetWrapperGlobal;
    private volatile boolean stop = false;
    private PcapInputStreamCallback pcapInputStreamCallback;
    //private boolean asyncProcess = false;
    private long packetId;
    private RandomFilePcapInputStream randomFilePcapInputStream = new RandomFilePcapInputStream();
    /**
     *
     */
    public DumpPcapInputStream(LinkedBlockingQueue<Object> queue) {
        this.queue = queue;
        packetWrapperGlobal = new PacketWrapper();
    }

    public void setPcapInputStreamCallback(PcapInputStreamCallback pcapInputStreamCallback) {
        this.pcapInputStreamCallback = pcapInputStreamCallback;
    }

    public void stop(){
        stop = true;
    }

    @Override
    public void readFrame(byte[] buffer){
        try {
            //初始化一个文件
            String fileName1 = (String) queue.poll(5000, TimeUnit.SECONDS);
            String lastFileName = fileName1;
            int lastNumber = 0;
            if (fileName1 != null) {
                accessFile = new RandomAccessFile(fileName1, "r");
                randomFilePcapInputStream.setRandomAccessFile(accessFile);
            }else{
                throw new RuntimeException("pcap inputStream init error! [fileQueue] can not get a file name");
            }
            boolean switchFile = false; //是否切换文件
            for (;;) {
                Integer value = null;
                if (!switchFile) {
                    for (int i = 0; i < 5 ; i++){
                        Object tmp = queue.poll(50,TimeUnit.MILLISECONDS);
                        if (tmp == null && value != null){
                            break;
                        }
                        if (tmp == null){
                            continue;
                        }
                        if (tmp instanceof String){
                            lastFileName = fileName1;
                            switchFile = true;
                            fileName1 = (String)tmp;
                            break;
                        }else{
                            value = (Integer) tmp;
                        }
                    }
                    if (value == null){
                        if (stop){
                            break;
                        }
                        continue;
                    }
                    long offset = accessFile.getFilePointer();
                    accessFile.seek(offset);
                    for (int i = 0, readLen = value - lastNumber; i < readLen; i++) {
                        PacketWrapper packetWrapper = getPacketWrapper();
                        randomFilePcapInputStream.read(buffer,packetWrapper);
                        packetWrapper.buffer = buffer;
                        packetId ++;
                        if (packetId == Long.MAX_VALUE){
                            packetId = 0;
                        }
                        packetWrapper.packetId = packetId;
                        if (packetWrapper.packetType == 0x06 && pcapInputStreamCallback!=null)
                            pcapInputStreamCallback.packetValid(packetWrapper);
                        offset += (packetWrapper.validLen);
                        offsetUpdate(fileName1,offset);
                    }
                    if (lastNumber != value) {
                        lastNumber = value;
                        if (pcapInputStreamCallback != null){
                            pcapInputStreamCallback.recvPacketNumber(value);
                        }
                    }
                }
                else {
                    if (pcapInputStreamCallback != null){
                        pcapInputStreamCallback.switchFile(lastFileName);
                    }
                    if (fileName1.equals("exit now!")){
                        break;
                    }
                    accessFile = new RandomAccessFile(fileName1, "r");
                    randomFilePcapInputStream.setRandomAccessFile(accessFile);
                    try {
                        fileUpdate(fileName1, lastFileName);
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                    switchFile = false;
                }
            }
        }catch (InterruptedException | IOException e) {
            e.printStackTrace();
            System.err.println(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                accessFile.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

//    @Override
//    public void readFrame1(int bufferSize) {
//        asyncProcess = true;
//        readFrame();
//    }

    private PacketWrapper getPacketWrapper(){
//        if (asyncProcess){
//            return new PacketWrapper();
//        }else{
//            return packetWrapperGlobal;
//        }
        return packetWrapperGlobal;
    }

    public static class PacketWrapper {
        public int packetType;
        public byte[] buffer;
        public long packetId;
        public int validLen;
        public byte[] data;
        public int dataLen;

        public PacketWrapper(){
            data = new byte[65535];
        }
    }

    protected void fileUpdate(String newFile,String oldFile){

    }

    protected void offsetUpdate(String currentFile,long offset){

    }

    public interface PcapInputStreamCallback{
        void packetValid(PacketWrapper packetWrapper) throws InterruptedException;
        default void switchFile(String oldFile){
            try {
                Files.deleteIfExists(Paths.get(oldFile));
            } catch (IOException e) {

            }
        }
        default void recvPacketNumber(long recvNumber){}
    }
}
