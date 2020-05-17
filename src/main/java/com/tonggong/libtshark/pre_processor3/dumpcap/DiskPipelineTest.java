package com.tonggong.libtshark.pre_processor3.dumpcap;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

public class DiskPipelineTest {

    private static File operateFile;
    private static final String fileName = "temp";
    static {
        try {
            operateFile = initFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static File initFile() throws IOException {
        Path path = Paths.get(fileName);
        Files.deleteIfExists(path);
        Files.createFile(path);
        return path.toFile();
    }

    public static void main(String[] args) throws InterruptedException {
        File file = operateFile;
        final LinkedBlockingQueue<Integer> linkedBlockingQueue = new LinkedBlockingQueue<>();
        Thread dataAppendThread = new DataAppendThread(file,linkedBlockingQueue);
        dataAppendThread.start();
        Thread dataReadThread = new DataReadThread(file,linkedBlockingQueue);
        dataReadThread.start();
        new CountDownLatch(1).await();
    }

    private static class DataAppendThread extends Thread{

        private File file;
        private LinkedBlockingQueue<Integer> queue;
        public DataAppendThread(File file, LinkedBlockingQueue<Integer> queue){
            this.file = file;
            this.queue = queue;
        }

        @Override
        public void run() {
            int writeIndex = 0;
            long allNumber = 0;
            final int writeAverage = 10000;
            /*
             * head 00 01 02 03
             * length 00 00
             * index
             * data xxx
             */
            byte[] data = "hongqianhui".getBytes();
            int dataLength = data.length + 4;
            byte[] head = new byte[]{0x00,0x01,0x02,0x03};
            try(DataOutputStream bfWriteStream = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(file)))){
                for (;allNumber < 100_000_000;){
                    bfWriteStream.write(head);
                    bfWriteStream.writeShort(dataLength);
                    bfWriteStream.writeInt(writeIndex);
                    bfWriteStream.write(data);
                    writeIndex ++;
                    bfWriteStream.flush();
                    if (writeIndex % writeAverage == 0){
                        if (queue.offer(writeIndex)){
                            writeIndex = 0;
                        }
                    }
                    allNumber ++;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    private static class DataReadThread extends Thread{
        private File file;
        private LinkedBlockingQueue<Integer> queue;
        public DataReadThread(File file, LinkedBlockingQueue<Integer> queue){
            this.file = file;
            this.queue = queue;
        }
        @Override
        public void run() {
            try{
                RandomAccessFile randomAccessFile = new RandomAccessFile(file,"r");
                byte[] head = new byte[4];
                byte[] buffer = new byte[1024];
                for (;;){
                    int value = queue.take();
                    randomAccessFile.seek(randomAccessFile.getFilePointer());
                    for (int i = 0; i < value; i++) {
                        int readLength = randomAccessFile.read(head);
                        assert readLength > 0;
                        assert head[0] == 0x00 && head[1] == 0x01 && head[2] == 0x02 && head[3] == 0x03;
                        int dataLength = randomAccessFile.readShort();
                        readLength = randomAccessFile.read(buffer,0,dataLength);
                        assert readLength > 0;
                        System.out.print(getInt(buffer));
                        System.out.println(new String(buffer,4,readLength - 4));
                    }
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    private static int getInt(byte[] data){
        int a = Byte.toUnsignedInt(data[0]) << 24;
        int b = Byte.toUnsignedInt(data[1]) << 16;
        int c = Byte.toUnsignedInt(data[2]) << 8;
        int d = Byte.toUnsignedInt(data[3]);
        return a + b + c + d;
    }
}
