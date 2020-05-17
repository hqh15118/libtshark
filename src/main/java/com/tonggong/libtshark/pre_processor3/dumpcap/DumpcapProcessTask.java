package com.tonggong.libtshark.pre_processor3.dumpcap;


import java.io.InputStream;
import java.util.concurrent.BlockingQueue;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-13 - 15:56
 */


class DumpcapProcessTask extends ProcessTask {

    private BlockingQueue<Object> queue;
    private DumpPcapInputStream pcapInputStream;
    private ProcessStateMonitor processStateMonitor;

    /**
     *
     * @param source DUMPCAP进程的标准输出
     * @param pcapInputStream DUMPCAP进程将packet byte写入本地文件，该实例是从本地文件中读取packet byte
     *
     */
    public DumpcapProcessTask(InputStream source,
                              BlockingQueue<Object> queue,
                              DumpPcapInputStream pcapInputStream,
                              ProcessStateMonitor processStateMonitor) {
        super(source);
        this.queue = queue;
        this.pcapInputStream = pcapInputStream;
        this.processStateMonitor = processStateMonitor;
    }

    /**
     * dumpcap -b filesize：<file_size_in_KB> -w <filename>
     Capturing on 'Wi-Fi: en0'
     File: /Users/hongqianhui/Desktop/temp_00001_20200205181810
     Packets: 1358 File: /Users/hongqianhui/Desktop/temp_00002_20200205181843
     Packets: 287
     Packets received/dropped on interface 'Wi-Fi: en0': 1611/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
     */

    @Override
    public void callback(String data) {
        if (data.startsWith("Capturing on")){
            if (processStateMonitor != null){
                processStateMonitor.start();
            }
        }else if(data.startsWith("File:")){
            //first file
            try {
                String fileName = data.substring(6);
                if (processStateMonitor != null){
                    processStateMonitor.running("start capturing packet on {" + fileName + "}");
                }
                queue.put(fileName);
            } catch (InterruptedException e) {
                if (processStateMonitor != null){
                    processStateMonitor.error(e,"new file name can not put into [fileNameQueue]");
                }
                stop();
            }
        }else{
            String[] splitStr = data.split(" ");
            if (splitStr.length == 2){
                try {
                    queue.put(Integer.parseInt(splitStr[1]));
                } catch (InterruptedException e) {
                    stop();
                }
            }else if(splitStr.length == 4){
                //switch file!
                try {
                    queue.put(Integer.parseInt(splitStr[1]));
                    //switch read file！
                    queue.put(splitStr[3]);
                } catch (InterruptedException e) {
                    stop();
                }
            }else if (data.startsWith("Packets received/dropped")){
                //stop capture
                try {
                    queue.put("exit now!");
                } catch (InterruptedException e) {
                    stop();
                }
                stop();
            }else{
                /*
                 * Packets captured: 500
                 * [Packets received/dropped on interface 'Wi-Fi: en0': 500/2 (pcap:0/dumpcap:0/flushed:2/ps_ifdrop:0) (99.6%)]
                 */
                if (processStateMonitor != null){
                    processStateMonitor.error(null,"dumpcap process output error data which can not be processed! { " + data + "}");
                }
            }
        }
    }

    @Override
    public void stop() {
        super.stop();
        pcapInputStream.stop();
    }

    @Override
    protected void finish(Exception e) {
        processStateMonitor.finish(e);
    }

    public void setMonitor(ProcessStateMonitor processStateMonitor){
        this.processStateMonitor = processStateMonitor;
    }
}
