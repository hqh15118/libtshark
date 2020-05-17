package com.tonggong.libtshark.pre_processor3.dumpcap;


import com.sun.istack.internal.NotNull;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-13 - 17:30
 */
public class DumpcapProcess {

    private DumpcapProcessTask dumpcapProcessTask;
    private ExecutorService dumpcapExecutor;
    private Process process;
    private DumpPcapInputStream pcapInputStream;
    private String captureIFace;
    //private Jedis jedis;

    private Properties getProperty(){
        Properties properties = new Properties();
        String filePath = DumpcapProcess.class.getResource("/application.properties").getPath();
        try {
            properties.load(new FileInputStream(filePath));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }

    private static final String REDIS_KEY_HASH = "hpcap_index";
    private static final String REDIS_KEY_LIST = "lpcap_name";

    public void setMonitor(ProcessStateMonitor processStateMonitor){
        dumpcapProcessTask.setMonitor(processStateMonitor);
    }

    public void setDataCallback(DumpPcapInputStream.PcapInputStreamCallback pcapInputStreamCallback){
        pcapInputStream.setPcapInputStreamCallback(pcapInputStreamCallback);
    }

    public DumpcapProcess(@NotNull String DUMPCAP_TEMP_FILE_NAME,
                          @NotNull String captureIFace){
        this(DUMPCAP_TEMP_FILE_NAME,captureIFace,"500000","1000000",null,null);
    }
    /**
     *
     * @param DUMPCAP_TEMP_FILE_NAME tmp file path save tmp dumpcap .pcapng file
     * @param fileSize single tmp file size
     * @param limit null means no limit
     * @param processStateMonitor process monitor
     * @param pcapInputStreamCallback data callback
     * @param captureIFace capture network interface
     */
    public DumpcapProcess(@NotNull String DUMPCAP_TEMP_FILE_NAME,
                          @NotNull String captureIFace,
                          @NotNull String fileSize,
                          String limit,
                          ProcessStateMonitor processStateMonitor,
                          DumpPcapInputStream.PcapInputStreamCallback pcapInputStreamCallback){
        //Properties properties = getProperty();
        //String host = (String) properties.get("redis-host");
        //int port = Integer.parseInt((String) properties.get("redis-port"));
        //jedis = JedisUtil.getJedisInstance(host,port);
        this.captureIFace = captureIFace;
        initDumpcapProcess(DUMPCAP_TEMP_FILE_NAME, fileSize, limit,processStateMonitor,pcapInputStreamCallback);
    }

    private void initDumpcapProcess(@NotNull String DUMPCAP_TEMP_FILE_NAME,
                                    @NotNull String fileSize,
                                    String limit,
                                    @NotNull ProcessStateMonitor processStateMonitor,
                                    @NotNull DumpPcapInputStream.PcapInputStreamCallback pcapInputStreamCallback){
        LinkedBlockingQueue<Object> queue = new LinkedBlockingQueue<>();
        dumpcapExecutor = Executors.newFixedThreadPool(2, new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("dumpcap-service-pool");
                return thread;
            }
        });
        pcapInputStream = new DumpPcapInputStream(queue){
//            @Override
//            protected void fileUpdate(String newFile,String oldFile) {
//                jedis.rpop(REDIS_KEY_LIST);
//                jedis.hdel(REDIS_KEY_HASH,oldFile);
//                jedis.lpush(REDIS_KEY_LIST,newFile);
//            }
//
//            @Override
//            protected void offsetUpdate(String currentFile,long offset) {
//                jedis.hset(REDIS_KEY_HASH,currentFile,String.valueOf(offset));
//            }
        };
        pcapInputStream.setPcapInputStreamCallback(pcapInputStreamCallback);
        try{
            Integer.parseInt(fileSize);
            if (limit != null){
                Integer.parseInt(limit);
            }
        }catch (NumberFormatException e){
            e.printStackTrace();
        }
        ArrayList<String> dumpcapProcess = new ArrayList<>();
        dumpcapProcess.add("dumpcap");
        dumpcapProcess.add("-i");
        dumpcapProcess.add(captureIFace);
        dumpcapProcess.add("-b");
        dumpcapProcess.add("filesize:" + fileSize);
        dumpcapProcess.add("-w");
        dumpcapProcess.add(DUMPCAP_TEMP_FILE_NAME);
        if (limit != null){
            dumpcapProcess.add("-c");
            dumpcapProcess.add(limit);
        }


        ProcessBuilder processBuilder = new ProcessBuilder(dumpcapProcess);
        try {
            process = processBuilder.start();
            dumpcapProcessTask = new DumpcapProcessTask(process.getErrorStream(),queue,pcapInputStream, processStateMonitor){
                @Override
                protected void finish(Exception e) {
                    super.finish(e);
                    dumpcapExecutor.shutdown();
                }
            };

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void start(){
        dumpcapExecutor.submit(() -> pcapInputStream.readFrame(new byte[65536]));
        dumpcapExecutor.submit(dumpcapProcessTask);
    }

    /**
     * 关闭资源
     * 1.dumpcap 进程资源
     * 2.停止从dumpcap中读取字符串
     * 3.消费完Queue中所有的数据后退出
     */
    public void stop(){
        process.destroy();
        dumpcapProcessTask.stop();
    }
}
