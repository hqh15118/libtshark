package com.tonggong.libtshark.pre_processor3.log;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class TsharkLog {

    private static PrintWriter bufferedWriter , oldBufferedWriter;
    private static final AtomicLong lastInitLogFileTime = new AtomicLong(System.currentTimeMillis());
    private static final long ONE_DAY = 1000 * 60 * 60 * 24;
    static {
        initLogFile();
    }

    private static synchronized void initLogFile(){
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastInitLogFileTime.get() < ONE_DAY || bufferedWriter == null){
            return;
        }
        oldBufferedWriter = bufferedWriter;
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-mm-dd");
        String logName = "tshark_log_" + simpleDateFormat.format(new Date()) + ".log";
        File logFile = new File("/config/" +logName);
        if (!logFile.exists()){
            try {
                if (logFile.createNewFile()){
                    if (log.isInfoEnabled()){
                        log.info("init tshark log file successfully!");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
                log.error("create tshark log file failed!");
            }
        }
        assert logFile.exists();
        try {
            bufferedWriter = new PrintWriter(
                    new OutputStreamWriter(new FileOutputStream(logFile))
            );
            oldBufferedWriter.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void log(String data){
        initLogFile();
        if (bufferedWriter == null){
            System.out.println(data);
        }
        bufferedWriter.println(data);
    }

    public static void release(){
        if (bufferedWriter != null){
            bufferedWriter.close();
        }
    }
}
