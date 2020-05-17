package com.tonggong.libtshark.pre_processor3.dumpcap;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * #project MLenningPro
 *
 * @author hongqianhui
 * @create_time 2020-03-13 - 15:54
 */
public abstract class ProcessTask implements Runnable{

    protected InputStream source;
    private volatile boolean running = true;
    public ProcessTask(InputStream source){
        this.source = source;
    }

    public abstract void callback(String data);

    @Override
    public void run() {
        Exception exception = null;
        BufferedReader bfReader = new BufferedReader(new InputStreamReader(source));
        try {
            for (;running;) {
                String data = bfReader.readLine();
                if (data != null){
                    callback(data);
                }else{
                    break;
                }
            }
        }catch (IOException e){
            exception = e;
        }finally {
            try {
                finish(exception);
                bfReader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * stop read from process
     */
    public void stop(){
        running = false;
    }

    protected void finish(Exception e){

    }
}
