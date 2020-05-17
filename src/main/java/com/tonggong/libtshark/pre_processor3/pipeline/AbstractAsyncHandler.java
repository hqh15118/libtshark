package com.tonggong.libtshark.pre_processor3.pipeline;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * #project spring-boot-starter
 *
 * @author hongqianhui
 * #create_time 2019-04-24 - 13:00
 */
public abstract class AbstractAsyncHandler extends AbstractHandler {

    private ExecutorService executor;
    /**
     * 与该handle并行的pipeline
     */
    private final List<PipeLine> pipeLines = new ArrayList<>(1);

    public void addPipeLine(PipeLine pipeLines){
        this.pipeLines.add(pipeLines);
        pipeLines.addLast(this);
    }

    public AbstractAsyncHandler(ExecutorService executor){
        this.executor = executor;
    }

    protected AbstractAsyncHandler(){
    }

    public ExecutorService getExecutor(){
        return executor;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void handleAndPass(Object inValue){
        if (executor==null){
            //run handle in sync schema
            Object t = handle(inValue);
            if (nextHandler()!=null) {
                nextHandler().handleAndPass(t);
            }
            for (PipeLine pipeLine : pipeLines) {
                pipeLine.pushDataAtHead(t);
            }
        }else{
            //run handle in async schema
            executor.execute(new ExceptionSafeRunnable(){
                @Override
                public void doRun() {
                    Object t = handle(inValue);
                    if (nextHandler()!=null) {
                        nextHandler().handleAndPass(t);
                    }
                    /**
                     * 把该部分的处理结果推送到其他的pipeLine
                     */
                    if (pipeLines.size() > 0){
                        for (PipeLine pipeLine : pipeLines) {
                            pipeLine.pushDataAtHead(t);
                        }
                    }
                }
            });
        }
    }

    @Slf4j
    private static abstract class ExceptionSafeRunnable implements Runnable{

        @Override
        public void run() {
            try{
                doRun();
            }catch (Exception e){
                handleException(e);
            }
        }

        public void handleException(Exception e){
            log.error("exception {} raise in exception safe runnable" , e.getMessage() , e);
        }

        public abstract void doRun();
    }

    @Override
    public String toString() {
        return " ---> " + id;
    }

    public List<PipeLine> getPipeLines(){
        return pipeLines;
    }

    public void directPass(Object t){
        if (nextHandler()!=null){
            nextHandler().handleAndPass(t);
        }else{
            throw new RuntimeException("can not pass object[T] to next handler cause next handler is null!");
        }
    }

}
