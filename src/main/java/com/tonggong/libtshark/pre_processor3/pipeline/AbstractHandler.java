package com.tonggong.libtshark.pre_processor3.pipeline;

/**
 * #project spring-boot-starter
 *
 * @author hongqianhui
 * #create_time 2019-04-25 - 12:15
 */

/**
 **/
public abstract class AbstractHandler implements Handler{

    private AbstractHandler prevHandler;
    private AbstractHandler nextHandler;
    protected String id;
    /**
     *
     */
    private PipeLine pipeLine;
    public AbstractHandler(){
        id = this.getClass().getSimpleName();
    }

    public AbstractHandler setId(String id){
        this.id = id;
        return this;
    }

    @Override
    public void setPipeLine(PipeLine line) {
        this.pipeLine = line;
    }

    @Override
    public PipeLine getPipeLine() {
        return pipeLine;
    }

    @Override
    public AbstractHandler prevHandler() {
        return prevHandler;
    }

    @Override
    public AbstractHandler nextHandler() {
        return nextHandler;
    }

    @Override
    public void setPrevHandler(AbstractHandler prevHandler) {
        this.prevHandler = prevHandler;
    }

    @Override
    public void setNextHandler(AbstractHandler nextHandler) {
        this.nextHandler = nextHandler;
    }

    public abstract void handleAndPass(Object t);


}
