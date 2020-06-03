package com.tonggong.libtshark.pre_processor3;

import com.alibaba.fastjson.JSON;
import com.tonggong.libtshark.pre_processor3.bean.DecodeClazz;
import com.tonggong.libtshark.pre_processor3.bean.GlobalArgs;
import com.tonggong.libtshark.pre_processor3.bean.TsharkArgs;
import com.tonggong.libtshark.pre_processor3.dumpcap.DumpPcapInputStream;
import com.tonggong.libtshark.pre_processor3.dumpcap.DumpcapProcess;
import com.tonggong.libtshark.pre_processor3.dumpcap.ProcessStateMonitor;
import com.tonggong.libtshark.pre_processor3.log.TsharkLog;
import com.tonggong.libtshark.pre_processor3.pipeline.PipeLine;
import com.tonggong.libtshark.pre_processor3.tshark.BasePreProcessor;
import com.tonggong.libtshark.pre_processor3.tshark.PreProcessorListener;
import com.tonggong.libtshark.pre_processor3.tshark.UndefinedPreProcessor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class PacketAnalyzeEngine {

    private TsharkArgs tsharkArgs;
    private BasePreProcessor[] basePreProcessors;
    private ExecutorService basePreProcessThreadPool;
    private final AtomicInteger id = new AtomicInteger();
    private DataCallback dataCallback;
    private static final int RESTART_PROCESS_MIN_PACKET_NUMBER = 100000,
            RESTART_PROCESS_MAX_PACKET_NUMBER = 1000000;
    private static final String TSHARK_PROCESS_FILE = "config/tsharkprocess.json";
    private long recvPacket = 0,pointRecvPacket = 0;
    private long[] lastPreProcessorRecvPacket;
    private final Object LOCK = new Object();
    private volatile boolean waiting = true;
    private volatile boolean restartAllTsharkProcessSuccessfully = true;
    private DumpcapProcess dumpcapProcess;
    private volatile boolean restarting = false;
    private final class DetectTask implements Runnable {
        @Override
        public void run() {
            if (!restarting) {
                return;
            }
            boolean restart = true;
            for (int i = 0; i < basePreProcessors.length; i++) {
                BasePreProcessor basePreProcessor = basePreProcessors[i];
                long recv = basePreProcessor.getRecvPacket();
                if (basePreProcessor instanceof UndefinedPreProcessor) {
                    // 忽略UndefinedPreProcessor，这个进程可能会收到其他非主要报文，这些报文是可以忽略的.
                    if (recv - lastPreProcessorRecvPacket[i] > 1000) {
                        lastPreProcessorRecvPacket[i] = recv;
                        restart = false;
                    }
                    continue;
                }
                if (recv != lastPreProcessorRecvPacket[i]) {
                    lastPreProcessorRecvPacket[i] = recv;
                    restart = false;
                }
            }
            // 所有的核心tshark进程都没有分析报文，表明所有的分析进程已经结束了
            if (restart) {
                log.info("2.start restarting[" + basePreProcessors.length + "] processes!");
                restarting = false;
                for (BasePreProcessor basePreProcessor : basePreProcessors) {
                    basePreProcessThreadPool.submit(basePreProcessor::restartCapture);
                }
                clearTsharkTmpFile();
            }
        }
    }

    private void clearTsharkTmpFile() {
        Map<String,String> env = System.getenv();
        String TEMP = env.get("TEMP");
        if (TEMP == null){
            throw new RuntimeException("not define TEMP environment variable");
        }
        File file = new File(TEMP);
        if (file.exists()){
            File[] files = file.listFiles();
            if (files != null) {
                for (File file1 : files) {
                    if (file1.getName().toLowerCase().startsWith("wireshark")) {
                        try {
                            if (file1.delete()) {
                                log.info("delete tshark tmp dump file successfully! name : " + file1.getName());
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        }
    }

    private final PreProcessorListener preProcessorListener = new PreProcessorListener() {
        @Override
        public void tsharkProcessStarted(int id, Process process, String command, List<String> protocol) {
            synchronized (PacketAnalyzeEngine.class) {
                log.info("***********3.process + [" + protocol + "] restart successfully！***********");
                lastPreProcessorRecvPacket[id] = -1;
                for (int i = 0; i < lastPreProcessorRecvPacket.length; i++) {
                    long l = lastPreProcessorRecvPacket[i];
                    if (l != -1) {
                        log.info("wait for [{}] process restart.." , basePreProcessors[i].getPreProcessorName());
                        return;
                    }
                }
                Arrays.fill(lastPreProcessorRecvPacket, 0);
                //避免notify信号丢失
                while (!waiting) {
                    sleep(10);
                }
                log.info("4.resume dumpcap process!");
                synchronized (LOCK) {
                    restartAllTsharkProcessSuccessfully = true;
                    LOCK.notifyAll();
                }
            }
        }

        @Override
        public void tsharkProcessFailed(int id, Process process, String command, List<String> protocol) {
            restartAllTsharkProcessSuccessfully = false;
            log.error("3.process [{}] restart failed,try to restart it now! command : [{}]" , process,command);
            sleep(2000);
            basePreProcessors[id].restartCapture();
        }
    };

    @SneakyThrows
    private static void sleep(long time) {
        Thread.sleep(time);
    }


    public PacketAnalyzeEngine() {
        if (!init()) {
            log.error("load 「tsharkprocess.json」 failed , init error and exit!");
            return;
        }
        try {
            postInitTsharkArgs();
        } catch (Exception e) {
            log.error("undefinedPacket clazz instance raise error, init error and exit!" , e );
            return;
        }
        log.info("********************************tshark config loaded********************************");
        log.info(JSON.toJSONString(tsharkArgs));
        log.info("********************************tshark config loaded********************************");
        redefineRestartProcessPacket();
        log.info("start init all tshark processes");
        try {
            initBaseProcessors();
        } catch (Exception e) {
            log.error("tshark process init error!");
            e.printStackTrace();
            return;
        }
        log.info("init all tshark processes successfully! \n start init dumpcap process > ");
        if (!initDumpcapProcess()) {
            BasePreProcessor.releaseProcess();
        }
        // start tshark process restart detect service
        DetectTask detectorTask = new DetectTask();
        ScheduledThreadPoolExecutor preProcessorPacketDetector = new ScheduledThreadPoolExecutor(1,
                new ThreadFactory() {
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread scheduledThread = new Thread(r);
                        scheduledThread.setName("-preprocessor-restart-detector-");
                        return scheduledThread;
                    }
                });
        preProcessorPacketDetector.scheduleAtFixedRate(detectorTask, 500, 1000, TimeUnit.MILLISECONDS);
        registerHook();
    }

    private void postInitTsharkArgs() throws Exception {
        if (tsharkArgs.getUndefinedPacket() != null && tsharkArgs.getUndefinedPacket().length() > 0) {
            Class<?> raw = Class.forName(tsharkArgs.getUndefinedPacket());
            boolean find = false;
            for (Field declaredField : raw.getDeclaredFields()) {
                if (declaredField.getName().toLowerCase().contains("layer")){
                    GlobalArgs.undefinedPacketClass = declaredField.getType();
                    find = true;
                    break;
                }
            }
            if (!find){
                throw new RuntimeException("can not find field named (*layer*) in " + tsharkArgs.getUndefinedPacket() + " clazz!");
            }
            if (log.isInfoEnabled()){
                log.info("use error protocol default packet : {}" , GlobalArgs.undefinedPacketClass);
            }
        }else{
            log.warn("undefined packet is not define!");
        }
    }

    private void registerHook() {
        Thread thread = new Thread(() -> {
            log.info("hook start working");
            BasePreProcessor.releaseProcess();
            if (dumpcapProcess != null) {
                dumpcapProcess.stop();
            }
            TsharkLog.release();
            log.info("hook finish working");
        });
        Runtime.getRuntime().addShutdownHook(thread);
    }


    private boolean initDumpcapProcess() {
        // create tmp directory
        String tmpFileDir = tsharkArgs.getDumpcap().getTmpFile();
        if (tmpFileDir == null || tmpFileDir.length() == 0){
            throw new RuntimeException("you must define [dumpcap > tmpFile] directory and make sure it exits!");
        }
        tmpFileDir = tmpFileDir.substring(0,tmpFileDir.lastIndexOf("\\"));
        if (Files.notExists(Paths.get(tmpFileDir))) {
            throw new RuntimeException("you must define [dumpcap > tmpFile] directory and make sure it exits!");
        }
        dumpcapProcess = null;
        PcapHandle pcapHandle = null;
        try {
            dumpcapProcess = new DumpcapProcess(
                    tsharkArgs.getDumpcap().getTmpFile(),
                    tsharkArgs.getDumpcap().getIFace()
            );
            //set default monitor
            dumpcapProcess.setMonitor(new ProcessStateMonitor() {
                @Override
                public void start() {
                    log.info("dumpcap process start running! (detect [CAPTURE ON XXX])");
                }

                @Override
                public void error(Throwable e, String errorMsg) {
                    if (e == null) {
                        log.warn("[DUMPCAP PROCESS WARN]dumpcap process raise warn [{}]", errorMsg);
                    }else {
                        log.warn("[DUMPCAP PROCESS ERROR]dumpcap process raise error [{}]", errorMsg, e);
                    }
                }

                @Override
                public void running(String info) {
                    log.info(info);
                }

                @Override
                public void finish(Throwable e) {
                    log.info("dumpcap process end , error msg => [{}]" , e == null ? "":e.getMessage(),e);
                }
            });
            PcapNetworkInterface pcapNetworkInterface = Pcaps.getDevByName(tsharkArgs.getIFace());
            pcapHandle = pcapNetworkInterface.openLive(65535, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);
            PcapHandle finalPcapHandle = pcapHandle;
            dumpcapProcess.setDataCallback(packetWrapper -> {
                try {
                    handlePacket(packetWrapper,finalPcapHandle);
                    ++recvPacket;
                    ++pointRecvPacket;
                    if (pointRecvPacket >= tsharkArgs.getPointRestartProcessPacket()){
                        pointRecvPacket = 0;
                        TsharkLog.log("recv point packet!");
                    }
                    if (recvPacket >= tsharkArgs.getRestartProcess()) {
                        System.out.println("=======================================");
                        log.info("***********1.dumpcap process recv threshold packet number，ready to restart all tshark processes!");
                        synchronized (LOCK) {
                            restartAllProcess();
                            waiting = true;
                            LOCK.wait();
                            waiting = false;
                            log.info("***********5.dumpcap continue running！");
                            System.out.println("=======================================");
                            if (!restartAllTsharkProcessSuccessfully) {
                                throw new RuntimeException("tshark restart failed!");
                            }
                            recvPacket = 0;
                        }
                    }
                } catch (NotOpenException | PcapNativeException e) {
                    e.printStackTrace();
                }
            });
        } catch (Exception e) {
            if (pcapHandle != null) {
                pcapHandle.close();
            }
            if (dumpcapProcess != null) {
                dumpcapProcess.stop();
            }
            log.error("init dumpcap process failed");
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * 重启tshark进程，当所有的tshark进程一段时间内都没有接收到报文
     * 即认为所有的tshark进程已经结束当前的报文分析工作
     * 可以重启进程，反之等待直到所有进程分析结束
     */
    private void restartAllProcess() {
        restarting = true;
    }

    protected void handlePacket(DumpPcapInputStream.PacketWrapper packetWrapper, PcapHandle pcapHandle) throws NotOpenException, PcapNativeException {
        pcapHandle.sendPacket(packetWrapper.data,packetWrapper.dataLen);
    }

    private void initBaseProcessors() {
        int processNumber = tsharkArgs.getArgs().size();

        // init processor
        if (tsharkArgs.isUndefined()) {
            processNumber += 1;
        }

        //init restart arg
        lastPreProcessorRecvPacket = new long[processNumber];

        //init thread pool
        basePreProcessThreadPool = new ThreadPoolExecutor(
                processNumber * 2,
                processNumber * 2,
                100,
                TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                r -> {
                    Thread thread = new Thread(r);
                    thread.setName("-base-processor-" + id.getAndIncrement());
                    return thread;
                },
                (r, executor) -> log.error("can not submit BasePreProcess task to thread pool!")
        );

        basePreProcessors = new BasePreProcessor[processNumber];
        for (int i = 0; i < tsharkArgs.getArgs().size(); i++) {
            try {
                doInitBaseProcessors(i);
            } catch (ClassNotFoundException e) {
                BasePreProcessor.releaseProcess();
                throw new RuntimeException("can not find decode clazz",e);
            }
        }

        if (tsharkArgs.isUndefined()) {
            initUndefinedPreProcessor(processNumber);
        }
    }

    protected void initUndefinedPreProcessor(int processNumber) {
        BasePreProcessor undefinedPreProcessor = new UndefinedPreProcessor() {
            @Override
            public void decodeJSONString(int preProcessorId, String packetJSON) {
                super.decodeJSONString(preProcessorId, packetJSON);
                if (dataCallback != null) {
                    dataCallback.callback(preProcessorId, packetJSON);
                }
            }
        };
        basePreProcessors[processNumber - 1] = undefinedPreProcessor;
        undefinedPreProcessor.setPreProcessorListener(preProcessorListener);
        undefinedPreProcessor.setCurrentPreProcessId(processNumber - 1);
        DecodeClazz decodeClazz = new DecodeClazz(null,null);
        undefinedPreProcessor.setDecodeClazz(decodeClazz);
    }

    public void start() {
        if (basePreProcessors == null) {
            throw new RuntimeException("packet engine start error init failed!");
        }
        for (BasePreProcessor basePreProcessor : basePreProcessors) {
            basePreProcessThreadPool.submit(() -> {
                basePreProcessor.startCapture(tsharkArgs.getIFace());
            });
        }
        dumpcapProcess.start();
    }

    public void setDataCallback(DataCallback dataCallback) {
        this.dataCallback = dataCallback;
    }

    public interface DataCallback {
        void callback(int processId, String json);
    }

    private void doInitBaseProcessors(int id) throws ClassNotFoundException {
        TsharkArgs.Args args = tsharkArgs.getArgs().get(id);
        BasePreProcessor basePreProcessor = new BasePreProcessor() {
            @Override
            public List<String> protocolFilterField() {
                return args.getProtocol();
            }

            @Override
            public List<String> filterFields() {
                return args.getFilterFields();
            }

            @Override
            public void decodeJSONString(int preProcessorId, String packetJSON) {
                super.decodeJSONString(preProcessorId, packetJSON);
                if (dataCallback != null) {
                    dataCallback.callback(preProcessorId, packetJSON);
                }
            }
        };
        basePreProcessors[id] = basePreProcessor;
        basePreProcessor.setPreProcessorName(args.getProtocol());
        basePreProcessor.setOutput2Console(tsharkArgs.getArgs().get(id).isShowConsole());
        basePreProcessor.setPreProcessorListener(preProcessorListener);
        basePreProcessor.setCurrentPreProcessId(id);
        String[] protocols = new String[args.getProtocol().size()];
        args.getProtocol().toArray(protocols);

        String[] decodeClazzNames = tsharkArgs.getArgs().get(id).getClazz();
        if (decodeClazzNames == null || decodeClazzNames.length == 0){
            log.warn("[{}] decode PACKET not defines" , tsharkArgs.getArgs().get(id).getProtocol());
            return;
        }
        Class<?>[] clazz = new Class[decodeClazzNames.length];
        int index = 0;
        for (String decodeClazzName : decodeClazzNames) {
            clazz[index] = Class.forName(decodeClazzName);
            index++;
        }
        basePreProcessor.setDecodeClazz(new DecodeClazz(protocols,clazz));
    }

    public void setPipeline(PipeLine pipeline) {
        for (BasePreProcessor basePreProcessor : basePreProcessors) {
            basePreProcessor.setPipeline(pipeline);
        }
    }

    private void redefineRestartProcessPacket() {
        if (tsharkArgs.isDebug()) {
            return;
        }
        if (tsharkArgs.getRestartProcess() < RESTART_PROCESS_MIN_PACKET_NUMBER) {
            tsharkArgs.setRestartProcess(RESTART_PROCESS_MIN_PACKET_NUMBER);
        }
        if (tsharkArgs.getRestartProcess() > RESTART_PROCESS_MAX_PACKET_NUMBER) {
            tsharkArgs.setRestartProcess(RESTART_PROCESS_MAX_PACKET_NUMBER);
        }
    }


    private boolean init() {
        try {
            tsharkArgs = preInitTsharkArgs();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        if (tsharkArgs != null) {
            return true;
        }
        StringBuilder jsonReader = new StringBuilder();
        try (BufferedReader buffReader = new BufferedReader(new InputStreamReader(new FileInputStream(TSHARK_PROCESS_FILE)))) {
            for (; ; ) {
                String data = buffReader.readLine();
                if (data == null) {
                    break;
                }
                if (data.startsWith("//")){//ignore //
                    continue;
                }
                jsonReader.append(data);
            }
            tsharkArgs = JSON.parseObject(jsonReader.toString(), TsharkArgs.class);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    protected TsharkArgs preInitTsharkArgs() throws Exception {
        return null;
    }

    public void setDumpcapProcessMonitor(ProcessStateMonitor processMonitor){
        dumpcapProcess.setMonitor(processMonitor);
    }
}
