package com.tonggong.libtshark.pre_processor3;

import com.alibaba.fastjson.JSON;
import com.tonggong.libtshark.pre_processor3.bean.TsharkArgs;
import com.tonggong.libtshark.pre_processor3.dumpcap.DumpPcapInputStream;
import com.tonggong.libtshark.pre_processor3.dumpcap.DumpcapProcess;
import com.tonggong.libtshark.pre_processor3.log.TsharkLog;
import com.tonggong.libtshark.pre_processor3.pipeline.PipeLine;
import com.tonggong.libtshark.pre_processor3.tshark.BasePreProcessor;
import com.tonggong.libtshark.pre_processor3.tshark.PreProcessorListener;
import com.tonggong.libtshark.pre_processor3.tshark.UndefinedPreProcessor;
import com.tonggong.libtshark.pre_processor3.util.ByteUtils;
import com.tonggong.libtshark.pre_processor3.util.sm4.SM4Utils;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.io.*;
import java.util.Arrays;
import java.util.List;
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
    private long recvPacket = 0;
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
                System.out.println("2.开始重启两个进程!");
                for (BasePreProcessor basePreProcessor : basePreProcessors) {
                    basePreProcessThreadPool.submit(basePreProcessor::restartCapture);
                }
                restarting = false;
            }
        }
    }

    private final PreProcessorListener preProcessorListener = new PreProcessorListener() {
        @Override
        public void tsharkProcessStarted(int id, Process process, String command, List<String> protocol) {
            synchronized (PacketAnalyzeEngine.class) {
                System.out.println("3.进程 + " + protocol + " 重启成功！");
                lastPreProcessorRecvPacket[id] = -1;
                for (long l : lastPreProcessorRecvPacket) {
                    if (l != -1) {
                        return;
                    }
                }
                Arrays.fill(lastPreProcessorRecvPacket, 0);
                while (!waiting) {
                    sleep(10);
                }
                System.out.println("4.重新激活dumpcap线程!");
                synchronized (LOCK) {
                    LOCK.notifyAll();
                }
            }
        }

        @Override
        public void tsharkProcessFailed(int id, Process process, String command, List<String> protocol) {
            restartAllTsharkProcessSuccessfully = false;
            lastPreProcessorRecvPacket[id] = -1;
            while (!waiting) {
                sleep(10);
            }
            synchronized (LOCK) {
                LOCK.notifyAll();
            }
        }
    };

    @SneakyThrows
    private static void sleep(long time) {
        Thread.sleep(time);
    }


    public PacketAnalyzeEngine() {
        if (!init()) {
            log.error("load tsharkprocess.json failed , init error and exit!");
            return;
        }
        System.out.println(tsharkArgs);
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

    private void registerHook() {
        Thread thread = new Thread(() -> {
            System.out.println("hook start working");
            BasePreProcessor.releaseProcess();
            if (dumpcapProcess != null) {
                dumpcapProcess.stop();
            }
            TsharkLog.release();
            System.out.println("hook finish working");
        });
        Runtime.getRuntime().addShutdownHook(thread);
    }

    private byte[] dataHandle(DumpPcapInputStream.PacketWrapper packetWrapper) {
        try {
            byte[] data = packetWrapper.data;
            int dataLen = packetWrapper.dataLen;// 数据有效长度
            byte[] decryptBytes = SM4Utils.decryptData_ECB(ByteUtils.division(data, 14, dataLen));// 解密数据
            byte[] mergerBytes = ByteUtils.merger(ByteUtils.division(data, 0, 14), decryptBytes);// 转发数据 = MAC头 + 解密数据
            return mergerBytes;
        } catch (Exception e) {
            log.error("PacketAnalyzeEngine → initDumpcapProcess() → dataHandle(): Data decryption failed ~");
            e.printStackTrace();
        }
        return new byte[]{};
    }

    private boolean initDumpcapProcess() {
        dumpcapProcess = null;
        PcapHandle pcapHandle = null;
        try {
            dumpcapProcess = new DumpcapProcess(
                    tsharkArgs.getDumpcap().getTmpFile(),
                    tsharkArgs.getDumpcap().getIFace()
            );
            PcapNetworkInterface pcapNetworkInterface = Pcaps.getDevByName(tsharkArgs.getIFace());
            pcapHandle = pcapNetworkInterface.openLive(65535, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);
            PcapHandle finalPcapHandle = pcapHandle;
            dumpcapProcess.setDataCallback(packetWrapper -> {
                try {
                    if (handlePacket(packetWrapper)) {
//                        finalPcapHandle.sendPacket(packetWrapper.data, packetWrapper.dataLen);
                        finalPcapHandle.sendPacket(dataHandle(packetWrapper));
                    }
                    recvPacket++;
                    if (recvPacket >= tsharkArgs.getRestartProcess()) {
                        System.out.println("=======================================");
                        System.out.println("1.接收到阈值报文数量，准备重启进程");
                        synchronized (LOCK) {
                            restartAllProcess();
                            waiting = true;
                            LOCK.wait();
                            waiting = false;
                            System.out.println("dumpcap进程被激活！");
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

    protected boolean handlePacket(DumpPcapInputStream.PacketWrapper packetWrapper) {
        return true;
    }

    private void initBaseProcessors() {
        int processNumber = tsharkArgs.getArgs().size();

        // init processor
        if (tsharkArgs.isUndefined()) {
            processNumber += 1;
        }

        //init restart arg
        lastPreProcessorRecvPacket = new long[processNumber];

        //init pool
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
                new RejectedExecutionHandler() {
                    @Override
                    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                        log.error("can not submit BasePreProcess task to thread pool!");
                    }
                }
        );

        basePreProcessors = new BasePreProcessor[processNumber];
        for (int i = 0; i < tsharkArgs.getArgs().size(); i++) {
            doInitBaseProcessors(i);
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

    private void doInitBaseProcessors(int id) {
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
            tsharkArgs = initTsharkArgs();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        if (tsharkArgs != null) {
            return true;
        }
        StringBuilder jsonReader = new StringBuilder();
        try (BufferedReader buffReader = new BufferedReader(new InputStreamReader
                (new FileInputStream(new File("config/tsharkprocess.json"))))) {
            for (; ; ) {
                String data = buffReader.readLine();
                if (data == null) {
                    break;
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

    protected TsharkArgs initTsharkArgs() throws Exception {
        return null;
    }
}
