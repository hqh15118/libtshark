package com.tonggong.libtshark.pre_processor3.tshark;

import com.tonggong.libtshark.pre_processor3.pipeline.PipeLine;
import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.util.*;


/**
 * #project packet-master-web
 *
 * @author hongqianhui
 * #create_time 2019-05-11 - 19:19
 *
 * 信息流向：
 *                     JSON                                    FvDimensionLayer                    FvDimensionLayer
 * xxxPreProcessor1 ------------> decodeThreadPool1[xxxPacket1] ------------> fvDimensionHandler --------------------> badpacketanalyzeHandler
 *                                                                    ↑        五元组发送 + 报文统计                             恶意报文分析
 *  输出JSON字符串                将JSON字符串解析为具体的Packet实体对象     ↑          单线程，无限队列                              多线程，无限队列
 *                              这部分还会将传送上来的协议替换为本地的协议    ↑
 *                                                                    ↑
 * xxxPreProcessor2 ------------> decodeThreadPool2[xxxPacket2] -----→J
 *                                                                    ↑
 * xxxPreProcessor3 ------------> decodeThreadPool3[xxxPacket3] -----→J
 */
@Slf4j
public abstract class BasePreProcessor implements PreProcessor {
    private String filePath = null;
    private volatile boolean processRunning = true;
    protected PipeLine pipeLine;
    private String bindCommand;
    private boolean output2Console;
    private static final List<String> filterPacketName = new ArrayList<>();
    private List<String> preProcessorName;
    private Process process = null;
    private static final TsharkProperties tsharkProperties = new TsharkProperties();
    private static class TsharkProperties{
        public String libpcapFilter;
        public String tsharkSessionReset = "100000";
        public String macAddress = "11:22:33:44:55:66";
    }
    private int currentPreProcessId;
    private static final Set<Process> aliveTsharkProcess = new HashSet<>();
    public void setPipeline(PipeLine pipeline){
        this.pipeLine = pipeline;
    }
    private long recvPacket = 0;
    private boolean restart = false;
    public static List<String> announcedProtocols(){
        return filterPacketName;
    }
    public static void releaseProcess(){
        for (Process tsharkProcess : aliveTsharkProcess) {
            if (tsharkProcess.isAlive()){
                tsharkProcess.destroy();
            }
        }
    }
    private PreProcessorListener preProcessorListener;
    public void setCurrentPreProcessId(int id){
        this.currentPreProcessId = id;
    }
    public void setPreProcessorListener(PreProcessorListener preProcessorListener){
        this.preProcessorListener = preProcessorListener;
    }

    public List<String> getPreProcessorName() {
        if (preProcessorName == null){
            return protocolFilterField();
        }
        return preProcessorName;
    }

    public void setPreProcessorName(List<String> preProcessorName) {
        this.preProcessorName = preProcessorName;
    }

    static {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(new File("config/tshark.properties")));
            tsharkProperties.macAddress = properties.getProperty("mac_address");
        } catch (IOException e) {
            log.error("load tshark properties failed,use default properties : [{}]" , tsharkProperties);
        }
    }

    /**
     * tsharkPath :tshark
     * macAddress : ignored
     * @param iFace iface
     */
    @Override
    public void startCapture(String iFace) {
        execCommand("tshark",tsharkProperties.macAddress,
                iFace,null,TsharkType.ONLINE,-1);
    }

    /**
     * @param tsharkPath
     * @param macAddress
     * @param interfaceName
     * @param type
     * @param limit
     */
    @Override
    public void startCapture(String tsharkPath , String macAddress, String interfaceName,
                             TsharkType type , int limit) {
        execCommand(tsharkPath,macAddress,interfaceName,pipeLine,type,limit);
    }

    private void execCommand(String tsharkPath , String macAddress,
                             String interfaceName, PipeLine pipeLine,
                             TsharkType type , int limit) {
        this.pipeLine = pipeLine;
        doExecCommand(buildCommand(tsharkPath, macAddress, interfaceName, type, limit));
    }

    private static synchronized void addCaptureProtocol(List<String> filterPacket){
        filterPacketName.addAll(filterPacket);
    }

    private String buildCommand(String tsharkPath , String macAddress,
                                String interfaceName,
                                TsharkType type , int limit) {
        StringBuilder commandBuilder = new StringBuilder();
        /*
         * command builder
         */
        List<String> fieldList = filterFields();
        appendBaseCommand(fieldList);       //init fv dimension packet format add all fv dimension into field list

        commandBuilder.append(tsharkPath).append(" ")
                .append("-l -n").append(" ");           //tshark -l -n

        if (type == TsharkType.OFFLINE) {
            pcapFilePath(limit);                        //init pcap file path
        }else{
            commandBuilder.append(" -i ").append(interfaceName).append(" ");    // -i capture_service
        }

        commandBuilder.append("-T ek").append(" ");       // -T ek
        for (String field : fieldList) {
            commandBuilder.append("-e ").append(field).append(" "); // -e xxx ... 根据需要的协议设置 + 五元组
        }

        if (!protocolFilterField().get(0).contains("not")){
            addCaptureProtocol(protocolFilterField());
        }

        if (type == TsharkType.OFFLINE) {
            if (filePath!=null && filePath.length() > 0) {
                commandBuilder.append(filePath);          //-r pcap file
            }
        }else{
            if(limit > 0){
                commandBuilder.append(" -c ").append(limit);
            }
            // -f "xxx not mac"
            if (filter() != null && filter().length() > 0){
                commandBuilder.append(" -f ").append("\"").append(filter())
                        .append(" and not ether src ").append(macAddress).append("\"");
            }else{
                commandBuilder.append(" -f ").append("\"").append(" not ether src ")
                        .append(macAddress).append("\"");
            }
        }
        if (extConfig()!=null && extConfig().length() > 0) {
            commandBuilder.append(" ").append(extConfig());
        }
        commandBuilder/*.append(" -b filesize:102400 -b files:5 ")*/.append(" -Y ").append("\"");
        for (int i = 0; i < protocolFilterField().size() - 1; i++) {
            commandBuilder.append(protocolFilterField().get(i)).append(" or");
        }
        commandBuilder.append(" ").append(protocolFilterField().get(protocolFilterField().size() - 1));
        commandBuilder.append("\"");   // 最后的部分 + s7comm/...用于过滤
        commandBuilder.append(" -M ").append(tsharkProperties.tsharkSessionReset);    //设置n条之后重置回话
        return commandBuilder.toString();
    }


    @Override
    public void pcapFilePath(int limit) {
        if (limit < 0)
            filePath =  " -r  " + pcapPath();
        else
            filePath = " -c " + limit + " -r " +  pcapPath();
    }

    @Override
    public void stopCapture() {
        processRunning = false; //停止读取数据流
        if (process.isAlive()){
            process.destroy();
        }
    }

    protected void appendBaseCommand(List<String> fields){
        //-e tcp.srcport -e tcp.dstport
        if (!fields.contains("frame.protocols")){
            fields.add("frame.protocols");
        }
        if (!fields.contains("eth.dst")){
            fields.add("eth.dst");
        }
        if (!fields.contains("eth.src")){
            fields.add("eth.src");
        }
        if (!fields.contains("frame.cap_len")){
            fields.add("frame.cap_len");
        }
        if (!fields.contains("ip.dst")){
            fields.add("ip.dst");
        }
        if (!fields.contains("ip.src")){
            fields.add("ip.src");
        }
        if (!fields.contains("tcp.srcport")){
            fields.add("tcp.srcport");
        }
        if (!fields.contains("tcp.dstport")){
            fields.add("tcp.dstport");
        }
        if (!fields.contains("tcp.payload")){
            fields.add("tcp.payload");
        }
        if (!fields.contains("tcp.flags.syn")){
            fields.add("tcp.flags.syn");
        }
        if (!fields.contains("tcp.flags.ack")){
            fields.add("tcp.flags.ack");
        }
        if (!fields.contains("-e custom_ext_raw_data")){
            fields.add("custom_ext_raw_data");
        }
    }

    public String pcapPath(){
        return "";
    }

    @Override
    public String filter() {
        return tsharkProperties.libpcapFilter;
    }

    public String extConfig() {
        return null;
    }

    private void createProcess(String command) throws IOException {
        synchronized (BasePreProcessor.class){
            process = Runtime.getRuntime().exec(command);
            aliveTsharkProcess.add(process);
        }
    }

    private void doExecCommand(String command) {
        bindCommand = command;
        try {
            createProcess(command);
            //本地离线不需要设置error stream
            doWithErrorStream(process.getErrorStream(), command);
            try (BufferedReader bfReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                while (processRunning) {
                    String packetInJSON = bfReader.readLine();
                    if (packetInJSON != null) {
                        if (packetInJSON.length() > 85) {
                            recvPacket += 1;
                            decodeJSONString(currentPreProcessId, packetInJSON);
                            if (output2Console){
                                System.out.println(packetInJSON);
                            }
                        }
                    }else{
                        if (!processRunning) {
                            //System.out.println("tshark process out by finishing read data");
                            if (!restart){
                                log.info("{} stop packet analyze ..", getPreProcessorName());
                            }else{
                                log.info("{} restart packet analyze .." , getPreProcessorName());
                            }
                        }else {
                            //System.out.println("tshark process out by stop capture");
                            throw new RuntimeException("tshark service exit unexpected! {" + this.getClass() + getClass() + "}"
                             + "[" + this.getBindCommand() +"]");
                        }
                        break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            log.error("can not run command {} " , getBindCommand());
            e.printStackTrace();
        }finally {
            if (process!=null){
                aliveTsharkProcess.remove(process);
                if (process.isAlive()){
                    process.destroy();
                }
            }
        }
    }

    public long getRecvPacket(){
        return recvPacket;
    }

    private void doWithErrorStream(InputStream errorStream , String command) {
        try(BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(errorStream))) {
            String str;
            List<String> protocol = protocolFilterField();
            if ((str = bufferedReader.readLine()) != null) {
                if (!str.startsWith("Capturing")){
                    if (!"".equals(str)) {
                        System.err.println("启动失败 >>>>>>>>>>>>>" + str + " command : " + bindCommand);
                        if (preProcessorListener != null){
                            preProcessorListener.tsharkProcessFailed(currentPreProcessId, process,
                                    bindCommand,protocol);
                        }
                    }
                }else{
                    if (preProcessorListener != null){
                        preProcessorListener.tsharkProcessStarted(currentPreProcessId, process,
                                bindCommand,protocol);
                    }
                    System.out.println("启动成功 >>>>>>>>>>>>>" + str + " " + getPreProcessorName());
                }
            }
        } catch (IOException e) {
            log.error("exception is caught while exec [{}]",command,e);
        }
    }


    @Override
    public void restartCapture() {
        restart = true;
        if (process.isAlive()){
            process.destroy();
        }
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        recvPacket = 0;
        doExecCommand(bindCommand);
    }

    public void setOutput2Console(boolean output2Console){
        this.output2Console = output2Console;
    }

    public String getBindCommand(){
        return bindCommand;
    }

    protected String preDecode(String jsonData,PipeLine pipeLine){
        return jsonData;
    }

    @Override
    public void decodeJSONString(int preProcessorId, String packetJSON) {
        if (pipeLine != null){
            pipeLine.pushDataAtHead(packetJSON);
        }
    }
}
