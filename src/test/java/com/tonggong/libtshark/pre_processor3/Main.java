package com.tonggong.libtshark.pre_processor3;

//import com.tonggong.libtshark.pre_processor3.dumpcap.DumpcapProcess;
//import com.tonggong.libtshark.pre_processor3.dumpcap.ProcessStateMonitor;
//import org.pcap4j.core.*;

public class Main {

//    public static void main(String[] args) throws Exception {
//        packetAnalyzeEngineTest();
//    }
//
//    private static void dumpTransmitTest() throws Exception {
//        DumpcapProcess dumpcapProcess = new DumpcapProcess("C:\\Users\\zjucsc\\Desktop\\dumpcap_tmp\\tmp",
//                "WLAN");
//        dumpcapProcess.setMonitor(new ProcessStateMonitor() {
//            @Override
//            public void start() {
//                System.out.println("start!");
//            }
//
//            @Override
//            public void error(Throwable e, String errorMsg) {
//                System.out.println(errorMsg);
//            }
//
//            @Override
//            public void running(String info) {
//                System.out.println(info);
//            }
//
//            @Override
//            public void finish(Throwable e) {
//                System.out.println(e);
//            }
//        });
//        PcapNetworkInterface pcapNetworkInterface = Pcaps.getDevByName("\\Device\\NPF_{85B3D44A-D5EF-4256-97A3-2002C1D08DB3}");
//        final PcapHandle pcapHandle = pcapNetworkInterface.openLive(65535, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,1000);
//        dumpcapProcess.setDataCallback(packetWrapper -> {
//            try {
//                pcapHandle.sendPacket(packetWrapper.data,packetWrapper.dataLen);
//            } catch (NotOpenException | PcapNativeException e) {
//                e.printStackTrace();
//            }
//        });
//        dumpcapProcess.start();
//    }
//
//
//    /**
//     * Pcap库报文转发效率检测
//     * 10w packets / s
//     * @throws Exception
//     */
//    private static void pcapSendSpeedTest() throws Exception{
//        PcapNetworkInterface pcapNetworkInterface = Pcaps.getDevByName("\\Device\\NPF_{235EDB77-6B88-41E1-8C1E-29DB35754E3D}");
//        final PcapHandle pcapHandle = pcapNetworkInterface.openLive(65535, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,1000);
//        final PcapHandle sendHandler = pcapNetworkInterface.openLive(65535, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,1000);
//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    pcapHandle.loop(-1, new PacketListener() {
//                        @Override
//                        public void gotPacket(PcapPacket pcapPacket) {
//                            System.out.println(pcapPacket);
//                        }
//                    });
//                } catch (PcapNativeException | InterruptedException | NotOpenException e) {
//                    e.printStackTrace();
//                }
//            }
//        }).start();
//        String dataHex = "dcfe1892217b30b49efeaefd0800450000290aad40008006ed8dc0a8016a700dd074fd3e01bbe59243c15122217050101802fa5c000000";
//        byte[] data = new byte[dataHex.length() / 2];
//        for (int i = 0; i < data.length; i++) {
//            data[i] = (byte)Integer.parseInt(dataHex.substring(i * 2 , i * 2 + 2),16);
//        }
//        int time = 0;
//        for (;;){
//            long start = System.currentTimeMillis();
//            sendHandler.sendPacket(data);
//            System.out.println(System.currentTimeMillis() - start);
//            Thread.sleep(5000);
//        }
//    }
//
//
//    private static void packetAnalyzeEngineTest(){
//        PacketAnalyzeEngine packetAnalyzeEngine = new PacketAnalyzeEngine();
//        packetAnalyzeEngine.start();
//    }
}
