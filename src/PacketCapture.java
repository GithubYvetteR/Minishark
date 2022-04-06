import com.sun.xml.internal.bind.v2.runtime.reflect.Lister;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;

import java.io.*;
import java.util.Arrays;
import java.util.Date;

import static java.lang.Thread.sleep;

/**
 * 数据包捕获
 */
public class PacketCapture implements Runnable {

    PcapIf device;
    private volatile boolean IS_CLOSED = false;
    public PipedOutputStream outputPipe;  //管道
    public String filterExpression;
    public boolean MODE = true;    // 是否开启混杂模式
    public String filename = null;

    public void setDevice(PcapIf device){
        this.device = device;
    }


    /**
     * 抓包线程
     * TODO： 设置timeout，在抓到空网卡的时候出现提示。
     * TODO：但是其实wireshark里也不会对时延进行提示，它是在捕获0数据包的时候提示。可以在解析的时候弹窗。
     */
    public void run(){

        /*打开选中的设备*/
        StringBuilder errbuf = new StringBuilder(); //  获取错误信息

        outputPipe = new PipedOutputStream();

        /*创建十六进制输出文件*/
        File hexfile = new File("hexfile.txt");
        if(hexfile.exists()) {
            hexfile.delete();
        }
        try {
            hexfile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }

        /*创建detail输出文件*/
        File detailfile = new File("detailfile.txt");
        if(detailfile.exists()) {
            detailfile.delete();
        }
        try {
            detailfile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }


        int snaplen = 64 * 1024;
        // Capture all packets, no trucation 不截断的捕获所有包

        int flags;

        if (MODE) {
            flags = Pcap.MODE_PROMISCUOUS; // 混杂模式，capture all packets
        } else {
            flags = Pcap.MODE_NON_PROMISCUOUS;
        }

        int timeout = 10 * 1000;           // 10 seconds in millis

        if (device == null) {
            System.out.println("NOT SET DEVICE YET");
            return;
        }

        System.out.println("开始监听设备……");

        Pcap pcap;
        if (filename != null) {
            pcap = Pcap.openOffline(filename,errbuf);
        } else {
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        }
        if (pcap == null) {  // 如果获取的pcap是null，则返回相关的错误信息
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        /*设置包过滤器*/
        if (filterExpression != null) {
            PcapBpfProgram filter = new PcapBpfProgram();
            int res = pcap.compile(filter, filterExpression, 1, 0);
            pcap.setFilter(filter);
            if (res != 0) {
                System.out.println("Filter error:" + pcap.getErr());
            }
        }
        
        System.out.println("准备处理数据包……");

        String ss = new Date().toString();

        /*处理接收的数据包*/
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {
                // 数据包解析
                // System.out.println("正在解析数据包……");
                PacketParser.update(packet);
                String infostr = PacketParser.getFrameNo() + "\t" +
                        PacketParser.getIntervalTime() + "\t" +
                        PacketParser.getSource() + "\t" +
                        PacketParser.getSrcPort() + "\t" +
                        PacketParser.getDestination() + "\t" +
                        PacketParser.getDestPort() + "\t" +
                        PacketParser.getProtocol() + "\t" +
                        PacketParser.getLength() + "\n";

                /*输出到管道*/
                try {
                    byte[] infobuf = infostr.getBytes("utf-8");
                    outputPipe.write(infobuf);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                /*输出payload到文件*/
                try (
                        FileWriter hexwriter = new FileWriter(hexfile,true);
                        BufferedWriter hexout = new BufferedWriter(hexwriter);
                ) {
                    hexout.write(Integer.toString(PacketParser.getFrameNo()));
                    hexout.write("\r\n");
                    if (PacketParser.getPayload() != null) {
                        String payload = PacketParser.getPayload();
                        hexout.write(payload);
                    }
                    hexout.write("\r\n\r\n");
                    hexout.flush();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }

                /**
                 * 输出detail到文件
                 */
                try (
                        FileWriter detailwriter = new FileWriter(detailfile,true);
                        BufferedWriter detailout = new BufferedWriter(detailwriter);
                ) {

                    detailout.write(Integer.toString(PacketParser.getFrameNo()));
                    if (packet.toString() != null) {
                        detailout.write(packet.toString());
                    }
                    detailout.write("\r\n\r\n");
                    detailout.flush();
                }
                catch (IOException e) {
                    e.printStackTrace();
                }

            }
        };

        try {
            while (true) {
                if (!IS_CLOSED) {
                    pcap.loop(1, jpacketHandler, ss);
                } else {
                    pcap.breakloop();
                    break;
                }
            }
        } catch (Exception e){
            System.out.println("抓包线程寄了！");
        }

        /*最后一定要关闭pcap，否则抛出异常*/
        pcap.close();
        System.out.println("抓包线程已结束");

    }

    public void close() {
        this.IS_CLOSED = true;
    }

    public void restart() {this.IS_CLOSED = false;}

}
