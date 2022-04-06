import org.jnetpcap.Pcap;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.Date;

/**
 * 数据包解析类
 */
public class PacketParser {

    /*解析到的协议*/
    private static Ip4 ip4 = new Ip4();
    private static Ip6 ip6 = new Ip6();
    private static Ethernet eth = new Ethernet();
    private static Tcp tcp = new Tcp();
    private static Udp udp = new Udp();

    /*需要操作的数据结构*/
    private static int frameNo;
    private static int packlen;
    private static String arriveTime;

    private static String srcEth;
    private static String srcLG;    // 0为出厂MAC，1为分配的MAC
    private static String srcIG;    // 0为单播，1为广播

    private static String destEth;
    private static String destLG;
    private static String destIG;

    private static String srcIp;
    private static String destIp;

    private static String protocol;

    private static String srcPort;
    private static String destPort;
    private static String ack;
    private static String seq;

    private static boolean ifUseHttp;

    private static Payload payload = new Payload();
    private static byte[] data;

    public static Double starttime;
    private static String intervalTime;

    /**
     * 动态更新数据
     */
    public static void update(PcapPacket packet) {
        frameNo ++;
        //arriveTime = new Date(packet.getCaptureHeader().timestampInMillis()).toString();
        arriveTime = Long.toString(packet.getCaptureHeader().timestampInMillis());
        if (frameNo == 1){
            starttime =(double) packet.getCaptureHeader().timestampInMillis();
        }
        intervalTime = Double.toString((packet.getCaptureHeader().timestampInMillis()-starttime) / 1000);  // 毫秒单位换算成秒
        srcEth = parseSrcMAC(packet);
        srcLG = Long.toString(eth.source_LG());
        srcIG = Long.toString(eth.source_IG());
        destEth = parseDestMAC(packet);
        destLG = Long.toString(eth.destination_LG());
        destIG = Long.toString(eth.destination_IG());
        srcIp = parseSrcIp(packet);
        destIp = parseDestIp(packet);
        protocol = parseProtocol(packet);
        srcPort = parseSrcPort(packet);
        destPort = parseDestPort(packet);
        packlen = packet.getCaptureHeader().caplen();
        payload = parsePayload(packet);
        if (packet.hasHeader(tcp)) {
            ack = Long.toString(tcp.ack());
            seq = Long.toString(tcp.seq());
        } else {
            ack = seq = null;
        }
        ifUseHttp = packet.hasHeader(Http.ID);
        data = parseData(packet);
    }


    /**
     * 解析源MAC地址
     */
    private static String parseSrcMAC(PcapPacket packet) {
        if (packet.hasHeader(eth)) {
            return FormatUtils.mac(eth.source());
        }
        return null;
    }

    /**
     * 解析目的MAC地址
     */
    private static String parseDestMAC(PcapPacket packet) {
        if (packet.hasHeader(eth)) {
            return FormatUtils.mac(eth.destination());
        }
        return null;
    }

    /**
     * 解析出源IP
     */
    private static String parseSrcIp(PcapPacket packet) {
        if (packet.hasHeader(ip4)) {
            return FormatUtils.ip(ip4.source());
        } else if (packet.hasHeader(ip6)) {
            return FormatUtils.ip(ip6.source());
        } else return null;
    }

    /**
     * 解析出目的IP
     */
    private static String parseDestIp(PcapPacket packet) {
        if (packet.hasHeader(ip4)) {
            return FormatUtils.ip(ip4.destination());
        } else if (packet.hasHeader(ip6)) {
            return FormatUtils.ip(ip6.destination());
        } else return null;
    }

    /**
     * 解析出协议类型
     */
    private static String parseProtocol(PcapPacket packet) {
        //逆向遍历协议表找到最精确（最高层）的协议名
        JProtocol[] protocols = JProtocol.values();
        for (int i = protocols.length - 1; i >= 0; i--) {
            if (packet.hasHeader(protocols[i].getId())) {
                return protocols[i].name();
            }
        }
        return null;
    }

    /**
     * 解析出源port
     */
    private static String parseSrcPort(PcapPacket packet) {
        if (packet.hasHeader(eth)) {
            return FormatUtils.mac(eth.source());
        }
        return null;
    }

    /**
     * 解析出目的port
     */
    private static String parseDestPort(PcapPacket packet) {
        if (packet.hasHeader(eth)) {
            return FormatUtils.mac(eth.destination());
        }
        return null;
    }

    /**
     * 解析出data为bytes
     */
    private static byte[] parseData(PcapPacket packet) {
        byte[] data = new byte[2048];
        packet.transferStateAndDataTo(data);
        return data;
    }

    /**
     * 解析payload
     */
    private static Payload parsePayload(PcapPacket packet) {
        if (payload == null) {
            payload = new Payload();
        }
        if (packet.hasHeader(payload)) {
            return payload;
        }
        return null;
    }


    /**
     * 返回包序号
     */
    public static int getFrameNo() {
        return frameNo;
    }

    /**
     * 返回包到达时间
     */
    public static String getArriveTime() {
        return arriveTime;
    }

    /**
     * 返回包间隔时间
     */
    public static String getIntervalTime() {
        return intervalTime;
    }

    /**
     * 返回Sourse
     */
    public static String getSource() {
        /*如果没有IP就显示MAC地址*/
        if (srcIp == null) {
            // MAC地址
            return srcEth;
        } else {
            // IP地址（默认IPV4)
            return srcIp;
        }
    }

    /**
     * 返回Destination
     */
    public static String getDestination() {
        /*如果没有IP就显示MAC地址*/
        if (destIp == null) {
            // MAC地址
            return destEth;
        } else {
            // IP地址（默认IPV4)
            return destIp;
        }
    }

    /**
     * 返回Protocol
     */
    public static String getProtocol() {
        return protocol;
    }

    /**
     * 返回Length
     */
    public static int getLength() {
        return packlen;
    }


    /**
     * 返回payload
     */
    public static String getPayload() {
        if (payload != null) {
            return payload.toHexdump();
        } else {
            return null;
        }
    }

    public static Ip4 getIp4() {
        return ip4;
    }

    public static Ip6 getIp6() {
        return ip6;
    }

    public static Ethernet getEth() {
        return eth;
    }

    public static Tcp getTcp() {
        return tcp;
    }

    public static String getSrcEth() {
        return srcEth;
    }

    public static String getSrcLG() {
        return srcLG;
    }

    public static String getSrcIG() {
        return srcIG;
    }

    public static String getDestEth() {
        return destEth;
    }

    public static String getDestLG() {
        return destLG;
    }

    public static String getDestIG() {
        return destIG;
    }

    public static String getSrcIp() {
        return srcIp;
    }

    public static String getDestIp() {
        return destIp;
    }



    public static String getSrcPort() {
        return srcPort;
    }

    public static String getDestPort() {
        return destPort;
    }

    public static String getAck() {
        return ack;
    }

    public static String getSeq() {
        return seq;
    }

    public static boolean getIfUseHttp() {
        return ifUseHttp;
    }

    public static void resetNo() {
        frameNo = 0;
    }

}
