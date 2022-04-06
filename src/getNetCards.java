import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;

public class getNetCards {

    /**
     * 获取网卡设备列表
     */
    public static List<PcapIf> getDevices() {

        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();
        /*获取网卡*/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("获取网卡失败，错误信息是：%s\n", errbuf.toString());
            return null;
        }

        return alldevs;
    }

    /**
     * 处理某网卡设备信息为字符串
     */
    public static String getDeviceInfo(PcapIf device) {

        String deviceInfo = new String();
        int flag = device.getFlags();
        String name = device.getName();
        String addr = processAddr(device.getAddresses());
        String desc = device.getDescription();
        deviceInfo = deviceInfo + "设备名称：" + name + "<br>" +
                "地址：<br>" + addr +
                "标志位：" + flag + "<br>" +
                "详细信息：" + desc + "<br>";
        return  deviceInfo;
    }

    /**
     * 处理网卡的地址信息
     */
    public static String processAddr(List<PcapAddr> addrlist) {
        String processedaddr = new String();
        int i = 1;
        for (PcapAddr addr : addrlist) {
            processedaddr = processedaddr + "(" + Integer.toString(i) + ")<br>";
            processedaddr = processedaddr + "addr=" + addr.getAddr().toString() + ",<br>"
                    + "mask=" + addr.getNetmask().toString() + ",<br>"
                    + "broadcast=" + addr.getBroadaddr().toString() + ",<br>";
            if (addr.getDstaddr() != null) {
                processedaddr = processedaddr + "dstaddr=" + addr.getDstaddr().toString();
            } else {
                processedaddr = processedaddr + "dstaddr=" + "null<br>";
            }
            i++;
        }

        return processedaddr;
    }


}
