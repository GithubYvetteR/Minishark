import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class tools {

    public static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if(hex.length() < 2){
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * 工具函数，根据所给的序号从文件中读对应的信息
     */
    public static String getInfo(int id, String infotype) throws FileNotFoundException {
        String filename;
        boolean READING = false;
        String info = new String("");
        /*判断打开哪种文件*/
        if (infotype == "Packet in Binary") {
            filename = "hexfile.txt";
        } else if (infotype == "packetdetails") {
            filename = "detailfile.txt";
        } else {
            return null;
        }
        /*读文件*/
        try (FileReader reader = new FileReader(filename);
             BufferedReader br = new BufferedReader(reader)
        ) {
            String line;
            while ((line = br.readLine()) != null) {
                // 连续读行
                if (READING) {
                    info  = info + line + "<br>";
                    // 如果该行是空行，则关闭连续读行模式
                    if (line.length() < 1) {
                        break;
                    } else {
                        continue;
                    }
                }
                // 如果该行是空行，直接下一个循环
                if (line.length() < 1) continue;

                // 如果该行是序号位
                if (line.charAt(0) != '0' && Character.isDigit(line.charAt(0))) {
                    // 如果该行序号符合查找条件
                    if (Integer.parseInt(line) == id) {
                        // 开始连续读行模式
                        READING = true;
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return info;
    }

    /**
     * 工具函数，为绘制流量图处理时间序列
     * @param timecol
     * @return
     */
    public static Map<Integer, Integer> processTimeSeq(ArrayList<Double> timecol) {
        ArrayList<Integer> timeseq = new ArrayList<Integer>();
        // 首先将timecol里的数据向下取整
        for(int i=0; i<timecol.size(); i++){
            timeseq.add((int) Math.floor(timecol.get(i)));
        }
        // 然后统计重复值
        Map<Integer,Integer> map = new TreeMap<Integer, Integer>();
        for (Integer i : timeseq) {
            if (map.get(i) == null) {
                map.put(i, 1);
            } else {
                map.put(i,map.get(i) + 1);
            }
        }
        return map;
    }

    /**
     * 工具函数，解析分组长度信息
     * @param lencol
     * @return
     */
    public static String processLengthSeq(ArrayList<Integer> lencol) {
        String leninfo = new String("<html><pre>Packet Length    Count<br>");
        ArrayList<Integer> lenseq = new ArrayList<>();
        // 分组统计规则和wireshark一样，先除以10再取log2
        for (int i=0; i<lencol.size(); i++) {
            lenseq.add((int) Math.floor(log2((double) lencol.get(i) / 10)));
        }
        // 统计重复值
        Map<Integer,Integer> map = new TreeMap<>();
        for (Integer i : lenseq) {
            if (map.get(i) == null) {
                map.put(i, 1);
            } else {
                map.put(i,map.get(i) + 1);
            }
        }
        // 将长度与字符串对上
        leninfo += "total            " + map.values().stream().collect(Collectors.summarizingInt(x->x.intValue())).getSum() + "<br>";
        leninfo += "0-19             " + getmap(map,0) + "<br>";
        leninfo += "20-39            " + getmap(map,1) + "<br>";
        leninfo += "40-79            " + getmap(map,2) + "<br>";
        leninfo += "80-159           " + getmap(map,3) + "<br>";
        leninfo += "160-319          " + getmap(map,4) + "<br>";
        leninfo += "320-639          " + getmap(map,5) + "<br>";
        leninfo += "640-1279         " + getmap(map,6) + "<br>";
        leninfo += "1280-2559        " + getmap(map,7) + "<br>";
        leninfo += "2560-5119        " + getmap(map,8) + "<br>";
        leninfo += "5120 and greater " + (map.values().stream().collect(Collectors.summarizingInt(x->x.intValue())).getSum() -
                getmap(map,0) - getmap(map,1) - getmap(map,2) - getmap(map,3) - getmap(map,4) -
                getmap(map,5) - getmap(map,6) - getmap(map,7) - getmap(map,8)) + "<br>";

        return leninfo + "</pre></html>";
    }

    /**
     * 工具函数，判断键值下有无值，没有则返回0
     */
    public static int getmap(Map<Integer,Integer> map, int index) {
        Integer tempvalue;
        if (map.get(index) != null) {
            tempvalue = map.get(index).intValue();
        } else {
            tempvalue = 0;
        }
        return tempvalue;
    }

    /**
     * 工具函数，实现Log2
     * @param N
     * @return
     */
    public static double log2(double N) {
        return Math.log(N)/Math.log(2);//Math.log的底为e
    }


    public static void main(String args[]) throws FileNotFoundException {
        // 测试功能
        //System.out.println(getInfo(4,"Packet in Binary"));
        ArrayList<Integer> obj = new ArrayList<Integer>(Arrays.asList(10,30,50,100,6000,230,124,1350,55555555,2355));
        System.out.println(processLengthSeq(obj));
    }


}
