import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.NumberTickUnit;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.ui.RectangleInsets;
import org.jnetpcap.PcapIf;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PipedInputStream;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class demo{

    static PcapIf DEVICE;
    static PacketCapture packetcapture = new PacketCapture();
    static DefaultTableModel model;
    static JTable packetTable;
    static volatile boolean TABLE_STOPPED = false;
    static PipedInputStream inputPipe = new PipedInputStream();
    static int packcol = -1;//获取选中的列

    // 我他妈直接把所有组件设成static
    static JComponent binary;
    static JComponent packetdetails;
    static JFrame jf;
    static JPanel Panel1;
    static JPanel Panel2;
    static JPanel Panel3;
    static JPanel packpanel;
    static JPanel chartpanel;
    static JScrollPane binaryjsp;
    static JScrollPane detailjsp;


    public static void main(String[] args) throws FileNotFoundException {

        /* 设置主格式 */
        jf = new JFrame("Minishark");
        jf.setSize(900, 600);
        jf.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);     // 设置关闭退出
        jf.setLocationRelativeTo(null);
        jf.setIconImage(new ImageIcon("res/minishark.png").getImage());

        /* 创建菜单栏 */
        JMenuBar menuBar = buildJMenuBar();
        jf.setJMenuBar(menuBar);

        /* 创建选项卡 */
        Panel1 = netPanel();
        Panel2 =packPanel();
        Panel3 = stasticPanel();
        final JTabbedPane tabbedPane = buildJTabbedPane(Panel1,Panel2,Panel3);
        tabbedPane.addChangeListener(e -> {
            // System.out.println("当前选中的选项卡: " + tabbedPane.getSelectedIndex());
        });

        tabbedPane.setSelectedIndex(0);     // 设置默认选中的选项卡
        jf.setContentPane(tabbedPane);
        jf.setVisible(true);
    }

    /**
     * 创建菜单
     */
    private static JMenuBar buildJMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu menu1 = new JMenu("文件");
        JMenu menu2 = new JMenu("捕获");
        JMenu menu4 = new JMenu("统计");
        JMenu menu5 = new JMenu("帮助");
        menuBar.add(menu1);
        menuBar.add(menu2);
        menuBar.add(menu4);
        menuBar.add(menu5);
        JMenuItem item1_1 = new JMenuItem("打开");
        JMenuItem item1_2 = new JMenuItem("保存");
        JMenuItem item1_4 = new JMenuItem("退出");
        item1_1.addActionListener(ActionOpenListener);
        item1_2.addActionListener(ActionSaveListener);
        item1_4.addActionListener(ActionExitListener);
        menu1.add(item1_1);
        menu1.add(item1_2);
        menu1.addSeparator();
        menu1.add(item1_4);
        JMenuItem item2_2 = new JMenuItem("开始");
        JMenuItem item2_3 = new JMenuItem("停止");
        JMenuItem item2_4 = new JMenuItem("重新捕获");
        JMenuItem item2_5 = new JMenuItem("过滤器设置");
        JMenuItem item2_6 = new JMenuItem("刷新接口列表");
        item2_2.addActionListener(ActionStartListener);
        item2_3.addActionListener(ActionStopListener);
        item2_4.addActionListener(ActionRestartListener);
        item2_5.addActionListener(ActionSettingListener);
        item2_6.addActionListener(ActionRefreshNetcardsListener);
        menu2.add(item2_2);
        menu2.add(item2_3);
        menu2.add(item2_4);
        menu2.add(item2_5);
        menu2.add(item2_6);
        JMenuItem item4_1 = new JMenuItem("捕获概览");
        JMenuItem item4_2 = new JMenuItem("已解析的地址");
        JMenuItem item4_6 = new JMenuItem("分组长度");
        JMenuItem item4_8 = new JMenuItem("流量图");
        item4_1.addActionListener(ActionOverlookListener);
        item4_2.addActionListener(ActionAddressListener);
        item4_6.addActionListener(ActionGroupLensListener);
        item4_8.addActionListener(ActionFlowListener);
        menu4.add(item4_1);
        menu4.add(item4_2);
        menu4.add(item4_6);
        menu4.add(item4_8);
        JMenuItem item5_1 = new JMenuItem("使用说明");
        JMenuItem item5_2 = new JMenuItem("关于Minishark");
        item5_1.addActionListener(ActionHelpListener);
        item5_2.addActionListener(ActionAboutListener);
        menu5.add(item5_1);
        menu5.add(item5_2);

        return menuBar;
    }


    /**
     * 创建选项卡
     */
    private static JTabbedPane buildJTabbedPane(JPanel Panel1, JPanel Panel2, JPanel Panel3) {
        // 选项卡面板
        JTabbedPane tabbedPane = new JTabbedPane();
        // 通过BorderFactory来设置边框的特性
        tabbedPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        tabbedPane.add("网卡选择", Panel1);
        tabbedPane.add("抓包界面", Panel2);
        tabbedPane.add("统计界面",Panel3);

        return tabbedPane;
    }

    /**
     * 创建网卡选择面板
     */
    private static JPanel netPanel() {

        JPanel netpanel = new JPanel();
        netpanel.setLayout(null);

        /*添加列表*/
        // 获取网卡
        List<PcapIf> devices = getNetCards.getDevices();
        assert devices != null;
        JList netinfolist = buildDeviceList(devices,"网卡列表",70,50,700,300);
        netpanel.add(netinfolist);
        /*添加滚动条*/
        JScrollPane jsp = new JScrollPane(netinfolist);
        jsp.setBounds(70,50,700,300);
        netpanel.add(jsp);

        /*添加下拉条*/
        JComboBox comboBox = buildJComboBox(devices,"netcard", 180, 380, 300, 30);
        netpanel.add(comboBox);

        /*添加按钮*/
        JButton button = buildJButton("确定", "null", 510, 380, 100, 30);
        addActionListener(button);
        netpanel.add(button);

        return netpanel;
    }


    /**
     * 创建抓包界面面板
     */
    private static JPanel packPanel() throws FileNotFoundException {

        packpanel = new JPanel();
        packpanel.setLayout(null);
        /*五个按钮：开始、停止、重新捕获、设置、打开*/
        JButton button1 = buildJButton("", "./res/start.png", 2,1,20,20);
        JButton button2 = buildJButton("", "./res/stop.png", 25,1,20,20);
        JButton button3 = buildJButton("", "./res/restart.png", 47,1,20,20);
        JButton button4 = buildJButton("", "./res/settings.png", 69,1,20,20);
        JButton button5 = buildJButton("", "./res/open.png", 91,1,20,20);
        button1.addActionListener(ActionStartListener);
        button2.addActionListener(ActionStopListener);
        button3.addActionListener(ActionRestartListener);
        button4.addActionListener(ActionSettingListener);
        button5.addActionListener(ActionOpenListener);
        packpanel.add(button1);
        packpanel.add(button2);
        packpanel.add(button3);
        packpanel.add(button4);
        packpanel.add(button5);

        /*Packet List面板*/
        String[] tableTitle = {"NO.","Time","Source","Destination","Protocol","Length"};    // 不想要Info了
        packetTable = buildPacketTable(tableTitle,2,25,580,300);
        //packetTable = buildPacketTable(tableTitle,2,25,780,300);

        packpanel.add(packetTable);
        /*添加滚动条*/
        JScrollPane packetjsp = new JScrollPane(packetTable);
        packetjsp.setBounds(2,25,580,300);
        packpanel.add(packetjsp);

        /*Packet Details面板*/
        packetdetails = buildTextPanel("packetdetails",585,25,250,455);
        packpanel.add(packetdetails);
        /*添加滚动条*/
        detailjsp = new JScrollPane(packetdetails);
        detailjsp.setBounds(585,25,250,455);
        packpanel.add(detailjsp);

        /*Packet in Binary面板*/
        binary = buildTextPanel("Packet in Binary",2,328,580,153);
        packpanel.add(binary);
        /*添加滚动条*/
        binaryjsp = new JScrollPane(binary);
        binaryjsp.setBounds(2,328,580,153);
        packpanel.add(binaryjsp);

        return packpanel;
    }


    /**
     * 创建统计界面面板
     */
    private static JPanel stasticPanel() {
        JPanel stasticpanel = new JPanel();
        stasticpanel.setLayout(null);
        /*设置按钮，点击则绘制流量图*/
        JButton flowbutton = buildJButton("", "./res/netflow.png", 2,1,20,20);
        flowbutton.addActionListener(ActionFlowListener);
        stasticpanel.add(flowbutton);
        return stasticpanel;
    }


    /**
     * 创建网卡下拉框，选中后面需要抓包的网卡
     */
    private static JComboBox buildJComboBox(List<PcapIf> devices, String name, int x, int y, int width, int height) {

        /*获取网卡名称*/
        int n_devices = devices.size();
        String[] devicesname = new String[n_devices];
        for (int i=0; i < n_devices; i++) {
            devicesname[i] = devices.get(i).getName();
        }
        /*建立下拉框*/
        DefaultComboBoxModel codeTypeModel = new DefaultComboBoxModel();
        // elements 下拉框中的选项
        for (String element : devicesname) {
            codeTypeModel.addElement(element);
        }
        JComboBox codeTypeBox = new JComboBox(codeTypeModel);
        codeTypeBox.setName(name);
        codeTypeBox.setBounds(x, y, width, height);
        // 添加下拉框事件监听器
        codeTypeBox.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                // 选择的下拉框选项
                for (int i=0; i < n_devices; i++) {
                    if (devicesname[i] == e.getItem()) {
                        DEVICE = devices.get(i);
                        packetcapture.setDevice(DEVICE);
                        System.out.println(packetcapture.device);
                    }
                }
            }
        });
        codeTypeBox.setBackground(Color.WHITE);
        return codeTypeBox;
    }

    /**
     * 创建按钮
     */
    private static JButton buildJButton(String name, String icon, int x, int y, int width, int height) {

        JButton button = new JButton(name,new ImageIcon(icon));
        button.setBounds(x, y, width, height);
        return button;
    }

    /**
     * 创建文本面板——用于选中包展示binary和details
     */
    private static JComponent buildTextPanel(String text, int x, int y, int width, int height) throws FileNotFoundException {

        JPanel panel = new JPanel();

        // 如果有行被点击
        JLabel label;
        if (packcol != -1) {
            // 创建新的label展示细节
            label = new JLabel(tools.getInfo(packcol, text));
            label.setOpaque(true);
            label.setBackground(Color.WHITE);
            // 添加标签到面板
        } else {
            // 创建空白标签
            label = new JLabel(text);
            label.setOpaque(true);
            label.setBackground(Color.WHITE);
            //label.setFont(new Font(null, Font.PLAIN, 15));
            label.setHorizontalAlignment(SwingConstants.CENTER);
            // 添加标签到面板
        }
        panel.add(label);

        panel.setBackground(Color.WHITE);
        panel.setBounds(x, y, width, height);

        return panel;
    }

    /**
     * 为按钮绑定监听器
     */
    private static void addActionListener(JButton saveButton) {
        // 为按钮绑定监听器
        saveButton.addActionListener(e -> {
            // 对话框
            JOptionPane.showMessageDialog(null, "设置成功！");

        });
    }

    /**
     * 保存监听器，点击则保存数据文件
     * TODO: 目前是假保存，因为这个在抓包的时候本身就会生成记录文件
     */
    private static final ActionListener ActionSaveListener = e -> JOptionPane.showMessageDialog(null, "保存成功！");

    /**
     * 退出监听器，点击则退出程序
     */
    private static final ActionListener ActionExitListener = e -> System.exit(0);

    /**
     * 开始监听器，点击则开始抓包
     */
    private static final ActionListener ActionStartListener = e -> {
        // 创建抓包线程
        if (packetcapture.device == null) {
            JOptionPane.showMessageDialog(null, "请先设置网卡！");
            return;
        }
        packetcapture.restart();    // 重新设置标志位
        packetcapture.filename = null;
        new Thread(packetcapture).start();  // 重新创建一个线程，因为同一个线程不能重复启动

        // 创建一个新线程，为packetTable添加行
        System.out.println("刷新线程已创建");
        TABLE_STOPPED = false;  // 重新设置标志位
        new Thread(new UpdateTable()).start();
    };

    /**
     * 停止监听器，点击则停止抓包
     */
    private static final ActionListener ActionStopListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            // 停止抓包
            packetcapture.close();
            try {
                Thread.sleep(1000);
            } catch (InterruptedException interruptedException) {
                interruptedException.printStackTrace();
            }
            // 停止往packetTable中添加行
            TABLE_STOPPED = true;
            // 清空之前的流量图
            if (chartpanel != null) Panel3.remove(chartpanel);
        }
    };

    /**
     * 重新开始监听器，点击则停止上个抓包线程，并清除表格UI
     */
    private  static final ActionListener ActionRestartListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            // stop
            packetcapture.close();
            TABLE_STOPPED = true;

            model.setRowCount(0);   // 清空表格
            packetTable.updateUI(); // 刷新UI

            PacketParser.resetNo();     // 重置包序号
        }
    };

    /**
     * 打开文件监听器，点击则读取指定文件的数据
     */
    private static final ActionListener ActionOpenListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFileChooser chooser = new JFileChooser();
            // 文件类型过滤器，只能打开.pcap文件
            FileNameExtensionFilter filter = new FileNameExtensionFilter("仅能打开*.pcap","pcap");
            chooser.setFileFilter(filter);
            /*弹出打开文件的对话框*/
            int value = chooser.showOpenDialog(packpanel);
            if (value == JFileChooser.APPROVE_OPTION) {
                packetcapture.filename = chooser.getSelectedFile().getAbsolutePath();
            }
            // 创建抓包线程
            packetcapture.restart();    // 重新设置标志位
            new Thread(packetcapture).start();  // 重新创建一个线程，因为同一个线程不能重复启动

            // 创建一个新线程，为packetTable添加行
            System.out.println("刷新线程已创建");
            TABLE_STOPPED = false;  // 重新设置标志位
            new Thread(new UpdateTable()).start();
        }
    };

    /**
     * 设置按钮监听器，点击则弹出过滤器设置窗口。
     * 可以勾选是否启动混杂模式
     */
    private static final ActionListener ActionSettingListener = e -> {
        /*弹出设置窗口*/
        // 创建新panel
        JPanel settingpanel = new JPanel();
        JTextField protocolField = new JTextField(5);
        JRadioButton rb = new JRadioButton("混杂模式",true);
        rb.addItemListener(e1 -> {
            // 选中为1，不选为2
            if (e1.getStateChange() == 1) {
                packetcapture.MODE = true;
            } else {
                packetcapture.MODE = false;
            }
        });
        settingpanel.add(new JLabel("填写过滤条件（Bpf语法）："));
        settingpanel.add(protocolField);
        settingpanel.add(rb);
        int result = JOptionPane.showConfirmDialog(null,settingpanel,"设置过滤器",JOptionPane.OK_CANCEL_OPTION);
        if(result == JOptionPane.OK_OPTION) {
            //System.out.println(protocolField.getText());
            packetcapture.filterExpression = protocolField.getText();
        }
    };

    /**
     * 刷新接口监听器，点击则刷新网络接口（网卡）
     */
    private static final ActionListener ActionRefreshNetcardsListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            // 重新构建网络接口面板
            Panel1 = netPanel();
            JOptionPane.showMessageDialog(null, "网络接口已刷新");
        }
    };

    /**
     * 显示概览信息监听器，点击则弹窗显示概览信息
     * 要显示的概览信息包括
     * 时间【第一个分组、最后分组、经过时间】
     * 接口信息，即DEVICE的详细信息
     * 协议信息，即各种协议捕获到的数据包数
     * 统计【已捕获分组数，平均分组大小】
     */
    private static final ActionListener ActionOverlookListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            JLabel infoLabel;
            int linenum = model.getRowCount();
            if (linenum > 0) {
                String info = "<html><pre>";
                /*时间信息*/
                info += "<br>-------------------时间-------------------<br>";
                info += "第一个分组：\t" + new Date(PacketParser.starttime.longValue()) + "<br>";
                /*读取JTable最后一行时间信息*/

                Double lasttime = Double.valueOf(model.getValueAt(linenum - 1, 1).toString()) * 1000;
                info += "最后一个分组：\t" + new Date(PacketParser.starttime.longValue() + lasttime.longValue()) + "<br>";
                info += "经过时间：\t" + model.getValueAt(linenum - 1, 1).toString() + "<br>";
                /*接口信息*/
                info += "<br>-------------------接口信息-------------------<br>";
                info += getNetCards.getDeviceInfo(DEVICE);
                /*协议信息*/
                info += "<br>-------------------协议信息-------------------<br>";
                // 读取第5列协议信息
                ArrayList<String> protocol = new ArrayList<>();
                for (int i = 0; i < linenum; i++) {
                    protocol.add(model.getValueAt(i, 4).toString());
                }
                // 构造map统计协议信息
                Map<String, Integer> protomap = new TreeMap<>();
                for (String i : protocol) {
                    protomap.merge(i, 1, Integer::sum);
                }
                // 遍历map加入协议信息
                for (Map.Entry<String, Integer> entry : protomap.entrySet()) {
                    if (entry.getKey() == "ETHERNET") {
                        info += entry.getKey() + "\t" + entry.getValue() + "<br>";
                    } else {
                        info += entry.getKey() + "\t\t" + entry.getValue() + "<br>";
                    }
                }
                /*其他统计信息*/
                info += "<br>-------------------其他统计信息-------------------<br>";
                info += "已捕获分组数：\t" + linenum + "<br>";

                // 读取第6列包长度信息
                ArrayList<Integer> lencol = new ArrayList<>();
                for (int i = 0; i < linenum; i++) {
                    lencol.add(Integer.valueOf(model.getValueAt(i, 5).toString()));
                }
                // 构造map统计长度信息
                Map<Integer, Integer> lenmap = new TreeMap<>();
                for (Integer i : lencol) {
                    lenmap.merge(i, 1, Integer::sum);
                }
                info += "平均分组大小：\t" + lenmap.values().stream().collect(Collectors.summarizingInt(Integer::intValue)).getAverage() + "<br>";
                info += "最大分组大小：\t" + lenmap.values().stream().collect(Collectors.summarizingInt(Integer::intValue)).getMax() + "<br>";
                info += "最小分组大小：\t" + lenmap.values().stream().collect(Collectors.summarizingInt(Integer::intValue)).getMin() + "<br>";

                info += "</pre></html>";
                infoLabel = new JLabel(info);
                JOptionPane.showMessageDialog(null, infoLabel, "统计信息概览", JOptionPane.PLAIN_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(null, "请先获取数据包！");
            }
        }
    };

    /**
     * 显示已解析的地址监听器，点击则显示JTable中的所有地址，用JList表示
     */
    private static final ActionListener ActionAddressListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            /*读取JTable第三列和第四列地址信息*/
            ArrayList<String> addrcol = new ArrayList<>();
            int linenum = model.getRowCount();
            if (linenum > 0) {
                for (int i=0; i<linenum; i++){
                    addrcol.add(model.getValueAt(i,2).toString());
                    addrcol.add(model.getValueAt(i,3).toString());
                }
                /*构建JList，显示地址信息*/
                String[] addrinfo;
                addrinfo = addrcol.toArray(new String[0]);
                JList addrlist = new JList(addrinfo);
                JPanel addrpanel = new JPanel();
                addrpanel.setSize(900,600);
                addrpanel.add(addrlist);
                /*添加滚动条*/
                JScrollPane jsp = new JScrollPane(addrlist);
                addrpanel.add(jsp);
                JOptionPane.showMessageDialog(null,addrpanel,"已解析的地址", JOptionPane.PLAIN_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(null, "请先获取数据包！");
            }
        }
    };

    /**
     * 显示分组长度监听器，点击则解析JTable中的分组长度
     */
    private static final ActionListener ActionGroupLensListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            /*读取JTable第六列包长度信息*/
            ArrayList<Integer> lencol = new ArrayList<>();
            int linenum = model.getRowCount();
            if (linenum > 0) {
                for (int i=0; i<linenum; i++){
                    lencol.add(Integer.valueOf(model.getValueAt(i,5).toString()));
                }
                // 利用tools里的函数解析长度信息
                String leninfo = tools.processLengthSeq(lencol);
                /*设置弹窗*/
                JOptionPane.showMessageDialog(null, leninfo);
            } else {
                JOptionPane.showMessageDialog(null, "请先获取数据包！");
            }
        }
    };

    /**
     * 绘制流量图监听器，点击则通过读取JTable中的时间数据绘制流量图
     * TODO: 其实另开一个线程实时画图会更帅，但是好麻烦，感觉又要写管道了
     */
    private static final ActionListener ActionFlowListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            /*读取JTable第二列时间数据*/
            ArrayList<Double> timecol = new ArrayList<>();
            int linenum = model.getRowCount();
            if (linenum > 0) {
                for (int i=0; i<linenum; i++){
                    timecol.add(Double.valueOf(model.getValueAt(i,1).toString()));
                }
                // 将时间数据向下取整，统计每秒接收到的数据包数
                Map<Integer,Integer> timemap = tools.processTimeSeq(timecol);
                if (chartpanel != null) Panel3.remove(chartpanel);
                chartpanel = buildLineChart(timemap);
                chartpanel.setBounds(76,25,700,400);
                Panel3.add(chartpanel);
                Panel3.updateUI();
            } else {
                JOptionPane.showMessageDialog(null, "请先抓取数据包！");
            }
        }
    };

    /**
     * 帮助监听器，点击则弹出帮助文档
     */
    private static final ActionListener ActionHelpListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            String helpinfo = "<html><pre>本软件用于网络嗅探，可实现抓包、解析、统计等功能。<br>" +
                    "使用说明如下：<br><br>" +
                    "<开始>菜单中可以打开通过wireshark保存的.pcap文件，以及保存当前抓取到的文件<br><br>" +
                    "<捕获>菜单用于数据包捕获。点击【开始】进行数据包捕获，【停止】暂停捕获，<br>" +
                    "【重新开始】则清空之前捕获的所有数据包。点击【过滤器设置】可以根据bpf语法过滤数据包，<br>" +
                    "并且可以选择是否以混杂模式监听网卡。点击【刷新网络接口】可以刷新网卡界面的所有接口。<br><br>" +
                    "<统计>菜单用于对捕获到的数据包做一些基础的统计。其中【流量图】绘制在统计界面中。<br><br>" +
                    "本工具有三个界面：<br>" +
                    "网卡界面展示所有网络接口，点击列表中设备可查看详细信息，通过下拉框选择要监听的设备。<br>" +
                    "抓包界面用于捕获数据包，点击数据包列表可查看某数据包的详细信息。<br>" +
                    "统计界面用于展示统计信息，目前只能展示流量图。<br>" +
                    "</pre></html>";
            JLabel helplabel = new JLabel(helpinfo);
            JOptionPane.showMessageDialog(null,helplabel,"帮助", JOptionPane.PLAIN_MESSAGE);
        }
    };

    /**
     * 关于监听器，点击则弹出关于Minishark
     */
    private static final ActionListener ActionAboutListener = new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            String aboutinfo = "<html><i>\"I see you're eyeballin' the Minishark.. <br>" +
                    "You really don't want to know how it was made.\"</i><br><br><br>" +
                    "Conducted by <i>GameYvetteRed</i></html>";
            JLabel aboutlabel = new JLabel(aboutinfo);
            JOptionPane.showMessageDialog(null,aboutlabel,"关于Minishark", JOptionPane.PLAIN_MESSAGE);
        }
    };


    /**
     * 画折线图函数
     */
    private static JPanel buildLineChart(Map<Integer,Integer> datamap) {
        /*构造数据集*/
        XYSeriesCollection dataset = new XYSeriesCollection();
        XYSeries netflow = new XYSeries("netflow");
        for (Map.Entry<Integer, Integer> entry : datamap.entrySet()) {
            netflow.add(entry.getKey(),entry.getValue());
        }
        dataset.addSeries(netflow);
        /*构造XY图*/
        JFreeChart jfreechart = ChartFactory.createXYLineChart(
                "netflow charts", "second", "Packets", dataset,
                PlotOrientation.VERTICAL, false, true, false);

        jfreechart.setBorderPaint(new Color(0,204,205));
        jfreechart.setBorderVisible(true);

        XYPlot xyplot = (XYPlot) jfreechart.getPlot();

        // Y轴
        NumberAxis numberaxis = (NumberAxis) xyplot.getRangeAxis();
        numberaxis.setAutoRange(true);
        numberaxis.setTickUnit(new NumberTickUnit(100d));
        // 只显示整数值
        numberaxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        // numberaxis.setAutoRangeIncludesZero(true);
        numberaxis.setLowerMargin(0); // 数据轴下（左）边距 ­
        numberaxis.setMinorTickMarksVisible(false);// 标记线是否显示
        numberaxis.setTickMarkInsideLength(0);// 外刻度线向内长度
        numberaxis.setTickMarkOutsideLength(0);

        // X轴的设计
        NumberAxis x = (NumberAxis) xyplot.getDomainAxis();
        x.setAutoRange(true);// 自动设置数据轴数据范围
        // 数据轴的数据标签：只显示整数标签
        x.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        x.setAxisLineVisible(true);// X轴竖线是否显示
        x.setTickMarksVisible(false);// 标记线是否显示

        RectangleInsets offset = new RectangleInsets(0, 0, 0, 0);
        xyplot.setAxisOffset(offset);// 坐标轴到数据区的间距
        xyplot.setBackgroundAlpha(0.0f);// 去掉柱状图的背景色
        xyplot.setOutlinePaint(null);// 去掉边框

        return new ChartPanel(jfreechart, true);
    }


    /**
     * 建立网卡JList
     */
    private static JList buildDeviceList(List<PcapIf> devices, String title, int x, int y, int width, int height) {

        /*获取网卡名称*/
        int n_devices = devices.size();
        String[] devicesname = new String[n_devices];
        for (int i=0; i < n_devices; i++) {
            devicesname[i] = devices.get(i).getName();
        }
        /*建立列表*/
        JList list = new JList(devicesname);
        list.setBounds(x, y, width, height);
        list.setBorder(BorderFactory.createTitledBorder(title));
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        //为列表绑定监听器
        list.addListSelectionListener(e -> {
            JList l = (JList)e.getSource();
            if(e.getValueIsAdjusting()) return;     //检查是否正在被修改
            /*弹出详细信息*/
            JOptionPane.showMessageDialog(null, "<html>"+getNetCards.getDeviceInfo(devices.get(l.getSelectedIndex()))+"</html>","详细信息",JOptionPane.PLAIN_MESSAGE);
        });

        return list;
    }


    /**
     * 建立数据包JTable
     */
    private static JTable buildPacketTable(String[] title, int x, int y, int width, int height) {
        model = new DefaultTableModel(new Object[][]{}, title);
        JTable table = new JTable(model);
        // 选中行监听
        table.getSelectionModel().addListSelectionListener(e -> {
            if(e.getValueIsAdjusting()) return;     //检查是否正在被修改
            packcol = table.getSelectedRow()+1;
            /*移除之前的组件并新建组件*/
            packpanel.remove(binary);
            packpanel.remove(binaryjsp);
            packpanel.remove(packetdetails);
            packpanel.remove(detailjsp);
            try {
                binary = buildTextPanel("Packet in Binary",2,328,580,153);
                packetdetails = buildTextPanel("packetdetails",585,25,270,455);
            } catch (FileNotFoundException fileNotFoundException) {
                fileNotFoundException.printStackTrace();
            }
            packetdetails.updateUI();
            binary.updateUI();
            packpanel.add(binary);
            packpanel.add(packetdetails);
            /*添加滚动条*/
            binaryjsp = new JScrollPane(binary);
            detailjsp = new JScrollPane(packetdetails);
            binaryjsp.setBounds(2,328,580,153);
            detailjsp.setBounds(585,25,270,455);
            binaryjsp.updateUI();
            detailjsp.updateUI();
            packpanel.add(binaryjsp);
            packpanel.add(detailjsp);
            packpanel.updateUI();
            // System.out.println(table.getSelectedRow()+1);
        });
        setColumnColor(table);
        table.setShowGrid(false);      // 去掉列框线
        table.setBounds(x,y,width,height);

        return table;
    }

    /**
     * 设置JTable底色——隔行不同
     */
    public static void setColumnColor(JTable table) {
        try
        {
            DefaultTableCellRenderer tcr = new DefaultTableCellRenderer(){
                private static final long serialVersionUID = 1L;
                public Component getTableCellRendererComponent(JTable table,Object value, boolean isSelected, boolean hasFocus,int row, int column){
                    if(row%2 == 0)
                        setBackground(Color.WHITE);//设置奇数行底色
                    else if(row%2 == 1)
                        setBackground(new Color(243,248,255));//设置偶数行底色
                    return super.getTableCellRendererComponent(table, value,isSelected, hasFocus, row, column);
                }
            };
            for(int i = 0; i < table.getColumnCount(); i++) {
                table.getColumn(table.getColumnName(i)).setCellRenderer(tcr);
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }


    static class UpdateTable implements Runnable {

        public void run() {

            // 连接管道
            try {
                inputPipe = new PipedInputStream();     // 重新创建一个管道，因为管道不能重复连接
                inputPipe.connect(packetcapture.outputPipe);
                System.out.println("管道连接成功！");
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }

            String rest = null;

            while (true) {
                if (!TABLE_STOPPED) {
                    try {
                        byte[] Infobuf = new byte[1024];
                        String[] Infolines;
                        inputPipe.read(Infobuf);
                        //System.out.print("尝试从管道中读取数据:");
                        String InfoStr = new String(Infobuf, "utf-8");

                        /*处理字符串*/
                        Infolines = InfoStr.split("\n");

                        for (String line : Infolines) {
                            String[] cols = line.split("\t");
                            if (cols.length < 6) {
                                if (rest != null) {
                                    /*如果上一次读取有剩余，就将该行拼接上去再插入表格*/
                                    String newrest = rest + line;
                                    String[] newcol = newrest.split("\t");
                                    model.insertRow(model.getRowCount(), newcol);
                                    rest = null;    // rest置空
                                } else {
                                    /*如果上一次没有剩余，就把这行当成是剩余*/
                                    rest = line;
                                }
                                continue;   // 不插入cols
                            }
                            /*如果这一列有6组数据，但是rest却不为空，说明序号被截断了,将rest和line拼接作为新的line插入表格*/
                            if (rest != null) {
                                line = rest + line;
                                cols = line.split("\t");
                                rest = null;    // rest置空
                            }

                            model.insertRow(model.getRowCount(), cols);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    //packetTable.updateUI(); // 用updateUI刷新会产生空指针异常
                    packetTable.addNotify();  // 改用addNotiry，就完全正常了

                    try {
                        Thread.currentThread().sleep(100);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    break;
                }

            }
            System.out.println("刷新线程已结束");
        }


    }



}


