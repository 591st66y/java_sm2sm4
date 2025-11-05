package cn.htaw.encryption.util;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.*;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * SM2+SM4文件加解密工具
 */
public class FileCryptoUI extends JFrame {
    private static final long serialVersionUID = 1L;

    // 常量定义 - 字体设置
    private static final Font LABEL_FONT = new Font("微软雅黑", Font.PLAIN, 18);
    private static final Font COMPONENT_FONT = new Font("微软雅黑", Font.PLAIN, 16);
    private static final Font SIZE_LABEL_FONT = new Font("微软雅黑", Font.BOLD, 16);
    private static final Font TIME_LABEL_FONT = new Font("微软雅黑", Font.PLAIN, 16);
    private static final Font LOADING_FONT = new Font("微软雅黑", Font.BOLD, 20);
    private static final Font TITLE_FONT = new Font("微软雅黑", Font.BOLD, 20);
    private static final Font DIGEST_FONT = new Font("微软雅黑", Font.PLAIN, 14);

    // 常量定义 - 尺寸设置
    private static final Dimension TEXT_FIELD_SIZE = new Dimension(0, 40);
    private static final Dimension BUTTON_SIZE = new Dimension(100, 40);
    private static final Dimension SMALL_BUTTON_SIZE = new Dimension(120, 40);
    private static final Insets COMPONENT_INSETS = new Insets(10, 10, 10, 10);
    private static final int WINDOW_WIDTH = 1366;
    private static final int WINDOW_HEIGHT = 680;
    private static final int MIN_WINDOW_WIDTH = 1024;
    private static final int MIN_WINDOW_HEIGHT = 660;

    // 常量定义 - 颜色设置
    private static final Color BORDER_COLOR = new Color(184, 207, 229);
    private static final Color SIZE_LABEL_COLOR = new Color(60, 120, 180);
    private static final Color TIME_LABEL_COLOR = new Color(102, 102, 102);
    private static final Color LOADING_BACKGROUND = new Color(255, 255, 255, 200);
    private static final Color PROGRESS_COLOR = new Color(50, 100, 180);
    private static final Color DIGEST_COLOR = new Color(100, 100, 150);
    private static final Color DIGEST_HOVER_COLOR = new Color(50, 50, 150);

    // Windows风格按钮颜色
    private static final Color BUTTON_NORMAL_BG = new Color(240, 240, 240);
    private static final Color BUTTON_HOVER_BG = new Color(220, 220, 220);
    private static final Color BUTTON_PRESSED_BG = new Color(200, 200, 200);
    private static final Color BUTTON_DISABLED_BG = new Color(240, 240, 240);
    private static final Color BUTTON_BORDER = new Color(160, 160, 160);
    private static final Color BUTTON_FOCUS_BORDER = new Color(0, 120, 215); // Windows蓝

    // 常量定义 - 其他设置
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyyMMddHHmmss", Locale.CHINA);
    private static final SimpleDateFormat FULL_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA);
    private static final int BUFFER_SIZE = 8192;
    private static final String ICON_PATH = "/crypto_icon_large.png";
    private static final String APP_TITLE = "SM2+SM4文件加解密工具";
    private static final int BUTTON_DELAY = 1000; // 按钮防连击延迟(毫秒)

    // 系统密钥配置文件路径（resources目录下）
    private static final String SYSTEM_KEY_CONFIG_FILE = "/sm2_keys.properties";

    // 组件定义
    private JTextField inputFileField;
    private JTextField outputFileField;
    private JTextField publicKeyField;
    private JPasswordField privateKeyField;
    private JLabel fileSizeLabel;
    private JLabel timeCostLabel;
    private JPanel loadingPanel;
    private JLabel loadingLabel;
    private JProgressBar progressBar;
    private SwingWorker<Void, Integer> currentWorker;
    private JLabel inputFileSm3Label;
    private JLabel outputFileSm3Label;
    private JButton encryptBtn;
    private JButton decryptBtn;
    private JButton loadKeyFileBtn; // 新增：加载密钥文件按钮

    static {
        // 添加BouncyCastle加密提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    public FileCryptoUI() {
        configureWindow();
        initMenuBar(); // 初始化菜单栏
        initComponents();
        initLoadingPanel();
        loadSystemKeyFile(); // 启动时尝试加载系统密钥
        setProgramIcon();
        setupSm3LabelListeners(); // 设置SM3标签的交互监听
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // 窗口关闭时取消正在进行的任务
                if (currentWorker != null && !currentWorker.isDone()) {
                    currentWorker.cancel(true);
                }
            }
        });
    }

    /**
     * 初始化菜单栏，优化显示为统一风格并调整标题字体
     */
    private void initMenuBar() {
        // 创建风格统一的菜单栏
        JMenuBar menuBar = new JMenuBar() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(BUTTON_NORMAL_BG);
                g.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        menuBar.setBorder(BorderFactory.createLineBorder(BUTTON_BORDER));
        menuBar.setFont(new Font("微软雅黑", Font.PLAIN, 16)); // 菜单标题字体16号

        // 创建"密钥管理"菜单
        JMenu keyMenu = createStyledMenu("密钥管理");

        // 创建"生成SM2新密钥"菜单项
        JMenuItem generateKeyItem = createStyledMenuItem("生成SM2新密钥");
        generateKeyItem.addActionListener(e -> generateAndSaveSM2Keys());

        // 创建"加载系统密钥"菜单项
        JMenuItem loadSystemKeyItem = createStyledMenuItem("加载系统密钥");
        loadSystemKeyItem.addActionListener(e -> loadSystemKeyFile());

        keyMenu.add(generateKeyItem);
        keyMenu.add(loadSystemKeyItem);
        menuBar.add(keyMenu);

        setJMenuBar(menuBar);
    }

    /**
     * 创建风格统一的菜单（标题字体20号）
     */
    private JMenu createStyledMenu(String text) {
        JMenu menu = new JMenu(text) {
            private boolean isHovered = false;

            @Override
            protected void processMouseEvent(MouseEvent e) {
                boolean oldHovered = isHovered;

                if (e.getID() == MouseEvent.MOUSE_ENTERED) {
                    isHovered = true;
                } else if (e.getID() == MouseEvent.MOUSE_EXITED) {
                    isHovered = false;
                }

                if (oldHovered != isHovered) {
                    repaint();
                }

                super.processMouseEvent(e);
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // 菜单状态颜色逻辑
                if (!isEnabled()) {
                    g2.setColor(BUTTON_DISABLED_BG);
                } else if (isSelected() || isHovered) {
                    g2.setColor(BUTTON_HOVER_BG);
                } else {
                    g2.setColor(BUTTON_NORMAL_BG);
                }

                g2.fillRect(0, 0, getWidth(), getHeight());
                setForeground(isEnabled() ? Color.BLACK : Color.GRAY);
                super.paintComponent(g);
                g2.dispose();
            }

            @Override
            protected void paintBorder(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setColor(BUTTON_BORDER);
                g2.drawLine(0, 0, getWidth() - 1, 0);
                g2.drawLine(0, getHeight() - 1, getWidth() - 1, getHeight() - 1);
                g2.drawLine(getWidth() - 1, 0, getWidth() - 1, getHeight() - 1);
                g2.dispose();
            }
        };

        // 菜单标题字体设置为16号，与整体标题风格统一
        menu.setFont(new Font("微软雅黑", Font.PLAIN, 16));
        menu.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 14));
        menu.setMargin(new Insets(3, 5, 3, 5));
        menu.setOpaque(true);
        menu.setPreferredSize(new Dimension(150, 45)); // 适配20号字体的高度
        menu.setMinimumSize(new Dimension(150, 45));

        return menu;
    }

    /**
     * 创建风格统一的菜单项
     */
    private JMenuItem createStyledMenuItem(String text) {
        JMenuItem menuItem = new JMenuItem(text) {
            private boolean isHovered = false;

            @Override
            protected void processMouseEvent(MouseEvent e) {
                boolean oldHovered = isHovered;

                if (e.getID() == MouseEvent.MOUSE_ENTERED) {
                    isHovered = true;
                } else if (e.getID() == MouseEvent.MOUSE_EXITED) {
                    isHovered = false;
                }

                if (oldHovered != isHovered) {
                    repaint();
                }

                super.processMouseEvent(e);
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // 菜单项状态颜色逻辑
                if (!isEnabled()) {
                    g2.setColor(BUTTON_DISABLED_BG);
                } else if (isArmed() || isHovered) {
                    g2.setColor(BUTTON_HOVER_BG);
                } else {
                    g2.setColor(Color.WHITE);
                }

                g2.fillRect(0, 0, getWidth(), getHeight());
                setForeground(isEnabled() ? Color.BLACK : Color.GRAY);
                super.paintComponent(g);
                g2.dispose();
            }

            @Override
            protected void paintBorder(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setColor(BUTTON_BORDER);
                g2.drawLine(0, getHeight() - 1, getWidth() - 1, getHeight() - 1);
                g2.dispose();
            }
        };

        // 菜单项字体稍小于标题，保持层次
        menuItem.setFont(new Font("微软雅黑", Font.PLAIN, 14));
        menuItem.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        menuItem.setMargin(new Insets(3, 5, 3, 5));
        menuItem.setOpaque(true);
        menuItem.setPreferredSize(new Dimension(220, 45)); // 适配字体高度
        menuItem.setFocusPainted(false);

        return menuItem;
    }

    /**
     * 调整标题栏字体为20号
     */
    private void adjustTitleFont() {
        try {
            // 明确设置标题栏字体为20号微软雅黑
            UIManager.put("TitlePane.font", new Font("微软雅黑", Font.BOLD, 24));
            SwingUtilities.updateComponentTreeUI(this);
        } catch (Exception e) {
            // 忽略不支持的操作
        }
    }

    /**
     * 生成并保存SM2新密钥对到配置文件
     */
    private void generateAndSaveSM2Keys() {
        // 生成SM2密钥对
        Map<String, byte[]> sm2Keys;
        try {
            sm2Keys = SM2Util.generateKeyPair();
        } catch (Exception e) {
            showErrorDialog("生成SM2密钥对失败: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // 转换为十六进制字符串
        String publicKey = Hex.toHexString(sm2Keys.get("publicKey"));
        String privateKey = Hex.toHexString(sm2Keys.get("privateKey"));

        // 让用户选择保存路径
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFont(COMPONENT_FONT);
        fileChooser.setDialogTitle("保存SM2密钥配置文件");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        // 设置默认文件名
        fileChooser.setSelectedFile(new File("sm2_keys.properties"));

        int result = fileChooser.showSaveDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return; // 用户取消选择
        }

        File saveFile = fileChooser.getSelectedFile();
        // 确保文件扩展名为.properties
        if (!saveFile.getName().endsWith(".properties")) {
            saveFile = new File(saveFile.getAbsolutePath() + ".properties");
        }

        // 检查文件是否已存在
        if (saveFile.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(
                    this,
                    "文件已存在，是否覆盖？",
                    "确认覆盖",
                    JOptionPane.YES_NO_OPTION
            );
            if (overwrite != JOptionPane.YES_OPTION) {
                return;
            }
        }

        // 保存密钥到文件
        try (FileOutputStream fos = new FileOutputStream(saveFile);
             OutputStreamWriter osw = new OutputStreamWriter(fos, "UTF-8");
             BufferedWriter writer = new BufferedWriter(osw)) {

            writer.write("# SM2密钥对");
            writer.newLine();
            writer.write("# 生成时间: " + FULL_DATE_FORMAT.format(new Date()));
            writer.newLine();
            writer.write("sm2.publicKey=" + publicKey);
            writer.newLine();
            writer.write("sm2.privateKey=" + privateKey);
            writer.newLine();

            showInfoDialog("SM2密钥对已成功生成并保存至:\n" + saveFile.getAbsolutePath());

            // 更新界面显示的密钥
            updateKeyFields(publicKey, privateKey);

        } catch (IOException e) {
            showErrorDialog("保存密钥文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 加载系统密钥（src/main/resources目录下的sm2_keys.properties）
     */
    private void loadSystemKeyFile() {
        try (InputStream is = getClass().getResourceAsStream(SYSTEM_KEY_CONFIG_FILE)) {
            if (is == null) {
                showErrorDialog("未找到系统密钥配置文件: " + SYSTEM_KEY_CONFIG_FILE + "\n请确认该文件是否存在于resources目录下");
                return;
            }

            Properties props = new Properties();
            props.load(is);

            // 读取并验证密钥
            String publicKey = props.getProperty("sm2.publicKey", "").trim();
            String privateKey = props.getProperty("sm2.privateKey", "").trim();

            if (validateKeys(publicKey, privateKey)) {
                updateKeyFields(publicKey, privateKey);
                showInfoDialog("系统密钥加载成功");
            }

        } catch (IOException e) {
            showErrorDialog("读取系统密钥配置文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 让用户选择密钥配置文件并加载
     */
    private void loadUserSelectedKeyFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFont(COMPONENT_FONT);
        fileChooser.setDialogTitle("选择SM2密钥配置文件");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        // 设置文件过滤器，只显示properties文件
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                return f.isDirectory() || f.getName().toLowerCase().endsWith(".properties");
            }

            @Override
            public String getDescription() {
                return "密钥配置文件 (*.properties)";
            }
        });

        int result = fileChooser.showOpenDialog(this);
        if (result != JFileChooser.APPROVE_OPTION) {
            return; // 用户取消选择
        }

        File keyFile = fileChooser.getSelectedFile();
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            Properties props = new Properties();
            props.load(fis);

            // 读取并验证密钥
            String publicKey = props.getProperty("sm2.publicKey", "").trim();
            String privateKey = props.getProperty("sm2.privateKey", "").trim();

            if (validateKeys(publicKey, privateKey)) {
                updateKeyFields(publicKey, privateKey);
                showInfoDialog("密钥文件加载成功:\n" + keyFile.getAbsolutePath());
            }

        } catch (IOException e) {
            showErrorDialog("读取密钥文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 验证密钥有效性
     */
    private boolean validateKeys(String publicKey, String privateKey) {
        if (publicKey.isEmpty() || privateKey.isEmpty()) {
            showErrorDialog("配置文件中存在空密钥，请检查");
            return false;
        }

        // 验证公钥格式
        try {
            Hex.decode(publicKey);
        } catch (Exception e) {
            showErrorDialog("公钥格式错误，必须是十六进制字符串");
            return false;
        }

        // 验证私钥格式
        try {
            Hex.decode(privateKey);
        } catch (Exception e) {
            showErrorDialog("私钥格式错误，必须是十六进制字符串");
            return false;
        }

        return true;
    }

    /**
     * 更新界面上的密钥显示
     */
    private void updateKeyFields(String publicKey, String privateKey) {
        publicKeyField.setText(publicKey);
        privateKeyField.setText(privateKey);
    }

    /**
     * 配置窗口基本属性
     */
    private void configureWindow() {
        setTitle(APP_TITLE);
        setSize(WINDOW_WIDTH, WINDOW_HEIGHT);
        setMinimumSize(new Dimension(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridBagLayout());
        setLocationRelativeTo(null);
        setResizable(false);
        setType(Type.NORMAL);
        adjustTitleFont();
    }

    /**
     * 初始化所有界面组件
     */
    private void initComponents() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = COMPONENT_INSETS;
        gbc.anchor = GridBagConstraints.CENTER;

        // 待处理文件文本框设置为不可编辑
        inputFileField = createTextField();
        inputFileField.setEditable(false);
        inputFileField.setBackground(Color.WHITE);
        inputFileField.setDisabledTextColor(Color.BLACK);

        outputFileField = createTextField();
        outputFileField.setEditable(false);
        outputFileField.setBackground(Color.WHITE);
        outputFileField.setDisabledTextColor(Color.BLACK);

        // 公钥文本框设置为不可编辑
        publicKeyField = createTextField();
        publicKeyField.setEditable(false);
        publicKeyField.setBackground(Color.WHITE);
        publicKeyField.setDisabledTextColor(Color.BLACK);

        // 私钥文本框设置为不可编辑，保密显示
        privateKeyField = new JPasswordField();
        privateKeyField.setEditable(false);
        privateKeyField.setBackground(Color.WHITE);
        privateKeyField.setDisabledTextColor(Color.BLACK);
        setupComponent(privateKeyField);

        // 新增：加载密钥文件按钮
        loadKeyFileBtn = createButton("加载密钥文件");
        loadKeyFileBtn.setPreferredSize(SMALL_BUTTON_SIZE);
        loadKeyFileBtn.addActionListener(e -> {
            loadKeyFileBtn.setEnabled(false);
            loadUserSelectedKeyFile();
            // 防止连击
            Timer timer = new Timer(BUTTON_DELAY, evt -> loadKeyFileBtn.setEnabled(true));
            timer.setRepeats(false);
            timer.start();
        });

        inputFileSm3Label = new JLabel("待处理文件SM3: ");
        inputFileSm3Label.setFont(DIGEST_FONT);
        inputFileSm3Label.setForeground(DIGEST_COLOR);
        inputFileSm3Label.setToolTipText("双击复制SM3摘要");

        outputFileSm3Label = new JLabel("输出文件SM3: ");
        outputFileSm3Label.setFont(DIGEST_FONT);
        outputFileSm3Label.setForeground(DIGEST_COLOR);
        outputFileSm3Label.setToolTipText("双击复制SM3摘要");

        fileSizeLabel = new JLabel("未选择文件");
        fileSizeLabel.setFont(SIZE_LABEL_FONT);
        fileSizeLabel.setForeground(SIZE_LABEL_COLOR);

        timeCostLabel = new JLabel("");
        timeCostLabel.setFont(TIME_LABEL_FONT);
        timeCostLabel.setForeground(TIME_LABEL_COLOR);

        // 1. 文件大小显示区域
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        add(fileSizeLabel, gbc);
        gbc.gridwidth = 1;

        // 2. 待处理文件区域
        addLabelAndComponents(gbc, 1, "待处理文件:",
                inputFileField, createBrowseButton(e -> browseInputFile(e)));

        // 3. 待处理文件SM3摘要
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        add(inputFileSm3Label, gbc);
        gbc.gridwidth = 1;

        // 4. 输出文件区域
        addLabelAndSingleComponent(gbc, 3, "输出文件:", outputFileField);

        // 5. 输出文件SM3摘要
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        add(outputFileSm3Label, gbc);
        gbc.gridwidth = 1;

        // 6. SM2公钥区域
        addLabelAndSingleComponent(gbc, 5, "SM2公钥:", publicKeyField);

        // 7. SM2私钥区域 - 增加加载密钥文件按钮
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.EAST;
        JLabel privateKeyLabel = new JLabel("SM2私钥:");
        privateKeyLabel.setFont(LABEL_FONT);
        privateKeyLabel.setPreferredSize(new Dimension(120, TEXT_FIELD_SIZE.height));
        add(privateKeyLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy = 6;
        gbc.weightx = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        add(privateKeyField, gbc);

        gbc.gridx = 2;
        gbc.gridy = 6;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        add(loadKeyFileBtn, gbc);

        // 8. 操作按钮区域
        addOperationButtons(gbc, 7);

        // 9. 耗时显示区域
        gbc.gridx = 0;
        gbc.gridy = 8;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = GridBagConstraints.WEST;
        add(timeCostLabel, gbc);
        gbc.gridwidth = 1;
    }

    /**
     * 设置SM3摘要标签的交互监听
     */
    private void setupSm3LabelListeners() {
        // 为输入文件SM3标签添加鼠标监听
        inputFileSm3Label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                inputFileSm3Label.setForeground(DIGEST_HOVER_COLOR);
                inputFileSm3Label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                inputFileSm3Label.setForeground(DIGEST_COLOR);
                inputFileSm3Label.setCursor(Cursor.getDefaultCursor());
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) { // 双击事件
                    copySm3ToClipboard(inputFileSm3Label, "待处理文件");
                }
            }
        });

        // 为输出文件SM3标签添加鼠标监听
        outputFileSm3Label.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                outputFileSm3Label.setForeground(DIGEST_HOVER_COLOR);
                outputFileSm3Label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            }

            @Override
            public void mouseExited(MouseEvent e) {
                outputFileSm3Label.setForeground(DIGEST_COLOR);
                outputFileSm3Label.setCursor(Cursor.getDefaultCursor());
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) { // 双击事件
                    copySm3ToClipboard(outputFileSm3Label, "输出文件");
                }
            }
        });
    }

    /**
     * 复制SM3摘要到剪贴板
     */
    private void copySm3ToClipboard(JLabel label, String fileType) {
        String text = label.getText();
        // 提取SM3摘要部分（去掉前缀）
        String prefix = fileType + "SM3: ";
        if (text.startsWith(prefix) && text.length() > prefix.length()) {
            String sm3 = text.substring(prefix.length());
            if (!sm3.isEmpty() && !sm3.contains("计算失败") && !sm3.contains("文件不存在")) {
                // 将SM3摘要复制到剪贴板
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new StringSelection(sm3), null);
                showInfoDialog(fileType + "SM3摘要已复制到剪贴板");
            } else {
                showInfoDialog("没有有效的" + fileType + "SM3摘要可复制");
            }
        }
    }

    /**
     * 初始化全局加载面板
     */
    private void initLoadingPanel() {
        loadingPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(LOADING_BACKGROUND);
                g.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        loadingPanel.setLayout(new GridBagLayout());
        loadingPanel.setVisible(false);
        loadingPanel.setOpaque(false);

        JPanel loadingContent = new JPanel(new BorderLayout(10, 0));
        loadingContent.setOpaque(false);

        loadingLabel = new JLabel("处理中...");
        loadingLabel.setFont(LOADING_FONT);
        loadingLabel.setForeground(PROGRESS_COLOR);

        progressBar = new JProgressBar(0, 100);
        progressBar.setPreferredSize(new Dimension(300, 8));
        progressBar.setForeground(PROGRESS_COLOR);
        progressBar.setStringPainted(true); // 显示进度百分比

        loadingContent.add(loadingLabel, BorderLayout.WEST);
        loadingContent.add(progressBar, BorderLayout.CENTER);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.CENTER;
        loadingPanel.add(loadingContent, gbc);

        getLayeredPane().add(loadingPanel, JLayeredPane.MODAL_LAYER);
    }

    /**
     * 设置程序图标
     */
    private void setProgramIcon() {
        try (InputStream iconStream = getClass().getResourceAsStream(ICON_PATH)) {
            if (iconStream == null) {
                System.out.println("警告: 未找到图标文件 " + ICON_PATH);
                return;
            }

            Image iconImage = ImageIO.read(iconStream);
            setIconImage(iconImage);

            try {
                Method setIconImagesMethod = JFrame.class.getMethod("setIconImages", List.class);
                List<Image> icons = new ArrayList<>();
                icons.add(iconImage.getScaledInstance(16, 16, Image.SCALE_SMOOTH));
                icons.add(iconImage.getScaledInstance(32, 32, Image.SCALE_SMOOTH));
                icons.add(iconImage.getScaledInstance(64, 64, Image.SCALE_SMOOTH));
                setIconImagesMethod.invoke(this, icons);
            } catch (Exception e) {
                // 忽略不支持的操作
            }
        } catch (Exception e) {
            System.out.println("设置图标失败: " + e.getMessage());
        }
    }



    // 组件创建工具方法
    private JTextField createTextField() {
        JTextField textField = new JTextField();
        setupComponent(textField);
        return textField;
    }

    private void setupComponent(JComponent component) {
        component.setFont(COMPONENT_FONT);
        component.setPreferredSize(TEXT_FIELD_SIZE);
        if (component instanceof JTextComponent) {
            ((JTextComponent) component).setMargin(new Insets(2, 8, 2, 8));
        }
        component.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_COLOR, 1),
                BorderFactory.createEmptyBorder(2, 5, 2, 5)
        ));
    }

    /**
     * 创建Windows风格按钮，增加鼠标移入变色效果
     */
    private JButton createButton(String text) {
        JButton button = new JButton(text) {
            // 重绘按钮外观，实现自定义背景和边框
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // 根据按钮状态设置背景色
                if (!isEnabled()) {
                    g2.setColor(BUTTON_DISABLED_BG);
                } else if (getModel().isPressed()) {
                    g2.setColor(BUTTON_PRESSED_BG);
                } else if (getModel().isRollover()) {
                    g2.setColor(BUTTON_HOVER_BG);
                } else {
                    g2.setColor(BUTTON_NORMAL_BG);
                }

                // 绘制按钮背景
                g2.fillRect(0, 0, getWidth(), getHeight());

                // 绘制按钮文本
                super.paintComponent(g);
                g2.dispose();
            }

            @Override
            protected void paintBorder(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                // 根据焦点状态设置边框颜色
                if (hasFocus() && isEnabled()) {
                    g2.setColor(BUTTON_FOCUS_BORDER);
                    g2.setStroke(new BasicStroke(2));
                } else {
                    g2.setColor(BUTTON_BORDER);
                    g2.setStroke(new BasicStroke(1));
                }

                // 绘制边框
                g2.drawRect(0, 0, getWidth() - 1, getHeight() - 1);
                g2.dispose();
            }
        };

        // 按钮基础设置
        button.setFont(COMPONENT_FONT);
        button.setPreferredSize(BUTTON_SIZE);
        button.setFocusPainted(false);
        button.setBorderPainted(true);
        button.setContentAreaFilled(false); // 禁用默认内容区域绘制
        button.setOpaque(false);

        // 设置鼠标悬停状态检测
        button.getModel().setRollover(true);

        return button;
    }

    private JButton createBrowseButton(ActionListener listener) {
        JButton button = createButton("浏览");
        button.addActionListener(e -> {
            // 防止连击
            button.setEnabled(false);
            listener.actionPerformed(e);
            // 延迟恢复按钮状态，防止连击
            Timer timer = new Timer(BUTTON_DELAY, evt -> button.setEnabled(true));
            timer.setRepeats(false);
            timer.start();
        });
        return button;
    }

    // 布局工具方法
    private void addLabelAndSingleComponent(GridBagConstraints gbc, int row, String labelText, JComponent component) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.EAST;
        JLabel label = new JLabel(labelText);
        label.setFont(LABEL_FONT);
        label.setPreferredSize(new Dimension(120, TEXT_FIELD_SIZE.height));
        add(label, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        add(component, gbc);
        gbc.gridwidth = 1;
    }

    private void addLabelAndComponents(GridBagConstraints gbc, int row, String labelText,
                                       JComponent component, JButton button) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.anchor = GridBagConstraints.EAST;
        JLabel label = new JLabel(labelText);
        label.setFont(LABEL_FONT);
        label.setPreferredSize(new Dimension(120, TEXT_FIELD_SIZE.height));
        add(label, gbc);

        gbc.gridx = 1;
        gbc.gridy = row;
        gbc.weightx = 1;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        add(component, gbc);

        gbc.gridx = 2;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.WEST;
        add(button, gbc);
    }

    private void addOperationButtons(GridBagConstraints gbc, int row) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        gbc.anchor = GridBagConstraints.CENTER;
        JPanel btnPanel = new JPanel();
        btnPanel.setBorder(BorderFactory.createEmptyBorder(15, 0, 15, 0));
        btnPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 30, 0));

        // 加密按钮 - 添加防连击机制
        encryptBtn = createButton("加密");
        encryptBtn.addActionListener(e -> {
            // 禁用按钮防止连击
            encryptBtn.setEnabled(false);
            decryptBtn.setEnabled(false);
            encryptFile(e);
        });

        // 解密按钮 - 添加防连击机制
        decryptBtn = createButton("解密");
        decryptBtn.addActionListener(e -> {
            // 禁用按钮防止连击
            encryptBtn.setEnabled(false);
            decryptBtn.setEnabled(false);
            decryptFile(e);
        });

        btnPanel.add(encryptBtn);
        btnPanel.add(decryptBtn);
        add(btnPanel, gbc);
    }

    // 业务逻辑方法
    private void browseInputFile(ActionEvent e) {
        JFileChooser chooser = createFileChooser();
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = chooser.getSelectedFile();
            String inputPath = selectedFile.getAbsolutePath();
            inputFileField.setText(inputPath);
            outputFileField.setText(generateBaseOutputPath(inputPath));

            long fileSizeBytes = selectedFile.length();
            fileSizeLabel.setText("文件大小: " + formatFileSize(fileSizeBytes));
            timeCostLabel.setText("");
            calculateFileSm3(selectedFile, true);
            outputFileSm3Label.setText("输出文件SM3: ");
        }
    }

    private void calculateFileSm3(File file, boolean isInput) {
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                if (!file.exists() || !file.isFile()) {
                    return "文件不存在";
                }

                MessageDigest sm3 = MessageDigest.getInstance("SM3", "BC");
                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int len;
                    while ((len = fis.read(buffer)) != -1) {
                        sm3.update(buffer, 0, len);
                    }
                    return Hex.toHexString(sm3.digest());
                } catch (Exception e) {
                    return "计算失败: " + e.getMessage();
                }
            }

            @Override
            protected void done() {
                try {
                    String digest = get();
                    if (isInput) {
                        inputFileSm3Label.setText("待处理文件SM3: " + digest);
                    } else {
                        outputFileSm3Label.setText("输出文件SM3: " + digest);
                    }
                } catch (Exception e) {
                    if (isInput) {
                        inputFileSm3Label.setText("待处理文件SM3: 计算失败");
                    } else {
                        outputFileSm3Label.setText("输出文件SM3: 计算失败");
                    }
                }
            }
        }.execute();
    }

    private JFileChooser createFileChooser() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFont(COMPONENT_FONT);
        chooser.setFileHidingEnabled(false);
        chooser.setDialogTitle("选择文件");
        return chooser;
    }

    private String generateBaseOutputPath(String inputPath) {
        if (inputPath == null || inputPath.trim().isEmpty()) {
            return "";
        }
        String timeStr = DATE_FORMAT.format(new Date());
        File file = new File(inputPath);
        String parentDir = file.getParent();
        String fileName = file.getName();

        if (parentDir == null) {
            parentDir = System.getProperty("user.dir");
        }

        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            String nameWithoutExt = fileName.substring(0, dotIndex);
            String ext = fileName.substring(dotIndex);
            return parentDir + File.separator + nameWithoutExt + "_" + timeStr + ext;
        } else {
            return parentDir + File.separator + fileName + "_" + timeStr;
        }
    }

    private String generateFinalOutputPath(String basePath, boolean isEncrypt) {
        if (basePath == null || basePath.trim().isEmpty()) {
            return "";
        }
        String operation = isEncrypt ? "加密后" : "解密后";
        File file = new File(basePath);
        String parentDir = file.getParent();
        String fileName = file.getName();

        if (parentDir == null) {
            parentDir = System.getProperty("user.dir");
        }

        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            String nameWithoutExt = fileName.substring(0, dotIndex);
            String ext = fileName.substring(dotIndex);
            return parentDir + File.separator + nameWithoutExt + "_" + operation + ext;
        } else {
            return parentDir + File.separator + fileName + "_" + operation;
        }
    }

    private void encryptFile(ActionEvent e) {
        if (!isSM2UtilAvailable()) {
            showErrorDialog("SM2加密工具类不可用，请检查依赖");
            // 恢复按钮状态
            enableOperationButtons();
            return;
        }

        // 检查密钥是否存在
        String publicKeyStr = publicKeyField.getText().trim();
        String privateKeyStr = new String(privateKeyField.getPassword()).trim();
        if (publicKeyStr.isEmpty() || privateKeyStr.isEmpty()) {
            showErrorDialog("未检测到有效密钥，请先加载或生成密钥");
            enableOperationButtons();
            return;
        }

        // 如果有正在进行的任务，直接返回
        if (currentWorker != null && !currentWorker.isDone()) {
            enableOperationButtons();
            return;
        }

        String inputPath = inputFileField.getText().trim();
        String baseOutputPath = outputFileField.getText().trim();

        if (!validateInput(inputPath, baseOutputPath)) {
            enableOperationButtons();
            return;
        }

        String outputPath = generateFinalOutputPath(baseOutputPath, true);
        if (outputPath.isEmpty()) {
            showErrorDialog("无法生成输出文件路径");
            enableOperationButtons();
            return;
        }
        outputFileField.setText(outputPath);

        byte[] publicKey;
        try {
            publicKey = Hex.decode(publicKeyStr);
        } catch (Exception ex) {
            showErrorDialog("公钥格式错误，请重新加载或生成密钥");
            enableOperationButtons();
            return;
        }

        currentWorker = new EncryptWorker(inputPath, outputPath, publicKey);
        currentWorker.execute();
        showLoading("加密中");
    }

    private void decryptFile(ActionEvent e) {
        if (!isSM2UtilAvailable()) {
            showErrorDialog("SM2解密工具类不可用，请检查依赖");
            // 恢复按钮状态
            enableOperationButtons();
            return;
        }

        // 检查密钥是否存在
        String publicKeyStr = publicKeyField.getText().trim();
        String privateKeyStr = new String(privateKeyField.getPassword()).trim();
        if (publicKeyStr.isEmpty() || privateKeyStr.isEmpty()) {
            showErrorDialog("未检测到有效密钥，请先加载或生成密钥");
            enableOperationButtons();
            return;
        }

        // 如果有正在进行的任务，直接返回
        if (currentWorker != null && !currentWorker.isDone()) {
            enableOperationButtons();
            return;
        }

        String inputPath = inputFileField.getText().trim();
        String baseOutputPath = outputFileField.getText().trim();

        if (!validateInput(inputPath, baseOutputPath)) {
            enableOperationButtons();
            return;
        }

        String outputPath = generateFinalOutputPath(baseOutputPath, false);
        if (outputPath.isEmpty()) {
            showErrorDialog("无法生成输出文件路径");
            enableOperationButtons();
            return;
        }
        outputFileField.setText(outputPath);

        byte[] privateKey;
        try {
            privateKey = Hex.decode(privateKeyStr);
        } catch (Exception ex) {
            showErrorDialog("私钥格式错误，请重新加载或生成密钥");
            enableOperationButtons();
            return;
        }

        currentWorker = new DecryptWorker(inputPath, outputPath, privateKey);
        currentWorker.execute();
        showLoading("解密中");
    }

    /**
     * 恢复操作按钮可用状态
     */
    private void enableOperationButtons() {
        // 使用定时器延迟恢复，防止连击
        Timer timer = new Timer(BUTTON_DELAY, evt -> {
            encryptBtn.setEnabled(true);
            decryptBtn.setEnabled(true);
        });
        timer.setRepeats(false);
        timer.start();
    }

    // 加密解密Worker
    private class EncryptWorker extends SwingWorker<Void, Integer> {
        private final String inputPath;
        private final String outputPath;
        private final byte[] publicKey;
        private String errorMessage;
        private long timeCost;
        private final String operation = "加密中";

        public EncryptWorker(String inputPath, String outputPath, byte[] publicKey) {
            this.inputPath = inputPath;
            this.outputPath = outputPath;
            this.publicKey = publicKey;
        }

        @Override
        protected void done() {
            hideLoading();
            // 恢复按钮状态
            enableOperationButtons();

            if (isCancelled()) {
                showInfoDialog("加密已取消");
                timeCostLabel.setText("");
                // 清理可能的不完整文件
                new File(outputPath).delete();
            } else if (errorMessage != null) {
                showErrorDialog(errorMessage);
                new File(outputPath).delete();
            } else {
                timeCostLabel.setText("加密耗时: " + formatTimeCost(timeCost));
                calculateFileSm3(new File(outputPath), false);
                showInfoDialog("加密成功！\n文件已保存至：" + outputPath);
            }
            currentWorker = null;
        }

        @Override
        protected Void doInBackground() throws Exception {
            try {
                long startTime = System.currentTimeMillis();
                publish(0);

                if (isCancelled()) return null;

                // 生成SM4密钥和IV
                byte[] sm4Key = SM4Util.generateKey();
                byte[] iv = SM4Util.generateIV();
                publish(10);

                if (isCancelled()) return null;

                // 用SM2公钥加密SM4密钥
                byte[] encryptedSm4Key = SM2Util.encrypt(publicKey, sm4Key);
                publish(20);

                if (isCancelled()) return null;

                // 写入加密文件头部信息（包含加密的SM4密钥和IV）
                try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(outputPath))) {
                    dos.writeInt(encryptedSm4Key.length);
                    dos.write(encryptedSm4Key);
                    dos.write(iv);
                }

                // 加密文件内容
                File inputFile = new File(inputPath);
                long totalBytes = inputFile.length();
                long processedBytes = 0;

                try (FileInputStream fis = new FileInputStream(inputFile);
                     FileOutputStream fos = new FileOutputStream(outputPath, true);
                     org.bouncycastle.crypto.io.CipherOutputStream cos =
                             new org.bouncycastle.crypto.io.CipherOutputStream(fos, getSM4Cipher(sm4Key, iv, true))) {

                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        if (isCancelled()) return null;

                        cos.write(buffer, 0, bytesRead);
                        processedBytes += bytesRead;
                        int progress = (int) ((processedBytes * 80.0) / totalBytes + 20);
                        publish(Math.min(progress, 99));
                    }
                }

                timeCost = System.currentTimeMillis() - startTime;
                publish(100);
            } catch (Exception ex) {
                errorMessage = "加密过程失败: " + ex.getMessage();
                ex.printStackTrace();
            }
            return null;
        }

        @Override
        protected void process(List<Integer> chunks) {
            int progress = chunks.get(chunks.size() - 1);
            updateLoadingProgress(operation, progress);
        }
    }

    private class DecryptWorker extends SwingWorker<Void, Integer> {
        private final String inputPath;
        private final String outputPath;
        private final byte[] privateKey;
        private String errorMessage;
        private long timeCost;
        private final String operation = "解密中";

        public DecryptWorker(String inputPath, String outputPath, byte[] privateKey) {
            this.inputPath = inputPath;
            this.outputPath = outputPath;
            this.privateKey = privateKey;
        }

        @Override
        protected void done() {
            hideLoading();
            // 恢复按钮状态
            enableOperationButtons();

            if (isCancelled()) {
                showInfoDialog("解密已取消");
                timeCostLabel.setText("");
                // 清理可能的不完整文件
                new File(outputPath).delete();
            } else if (errorMessage != null) {
                showErrorDialog(errorMessage);
                new File(outputPath).delete();
            } else {
                timeCostLabel.setText("解密耗时: " + formatTimeCost(timeCost));
                calculateFileSm3(new File(outputPath), false);
                showInfoDialog("解密成功！\n文件已保存至：" + outputPath);
            }
            currentWorker = null;
        }

        @Override
        protected Void doInBackground() throws Exception {
            try {
                long startTime = System.currentTimeMillis();
                publish(0);

                if (isCancelled()) return null;

                try (DataInputStream dis = new DataInputStream(new FileInputStream(inputPath))) {
                    // 读取加密的SM4密钥长度和内容
                    int keyLen = dis.readInt();
                    byte[] encryptedSm4Key = new byte[keyLen];
                    dis.readFully(encryptedSm4Key);

                    // 读取IV
                    byte[] iv = new byte[16];
                    dis.readFully(iv);
                    publish(20);

                    if (isCancelled()) return null;

                    // 用SM2私钥解密SM4密钥
                    byte[] sm4Key = SM2Util.decrypt(privateKey, encryptedSm4Key);
                    publish(40);

                    if (isCancelled()) return null;

                    // 解密文件内容
                    File inputFile = new File(inputPath);
                    long skipBytes = 4 + keyLen + 16; // 头部信息长度
                    long totalBytes = inputFile.length() - skipBytes;
                    if (totalBytes <= 0) {
                        throw new Exception("加密文件内容为空");
                    }

                    long processedBytes = 0;

                    try (FileInputStream fis = new FileInputStream(inputFile);
                         FileOutputStream fos = new FileOutputStream(outputPath);
                         org.bouncycastle.crypto.io.CipherInputStream cis =
                                 new org.bouncycastle.crypto.io.CipherInputStream(fis, getSM4Cipher(sm4Key, iv, false))) {

                        // 跳过头部信息
                        long skipped = fis.skip(skipBytes);
                        if (skipped != skipBytes) {
                            throw new Exception("无法跳过足够的头部信息，文件可能已损坏");
                        }

                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        while ((bytesRead = cis.read(buffer)) != -1) {
                            if (isCancelled()) return null;

                            fos.write(buffer, 0, bytesRead);
                            processedBytes += bytesRead;
                            int progress = (int) ((processedBytes * 60.0) / totalBytes + 40);
                            publish(Math.min(progress, 99));
                        }
                    }
                }

                timeCost = System.currentTimeMillis() - startTime;
                publish(100);
            } catch (Exception ex) {
                errorMessage = "解密过程失败: " + ex.getMessage();
                ex.printStackTrace();
            }
            return null;
        }

        @Override
        protected void process(List<Integer> chunks) {
            int progress = chunks.get(chunks.size() - 1);
            updateLoadingProgress(operation, progress);
        }
    }

    // 工具方法
    private String formatFileSize(long bytes) {
        if (bytes < 0) {
            return "未知大小";
        } else if (bytes >= 1024 * 1024 * 1024) {
            double size = (double) bytes / (1024 * 1024 * 1024);
            return String.format("%.2f GB", size);
        } else if (bytes >= 1024 * 1024) {
            double size = (double) bytes / (1024 * 1024);
            return String.format("%.2f MB", size);
        } else if (bytes >= 1024) {
            double size = (double) bytes / 1024;
            return String.format("%.2f KB", size);
        } else {
            return bytes + " B";
        }
    }

    private String formatTimeCost(long milliseconds) {
        long totalSeconds = milliseconds / 1000;
        long hours = totalSeconds / 3600;
        long minutes = (totalSeconds % 3600) / 60;
        long seconds = totalSeconds % 60;

        if (hours > 0) {
            return String.format("%02d:%02d:%02d", hours, minutes, seconds);
        } else if (minutes > 0) {
            return String.format("%02d:%02d", minutes, seconds);
        } else {
            return String.format("00:%02d", seconds);
        }
    }

    private boolean isSM2UtilAvailable() {
        try {
            Class.forName("cn.htaw.encryption.util.SM2Util");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private boolean validateInput(String inputPath, String outputPath) {
        if (inputPath.isEmpty()) {
            showErrorDialog("请选择待处理文件");
            return false;
        }
        if (outputPath.isEmpty()) {
            showErrorDialog("无法生成输出文件路径，请重新选择输入文件");
            return false;
        }
        File inputFile = new File(inputPath);
        if (!inputFile.exists() || !inputFile.isFile()) {
            showErrorDialog("待处理文件不存在或不是有效文件");
            return false;
        }
        if (!inputFile.canRead()) {
            showErrorDialog("没有权限读取文件: " + inputPath);
            return false;
        }
        File outputFile = new File(outputPath);
        if (outputFile.exists() && !outputFile.canWrite()) {
            showErrorDialog("没有权限写入文件: " + outputPath);
            return false;
        }
        if (!outputFile.getParentFile().exists() && !outputFile.getParentFile().mkdirs()) {
            showErrorDialog("输出目录不存在且无法创建");
            return false;
        }
        return true;
    }

    private PaddedBufferedBlockCipher getSM4Cipher(byte[] key, byte[] iv, boolean isEncrypt) throws Exception {
        if (key == null || key.length != 16) {
            throw new IllegalArgumentException("SM4密钥必须是16字节");
        }
        if (iv == null || iv.length != 16) {
            throw new IllegalArgumentException("IV必须是16字节");
        }

        SM4Engine engine = new SM4Engine();
        CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, new PKCS7Padding());
        CipherParameters keyParam = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(isEncrypt, keyParam);
        return cipher;
    }

    // 加载和对话框方法
    private void showLoading(String message) {
        loadingLabel.setText(message);
        progressBar.setValue(0);
        loadingPanel.setBounds(0, 0, getWidth(), getHeight());
        loadingPanel.setVisible(true);
        setComponentEnabled(this.getContentPane(), false);
    }

    private void updateLoadingProgress(String message, int progress) {
        loadingLabel.setText(message);
        progressBar.setValue(progress);
        progressBar.setString(progress + "%");
    }

    private void hideLoading() {
        loadingPanel.setVisible(false);
        setComponentEnabled(this.getContentPane(), true);
    }

    private void setComponentEnabled(Component component, boolean enabled) {
        component.setEnabled(enabled);
        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                setComponentEnabled(child, enabled);
            }
        }
    }

    private void showErrorDialog(String message) {
        JOptionPane.showMessageDialog(this, message, "错误", JOptionPane.ERROR_MESSAGE);
    }

    private void showInfoDialog(String message) {
        JOptionPane.showMessageDialog(this, message, "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    @Override
    public void setSize(int width, int height) {
        super.setSize(width, height);
        if (loadingPanel != null) {
            loadingPanel.setBounds(0, 0, width, height);
        }
    }

    public static void main(String[] args) {
        // 确保在EDT线程中运行Swing组件
        SwingUtilities.invokeLater(() -> {
            try {
                // 设置系统外观
                UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
            } catch (Exception e) {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception ex) {
                    // 忽略
                }
            }
            FileCryptoUI ui = new FileCryptoUI();
            ui.setVisible(true);
        });
    }
}