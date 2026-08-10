package com.security.jsextractor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.HashSet;
import java.util.Set;

public class JSExtractorTab {

    private final MontoyaApi api;
    private final PythonBridgeClient pythonBridge;
    private final JTabbedPane mainTabbedPane;

    // Sub-tab 1: API Endpoints & BOLA Matrix
    private final DefaultTableModel epTableModel;
    private final TableRowSorter<DefaultTableModel> epSorter;
    private final JCheckBox scopeFilterCheckBox;
    private final JTextField epSearchField;
    private final Set<String> seenEndpoints;

    // Sub-tab 2: Secrets & Tokens
    private final DefaultTableModel secretTableModel;
    private final Set<String> seenSecrets;

    // Sub-tab 3: Feature Flags & Permissions
    private final DefaultTableModel flagTableModel;
    private final Set<String> seenFlags;

    public JSExtractorTab(MontoyaApi api, PythonBridgeClient pythonBridge) {
        this.api = api;
        this.pythonBridge = pythonBridge;
        this.seenEndpoints = new HashSet<>();
        this.seenSecrets = new HashSet<>();
        this.seenFlags = new HashSet<>();

        mainTabbedPane = new JTabbedPane();

        // ----------------------------------------------------
        // SUB-TAB 1: API Endpoints & BOLA Matrix
        // ----------------------------------------------------
        JPanel epPanel = new JPanel(new BorderLayout());
        JPanel epTopPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        // Scope filter UNCHECKED by default so it captures all JS files until user explicitly toggles it
        scopeFilterCheckBox = new JCheckBox("Filter by Burp Target Scope", false);
        JLabel searchLabel = new JLabel("Search:");
        epSearchField = new JTextField(15);
        JButton clearButton = new JButton("Clear All Data");
        clearButton.addActionListener(e -> clearAllData());

        epTopPanel.add(scopeFilterCheckBox);
        epTopPanel.add(Box.createHorizontalStrut(15));
        epTopPanel.add(searchLabel);
        epTopPanel.add(epSearchField);
        epTopPanel.add(clearButton);

        String[] epCols = {"Method", "Endpoint Path", "Category", "BOLA Candidate", "Parameters", "Request Body (JSON)", "Source Asset URL"};
        epTableModel = new DefaultTableModel(epCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        epSorter = new TableRowSorter<>(epTableModel);

        JTable epTable = new JTable(epTableModel);
        epTable.setRowSorter(epSorter);
        epTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Highlight BOLA candidates in bold red
        epTable.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val, boolean isSel, boolean hasFocus, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, val, isSel, hasFocus, r, c);
                if ("YES (ID Detected)".equals(val)) {
                    comp.setForeground(Color.RED);
                    comp.setFont(comp.getFont().deriveFont(Font.BOLD));
                } else {
                    comp.setForeground(isSel ? t.getSelectionForeground() : t.getForeground());
                }
                return comp;
            }
        });

        // Quick Search Listener
        epSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            private void filter() {
                String text = epSearchField.getText();
                epSorter.setRowFilter(text.trim().isEmpty() ? null : RowFilter.regexFilter("(?i)" + text));
            }
        });

        // Context Menu for Endpoints
        JPopupMenu epMenu = new JPopupMenu();
        JMenuItem sendToRepeaterItem = new JMenuItem("Send Request to Repeater");
        JMenuItem sendBolaPairItem = new JMenuItem("Send BOLA Pair to Repeater (Context A & B)");
        JMenuItem copyUrlItem = new JMenuItem("Copy Path / URL");
        JMenuItem copyBodyItem = new JMenuItem("Copy Request Body JSON");
        JMenuItem copyCurlItem = new JMenuItem("Copy as cURL Command");

        sendToRepeaterItem.addActionListener(e -> sendSelectedToRepeater(epTable, false));
        sendBolaPairItem.addActionListener(e -> sendSelectedToRepeater(epTable, true));
        copyUrlItem.addActionListener(e -> copySelectedCellToClipboard(epTable, 1, epTableModel));
        copyBodyItem.addActionListener(e -> copySelectedCellToClipboard(epTable, 5, epTableModel));
        copyCurlItem.addActionListener(e -> copySelectedAsCurl(epTable));

        epMenu.add(sendToRepeaterItem);
        epMenu.add(sendBolaPairItem);
        epMenu.addSeparator();
        epMenu.add(copyUrlItem);
        epMenu.add(copyBodyItem);
        epMenu.add(copyCurlItem);

        epTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { showPopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { showPopup(e); }
            private void showPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = epTable.rowAtPoint(e.getPoint());
                    if (r >= 0 && r < epTable.getRowCount()) epTable.setRowSelectionInterval(r, r);
                    else epTable.clearSelection();
                    if (epTable.getSelectedRow() >= 0) epMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        epPanel.add(epTopPanel, BorderLayout.NORTH);
        epPanel.add(new JScrollPane(epTable), BorderLayout.CENTER);

        // ----------------------------------------------------
        // SUB-TAB 2: Secrets & Tokens
        // ----------------------------------------------------
        JPanel secretPanel = new JPanel(new BorderLayout());
        String[] secretCols = {"Secret Type", "Key Name", "Discovered Secret Value", "Source Asset URL"};
        secretTableModel = new DefaultTableModel(secretCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable secretTable = new JTable(secretTableModel);
        secretTable.setAutoCreateRowSorter(true);

        JPopupMenu secMenu = new JPopupMenu();
        JMenuItem copySecretItem = new JMenuItem("Copy Secret Value");
        copySecretItem.addActionListener(e -> copySelectedCellToClipboard(secretTable, 2, secretTableModel));
        secMenu.add(copySecretItem);

        secretTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { showPopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { showPopup(e); }
            private void showPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = secretTable.rowAtPoint(e.getPoint());
                    if (r >= 0 && r < secretTable.getRowCount()) secretTable.setRowSelectionInterval(r, r);
                    if (secretTable.getSelectedRow() >= 0) secMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        secretPanel.add(new JScrollPane(secretTable), BorderLayout.CENTER);

        // ----------------------------------------------------
        // SUB-TAB 3: Feature Flags & Permissions
        // ----------------------------------------------------
        JPanel flagPanel = new JPanel(new BorderLayout());
        String[] flagCols = {"Type", "Name / Property", "Discovered Code Snippet", "Source Asset URL"};
        flagTableModel = new DefaultTableModel(flagCols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable flagTable = new JTable(flagTableModel);
        flagTable.setAutoCreateRowSorter(true);

        flagPanel.add(new JScrollPane(flagTable), BorderLayout.CENTER);

        // Add sub-tabs to main pane
        mainTabbedPane.addTab("API Endpoints & BOLA Matrix", epPanel);
        mainTabbedPane.addTab("Discovered Secrets & Tokens", secretPanel);
        mainTabbedPane.addTab("Feature Flags & Role Guards", flagPanel);
    }

    public Component getUiComponent() {
        return mainTabbedPane;
    }

    public boolean isScopeFilterOnly() {
        return scopeFilterCheckBox.isSelected();
    }

    public synchronized void addEndpoint(PythonBridgeClient.ExtractedEndpoint ep) {
        if (ep == null || ep.path == null) return;
        String key = (ep.method != null ? ep.method : "GET") + ":" + ep.path;
        if (!seenEndpoints.contains(key)) {
            seenEndpoints.add(key);
            String params = ep.parameters != null ? String.join(", ", ep.parameters) : "";
            String bodyJson = ep.request_body != null ? ep.request_body.toString() : "{}";
            String bolaStr = ep.is_bola_candidate ? "YES (ID Detected)" : "No";

            SwingUtilities.invokeLater(() -> {
                epTableModel.addRow(new Object[]{ep.method, ep.path, ep.category, bolaStr, params, bodyJson, ep.source_url});
            });
        }
    }

    public synchronized void addSecret(PythonBridgeClient.ExtractedSecret sec) {
        if (sec == null || sec.value == null) return;
        String key = sec.secret_type + ":" + sec.value;
        if (!seenSecrets.contains(key)) {
            seenSecrets.add(key);
            SwingUtilities.invokeLater(() -> {
                secretTableModel.addRow(new Object[]{sec.secret_type, sec.key_name, sec.value, sec.source_url});
            });
        }
    }

    public synchronized void addFlag(PythonBridgeClient.ExtractedFlag flag) {
        if (flag == null || flag.name == null) return;
        String key = flag.flag_type + ":" + flag.name;
        if (!seenFlags.contains(key)) {
            seenFlags.add(key);
            SwingUtilities.invokeLater(() -> {
                flagTableModel.addRow(new Object[]{flag.flag_type, flag.name, flag.snippet, flag.source_url});
            });
        }
    }

    public void clearAllData() {
        seenEndpoints.clear();
        seenSecrets.clear();
        seenFlags.clear();
        epTableModel.setRowCount(0);
        secretTableModel.setRowCount(0);
        flagTableModel.setRowCount(0);
    }

    private void sendSelectedToRepeater(JTable table, boolean isBolaPair) {
        int row = table.getSelectedRow();
        if (row < 0) return;
        int modelRow = table.convertRowIndexToModel(row);

        String method = (String) epTableModel.getValueAt(modelRow, 0);
        String path = (String) epTableModel.getValueAt(modelRow, 1);
        String body = (String) epTableModel.getValueAt(modelRow, 5);
        String sourceUrl = (String) epTableModel.getValueAt(modelRow, 6);

        String host = "target.example";
        int port = 443;
        boolean isSecure = true;

        if (sourceUrl != null && sourceUrl.startsWith("http")) {
            try {
                java.net.URL u = new java.net.URL(sourceUrl);
                host = u.getHost();
                port = u.getPort() != -1 ? u.getPort() : (u.getProtocol().equals("https") ? 443 : 80);
                isSecure = u.getProtocol().equals("https");
            } catch (Exception ignored) {}
        }

        HttpService service = HttpService.httpService(host, port, isSecure);

        String reqStr = method + " " + path + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "User-Agent: Burp-JS-Extractor\r\n" +
                "Authorization: Bearer <INSERT_USER_A_TOKEN>\r\n" +
                "Content-Type: application/json\r\n" +
                (body != null && !body.equals("{}") && !body.isEmpty() ?
                        "Content-Length: " + body.getBytes().length + "\r\n\r\n" + body :
                        "Content-Length: 0\r\n\r\n");

        HttpRequest reqA = HttpRequest.httpRequest(service, reqStr);
        api.repeater().sendToRepeater(reqA, "JS-BOLA User A: " + method + " " + path);

        if (isBolaPair) {
            String reqStrB = reqStr.replace("<INSERT_USER_A_TOKEN>", "<INSERT_USER_B_TOKEN>");
            HttpRequest reqB = HttpRequest.httpRequest(service, reqStrB);
            api.repeater().sendToRepeater(reqB, "JS-BOLA User B: " + method + " " + path);
        }
    }

    private void copySelectedCellToClipboard(JTable table, int colIndex, DefaultTableModel model) {
        int row = table.getSelectedRow();
        if (row < 0) return;
        int modelRow = table.convertRowIndexToModel(row);
        String val = (String) model.getValueAt(modelRow, colIndex);
        if (val != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(val), null);
        }
    }

    private void copySelectedAsCurl(JTable table) {
        int row = table.getSelectedRow();
        if (row < 0) return;
        int modelRow = table.convertRowIndexToModel(row);

        String method = (String) epTableModel.getValueAt(modelRow, 0);
        String path = (String) epTableModel.getValueAt(modelRow, 1);
        String body = (String) epTableModel.getValueAt(modelRow, 5);

        StringBuilder curl = new StringBuilder("curl -X ").append(method).append(" \"").append(path).append("\"");
        curl.append(" -H \"Content-Type: application/json\"");
        if (body != null && !body.equals("{}") && !body.isEmpty()) {
            curl.append(" -d '").append(body).append("'");
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(curl.toString()), null);
    }
}
