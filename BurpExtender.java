package burp;

import java.awt.Component;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JPanel;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Dimension;
import java.io.PrintWriter;


public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, ActionListener{
    private final static String EXTENDER_NAME = "Parameter Sheet Generator";
    private final static String EXTENDER_VERSION = "v1.0";
    private static PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    public IHttpRequestResponsePersisted mostRecentReqRes;
    private int reqNum;
    
    // scroll panel
    JScrollPane scrollPane;
    
    // text fields
    JTextField fileExtentionTextField = new JTextField("js,gif,jpg,png,css",20);
    JCheckBox fileExtentionCheckbox = new JCheckBox("Exclude:",true);

    // table of log entries
    Table logTable = new Table(BurpExtender.this);
    
    // list for checking request is unique
    ArrayList<ArrayList<String>> pastReq = new ArrayList<>();

    public BurpExtender() {
        this.reqNum = 1;
    }
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {        
        stdout = new PrintWriter(callbacks.getStdout(), true);
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName(EXTENDER_NAME + "_" +EXTENDER_VERSION);
        
        // create our UI
        SwingUtilities.invokeLater(new Runnable() 
        {
            @Override
            public void run()
            {
                // main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                
                // upper pane
                JSplitPane upperPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                
                //log table scrollpane pane
                JScrollPane scrollPane = new JScrollPane(logTable);                   
                        
                //create utilPanel
                JPanel utilPanel = new JPanel();
                utilPanel.setLayout(null);
                utilPanel.setMinimumSize(new Dimension(1200,80));
                
                // add action button on utility panel
                JButton deleteButton = new JButton("delete rows");
                deleteButton.addActionListener(BurpExtender.this);
                deleteButton.setActionCommand("delete");
                JButton addRowButton = new JButton("add empty row");
                addRowButton.addActionListener(BurpExtender.this);
                addRowButton.setActionCommand("addRow");
                
                //add components on utility Panel
                utilPanel.add(fileExtentionTextField);
                utilPanel.add(deleteButton);
                utilPanel.add(addRowButton);
                utilPanel.add(fileExtentionCheckbox);
                
                // arrange location
                deleteButton.setBounds(770, 10, 120, 30);
                addRowButton.setBounds(900, 10, 120, 30);
                fileExtentionCheckbox.setBounds(130, 10, 100, 30);
                fileExtentionTextField.setBounds(220, 10, 200, 30);
                
                upperPane.setLeftComponent(scrollPane);
                upperPane.setRightComponent(utilPanel);
                splitPane.setLeftComponent(upperPane);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);
                
                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);
                
                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
        BurpExtender.this.scrollPane = scrollPane;
        stdout.println(EXTENDER_NAME + " Is Loaded Successfully!\nEnjoy!");
    }
    
    // eventlistner     
    @Override
    public void actionPerformed(ActionEvent e){
        String actionCommand = e.getActionCommand();
        int[] IndexOfSelectedRows = logTable.getSelectedRows();

        int NumberOfSelectedRows = IndexOfSelectedRows.length;
        if("delete".equals(actionCommand)){
            // delete button is clicked
            if(NumberOfSelectedRows >0){
                synchronized(log){
                    for(int counter=0;counter<NumberOfSelectedRows;counter++){
                        log.remove(IndexOfSelectedRows[counter]-counter);
                    }
                    fireTableRowsDeleted(IndexOfSelectedRows[0],IndexOfSelectedRows[0]+NumberOfSelectedRows);
                }
            }else{
                stdout.println("plese select rows you will delete");        
            }
        }else if("addRow".equals(actionCommand)){
            // add row button is clicked
            if(NumberOfSelectedRows != 1){
                stdout.println("invalid area selected");
           }
           synchronized(log){
               log.add(IndexOfSelectedRows[0],new LogEntry("",null,"","","",""));
               fireTableRowsInserted(1, 1);
           }
        }
    }
            
    // implement ITab
    @Override
    public String getTabCaption()
    {
        return "ParamSheet";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    // implement IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {           
        Utilities utils = new Utilities();
        // [method, url, param0, param1, param2, ...]
        ArrayList<String> urlParamList = new ArrayList<>();

        // get the information of method, url, parameters
        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
        int paramNumber = reqInfo.getParameters().size();
        List<IParameter> parameters = reqInfo.getParameters();
        String method = reqInfo.getMethod();
        URL url = reqInfo.getUrl();
        String currentUrl = utils.url2str(url);
        
        // add the data into list
        urlParamList.add(method);
        urlParamList.add(currentUrl);
        for(int counter=0; counter<paramNumber; counter++){
            urlParamList.add(parameters.get(counter).getName());
        }

        // check whether request is unique and whether request is in scope
        if (!messageIsRequest && callbacks.isInScope(url) && pastReq.contains(urlParamList) == false){
//        if (!messageIsRequest  && pastReq.contains(urlParamList) == false){
            String ext = utils.getExtension(url);            
            if(fileExtentionCheckbox.isSelected()){
               String text = BurpExtender.this.fileExtentionTextField.getText();
               String[] arr = text.split(",",0);
               if(Arrays.asList(arr).contains(ext)){
                   //stdout.println("exclude by extention filter");
                   return;
               }
            }
            
            String[] typeArray = {"URL","Body","Coockie","xml","xml_attr","multi_atter","JSON"};
            // add data into data on sheet
            if(paramNumber!=0){
                // create a new log entry with the message details
                synchronized(log){
                    int row = log.size();                            
                    for(int counter=0; counter<paramNumber; counter++){
                        String type = typeArray[parameters.get(counter).getType()];
                        String prmName = parameters.get(counter).getName();
                        String prmValue = parameters.get(counter).getValue();
                        if(counter==0){
                            log.add(new LogEntry(Integer.toString(this.reqNum), url,"","","", ""));
//                            stdout.println(Integer.toString(this.reqNum));
                            fireTableRowsInserted(1, 1);
                        }
                        log.add(new LogEntry("",null,method,type,prmName, prmValue));
                        fireTableRowsInserted(row, row);
                    }
                    log.add(new LogEntry("",null,"","","", ""));
                    this.reqNum++;
                }                
                // add resent request into pastReq
                pastReq.add(urlParamList);
                // renew most recent request and response
                mostRecentReqRes = callbacks.saveBuffersToTempFiles(messageInfo);
            }
        }else{
            //stdout.println("exclude by scope or unique filter");
        }
    }

    // extend AbstractTableModel    
    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 6;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "No.";
            case 1:
                return "URL";
            case 2:
                return "Method";
            case 3:
                return "Type";
            case 4:
                return "Parameter";
            case 5:
                return "Value";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex){
            case 0:
                return logEntry.num;
            case 1:
                return logEntry.url;
            case 2:
                return logEntry.method;
            case 3:
                return logEntry.type;
            case 4:
                return logEntry.prmName;
            case 5:
                return logEntry.prmValue;
            default:
                return "";
        }
    }

    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    //
    // extend JTable to handle cell selection
    //
    
    private class Table extends JTable{
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
//            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
//            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
//            currentlyDisplayedItem = logEntry.requestResponse;
            
            super.changeSelection(row, col, toggle, extend);
        }        
    }
    
    public static class Utilities{
        private String url2str(URL urlIn){
            String urlOut;
            if(urlIn!=null){
                String urlStr = urlIn.toString();
                int index = urlStr.indexOf("?");
                if(index == -1){
                    urlOut = urlStr;
                }else{
                    urlOut = urlStr.substring(0,index);
                }     
            }else{
                urlOut="";
            } 
            return urlOut;
        }
        private String getExtension(URL url){
            String u = url2str(url);
            int index = u.lastIndexOf(".");
            String ext = u.substring(index+1,u.length());
            return ext;
        }
    }
    
    //
    // class to hold details of each log entry
    //
    
    private static class LogEntry{
        final String num;
        final String url;
        final String method;
        final String type;
        final String prmName;
        final String prmValue;

        LogEntry(String num, URL url, String method, String type, String prmName, String prmValue)
        {
            Utilities utils = new Utilities();
            this.num = num;
            this.url = utils.url2str(url);
            this.method = method;
            this.type = type;
            this.prmName = prmName;
            this.prmValue = prmValue;
        }
    }
}