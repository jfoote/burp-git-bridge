from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory
from java.awt import Component
from java.awt.event import ActionListener
from java.io import PrintWriter
from java.util import ArrayList, List
from javax.swing import JScrollPane, JSplitPane, JTabbedPane, JTable, SwingUtilities, JPanel, JButton, JLabel, JMenuItem
from javax.swing.table import AbstractTableModel
from threading import Lock


'''
Entry point for Burp and Rally extension.
'''

class BurpExtender(IBurpExtender, IHttpListener):
    '''
    Entry point for plugin; creates UI, and Log
    Will create GitRepo and (probably) a standalone InputHandler later
    '''
    
    def	registerExtenderCallbacks(self, callbacks):
    
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp and Rally")
        
        self.log = Log()
        self.ui = BurpUi(callbacks, self.log)
        self.log.ui = self.ui
       
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            self.log.add_network_entry(toolFlag, messageInfo)
       

'''
Logging functionality.
'''

class Log(object):
    '''
    Log of burp activity: commands handles both the Burp UI log and the git 
    repo log.
    Used by BurpExtender (for now) when it logs input events.
    '''
    def __init__(self):
        self.ui = None

    def add_network_entry(self, toolFlag, messageInfo):
        self.ui.add_network_log_entry(toolFlag, messageInfo)
        # TODO: git stuff
 

'''
Implementation of extension's UI.
'''
class BurpUi(ITab):
    '''
    The collection of objects that make up this extension's Burp UI. Created
    by BurpExtender.
    '''

    def __init__(self, callbacks, log):

        # Create split pane with top and bottom panes

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.bottom_pane = UiBottomPane(callbacks)
        self.top_pane = UiTopPane(callbacks, self.bottom_pane)
        self._splitpane.setLeftComponent(self.top_pane)
        self._splitpane.setRightComponent(self.bottom_pane)


        # Create right-click handler

        self.log = log
        rc_handler = RightClickHandler(callbacks, log)
        callbacks.registerContextMenuFactory(rc_handler)

        
        # Add the plugin's custom tab to Burp's UI

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.addSuiteTab(self)

      
    def getTabCaption(self):
        return "Rally"
       
    def getUiComponent(self):
        return self._splitpane

    def add_network_log_entry(self, toolFlag, messageInfo):
        self.top_pane.logTable.add_network_entry(toolFlag, messageInfo)

class RightClickHandler(IContextMenuFactory):
    def __init__(self, callbacks, log):
        self.callbacks = callbacks
        self.log = log

    def createMenuItems(self, invocation):
        import sys
        sys.stdout.write("invoked\n")
        context = invocation.getInvocationContext()
        tool = invocation.getToolFlag()
        if tool == self.callbacks.TOOL_REPEATER:
            if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE]:
                item = JMenuItem("Send to Rally")
                item.addActionListener(self.RepeaterHandler(self.callbacks, invocation, self.log))
                items = ArrayList()
                items.add(item)
                return items
        else:
            # TODO: add support for other tools
            pass

    class RepeaterHandler(ActionListener):
        def __init__(self, callbacks, invocation, log):
            self.callbacks = callbacks
            self.invocation = invocation
            self.log = log

        def actionPerformed(self, actionEvent):
            import sys
            sys.stdout.write("actionPerformed\n")
            for message in self.invocation.getSelectedMessages():
                self.log.add_network_entry(self.callbacks.TOOL_REPEATER, message) 

class UiBottomPane(JTabbedPane, IMessageEditorController):
    '''
    The bottom pane in the this extension's UI tab. It shows detail of 
    whatever is selected in the top pane.
    '''
    def __init__(self, callbacks):
        self.sendPanel = SendPanel()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self.addTab("Request", self._requestViewer.getComponent())
        self.addTab("Response", self._responseViewer.getComponent())
        self.addTab("Send to Tools", self.sendPanel)
        callbacks.customizeUiComponent(self)

    def show_log_entry(self, log_entry):
        '''
        Shows the log entry in the bottom pane of the UI
        '''
        self._requestViewer.setMessage(log_entry.requestResponse.getRequest(), True)
        self._responseViewer.setMessage(log_entry.requestResponse.getResponse(), False)
        self._currentlyDisplayedItem = log_entry

        
    '''
    The three methods below implement IMessageEditorController st. requests 
    and responses are shown in the UI pane
    '''
    def getHttpService(self):
        return self._currentlyDisplayedItem.requestResponse.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.requestResponse.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

 
class UiTopPane(JTabbedPane):
    '''
    The top pane in this extension's UI tab. It shows either the in-burp 
    version of the Log or an "Options" tab (name TBD).
    '''
    def __init__(self, callbacks, bottom_pane):
        self.logTable = UiLogTable(callbacks, bottom_pane)
        scrollPane = JScrollPane(self.logTable)
        self.addTab("Log", scrollPane)
        options = OptionsPanel()
        self.addTab("Configuration", options)
        callbacks.customizeUiComponent(self)

from collections import namedtuple
LogEntry = namedtuple('LogEntry', ['tool', 'requestResponse', 'url'])
class UiLogTable(JTable):
    '''
    Table of log entries that are shown in the top pane of the UI when
    the corresponding tab is selected.
    
    Note, as a JTable, this stays synchronized with the underlying
    ArrayList. 
    '''
    def __init__(self, callbacks, bottom_pane):
        self.bottom_pane = bottom_pane
        self._callbacks = callbacks
        self._log = ArrayList()
        self._lock = Lock()
        self._helpers = callbacks.getHelpers()
        self._model = self.TableModel(callbacks, self._log)
        self.setModel(self._model)
        callbacks.customizeUiComponent(self)
    
    def changeSelection(self, row, col, toggle, extend):
        '''
        Displays the selected item in the content pane
        '''
    
        logEntry = self._log.get(row)
        JTable.changeSelection(self, row, col, toggle, extend)
        self.bottom_pane.show_log_entry(logEntry)

    def add_network_entry(self, toolFlag, messageInfo):
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
        self._model.fireTableRowsInserted(row, row)
        self._lock.release()


    class TableModel(AbstractTableModel):
        '''
        This is the model for that table that is show in the UI tab. This is 
        a nested class (for now) as the TableModel and JTable classes have 
        common ancestors.
        TODO: Maybe move this to Log (directly, as nested class, or something) 
        '''
        def __init__(self, callbacks, log):
            self._log = log
            self._callbacks = callbacks

        def getRowCount(self):
            try:
                return self._log.size()
            except:
                return 0
    
        def getColumnCount(self):
            return 2
    
        def getColumnName(self, columnIndex):
            if columnIndex == 0:
                return "Tool"
            if columnIndex == 1:
                return "URL"
            return ""
    
        def getValueAt(self, rowIndex, columnIndex):
            logEntry = self._log.get(rowIndex)
            if columnIndex == 0:
                return self._callbacks.getToolName(logEntry.tool)
            if columnIndex == 1:
                return logEntry.url.toString()
            return ""

class OptionsPanel(JPanel):
    def __init__(self):
        reloadButton = JButton("Reload UI from git repo")
        # see JButton::addActionListener
        self.add(reloadButton)

class SendPanel(JPanel):
    def __init__(self):
        label = JLabel("Send selected results to respective burp tools:")
        sendButton = JButton("Send")
        self.add(label)
        # see JButton::addActionListener
        self.add(sendButton)
