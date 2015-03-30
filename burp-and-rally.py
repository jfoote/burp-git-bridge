from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

class BurpExtender(IBurpExtender, IHttpListener):
    '''
    Entry point for plugin; creates UI, and Log
    Will create GitRepo and (probably) a standalone InputHandler later
    '''
    
    def	registerExtenderCallbacks(self, callbacks):
    
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp and Rally")
        
        self.ui = BurpUi(callbacks)
        self.log = Log(self.ui)
       
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            self.log.add_network_entry(toolFlag, messageInfo)
       
class Log(object):
    '''
    Log of burp activity: commands handles both the Burp UI log and the git 
    repo log.
    Used by BurpExtender (for now) when it logs input events.
    '''
    def __init__(self, ui):
        self.ui = ui

    def add_network_entry(self, toolFlag, messageInfo):
        self.ui.add_network_log_entry(toolFlag, messageInfo)
        # TODO: git stuff
 
class BurpUi(ITab):
    '''
    The collection of objects that make up this extension's Burp UI. Created
    by BurpExtender.
    '''

    def __init__(self, callbacks):

        # Create split pane with top and bottom panes

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.bottom_pane = UiBottomPane(callbacks)
        self.top_pane = UiTopPane(callbacks, self.bottom_pane)
        self._splitpane.setLeftComponent(self.top_pane)
        self._splitpane.setRightComponent(self.bottom_pane)

        
        # Add the plugin's custom tab to Burp's UI

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.addSuiteTab(self)

      
    def getTabCaption(self):
        return "Rally"
       
    def getUiComponent(self):
        return self._splitpane

    def add_network_log_entry(self, toolFlag, messageInfo):
        self.top_pane.logTable.add_network_entry(toolFlag, messageInfo)


class UiBottomPane(JTabbedPane, IMessageEditorController):
    '''
    The bottom pane in the this extension's UI tab. It shows detail of 
    whatever is selected in the top pane.
    '''
    def __init__(self, callbacks):
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        self.addTab("Request", self._requestViewer.getComponent())
        self.addTab("Response", self._responseViewer.getComponent())
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
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

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
        #self.addTab("Options", self._responseViewer.getComponent())
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
