# Git Bridge extension for Burp Suite Pro

The Git Bridge plugin lets Burp users store and share findings and other Burp 
items via git. Users can right-click supported items in Burp to send them to
a git repo and use the Git Bridge tab to send items back to their respective 
Burp tools.

This extension is a PoC and the code is kind of a mess. Right now only Repeater 
and Scanner are supported. If you're interested in a more polished version or 
more features let me know, or better yet consider sending me a pull request. 

Thanks for checking it out.

## Code Notes

The entire plugin is implemented in this single file. It's ugly but 
convenient. The file is broken into sections. Each section contains multiple 
classes. The sections are as follows:

### Entry Point

Implements BurpExtender, the entry point for the plugin.

### Logging

Objects that coordinate changes to the Git repo and in-Burp UI. Logging is 
divided into objects that support git functionality (GitLog) and objects that 
support in-Burp functionality (GuiLog). These two parts are wrapped into a 
single class (Log) that is used by the UI components.

### UI

Swing UI Components. Bad. No fun.

### Burp Interop

Objects that are used to store user data as it is passed to Burp callbacks 
(addScanIssue, etc.). 

