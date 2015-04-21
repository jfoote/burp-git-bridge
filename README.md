# Git Bridge extension for Burp Suite Pro

The Git Bridge plugin lets Burp users store and share findings and other Burp items via git. Users can right-click supported items in Burp to send them to a git repo and use the Git Bridge tab to send items back to their respective Burp tools.

## How to Use

### Load the extension

Download `burp_git_bridge.py` and load the plugin via the "Extender" tab as usual. 

![](burp-git-install.png)

This plugin is written in Python so you'll need follow the steps to setup Jython in Burp if you haven't already.

### Store

1. Right click on an interesting Scanner or Repeater item and choose `Send to Git Bridge`

![](burp-git-send-to-git.png)

2. View the item in the Git Repo

![](burp-git-view-repo.png)

### Share

1. `cd ~/.burp_git_bridge` in your favorite shell and set your git upstream to a shared (and maybe private) git server

```
$ git remote set-url origin ssh://git@github.com/jfoote/burp-git-bridge-test.git
```

2. Issue a git push

```
$ git push
```

3. Optionally, view items via a git web interface

TODO

### Load and Burp

1. `cd ~/.burp_git_bridge` in your favorite shell and isue a git pull

```
$ git pull
```

2. Back in Burp, flip to the "Git Bridge" tab and click "Reload"

![](burp-git-reload.png)

3. Send items to their respective tools 

![](burp-git-send-to-tools.png)

4. Keep Burping

![](burp-git-repeater.png)

## Installation

This extension is a PoC. Right now only Repeater and Scanner are supported, 
and the code could use refactoring. If you're interested in a more polished 
version or more features let me know, or better yet consider sending me a pull request. 

Thanks for checking it out.


