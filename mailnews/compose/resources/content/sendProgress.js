/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Mozilla Communicator client code, 
 * released March 31, 1998. 
 *
 * The Initial Developer of the Original Code is Netscape Communications 
 * Corporation.  Portions created by Netscape are 
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 *
 * Contributors:
 *     William A. ("PowerGUI") Law <law@netscape.com>
 *     Scott MacGregor <mscott@netscape.com>
 *     jean-Francois Ducarroz <ducarroz@netscape.com>
 */

var msgCompDeliverMode = Components.interfaces.nsIMsgCompDeliverMode;
var prefContractID = "@mozilla.org/preferences;1";

// dialog is just an array we'll use to store various properties from the dialog document...
var dialog;

// the msgProgress is a nsIMsgProgress object
var msgProgress = null; 

// random global variables...
var keepProgressWindowUpBox;
var targetFile;
var itsASaveOperation = false;

// all progress notifications are done through the nsIWebProgressListener implementation...
var progressListener = {
    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus)
    {
      if (aStateFlags & Components.interfaces.nsIWebProgressListener.STATE_START)
      {
        // Put progress meter in undetermined mode.
        dialog.progress.setAttribute( "value", 0 );
        dialog.progress.setAttribute( "mode", "undetermined" );
      }
      
      if (aStateFlags & Components.interfaces.nsIWebProgressListener.STATE_STOP)
      {
        // we are done sending/saving the message...
        // Indicate completion in status area.
        var msg;
        if (itsASaveOperation)
          msg = getString( "messageSaved" );
        else
          msg = getString( "messageSent" );
        dialog.status.setAttribute("value", msg);

        // Put progress meter at 100%.
        dialog.progress.setAttribute( "value", 100 );
        dialog.progress.setAttribute( "mode", "normal" );
        var percentMsg = getString( "percentMsg" );
        percentMsg = replaceInsert( percentMsg, 1, 100 );
        dialog.progressText.setAttribute("value", percentMsg);
        if (aStatus == 0)
          processEndOfDownload(false);
        else
          processEndOfDownload(true);
      }
    },
    
    onProgressChange: function(aWebProgress, aRequest, aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress, aMaxTotalProgress)
    {

      var overallProgress = aCurTotalProgress;

      // Calculate percentage.
      var percent;
      if ( aMaxTotalProgress != "-1" ) 
      {
        percent = parseInt( (overallProgress*100)/aMaxTotalProgress + .5 );
        if ( percent > 100 )
          percent = 100;
        
        // Advance progress meter.
        dialog.progress.setAttribute( "value", percent );
      } 
      else 
      {
        percent = "??";

        // Progress meter should be barber-pole in this case.
        dialog.progress.setAttribute( "mode", "undetermined" );
      }

      // Update status msg.
      dialog.status.setAttribute("value", status);

      // Update percentage label on progress meter.
      var percentMsg = getString( "percentMsg" );
      percentMsg = replaceInsert( percentMsg, 1, percent );
      dialog.progressText.setAttribute("value", percentMsg);
    },

	  onLocationChange: function(aWebProgress, aRequest, aLocation)
    {
      // we can ignore this notification
    },

    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage)
    {
      dialog.status.setAttribute("value", aMessage);
    },

    onSecurityChange: function(aWebProgress, aRequest, state)
    {
      // we can ignore this notification
    },

    QueryInterface : function(iid)
    {
     if (iid.equals(Components.interfaces.nsIWebProgressListener) || iid.equals(Components.interfaces.nsISupportsWeakReference))
      return this;
     
     throw Components.results.NS_NOINTERFACE;
    }
};

function getString( stringId ) {
   // Check if we've fetched this string already.
   if ( !dialog.strings[ stringId ] ) {
      // Try to get it.
      var elem = document.getElementById( "dialog.strings."+stringId );
      try {
        if ( elem
           &&
           elem.childNodes
           &&
           elem.childNodes[0]
           &&
           elem.childNodes[0].nodeValue ) {
         dialog.strings[ stringId ] = elem.childNodes[0].nodeValue;
        } else {
          // If unable to fetch string, use an empty string.
          dialog.strings[ stringId ] = "";
        }
      } catch (e) { dialog.strings[ stringId ] = ""; }
   }
   return dialog.strings[ stringId ];
}

function loadDialog() 
{
  if (itsASaveOperation)
  {
    keepProgressWindowUpBox.checked = false;
    keepProgressWindowUpBox.setAttribute("hidden", true);
  }
  else
  {
    var prefs = Components.classes[prefContractID].getService(Components.interfaces.nsIPref);
    if (prefs)
      keepProgressWindowUpBox.checked = prefs.GetBoolPref("mailnews.send.progressDnldDialog.keepAlive");
  }
}

function replaceInsert( text, index, value ) {
   var result = text;
   var regExp = eval( "/#"+index+"/" );
   result = result.replace( regExp, value );
   return result;
}

function onLoad() {
    // Set global variables.
    var subject = "";
    msgProgress = window.arguments[0];
    if (window.arguments[1])
    {
      var progressParams = window.arguments[1].QueryInterface(Components.interfaces.nsIMsgComposeProgressParams)
      if (progressParams)
      {
        itsASaveOperation = (progressParams.deliveryMode != msgCompDeliverMode.Now);
        subject = progressParams.subject;
      }
    }

    if ( !msgProgress ) {
        dump( "Invalid argument to downloadProgress.xul\n" );
        window.close()
        return;
    }

    dialog = new Object;
    dialog.strings = new Array;
    dialog.status      = document.getElementById("dialog.status");
    dialog.progress    = document.getElementById("dialog.progress");
    dialog.progressText = document.getElementById("dialog.progressText");
    dialog.cancel      = document.getElementById("cancel");
    keepProgressWindowUpBox = document.getElementById('keepProgressDialogUp');

    // Set up dialog button callbacks.
    var object = this;
    doSetOKCancel("", function () { return object.onCancel();});

    // Fill dialog.
    loadDialog();

    // set our web progress listener on the helper app launcher
    msgProgress.registerListener(progressListener);
    window.moveTo(opener.screenX + 16, opener.screenY + 32);

    //We need to delay the set title else dom will overwrite it
    return window.setTimeout( "SetTitle('" + subject + "');", 0 );
}

function onUnload() 
{
  if (!itsASaveOperation)
  {
    // remember the user's decision for the checkbox.
    var prefs = Components.classes[prefContractID].getService(Components.interfaces.nsIPref);
    if (prefs)
      prefs.SetBoolPref("mailnews.send.progressDnldDialog.keepAlive", keepProgressWindowUpBox.checked);
  }

  if (msgProgress)
  {
   try 
   {
     msgProgress.unregisterListener(progressListener);
     msgProgress = null;
   }
    
   catch( exception ) {}
  }
}

function SetTitle(subject)
{
  var prefix;
  if (itsASaveOperation)
    prefix = getString("titlePrefixSave");
  else
    prefix = getString("titlePrefixSend");
  window.title = prefix + " " + subject;
}

// If the user presses cancel, tell the app launcher and close the dialog...
function onCancel () 
{
  // Cancel app launcher.
   try 
   {
     msgProgress.processCanceledByUser = true;
   }
   catch( exception ) {return true;}
    
  // don't Close up dialog by returning false, the backend will close the dialog when everything will be aborted.
  return false;
}

// closeWindow should only be called from processEndOfDownload
function closeWindow(forceClose)
{
  // while the time out was fired the user may have checked the
  // keep this dialog open box...so we should abort and not actually
  // close the window.
  if (forceClose || itsASaveOperation || !keepProgressWindowUpBox.checked)
    window.close();
  else
    setupPostProgressUI();
}

function setupPostProgressUI()
{
  //dialog.cancel.childNodes[0].nodeValue = "Close";
  // turn the cancel button into a close button
  var cancelButton = document.getElementById('cancel');
  if (cancelButton)
  {
    cancelButton.setAttribute("label", getString("dialogCloseLabel"));
    cancelButton.setAttribute("onclick", "window.close()");
  }
}

// when we receive a stop notification we are done reporting progress on the send/save
// now we have to decide if the window is supposed to go away or if we are supposed to remain open
function processEndOfDownload(forceClose)
{
  if (forceClose || itsASaveOperation || !keepProgressWindowUpBox.checked)
//    return window.setTimeout( "closeWindow();", 2000 ); // shut down, we are all done.
    return closeWindow(forceClose); // shut down, we are all done.
  
  // o.t the user has asked the window to stay open so leave it open and enable the open and open new folder buttons
  setupPostProgressUI();
}
