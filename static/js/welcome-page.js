"use strict";

function makeWelcomeTabs(){
	var welcomeTabDIV = document.getElementsByClassName("welcome-tabs")[0];
	console.log("Received welcome tab element" + welcomeTabDIV);

}

// Document Ready Listener
if (document.addEventListener){
	document.addEventListener("DOMContentLoaded", function handler(){
		document.removeEventListener("DOMContentLoaded", handler, false);
		
		makeWelcomeTabs();
	}, false);
//IE Special Case
} else if (document.attachEvent){
	document.attachEvent("onreadystatechange", function handler(){
		if (document.readyState === "complete"){
			document.detachEvent("onreadystatechange", handler);
			
			makeWelcomeTabs();
		}
	});
}
