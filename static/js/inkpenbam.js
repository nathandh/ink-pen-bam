"use strict";

function getCookieData(cookie){
	console.log("In getCookieData....");
	console.log("Received cookie: " + cookie);

	var cookie_data = cookie.split('|');
	var user = cookie_data[0].split('=')[1]
	var pass_hash = cookie_data[1]

	var result = [user, pass_hash]
	return result
}

function displayLoggedIn_User(){
	var signup_login_div = document.getElementsByClassName("signup_login")[0];
	console.log("Received" + signup_login_div);

	if (document.cookie != ""){
		console.log("We have a cookie set...");
		console.log(document.cookie);

		// Get document.cookie values
		var cookie_val = getCookieData(document.cookie);
		console.log("Got Cookie Values: " + cookie_val);

		// Update DIV on page to display LoggedIn User
		var divClasses = signup_login_div.classList;
		if (divClasses.contains("signup_login")){
			console.log("Removing 'signup_login' class...");
			divClasses.remove("signup_login");
			
			console.log("Inserting 'loggedin-user' class...");
			divClasses.add("loggedin-user");

			// Remove main DIV Child Nodes
			while (signup_login_div.hasChildNodes()){
				signup_login_div.removeChild(signup_login_div.lastChild);
			}

			// Insert new Nodes with Logged in User Output
			var anchorLeft = document.createElement("a");
			anchorLeft.setAttribute("href", "/blog/welcome");
			signup_login_div.appendChild(anchorLeft);

			var userLinkDiv = document.createElement("div");
			userLinkDiv.setAttribute("class", "user-link");
			userLinkDiv.innerHTML = "Logged in: " + cookie_val[0];
			anchorLeft.appendChild(userLinkDiv);

			var divSeparator = document.createElement("div");
			divSeparator.innerHTML = " | ";
			signup_login_div.appendChild(divSeparator);

			var anchorRight = document.createElement("a");
			anchorRight.setAttribute("href", "/blog/logout");
			signup_login_div.appendChild(anchorRight);

			var logoutLinkDiv = document.createElement("div");
			logoutLinkDiv.setAttribute("class", "logout-link");
			logoutLinkDiv.innerHTML = "Logout";
			anchorRight.appendChild(logoutLinkDiv);

			console.log("Update page to display LOGGED IN user....");
		}
	} else {
		console.log("No User cookies found...");
	}
}

// Document Ready Listener
if (document.addEventListener){
	document.addEventListener("DOMContentLoaded", function handler(){
		document.removeEventListener("DOMContentLoaded", handler, false);
		
		displayLoggedIn_User();
	}, false);
//IE Special Case
} else if (document.attachEvent){
	document.attachEvent("onreadystatechange", function handler(){
		if (document.readyState === "complete"){
			document.detachEvent("onreadystatechange", handler);
			
			displayLoggedIn_User();
		}
	});
}
