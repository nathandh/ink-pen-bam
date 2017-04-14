"use strict";

function getCookieData(cookie){
	console.log("In getCookieData....");
	console.log("Received cookie: " + cookie);

	// First split on ';' to seperate out 'user_id' and 'session' cookies
	var all_cookies = cookie.split(';');
	
	// Extract the 'user_id' cookie for our purposes
	var userid_cookie = null;	
	for (var i = 0; i < all_cookies.length; i++){
		var curr_cookie = all_cookies[i];
		console.log("Examining curr cookie: " + curr_cookie);
		
		var curr_cookie_vals = curr_cookie.split('|');
		var curr_cookie_name = curr_cookie_vals[0].split('=')[0].trim();

		console.log("Current COOKIE name: " + curr_cookie_name.trim());
		if (curr_cookie_name === "user_id"){
			// Set out userid_cookie variable 
			userid_cookie = all_cookies[i];
			console.log("Grabbed cookie: " + userid_cookie);
			break;
		}
	}
	
	if (userid_cookie == null){
		return null;
	}

	var cookie_data = userid_cookie.split('|');
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
		console.log("Got 'user_id' Cookie Values: " + cookie_val);
		if (cookie_val == null){
			// Just exit and return null
			return null;
		}

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

function addMenuSticky(){
	console.log("In addMenuSticky....");
	var navMenu = document.querySelector(".nav-menu");
	console.log("Received navMenu item: " + navMenu);

	var headerTop = document.querySelector(".header-top");
	var header = document.querySelector(".header");
	var headerBottom = document.querySelector(".header-bottom");
	var title = document.querySelector(".title");
	var mainUserMsgs = document.getElementById("main-user-msgs");
	
	var navLogo = document.querySelector(".nav-logo");
	var homeLink = document.querySelector(".home-link");

	var navMenuPos = 0;
	try {
		navMenuPos = headerTop.clientHeight + header.clientHeight + headerBottom.clientHeight 
					+ title.clientHeight + mainUserMsgs.clientHeight;
	} catch (e){
		console.log(e);
	}

	console.log("navMenuPos calculated to be: " + navMenuPos);
	
	/* We know our standard header image has a height of 200
	   and that the surrounding elements usually alot a
	   total HEIGHT of 270px. In this case, if our calculated
	   MenuPos is less that 270px, just use 270px as default
	   for improved UserExperience. */
	if (navMenuPos < 270){
		navMenuPos = 270;
	} else {
		console.log("Our navMenuPos was calculated correct, and matched expectations!");
	}

	window.addEventListener("scroll", function navSticky(){
		if(window.scrollY >= navMenuPos){
			// Then we set menu item to nav fixed, top 0
			navMenu.style.position = "fixed";
			navMenu.style.top = "0px";
			navMenu.style.zIndex = "1";

			// Additionally change some Menu Display properties since we are in a scroll
			try {
				homeLink.classList.remove("home-link-visible");
				navLogo.classList.remove("nav-logo-hidden");
			} catch (e){
				console.log(e);
			}
			homeLink.classList.add("home-link-hidden");
			navLogo.classList.add("nav-logo-visible");
		} else {
			// Restore defaults
			navMenu.style.position = "static";
			navMenu.style.top = "";
			navMenu.style.zIndex = "";

			try {
				navLogo.classList.remove("nav-logo-visible");
				homeLink.classList.remove("home-link-hidden");
			} catch (e){
				console.log(e);
			}
			navLogo.classList.add("nav-logo-hidden");
			homeLink.classList.add("home-link-visible");

			// Fix Welcome Tab DIVs classes if they exist on this page
			// Since in 'welcome-page.js' we gave them room for our FIXED header
			try {
				var myPostsDIV = document.getElementById("my-posts");
				var allPostsDIV = document.getElementById("all-posts");

				if (myPostsDIV != null && allPostsDIV != null){
					myPostsDIV.classList.remove("welcome-tab-target");
					allPostsDIV.classList.remove("welcome-tab-target");
				}
			} catch(e) {
				console.log("Error resetting Welcome Tab Target DIVs");
				console.log(e);
			}
		}
	});
}

function setPageCurrent(){
	console.log("In setPageCurrent()...");
	var navMenu = document.querySelector(".nav-menu");
	var navMenuChildren = null;
	var navMenuDivs = [];

	navMenuChildren = navMenu.childNodes;
	for (var i = 0; i < navMenuChildren.length; i++){
		if (navMenuChildren[i].tagName == "DIV"){
			console.log(navMenuChildren[i]);
			navMenuDivs.push(navMenuChildren[i]);
		}
	}

	console.log("navMenuDivs is now: " + navMenuDivs);
	console.log(window.location.href);

	var url = window.location.href;
	var resource = url.split("://")[1].split("/");
	console.log(resource);
	console.log(resource.length);

	if (resource.length === 2 && resource[1].includes("blog")){
		console.log("We must be at the HOME Blog page!");
		// Set HOME Menu Item to Active
		navMenuDivs[1].classList.add("nav-menu-home-active");
	} else if (resource.length > 2){
		console.log("At an InkPenBam subpage....");
		if (resource[2].includes("welcome")){
			console.log("At Welcome Page...Setting as HOME Active, since this HOME for logged on User");
			navMenuDivs[1].classList.add("nav-menu-item-active");
			/* Hiding Signup and Login links
			   since these pages are are not applicable to
			   a logged in and valid user... */
			navMenuDivs[2].classList.add("nav-item-hidden");
			navMenuDivs[3].classList.add("nav-item-hidden");
		} else if (resource[2].includes("signup")){
			console.log("At Signup Page...Setting to Active...");
			navMenuDivs[2].classList.add("nav-menu-item-active");
		} else if (resource[2].includes("login")){
			console.log("At Login Page...Setting to Active...");
			navMenuDivs[3].classList.add("nav-menu-item-active");
		} else if (resource[2].includes("newpost")){
			console.log("At NEW Post page...setting to active...");
			navMenuDivs[4].classList.add("nav-menu-item-active");
			/* Hiding Signup and Login links
			   since these pages are are not applicable to
			   a logged in and valid user... */
			   navMenuDivs[2].classList.add("nav-item-hidden");
			   navMenuDivs[3].classList.add("nav-item-hidden");
		} else if (resource.length >= 2 && resource[1].includes("blog")) {
			console.log("We are likely on a Permalink page...");

			/*Check cookie data, if we have a user_id cookie 
			  then hide Signup and Login Nav menu items. */
			// Get document.cookie values
			var cookie_val = getCookieData(document.cookie);
			console.log("Got 'user_id' Cookie Values: " + cookie_val);
			if (cookie_val != null){
				// hide Signup and Login
				navMenuDivs[2].classList.add("nav-item-hidden");
				navMenuDivs[3].classList.add("nav-item-hidden");
			}
		} else {
			console.log("Couldn't parse resource: " + resource);
		}
	}
}

// Document Ready Listener
if (document.addEventListener){
	document.addEventListener("DOMContentLoaded", function handler(){
		document.removeEventListener("DOMContentLoaded", handler, false);
		
		displayLoggedIn_User();
		addMenuSticky();
		setPageCurrent();
	}, false);
//IE Special Case
} else if (document.attachEvent){
	document.attachEvent("onreadystatechange", function handler(){
		if (document.readyState === "complete"){
			document.detachEvent("onreadystatechange", handler);
			
			displayLoggedIn_User();
			addMenuSticky();
			setPageCurrent();
		}
	});
}
