"use strict";

function makeWelcomeTabs(){
	var welcomeTabDIV = document.getElementsByClassName("welcome-tab-container")[0];
	console.log("Received welcome tab element" + welcomeTabDIV);

	var firstAnchor = null;
	var secondAnchor = null;

	var myPostsDIV = document.getElementById("my-posts");
	var allPostsDIV = document.getElementById("all-posts");
	
	var tabChildren = welcomeTabDIV.childNodes;
	console.log(tabChildren.length);
	for (var i = 0; i < tabChildren.length; i++){
		var currTag = tabChildren[i];
		console.log("Examining: " + currTag.nodeName);
		
		if (currTag.nodeName === "UL"){
			var myList = currTag;
			firstAnchor = currTag.firstChild.nextElementSibling.firstChild;
			secondAnchor = currTag.firstChild.nextElementSibling.nextElementSibling.firstChild;
			console.log(firstAnchor);
			console.log(secondAnchor);
			break;
		}
		/*
		if (tabChildren[i].classList.contains("active")){
			console.log(tabChildre[i]);
		}*/
	}

	/* Add Click Listeners */
	var tabAnchors = [firstAnchor, secondAnchor];
	for (var i = 0; i < tabAnchors.length; i++){
		tabAnchors[i].addEventListener("click", function(e){
			console.log(this.innerHTML);
			if (!this.classList.contains("active")){
				// Add 'active' class if doesn't exist
				this.classList.add("active");

				if (this.innerHTML === "MY posts"){
					console.log("After click MyPosts tab is ACTIVE");
					allPostsDIV.style.display = "none";
					allPostsDIV.classList.remove("welcome-tab-target");
					myPostsDIV.classList.add("welcome-tab-target");
					myPostsDIV.style.display ="block";

					secondAnchor.classList.remove("active");
				} else if (this.innerHTML === "ALL posts"){
					console.log("After click AllPosts tab is ACTIVE");
					myPostsDIV.style.display = "none";
					myPostsDIV.classList.remove("welcome-tab-target");
					allPostsDIV.classList.add("welcome-tab-target");
					allPostsDIV.style.display = "block";

					firstAnchor.classList.remove("active");
				}

				this.style.display = "block";
			}
		});
	}

	if (firstAnchor.classList.contains("active")){
		console.log("MyPosts tab is ACTIVE");
		firstAnchor.style.display = "block";

		// Hide the AllPosts DIV
		allPostsDIV.style.display = "none";
	} else if (secondAnchor.classList.contains("active")){
		console.log("AllPosts tab is ACTIVE");
		secondAnchor.style.display = "block";

		// Hide MyPosts
		myPostsDIV.style.display = "none";
	} else {
		console.log("ERROR: No Tabs are marked as ACTIVE!");
	}
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
