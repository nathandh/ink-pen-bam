# ink-pen-bam
Ink, Pen, Bam Blog as built for Udacity's FullStack NanoDegree Program

Steps to deploy this project:

<ul>
	<li>"git clone" this repository</li>
	<li>Install and Configure 'Google App Engine' on your development machine</li>
	<li>Navigate to the top level directory of the clones 'ink-pen-bam' project</li>
	<li>Create a "secret key" 1 line character string of some length: (e.g. sjjdk86UOIOSKajaal9874j2jh5)
		<ul>
			<li>Store it in a top level directory file named: <b>inkpenbam.key</b>.</li>
			<li>The app looks for this "inkpenbam.key" file on load, <br/>
				and uses the secret key of choosing throughout the app to improve security.</li>
		</ul>
	</li>
	<li>Run App Engine Server on the Project: e.g. 'dev_appserver.py .'</li>
</ul>

Working demo at: <a href="http://ink-pen-bam.appspot.com/blog">Ink-Pen-Bam Home</a>

Copyright (2017) - Nathan Hernandez
