<?php
/*
Author: David Zimmer <dzzie@yahoo.com>

Input order of prescedence:
   1) POST["shellcode"]  //http post request
   2) GET["sc"]          //get request index.php?sc=9090eb15... (length limited by GET and data shows in logs)
   3) FILES['scfile']	 //file upload 					  

Runs submitted shellcode through scdbg and outputs the results to webpage
making a simple webservice. I would not expose this to the world, while I havent
seen any crashs of scdbg, they may exist. 

this assumes scdbg.exe is in the same directory as this web script.
If you change the path to scdbg, change the path to where it writes
the scfiles as well.

you can submit either text based shellcode, or file uploads. If you run 
av on the system you use this on, make sure that it ignores both the php 
upload directory, as well as the scripts home directory where temp shellcode
files are written.

Binary file uploads are the recommended, but the file upload can also be
any of the input file formats that scdbg can automatically detect and convert 
to binary. These conversion routines are basic. 

For text based input, we will let scdbg convert it to binary, 
i recommend a hexonly input. 9090eb15 or %xx it also supports %u 
whitespace will be ignored, but things like javascript variable 
assignments will bug it out ie no sc+="9090eb15"; 
its a basic converter only. mixed %xx%uyyyy will break it. 
if you need more robust, you can standardize it in JS on submit with
unescape, or process it further in php manually.


License: Copyright (C) 2013 David Zimmer <dzzie@yahoo.com>

         This program is free software; you can redistribute it and/or modify it
         under the terms of the GNU General Public License as published by the Free
         Software Foundation; either version 2 of the License, or (at your option)
         any later version.

         This program is distributed in the hope that it will be useful, but WITHOUT
         ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
         FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
         more details.

         You should have received a copy of the GNU General Public License along with
         this program; if not, write to the Free Software Foundation, Inc., 59 Temple
         Place, Suite 330, Boston, MA 02111-1307 USA
         
*/

	error_reporting(0);
	
	$shellcode = $_POST["shellcode"]; 
	if(strlen($shellcode) == 0) $shellcode = $_GET["sc"];   //for simplicity we do support GETs, but note the length is limited..
		  
	$org_fname = strip(strtolower($_FILES['scfile']['name']));
	$scfile  = $_FILES['scfile']['tmp_name']; //tmp path given by php not by user

	//echo "<h1>$org_fname   $scfile";

	if(strlen($shellcode) > 0){
		$scfile = md5($shellcode).'.sc'; 
		$org_fname = "md5: ".$scfile;
	    if( file_exists($scfile) ) unlink($scfile);
	    write_file($scfile, $shellcode);
		runScdbg($scfile);
		unlink($scfile);
	}		
	elseif( file_exists($scfile) ){
		runScdbg($scfile);
		unlink($scfile);
	}
	else{  
    ?>

    <html>
    <body bgcolor=white>
    <center>
    <script>
    	function example(){
	    	x = "31C966B96401E8FFFFFFFFC15E304C0E07E2FAEA12594E36CF61B1350B8B380797EDEAFA17FBFFEAE9E86855838285DEE32789B8BBBA36FCB335C1AC1E39F5BC3C6E22DB9721D9B2D7AD522BDD82A65F2CE8CDEB368C8A8D54E1D22B5820BFDA8E256FBCC393924F08CA84222A9B9A9A4C0B72BEDFF93E2D1EFD30C33A947EFC7CB0F5EB282B0CEEEC2F6AE0E0216E1E6C119ADE1591CD761B47F94013121597D11B5B5EF45DF15684D66B015AEA38040706BAFE286C7BBC01BE44CAB304B56AB4DA09A3F7400D7FD079CDE72721794509439E1C585E25395F5E62900302060207A91EB4C0961D1FB019B110BC15B17787EAFCB80E832C2E292D8EA2292BDE969945A9AB834C92939029041433100A072602FDEAFEE9EE9CD8FBE5C3EAE1E1F1FAD2E0FAEEE9F9E3FDF7C080D4EBEBC1FFE3DAB8FEC2D4C8EBD6C3D5D2D6B5F8D8D7CDE4C2C8DFCDDDD7E0A0D6D0C9C9C8C8D98D899699B3A8B0BDBFB2B681BB91BFA5AD8ACA3C2122276276753C33323933054F010C09E5";
	    	document.getElementById('shellcode').value=x
    	}
    </script>
    
	<br><br>
    <form method="POST" action="index.php" enctype="multipart/form-data">
      <table bordercolor=black cellpadding=3 cellspacing=0 border=1 style="font-family:arial;color:black;font-size:14pt;">
         <tr><td height=40 valign=center align=center>Shellcode Analyzer</td></tr>
         <tr><td>
           <table>
             <tr><td width=50 valign=top>Shellcode Text:</td>
             <td> 
             	<textarea name=shellcode id=shellcode cols=50 rows=10></textarea>
             </td></tr>
             <tr><td width=50 valign=top>or File</td>
             <td> 
             	<input type=file name=scfile style="width:425px">
             </td></tr>
             <tr>
             	 <td colspan=2><a href="javascript:example()">example</a>
             	 <input style='position:relative;left:275' type=submit value=submit>
             	  </td>
             </tr>
           </table>
         </td></tr>
      </table>
    </form>
       
    <?
}

function runScdbg($fpath){
    global $org_fname;
	
    $report = "<pre><b>Report for $org_fname</b>\n\n";
	$scdbg = run_command("scdbg.exe -r -findsc -auto -f $fpath"); //you can change path to scdbg.exe here...assumes in same dir as script..
	$scdbg = str_replace("<","&lt;",$scdbg);
	$scdbg = str_replace("'","",$scdbg);
	$report .= $scdbg;
	
	$report .= "\n\n";
	
	echo "<font size=+2><b>Actions:<ul><li><a href=index.php>Submit another sample</a></ul><br><br>";
	echo $report;

}

function run_command($cmd){
	$output = array();
	$retval = 0;
	//echo $cmd ."\n";
	exec($cmd, $output, $retval);
	$tmp = implode("\r\n",$output);
	return $tmp;
}

function write_file($path, $data){
	$f = fopen($path, 'wb');
    fwrite($f, $data);
	fclose($f);
}	

function strip($x){
    $y = str_replace("'","",trim($x));
    $y = str_replace('"',"",$y);	
    $y = str_replace('<',"",$y);
    $y = str_replace('>',"",$y);
    $y = str_replace("\x0","",$y);
    $y = str_replace('|',"",$y);
    $y = str_replace('%',"",$y);
    $y = str_replace('&',"",$y);
    $y = trim($y);
    return $y;
}

?>
