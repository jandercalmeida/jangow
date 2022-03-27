<?php
// Para usar use:
// http://siete.com.br/arquivo1.php?host=www.google.com.br;ls -l

exec("ping -c 4 " . $_GET['host'], $output);
echo "<pre>";
print_r($output);
echo "</pre>";
?>