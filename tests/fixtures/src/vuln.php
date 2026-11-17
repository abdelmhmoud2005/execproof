<?php
$cmd = $_GET['cmd'];
system("ping " . $cmd);
exec("whois " . $_POST['domain']);
$out = `id $user`;
eval($_REQUEST['payload']);
unserialize($_COOKIE['data']);
