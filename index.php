<!DOCTYPE html>
<html>
<head>
<style>
	table {
	    border-collapse: collapse;
	}

	table, th, td {
	    border: 1px solid black;
	}
</style>
</head>
<body>
<center>
<?php
echo "<h1>WELCOME TO THE NK NET OBSERVER!</h1><br><h3>Click on the links to view individual IP's information</h3>";
// if get variable ip not set AND  no order set.
if (empty($_GET['ip'])) {
  // Do something.
   class MyDB extends SQLite3 {
      function __construct() {
         $this->open('scans.db');
      }
   }
   
   $db = new MyDB();

	echo "<table><tr><th>IP Address</th><th>Hostname</th><th>Open Ports</th><th>Time Scanned</th></tr>";
    $ret = $db->query("SELECT * from hosts ORDER BY last_update DESC;");
    while($row = $ret->fetchArray(SQLITE3_ASSOC)) {
	    echo "<tr><td><a href='?ip=" . $row['ip'] . "'>" . $row['ip'] . "</a></td>";
	    echo "<td>" . $row['hostname'] ."</td><td>";

	    $ports_ret = $db->query("SELECT port,name from ports WHERE ip='" . $row['ip'] . "';");
	    while($ports_row = $ports_ret->fetchArray(SQLITE3_ASSOC)) {
	      	echo $ports_row['port'] . " - " . $ports_row['name'] . "<br>";

	    }
    echo "</td><td>" . gmdate("Y-m-d H:i:s", $row['last_update']) ."</td>";



    echo "</tr>";
   }
  $db->close();
  echo "</table>";
} else {
	if(!filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
		echo"Invalid ip!";
	} else {
    class MyDB extends SQLite3 {
      function __construct() {
         $this->open('scans.db');
      }
   }
   
   $db = new MyDB();

    $ret = $db->query("SELECT * from hosts WHERE ip='" . $_GET['ip'] . "';");
    while($row = $ret->fetchArray(SQLITE3_ASSOC)) {
	    echo "<h1>" . $row['ip'] . "</h1>";
	    echo "<h3>Hostname: " . $row['hostname'] ."</h3><h3> Open Ports: ";

	    $ports_ret = $db->query("SELECT port,name from ports WHERE ip='" . $_GET['ip'] . "';");
	    while($ports_row = $ports_ret->fetchArray(SQLITE3_ASSOC)) {
	      	echo $ports_row['port'] . " - " . $ports_row['name'] . ", ";

	    }
    echo "</h3><h3>Time Scanned: " . gmdate("Y-m-d H:i:s", $row['last_update']) ."</h3>";

	}
  }
}

?>
</center>
</body>
</html>