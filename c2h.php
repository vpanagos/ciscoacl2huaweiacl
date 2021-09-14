<html>

<head>
<title>Cisco to Huawei ACLs</title>
</head>
<body>
<?php
if (isset($_GET['tt'])) $tt=$_GET['tt']; else $tt='';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$t=$_POST['t'];
	$t=trim($t);
	$t=explode("\n",$t);

	$acl="";
	$remark="";
	$standardlist=FALSE;
	$n=10;
	foreach ($t as $line) {
		$line=trim($line);
		$line = preg_replace('/\s+/', ' ', $line);
		$p=explode(" ",$line);
		
		// Cisco standard list - Huawei basic list
		if ($p[0]=="access-list" && intval($p[1]>=1) && intval($p[1]<=99)) {
			$standardlist=TRUE;
			if ($n==10) {
				$aclnumber=intval($p[1])+2000;
				$acl.="acl $aclnumber\n";
				
			}
				$s=array_shift($p);
				$s=array_shift($p);
				$action=array_shift($p);
				$source1=array_shift($p);
				$source2=array_shift($p); if ($source2=="") $source2="0.0.0.0";
				$acl.="rule $action source $source1 $source2";
				
				
				$acl.="\n";
			
			$n+=10;
			continue;
		}
		
		
		if ($p[0]=="ip" && $p[1]=="access-list" && $p[2]=="extended") $acl="acl name $p[3]\ndescription *** Access list ".$p[3]." - [ ".date("d-m-Y H:i:s")." ]\n";
		
		$action=array_shift($p);
		
		if ($action=="remark") {
			$remark="description ";
			$remark.=implode(" ", $p)."\n";
		}
		if ($action=="permit" || $action=="deny") {

			$prot=array_shift($p);
			
			$acl.="rule $n $action $prot ";

			$source1=array_shift($p);
			$acl.="source ";
			if ($source1=="any")
				$acl.="any ";
			elseif ($source1=="host") {
				$source2=array_shift($p);
				$acl.="$source2 0.0.0.0 ";
			} else {
				$source2=array_shift($p);
				$acl.="$source1 $source2 ";
			}
			if ($p[0]=="eq" || $p[0]=="gt") {
				$sourceport1=array_shift($p);
				$sourceport2=array_shift($p);
				if ($sourceport2=="domain" && $prot=="udp") $sourceport2="dns";
				$acl.="source-port $sourceport1 $sourceport2 ";
			}

			$destination1=array_shift($p);
			$acl.="destination ";
			if ($destination1=="any")
				$acl.="any ";
			elseif ($destination1=="host") {
				$destination2=array_shift($p);
				$acl.="$destination2 0.0.0.0 ";
			} else {
				$destination2=array_shift($p);
				$acl.="$destination1 $destination2 ";
			}
			
			
			if ($p[0]=="eq" || $p[0]=="gt") {
				$destinationport1=array_shift($p);
				$destinationport2=array_shift($p);
				if ($destinationport2=="domain" && $prot=="udp") $destinationport2="dns";
				$acl.="destination-port $destinationport1 $destinationport2 ";
			}
			if ($p[0]=="range") {
				$destinationport1=array_shift($p);
				$destinationport2=array_shift($p);
				$destinationport3=array_shift($p);
				$acl.="destination-port range $destinationport2 $destinationport3 ";
			}

			$lastpiece=array_shift($p);
			
			if ($lastpiece=="established") $acl.="tcp-flag established ";

			if ($lastpiece=="echo-reply") $acl.="icmp-type echo-reply ";
			if ($lastpiece=="echo") $acl.="icmp-type echo ";
			if ($lastpiece=="source-quench") $acl.="icmp-type source-quench ";
			if ($lastpiece=="ttl-exceeded") $acl.="icmp-type ttl-exceeded ";
			if ($lastpiece=="port-unreachable") $acl.="icmp-type port-unreachable ";


			$acl.="\n";
			if ($remark!="") $acl.="rule $n $remark";
			$n+=5;
		}
	}
	if ($standardlist==TRUE) $acl.="rule deny source any\n";
	
}
?>

<form name="f" method="post">


<table>
	<tr><th>Cisco</th><th>Huawei</th></tr>
	<tr>
		<td>
			<textarea name="t" rows="48" cols="72" autofocus><?php if ($_SERVER['REQUEST_METHOD'] === 'POST') echo $_POST['t']; ?></textarea>
		</td>
		
		<td>
			<textarea name="h" rows=48 cols=112><?php echo $acl; ?></textarea>
			
		</td>
		
	</tr>
	<tr>
		<td><input type="submit" value="Convert"></td>
		<td>&nbsp;</td>
	</tr>
</table>


</form>

</body>
</html>
