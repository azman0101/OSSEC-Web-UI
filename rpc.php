<?php
/* Update the include path so that all library files can be
 * easily found.
 */

//phpinfo();

ini_set('include_path', ini_get('include_path').':'.dirname(__FILE__).'/lib');
include "/opt/bitnami/php/lib/php/Services/JSON.php";

$array_lib = array("ossec_conf.php", "lib/ossec_categories.php",
                          "lib/ossec_formats.php",
                          "lib/os_lib_handle.php",
                          "lib/os_lib_agent.php",
                          "lib/os_lib_mapping.php",
                          "lib/os_lib_stats.php",
                          "lib/os_lib_syscheck.php",
                          "lib/os_lib_firewall.php",
                          "lib/os_lib_alerts.php");

foreach ($array_lib as $mylib)
{
                if(!(include($mylib)))
                {
                    echo "$include_error '$mylib'.\n<br />";
                    echo "$int_error";
                    return(1);
                }
}

include "lib_rpc.php";

/* Getting user argument (page) */
$USER_f = false;
$ALERTS_n = 30;
if(isset($_GET['f']))
{
        $USER_f = $_GET['f'];
}
/* If nothing is set, default to the main page. */
else
{
        $USER_f = "m";
}


if(isset($_GET['num']))
{
        $ALERTS_n = $_GET['num'];

}

if(!os_check_config($ossec_dir, $ossec_max_alerts_per_page,
                    $ossec_search_level, $ossec_search_time,
                    $ossec_refresh_time))
{
        echo "$int_error";
        return(1);
}

/* OS PHP init */
if (!function_exists('os_handle_start'))
{
    echo "<b class='red'>You are not allowed direct access.</b><br />\n";
    return(1);
}


/* Starting handle */
$ossec_handle = os_handle_start($ossec_dir);
if($ossec_handle == NULL)
{
    echo "Unable to access ossec directory.\n";
    return(1);
}


/* Getting all agents */
if(($agent_list = os_getagents($ossec_handle)) == NULL)
{
    echo "No agent available.\n";
    return(1);
}

/* Getting syscheck information */
$syscheck_list = os_getsyscheck($ossec_handle);



/* Getting last alerts */
$alert_list = os_getanyalerts($ossec_handle, 1, time(), $ALERTS_n);

/* Getting alerts */

/* $alert_list = os_searchalerts($ossec_handle, $USER_searchid,
                                   $USER_init, $USER_final,
                                   $ossec_max_alerts_per_page,
                                   $USER_level,$USER_rule, $LOCATION_pattern,
                                   $USER_pattern, $USER_group,
                                   $USER_srcip, $USER_user,
                                   $USER_log);
*/

//var_dump($alert_list);
$json = new Services_JSON();

/* output in necessary format */
header('Content-type: application/json');

if($alert_list == NULL)
{
    echo "<b class='red'>Unable to retrieve alerts. </b><br />\n";
}
else
{
    $alert_count = $alert_list->size() -1;

    if ($alert_count >= 0)
    {
//	echo $alert_count;
	$output = $json->encode($alert_list);
	echo $output;
    }
}


?>
