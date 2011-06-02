<?php

/* @(#) $Id: lib_rpc.php,v 1.17 2011/06/02 10:30:43 $ */

/* Copyright (C) 2011 Julien BOULANGER <azman0101@hotmail.com>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/**
 * This file contains functions dealing with the retrieval of alert-related
 * information from an OSSEC installation.
 * 
 * @copyright Copyright (c) 2011, Julien BOULANGER, All rights reserved.
 * @package ossec_rpc
 * @author Julien BOULANGER <azman0101@hotmail.com> 
 * @license http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 * 
 */

require_once 'lib/Ossec/Alert.php';
require_once 'lib/Ossec/AlertList.php';

/**
 * Fetch an array of alert data, possibly constrained by time and
 * count. The returned array conforms to the following example:
 * 
 * <pre>
 *     [0] =&gt; Array
 *       (
 *           [time] =&gt; 1193749950
 *           [id] =&gt; 5402
 *           [level] =&gt; 3
 *           [user] =&gt; 
 *           [srcip] =&gt; (none)
 *           [description] =&gt; Successful sudo to ROOT executed
 *           [location] =&gt; laptop-&gt;/var/log/secure
 * 
 *           [msg] =&gt; Array
 *               (
 *                   [0] =&gt; Oct 30 09:12:30 hal sudo: dave : sorry, you must have a tty to run sudo ; TTY=unknown ; PWD=/home/dave ; USER=root ; COMMAND=/usr/sbin/open_podbay_door
 *                   [1] =&gt; 
 *               )
 *
 *       )
 * </pre>
 * 
 * @param array $ossec_handle
 *   Array of information representing an OSSEC installation.
 * @param integer $init_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur AFTER the given time. Passed directly to __os_parsealert.
 * @param unknown_type $final_time
 *   Unix timestamp used to constrain the list of retrieved alerts to those
 *   which occur BEFORE the given time. Passed directly to __os_parsealert.
 * @param unknown_type $max_count
 *   Maximum number of events to return. This is used go generate a guess
 *   at the correct file offset needed to return the specified number of
 *   events.
 * @return Ossec_AlertList
 *   An alert list
 */
// TODO: This is always called with init_time=0, final_time=0 and max_count=30.
function os_getanyalerts($ossec_handle, $init_time, $final_time, $max_count = 30, $min_level = 0,
                                     $rule_id = NULL, $location_pattern = NULL,
                                     $str_pattern = NULL, $group_pattern = NULL,
                                     $group_regex = NULL,
                                     $srcip_pattern = NULL, $user_pattern = NULL,
                                     $log_pattern = NULL, $log_regex = NULL,
                                     $rc_code_hash = NULL)
{
    $file = NULL;
    $file_count = 0;
    $file_list[0] = array();

    $alert_list = new Ossec_AlertList( );
    $curr_time = time(0);
    
    
    /* Checking if agent_dir is set */
    if(!isset($ossec_handle{'dir'})||($ossec_handle{'dir'}==NULL))
    {
        $ossec_handle{'error'} = "Unable to open ossec dir: ".
                                  $ossec_handle{'dir'};
        return(NULL);
    }


     /* Getting first file */
    $init_loop = $init_time;
    while($init_loop <= $final_time)
    {
        $l_year_month = date('Y/M',$init_loop);
        $l_day = date('d',$init_loop);
        
        $file_list[$file_count] = "logs/alerts/".
                                  $l_year_month."/ossec-alerts-".$l_day.".log";

        /* Adding one day */
        $init_loop+=86400;
        $file_count++;
    }
    
    /* Getting each file */
    foreach($file_list as $file)
    {

        // If the file does not exist, it must be gzipped so switch to a
        // compressed stream for reading and try again. If that also fails,
        // abort this log file and continue on to the next one.

        $log_file = $ossec_handle{'dir'}.'/'.$file;
        $fp = @fopen($log_file,'rb');
        if($fp === false) {
            $fp = @fopen("compress.zlib://$log_file.gz", 'rb');
            if($fp === false) { continue; }
        }

        /* Reading all the entries */
        while(1)
        {
            /* Dont get more than max count alerts per page */
            if($alert_list->size( ) > $max_count)
            {
            	break;
	    }
            
            $alert = __os_parsealert($fp, $curr_time, $init_time, 
                                     $final_time, $min_level,
                                     $rule_id, $location_pattern,
                                     $str_pattern, $group_pattern,
                                     $group_regex,
                                     $srcip_pattern, $user_pattern,
                                     $log_pattern, $log_regex,
                                     $rc_code_hash);
            if($alert == NULL)
            {
                break;
            }


            /* Adding alert */
            $alert_list->addAlert( $alert );

        }

        /* Closing file */
        fclose($fp);

    }

    return($alert_list);
}


?>
