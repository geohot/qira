<?php // -*- Mode: PHP; -*-

/**
 * Copyright (C) 2009 Marty Connor <mdc@etherboot.org>.
 * Copyright (C) 2009 Entity Cyber, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

// Include table of user-configurable iPXE options
require_once "flag-table.php";

// Include user-shadowable globals
require_once "globals.php";

// Allow user to shadow globals
if ( is_file ( 'local-config.php' ) ) {
    include_once "local-config.php";
}

////
// General utility functions
////

/**
 * Remove undesirable characters from a given string
 *
 * Certain characters have the potential to be used for
 * malicious purposes by web-based attackers.  This routine
 * filters out such characters.
 *
 * @param string $s supplied string
 *
 * @return string returned string with unwanted characters
 *                removed
 */
function cleanstring ( $s )
{
    $len = strlen ( $s );
    if ( $len > 80 ) {
        $s = substr ( $s, 0, 80 );
    }

    $s      = trim ( $s );
    $pos    = 0;
    $result = "";

    while ( $pos < $len ) {
        $ltr = ord ( ucfirst ( $s[$pos] ) );
        if ( ( $ltr >= ord ( "A" ) ) && ( $ltr <= ord ( "Z" ) ) ||
             ( $ltr >= ord ( "0" ) ) && ( $ltr <= ord ( "9" ) ) ||
             ( $ltr == ord ( "." ) ) && ( strlen ( $result ) > 0 ) ||
             ( $ltr == ord ( "_" ) ) ||
             ( $ltr == ord ( "+" ) ) ||
             ( $ltr == ord ( ":" ) ) ||
             ( $ltr == ord ( "/" ) ) ||
             ( $ltr == ord ( "-" ) ) ) {
            $result .= $s[$pos];
        }
        $pos++;
    }
    return $result;
}

/**
 * Return URL of the currently running script, minus the filename
 *
 * @return string the URL of the currently running script, minus the filename
 */
function curDirURL ()
{
        $dir = dirname ( $_SERVER['PHP_SELF'] );

        if ( $dir == "." || $dir == "/" ) {
                $dir = "";
        }

        $isHTTPS = ( isset ( $_SERVER["HTTPS"] ) && $_SERVER["HTTPS"] == "on" );
        $port = ( isset($_SERVER["SERVER_PORT"] ) &&
                          ( ( !$isHTTPS && $_SERVER["SERVER_PORT"] != "80" ) ||
                                ( $isHTTPS  && $_SERVER["SERVER_PORT"] != "443" ) ) );

        $port = ( $port ) ? ':' . $_SERVER["SERVER_PORT"] : '';

        $dest = ( $isHTTPS ? 'https://' : 'http://' ) .
                $_SERVER["SERVER_NAME"] . $dir . "/";

        return $dest;
}

/**
 * Extract NIC families and associated ROM PCI IDs from the src/bin/NIC file.
 *
 * $src_dir must contain the path of the iPXE src directory for this build
 *
 * @return array[0] array $new_nics
 * @return array[1] array $roms
 */
function parse_nic_file ()
{
    global $src_dir;

    $fd = fopen ( "$src_dir/bin/NIC", "r" );
    if ( ! $fd ) {
        die ( "Missing src/bin/NIC file.  'make bin/NIC'" );
    }

    $nics = array ();
    $roms = array ();
    $nic = "";

    while ( !feof ( $fd ) ) {

        $line = trim ( fgets ( $fd, 200 ) );

        $first_eight_chars = substr ( $line, 0, 8 );
        settype ( $first_eight_chars, "string" );

        if ( strpos ( $first_eight_chars, "family" ) === 0 ) {

            // get pathname of NIC driver
            #list ( $dummy, $nic ) = split( "[ \t]+", $line );
            list ( $dummy, $nic ) = explode("\t", $line);
            settype ( $nic, "string" );

            // extract filename name of driver from pathname
            $nic = substr ( $nic, strrpos ( $nic, "/" ) + 1,
			   strlen ( $nic ) - strrpos ( $nic, "/" ) + 1 );

            $nics[$nic] = $nic;

            // For each ISA NIC, there can only be one ROM variant
            $roms[$nic] = $nic;
        }

        // If the first 8 digits of the line are hex digits
        // add this rom to the current nic family.

        if (    ( strlen ( $first_eight_chars ) == 8 )
             && ( ctype_xdigit ( $first_eight_chars ) )
             && ( $nic != "" ) ) {

            $roms[$first_eight_chars] = $nic;
        }
    }
    fclose ( $fd );

    // put most NICs in nice alpha order for menu
    ksort ( $nics );

    // add special cases to the top

	$new_nics = array ( "all-drivers" => "ipxe",
						"undionly" => "undionly",
						"undi" => "undi",
    );

	foreach ( $nics as $key => $value ) {
		// skip the undi driver
		if ( $key != "undi" ) {
			$new_nics[$key] = $value;
		}
	}

	return array ( $new_nics, $roms );
}

////
// HTML form utility functions
////

/**
 * Return html code to create hidden form input fields
 *
 * @param string $flag  name of form variable to set
 * @param string $value value to give form variable
 *
 * @return string html code for given hidden form input field
 */
function hidden ( $flag, $value )
{
    $value = htmlentities ( $value );
    return "<input type=\"hidden\" value=\"$value\" name=\"$flag\"></input>";
}

/**
 * Return html code to create checkbox form input fields
 *
 * @param string $flag  name of form variable to set
 * @param string $value "on" means box should be checked
 *
 * @return string html code for given hidden form input field
 */
function checkbox ( $flag, $value )
{
    return "<input type=\"checkbox\" value=\"on\" name=\"$flag\"" .
        ($value == "on" ? " checked>" : ">" );
}

/**
 * Return html code to create text form input fields
 *
 * @param string $flag  name of form variable to set
 * @param string $value initial contents of field
 * @param string $size  size in characters of text box
 *
 * @return string html code for given text input field
 */
function textbox ( $flag, $value, $size )
{
    $value = htmlentities ( $value );
    return "<input type=\"text\" size=\"$size\" value=\"$value\" name=\"$flag\">";
}

/**
 * Return html code to create textarea form fields
 *
 * @param string $flag  name of form variable to set
 * @param string $value initial contents of textarea
 * @param string $rows  height of text area in rows
 * @param string $cols  width of text area in columns
 *
 * @return string html code for given textarea input field
 */
function textarea ( $flag, $value, $rows, $cols )
{
    $value = htmlentities ( $value );
    return "<textarea name=\"$flag\" rows=\"$rows\" cols=\"$cols\">"
            . $value . "</textarea>";
}

/**
 * Return html code to create select (menu) form fields
 *
 * Use array of strings as menu choices
 *
 * @param string $flag    name of form variable to set
 * @param array  $options array of strings representing choices
 * @param string $value   value of choice to select in menu
 *
 * @return string html code for given select (menu) input field
 */
function menubox ( $name, $options, $value )
{
    $s="<select name=\"$name\">";

	foreach ( $options as $ignore => $option ) {
        if ( !$value ) $value = $option;
        $s .= "<option" . ( $option == $value ? " selected>" : ">" ) .
            htmlentities ( $option ) . "</option>";
    }
    return $s . "</select>";
}

/**
 * Return html code to create select (menu) form fields
 *
 * Use indices of array of strings as menu choices rather than
 * the values pointed to by the indicies.
 *
 * @param string $flag    name of form variable to set
 * @param array  $options array of strings representing choices
 * @param string $value   value of choice to select in menu
 *
 * @return string html code for given select (menu) input field
 */
function keys_menubox ( $name, $options, $value )
{
    $s="<select name=\"$name\">";

    foreach ( $options as $option => $ignore ) {
        if ( !$value ) $value = $option;
        $s .= "<option" . ( $option == $value ? " selected>" : ">" ) .
            htmlentities ( $option ) . "</option>";
    }
    return $s . "</select>";
}

////
// Flag (compile option) handling functions
////

/**
 * Return default compile options (flags)
 *
 * Initial compile options are in a global called $flag_table.
 * Create and return an array containing the ones we want.
 *
 * @return array default compile options (flags)
 */
function default_flags ()
{
    global $flag_table;

    $flags = array ();

    foreach ( $flag_table as $key => $props ) {

        $flag  = $props["flag"];
        $type  = $props["type"];

        // Fields like headers have no "value" property
        if ( isset ( $props["value"] ) ) {
            $flags[$flag] = $props["value"];
        }
    }
    return $flags;
}

/**
 * Return combination of default and user compile options (flags)
 *
 * Initial compile options are in a global called $flag_table.
 * Compile options may have been changed via form input. We return
 * an array with either the default value of each option or a user
 * supplied value from form input.
 *
 * @return array combined default and user supplied compile options (flags)
 */
function get_flags ()
{
    global $flag_table;

    $flags = default_flags ();

    if ( ! isset ( $_POST["use_flags"] ) )
        return $flags;

    foreach ( $flag_table as $key => $props ) {

        $flag = $props["flag"];
        $type = $props["type"];

        if ( isset ( $_POST["$flag"] ) ) {
            $flags[$flag] = $_POST["$flag"];
            if ( $type == "integer-hex" ) {
                if ( strtolower ( substr ( $flags[$flag], 0, 2 ) ) != "0x" ) {
                    $flags[$flag] = "0x" . $flags[$flag];
                }
            }
        } else if ( $type == "on/off" ) {
			// Unchecked checkboxes don't pass any POST value
			// so we must check for them specially.  At this
			// point we know that there is no $_POST value set
			// for this option.  If it is a checkbox, this means
			// it is unchecked, so record that in $flags so we
			// can later generate an #undef for this option.
            $flags[$flag] = "off";
        }
    }
    return $flags;
}

/**
 * Output given value in appropriate format for iPXE config file
 *
 * iPXE config/*.h files use C pre-processor syntax.  Output the given
 * compile option in a format appropriate to its type
 *
 * @param string $key   index into $flag_table for given compile option
 * @param string $value value we wish to set compile option to
 *
 * @return string code to set compile option to given value
 */
function pprint_flag ( $key, $value )
{
    global $flag_table;

    // Determine type of given compile option (flag)
    $type = $flag_table[$key]["type"];
    $s = "";

    if ( $type == "on/off" && $value == "on" ) {
        $s = "#define $key";
    } else if ( $type == "on/off" && $value != "on" ) {
        $s = "#undef $key";
    } else if ( $type == "string" ) {
        $s = ( "#define $key \"" . cleanstring ( $value ) . "\"" );
    } else if ($type == "qstring" ) {
        $s = ( "#define $key \\\"" . cleanstring ( $value ) . "\\\"" );
    } else {
        $s = "#define $key " . cleanstring ( $value );
    }

    return $s;
}

/**
 * Output html code to display all compile options as a table
 *
 * @param array $flags array of compile options
 *
 * @return void
 */
function echo_flags ( $flags )
{
    global $flag_table;

    echo "<table>\n";

	foreach ( $flag_table as $key => $props ) {

        // Hide parameters from users that should not be changed.
        $hide_from_user = isset ( $props["hide_from_user"] ) ? $props["hide_from_user"] : "no";

        $flag = $props["flag"];
        $type = $props["type"];

        $value = isset ( $flags[$flag] ) ? $flags[$flag] : '';

        if ( $hide_from_user == "yes" ) {

            // Hidden flags cannot not be set by the user.  We use hidden form
            // fields to keep them at their default values.
            if ( $type != "header" ) {
                echo hidden ( $flag, $value );
            }

        } else {

            // Flag (iPXE compile option) should be displayed to user

            if ( $type == "header" ) {

                $label = $props["label"];
                echo "<td colspan=2><hr><h3>$label</h3><hr></td>";

            } else if ($type == "on/off" ) {

                echo "<td>", checkbox ( $flag, $value ), "</td><td><strong>$flag</strong></td>";

            } else {   // don't display checkbox for non-on/off flags

                echo "<td>&nbsp;</td><td><strong>$flag: </strong>";

                if ($type == "choice" ) {
                    $options = $props["options"];
                    echo menubox($flag, $options, $value);

                } else {

                    echo textbox($flag, $value, ($type == "integer" ||
                                                 $type == "integer-hex"
                                                     ? 7 : 25));
                }
                echo "</td>";
            }
            echo "</tr>\n";

            if ( $type != "header" ) {
				echo "<tr><td>&nbsp;</td>";
				echo "<td>\n";
				if ( is_file ( "doc/$flag.html" ) ) {
					include_once "doc/$flag.html";
				}
				echo "\n</td></tr>\n";
            }
        }
    }
    echo "</table>";
}

/**
 * Return an array of configuration sections used in all compile options
 *
 * $flag_table, the global list of compile options contains a 'cfgsec'
 * property for each flag we are interested in.  We return a list of
 * all the unique cfgsec options we find in $flag_table.
 *
 * @return array an array of strings representing all unique cfgsec values
 *               found in $flag_table
 */
function get_flag_cfgsecs ()
{
    global $flag_table;
    $cfgsecs = array ();

    foreach ( $flag_table as $key => $props ) {
        if ( isset ( $props['cfgsec'] ) ) {
            $cfgsec = $props["cfgsec"];
            $cfgsecs[$cfgsec] = $cfgsec;
        }
    }
    return $cfgsecs;
}

////
// File and directory handling functions
////

/**
 * Create a copy of a given source directory to a given destination
 *
 * Since we are going to modify the source directory, we create a copy
 * of the directory with a unique name in the given destination directory.
 * We supply a prefix for the tempnam call to prepend to the random filename
 * it generates.
 *
 * @param string $src    source directory
 * @param string $dst    destination directory
 * @param string $prefix string to append to directory created
 *
 * @return string absolute path to destination directory
 */
function mktempcopy ( $src, $dst, $prefix )
{
    if ( $src[0] != "/" ) {
        $src = dirname ( $_SERVER['SCRIPT_FILENAME'] ) . "/" . $src;
    }

    // Create a file in the given destination directory with a unique name
    $dir = tempnam ( $dst, $prefix );

    // Delete the file just created, since it would interfere with the copy we
    // are about to do.  We only care that the dir name we copy to is unique.
    unlink ( $dir );

    exec ( "/bin/cp -a '$src' '$dir' 2>&1", $cpytxt, $status );

    if ( $status != 0 ) {
        die ( "src directory copy failed!" );
    }
    return $dir;
}

/**
 * Write iPXE config files based on value of given flags
 *
 * iPXE compile options are stored in src/config/*.h .
 * We write out a config file for each set of options.
 *
 * @param string $config_dir directory to write .h files to
 * @param array  $flags array of compile options for this build
 *
 * @return void
 */
function write_ipxe_config_files ( $config_dir, $flags )
{
    global $flag_table;

    $cfgsecs = get_flag_cfgsecs ();

    foreach ( $cfgsecs as $cfgsec ) {

        $fname = $config_dir . "/" . $cfgsec . ".h";

        $fp = fopen ( $fname, "wb" );
        if ( $fp <= 0 ) {
            die ( "Unable to open $fname file for output!" );
        }

        $ifdef_secname = "CONFIG_" . strtoupper ( $cfgsec ) . "_H";

        fwrite ( $fp, "#ifndef ${ifdef_secname}\n" );
        fwrite ( $fp, "#define ${ifdef_secname}\n" );
        fwrite ( $fp, "#include <config/defaults.h>\n" );

        foreach ( $flags as $key => $value ) {
            // When the flag matches this section name, write it out
            if ( $flag_table[$key]["cfgsec"] == $cfgsec ) {
                fwrite ( $fp, pprint_flag ( $key, $value ) . "\n" );
            }
        }
        fwrite ( $fp, "#endif /* ${ifdef_secname} */\n" );
        fclose ( $fp );
    }
}

/**
 * Output a string to a file
 *
 * Output a given string to a given pathname. The file will be created if
 * necessary, and the string will replace the file's contents in all cases.
 *
 * @param string $fname pathname of file to output string to
 * @param string $ftext text to output to file
 *
 * @return void
 */
function write_file_from_string ( $fname, $ftext )
{
        $fp = fopen ( $fname, "wb" );
        if ( ! $fp ) {
            die ( "Unable to open $fname file for output!" );
        }
        fwrite ( $fp, $ftext );
        fclose ( $fp );
}

/**
 * Delete a file or recursively delete a directory tree
 *
 * @param   string   $file_or_dir_name  name of file or directory to delete
 * @return  bool     Returns TRUE on success, FALSE on failure
 */
function rm_file_or_dir ( $file_or_dir_name )
{
    if ( ! file_exists ( $file_or_dir_name ) ) {
        return false;
    }

    if ( is_file ( $file_or_dir_name ) || is_link ( $file_or_dir_name ) ) {
        return unlink ( $file_or_dir_name );
    }

    $dir = dir ( $file_or_dir_name );
    while ( ( $dir_entry = $dir->read () ) !== false ) {

        if ( $dir_entry == '.' || $dir_entry == '..') {
            continue;
        }
        rm_file_or_dir ( $file_or_dir_name . '/' . $dir_entry );
    }
    $dir->close();

    return rmdir ( $file_or_dir_name );
}

////
// Debugging functions
////

/**
 * Emit html code to display given array of compile options (flags)
 *
 * @param array  $flags array of compile options for this build
 *
 * @return void
 */
function show_flags ( $flags )
{
    echo ( "\$flags contains " . count ( $flags ) . " elements:" . "<br>" );

	foreach ( $flags as $key => $flag ) {
        echo ( "\$flags[" . $key . "]=" . "\"$flag\"" . "<br>" );
    }
}

/**
 * Emit HTML code to display default array of compile options (flags)
 *
 * $flag_table contains default compile options and properties.  This
 * routine outputs HTML code to display all properties of $flag_table.
 *
 * @return void
 */
function dump_flag_table ()
{
    global $flag_table;

    echo ( "\$flag_table contains " . count ( $flag_table ) . " elements:" . "<br>" );

	foreach ( $flag_table as $key => $props ) {
        print ( "flag_table[" . $key . "] = " . "<br>" );

		foreach ( $props as $key2 => $props2 ) {
            print ( "&nbsp;&nbsp;&nbsp;" . $key2 . " = " . $props2 . "<br>" );
        }
    }
}

// Parse src/bin/NIC file
list ( $nics, $roms ) = parse_nic_file ();

// For emacs:
// Local variables:
//  c-basic-offset: 4
//  c-indent-level: 4
//  tab-width: 4
// End:

?>
