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

// Get utility functions and set globals
require_once "utils.php";

// Make sure at least $A (action)  was supplied
if ( ! isset ( $_POST['A'] ) ) {

    // Present user with form to customize build options
    require_once "customize-flags.php";

    exit ();

// If user chose "Customize" option on form
} else if ( $_POST['A'] == "Customize" ) {

    // Present user with form to customize build options
    require_once "customize-flags.php";

    exit ();

// The following conditional includes all other cases except "Get Image"
// particularly the explicit ($A == "Start Over") case
} else if ( $_POST['A'] != "Get Image" ) {

    // Note that this method of redirections discards all the
    // configuration flags, which is intentional in this case.

    $dest = curDirURL ();
    header ( "Location: $dest" );

    // This next "echo" should normally not be seen, because
    // the "header" statement above should cause immediate
    // redirection but just in case...

    echo "Try this link: <a href=\"$dest\">$dest</a>";

    exit ();
}

// OK, we're going to try to use whatever options have been set
// to build an image.

// Make sure at least $nic was supplied
if ( ! isset ( $_POST['nic'] ) ) {
    die ( "No NIC supplied!" );
}
if ( isset ( $nics[$_POST['nic']] ) ) {
    $nic = $nics[$_POST['nic']];
} else {
    die ( "Invalid NIC \"${_POST['nic']}\" supplied!" );
}

// Fetch flags
$flags = get_flags ();

// Get requested format
$ofmt = isset ( $_POST['ofmt'] ) ? $_POST['ofmt'] : "";
$fmt_extension = isset ( $ofmts[$ofmt] ) ? $ofmts[$ofmt] : 'dsk';

// Handle some special cases

$pci_vendor_code = "";
$pci_device_code = "";

if ( $nic == 'undionly' && $fmt_extension == "pxe" ) {

    // undionly.pxe can't work because it unloads the PXE stack
    // that it needs to communicate with, so we set the extension
    // to .kpxe, which has a chance of working. The extension
    // .kkpxe is another option.

    $fmt_extension = "kpxe";

} else if ( $fmt_extension == "rom" ) {

    if ( ! isset ( $_POST['pci_vendor_code'] )
		 || ! isset ( $_POST['pci_device_code'] ) ) {
		die ( "rom output format selected but PCI code(s) missing!" );
	}

	$pci_vendor_code = $_POST['pci_vendor_code'];
	$pci_device_code = $_POST['pci_device_code'];

    if ( $pci_vendor_code == ""
		 || $pci_device_code == "" ) {
		die ( "rom output format selected but PCI code(s) missing!" );
	}

	// Try to be forgiving of 0xAAAA format
	if ( strtolower ( substr ( $pci_vendor_code, 0, 2 ) ) == "0x"
		 && strlen ( $pci_vendor_code ) == 6 ) {
		$pci_vendor_code = substr ( $pci_vendor_code, 2, 4 );
	}
	if ( strtolower ( substr ( $pci_device_code, 0, 2 ) ) == "0x"
		 && strlen ( $pci_device_code ) == 6 ) {
		$pci_device_code = substr ( $pci_device_code, 2, 4 );
	}

    // concatenate the pci codes to get the $nic part of the
    // Make target
    $pci_codes = strtolower (  $pci_vendor_code . $pci_device_code );

    $nic = $pci_codes;
    if ( ! isset ( $roms[$pci_codes] ) ) {
        die (   "Sorry, no network driver supports PCI codes<br>"
              . "${_POST['pci_vendor_code']}:"
              . "${_POST['pci_device_code']}" );
    }
} else if ( $fmt_extension != "rom"
            && ( $pci_vendor_code != "" || $pci_device_code != "" ) ) {
    die (   "'$fmt_extension' format was selected but PCI IDs were"
          . " also entered.<br>Did you mean to select 'rom' output format"
          . " instead?" );
}

/**
 * remove temporary build directory
 *
 * @return bool true if removal is successful, false otherwise
 */
function rm_build_dir ()
{
    global $build_dir;
    global $keep_build_dir;

    if ( $keep_build_dir !== true ) {
        rm_file_or_dir ( $build_dir );
    }
}

// Arrange for the build directory to always be removed on exit.
$build_dir = "";
$keep_build_dir = false;
register_shutdown_function ( 'rm_build_dir' );

// Make temporary copy of src directory
$build_dir = mktempcopy ( "$src_dir", "/tmp", "MDCROM" );
$config_dir = $build_dir . "/config";

// Write config files with supplied flags
write_ipxe_config_files ( $config_dir, $flags );

// Handle a possible embedded script
$emb_script_cmd = "";
$embedded_script = isset ( $_POST['embedded_script'] ) ? $_POST['embedded_script'] : "";
if ( $embedded_script != "" ) {
    $emb_script_path = "$build_dir" . "/script0.ipxe";

	if ( substr ( $embedded_script, 0, 5 ) != "#!ipxe" ) {
		$embedded_script = "#!ipxe\n" . $embedded_script;
	}

    // iPXE 0.9.7 doesn't like '\r\n" in the shebang...
    $embedded_script = str_replace ( "\r\n", "\n", $embedded_script );

    write_file_from_string ( $emb_script_path, $embedded_script );
    $emb_script_cmd = "EMBEDDED_IMAGE=${emb_script_path}";
}

// Make the requested image.  $status is set to 0 on success
$make_target = "bin/${nic}.${fmt_extension}";
$gitversion = exec('git describe --always --abbrev=1 --match "" 2>/dev/null');
if ($gitversion) {
	$gitversion = "GITVERSION=$gitversion";
}

$make_cmd = "make -C '$build_dir' '$make_target' $gitversion $emb_script_cmd 2>&1";

exec ( $make_cmd, $maketxt, $status );

// Uncomment the following section for debugging

/**

echo "<h2>build.php:</h2>";
echo "<h3>Begin debugging output</h3>";

//echo "<h3>\$_POST variables</h3>";
//echo "<pre>"; var_dump ( $_POST ); echo "</pre>";

echo "<h3>Build options:</h3>";
echo "<strong>Build directory is:</strong> $build_dir" . "<br><br>";
echo "\$_POST['ofmt'] = " . "\"${_POST['ofmt']}\"" . "<br>";
echo "\$_POST['nic'] = " . "\"${_POST['nic']}\"" .  "<br>";
echo "\$_POST['pci_vendor_code'] = " . "\"${_POST['pci_vendor_code']}\"" . "<br>";
echo "\$_POST['pci_device_code'] = " . "\"${_POST['pci_device_code']}\"" . "<br>";

echo "<h3>Flags:</h3>";
show_flags ( $flags );

if ( $embedded_script != "" ) {
    echo "<h3>Embedded script:</h3>";
    echo "<blockquote>"."<pre>";
    echo $embedded_script;
    echo "</pre>"."</blockquote>";
}

echo "<h3>Make output:</h3>";
echo "Make command: " . $make_cmd . "<br>";
echo "Build status = <? echo $status ?>" . "<br>";
echo "<blockquote>"."<pre>";
echo htmlentities ( implode ("\n", $maketxt ) );
echo "</pre>"."</blockquote>";
// Uncomment the next line if you want to keep the
// build directory around for inspection after building.
$keep_build_dir = true;
die ( "<h3>End debugging output</h3>" );

**/ //   End debugging section

// Send ROM to browser (with extreme prejudice)

if ( $status == 0 ) {

    $fp = fopen("${build_dir}/${make_target}", "rb" );
    if ( $fp > 0 ) {

        $len = filesize ( "${build_dir}/${make_target}" );
        if ( $len > 0 ) {

            $buf = fread ( $fp, $len );
            fclose ( $fp );

            // Delete build directory as soon as it is not needed
            rm_build_dir ();

            $output_filename = preg_replace('/[^a-z0-9\+\.\-]/i', '', "ipxe-${version}-${nic}.${fmt_extension}");

            // Try to force IE to handle downloading right.
            Header ( "Cache-control: private");
            Header ( "Content-Type: application/x-octet-stream; " .
                     "name=$output_filename");
            Header ( "Content-Disposition: attachment; " .
                     "Filename=$output_filename");
            Header ( "Content-Location: $output_filename");
            Header ( "Content-Length: $len");

            echo $buf;

            exit ();
        }
    }
}

/*
 * If we reach this point, the build has failed, and we provide
 * debugging information for a potential bug report
 *
 */

// Remove build directory
rm_build_dir ();

// Announce failure if $status from make was non-zero
echo "<h2>Build failed.  Status = " . $status . "</h2>";
echo "<h2>build.php:</h2>";
echo "<h3>Build options:</h3>";
echo "<strong>Build directory is:</strong> $build_dir" . "<br><br>";
echo "\$_POST['ofmt'] = " . "\"${_POST['ofmt']}\"" . "<br>";
echo "\$_POST['nic'] = " . "\"${_POST['nic']}\"" .  "<br>";
echo "\$_POST['pci_vendor_code'] = " . "\"${_POST['pci_vendor_code']}\"" . "<br>";
echo "\$_POST['pci_device_code'] = " . "\"${_POST['pci_device_code']}\"" . "<br>";

echo "<h3>Flags:</h3>";
show_flags ( $flags );

if ( $embedded_script != "" ) {
    echo "<h3>Embedded script:</h3>";
    echo "<blockquote>"."<pre>";
    echo $embedded_script;
    echo "</pre>"."</blockquote>";
}

echo "<h3>Make output:</h3>";
echo "Make command: " . $make_cmd . "<br>";
echo "<blockquote>"."<pre>";
echo htmlentities ( implode ("\n", $maketxt ) );
echo "</pre>"."</blockquote>";

echo "Please let us know that this happened, and paste the above output into your email message.<br>";

include_once $bottom_inc;

// For emacs:
//  Local variables:
//  c-basic-offset: 4
//  c-indent-level: 4
//  tab-width: 4
//  End:

?>
