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

// Directory containing iPXE source code tree
$src_dir = "../../src";

// Compute iPXE version based on source tree
exec ( "make -C '$src_dir' version 2>&1", $make_output, $status );
$version = ( $status == 0 && count ( $make_output  ) > 1 )
           ? trim ( $make_output[count ( $make_output ) - 2] )
           : "";

// Email address of person responsible for this website
$webmaster_email = "webmaster@example.com";

// Files that header and footer text
$top_inc = "top.php";
$bottom_inc = "bottom.php";

// Descriptive strings
$header_title = "ROM-o-matic for iPXE $version";
$html_tagline = "ROM-o-matic dynamically generates iPXE images";
$html_title   = "ROM-o-matic for iPXE $version";
$description  = "a dynamic iPXE image generator";

// For emacs:
// Local variables:
//  c-basic-offset: 4
//  c-indent-level: 4
//  tab-width: 4
// End:

?>
