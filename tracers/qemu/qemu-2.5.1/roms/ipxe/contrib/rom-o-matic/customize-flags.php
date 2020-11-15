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

// Prepare settable compile options for presentation to user
$flags = default_flags ();

$build = "<input type=\"submit\" name=\"A\" value=\"Get Image\">";
$restart = "<input type=\"submit\" name=\"A\" value=\"Start Over\">";

// Begin html output
include_once $top_inc;

?>

<form action="build.php" method=POST>
  <input type="hidden" name="version" value = "<?php echo $version ?>">
  <input type="hidden" name="use_flags" value="1">
  <h3>
    Make changes below and press <?php echo $build ?> to create an image, <br>
    Or press <?php echo $restart ?> to return to the main page.
  </h3>
  <hr>
  <ul>
  <?php require ( "directions.php" ); ?>
  </ul>
  <hr>
  <?php echo_flags( $flags ); ?>
  <hr>
  <h3>Embedded Script:</h3>
  <?php echo textarea ( "embedded_script", "", "10", "50" ); ?>
  <br><br>
  <hr>
  <center><table width="35%"><tr>
  <td align="left"> <?php echo $build; ?> </td>
  <td align="right"> <?php echo $restart ?></td>
  </tr></table></center>
</form>

<?php include_once $bottom_inc; ?>
<?
// For emacs:
//
// Local variables:
//  c-basic-offset: 4
//  c-indent-level: 4
//  tab-width: 4
// End:
?>
