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

// Begin html output
include_once $top_inc;

?>
<form action="build.php" method=POST>
  <input type="hidden" name="version" value = "<?php echo $version ?>">
  <h3>To create an image:</h3>
  <ol>
    <?php require ( "directions.php" ); ?>
    <li>
      Generate and download an image:
      <input type="submit" name="A" value="Get Image">
      <br><br>
    </li>
    <li>
      (optional) Customize image configuration options:
      <input type="submit" name="A" value="Customize">
      <br><br>
    </li>
  </ol>
</form>

<?php include_once $bottom_inc ?>
