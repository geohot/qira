<?php

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

?>
    <li>
      Choose an output format: <?php echo keys_menubox ( "ofmt", $ofmts,
      isset ( $_POST['ofmt'] ) ? $_POST['ofmt'] : "") ?>
      <br><br>
    </li>
    <li>
      Choose a NIC type: <?php echo keys_menubox ( "nic", $nics,
      isset ( $_POST['nic'] ) ? $_POST['nic'] : "" ) ?>
      <br><br>
    </li>
    <li>
      <strong>( optional &mdash; for binary ROM image format only )</strong> <br><br>
      If you choose <em>Binary ROM image</em> as your output format, you must<br>
      enter <strong>4 hex digits</strong> below for
      <em>PCI VENDOR CODE</em> and <em>PCI DEVICE CODE</em>  <br>
      that match the NIC device for which you are making this image.<br><br>
      Information on how to determine NIC PCI IDs may be found
      <a href="http://www.ipxe.org/howto/romburning"
      target="_blank">here</a>.
      <br><br>
      PCI VENDOR CODE:  <?php echo textbox ( "pci_vendor_code",
      isset ( $_POST['pci_vendor_code'] ) ? $_POST['pci_vendor_code']
              : "", 6 ); ?>
      &nbsp;&nbsp;
      PCI DEVICE CODE:  <?php echo textbox ( "pci_device_code",
      isset ( $_POST['pci_device_code'] ) ? $_POST['pci_device_code']
              : "", 6 ); ?>
      <h4>Please note for ROM images:</h4>
      <ul>
        <li>
          If you enter PCI IDs, we will attempt to determine the correct<br>
          driver to support them, and will ignore any NIC type entered
          above.<br><br>
        </li>
        <li>
          iPXE does not support all possible PCI IDs for supported
          NICs.
          <br><br>
        </li>
      </ul>
    </li>
