#!/usr/bin/env perl
#
# Generates list of supported NICs with PCI vendor/device IDs, driver name
# and other useful things.
#
# Initial version by Robin Smidsrød <robin@smidsrod.no>
#

use strict;
use warnings;
use autodie;
use v5.10;

use File::stat;
use File::Basename qw(basename);
use File::Find ();
use Getopt::Long qw(GetOptions);

GetOptions(
    'help'       => \( my $help     = 0      ),
    'format=s'   => \( my $format   = 'text' ),
    'sort=s'     => \( my $sort     = 'bus,ipxe_driver,ipxe_name' ),
    'columns=s'  => \( my $columns  = 'bus,vendor_id,device_id,'
                                    . 'vendor_name,device_name,ipxe_driver,'
                                    . 'ipxe_name,ipxe_description,file,legacy_api'
                     ),
    'pci-url=s'  => \( my $pci_url  = 'http://pciids.sourceforge.net/v2.2/pci.ids' ),
    'pci-file=s' => \( my $pci_file = '/tmp/pci.ids' ),
    'output=s'   => \( my $output   = '' ),
);

die(<<"EOM") if $help;
Usage: $0 [options] [<directory>]

Options:
    --help     This page
    --format   Set output format
    --sort     Set output sort order (comma-separated)
    --columns  Set output columns (comma-separated)
    --pci-url  URL to pci.ids file
    --pci-file Cache file for downloaded pci.ids
    --output   Output file (not specified is STDOUT)

Output formats:
    text, csv, json, html, dokuwiki

Column names (default order):
    bus, vendor_id, device_id, vendor_name, device_name,
    ipxe_driver, ipxe_name, ipxe_description, file, legacy_api
EOM

# Only load runtime requirements if actually in use
given($format) {
    when( /csv/  ) {
                       eval { require Text::CSV; };
                       die("Please install Text::CSV CPAN module to use this feature.\n")
                           if $@;
                   }
    when( /json/ ) {
                       eval { require JSON; };
                       die("Please install JSON CPAN module to use this feature.\n")
                           if $@;
                   }
    when( /html/ ) {
                       eval { require HTML::Entities; };
                       die("Please install HTML::Entities CPAN module to use this feature.\n")
                           if $@;
                   }
    default        { }
}

# Scan source dir and build NIC list
my $ipxe_src_dir = shift || '.'; # Default to current directory
my $ipxe_nic_list = build_ipxe_nic_list( $ipxe_src_dir );

# Download pci.ids file and parse it
fetch_pci_ids_file($pci_url, $pci_file);
my $pci_id_map = build_pci_id_map($pci_file);

# Merge 'official' vendor/device names and sort list
update_ipxe_nic_names($ipxe_nic_list, $pci_id_map);
my $sorted_list = sort_ipxe_nic_list($ipxe_nic_list, $sort);

# Run specified formatter
my $column_names = parse_columns_param($columns);
say STDERR "Formatting NIC list in format '$format' with columns: "
         . join(", ", @$column_names);
my $formatter = \&{ "format_nic_list_$format" };
my $report = $formatter->( $sorted_list, $column_names );

# Print final report
if ( $output and $output ne '-' ) {
    say STDERR "Printing report to '$output'...";
    open( my $out_fh, ">", $output );
    print $out_fh $report;
    close($out_fh);
}
else {
    print STDOUT $report;
}

exit;

# fetch URL into specified filename
sub fetch_pci_ids_file {
    my ($url, $filename) = @_;
    my @cmd = ( "wget", "--quiet", "-O", $filename, $url );
    my @touch = ( "touch", $filename );
    if ( -r $filename ) {
        my $age = time - stat($filename)->mtime;
        # Refresh if older than 1 day
        if ( $age > 86400 ) {
            say STDERR "Refreshing $filename from $url...";
            system(@cmd);
            system(@touch);
        }
    }
    else {
        say STDERR "Fetching $url into $filename...";
        system(@cmd);
        system(@touch);
    }
    return $filename;
}

sub build_pci_id_map {
    my ($filename) = @_;
    say STDERR "Building PCI ID map...";

    my $devices = {};
    my $classes = {};
    my $pci_id = qr/[[:xdigit:]]{4}/;
    my $c_id = qr/[[:xdigit:]]{2}/;
    my $non_space = qr/[^\s]/;

    # open pci.ids file specified
    open( my $fh, "<", $filename );

    # For devices
    my $vendor_id = "";
    my $vendor_name = "";
    my $device_id = "";
    my $device_name = "";

    # For classes
    my $class_id = "";
    my $class_name = "";
    my $subclass_id = "";
    my $subclass_name = "";

    while(<$fh>) {
        # skip # and blank lines
        next if m/^$/;
        next if m/^\s*#/;

        # Vendors, devices and subsystems. Please keep sorted.
        # Syntax:
        # vendor  vendor_name
        #   device  device_name             <-- single tab
        #       subvendor subdevice  subsystem_name <-- two tabs
        if ( m/^ ($pci_id) \s+ ( $non_space .* ) /x ) {
            $vendor_id = lc $1;
            $vendor_name = $2;
            $devices->{$vendor_id} = { name => $vendor_name };
            next;
        }

        if ( $vendor_id and m/^ \t ($pci_id) \s+ ( $non_space .* ) /x ) {
            $device_id = lc $1;
            $device_name = $2;
            $devices->{$vendor_id}->{'devices'} //= {};
            $devices->{$vendor_id}->{'devices'}->{$device_id} = { name => $device_name };
            next;
        }

        if ( $vendor_id and $device_id and m/^ \t{2} ($pci_id) \s+ ($pci_id) \s+ ( $non_space .* ) /x ) {
            my $subvendor_id = lc $1;
            my $subdevice_id = lc $2;
            my $subsystem_name = $3;
            $devices->{$vendor_id}->{'devices'}->{$device_id}->{'subvendor'} //= {};
            $devices->{$vendor_id}->{'devices'}->{$device_id}->{'subvendor'}->{$subvendor_id} //= {};
            $devices->{$vendor_id}->{'devices'}->{$device_id}->{'subvendor'}->{$subvendor_id}->{'devices'} //= {};
            $devices->{$vendor_id}->{'devices'}->{$device_id}->{'subvendor'}->{$subvendor_id}->{'devices'}->{$subdevice_id} = { name => $subsystem_name };
            next;
        }

        # List of known device classes, subclasses and programming interfaces
        # Syntax:
        # C class   class_name
        #   subclass    subclass_name       <-- single tab
        #       prog-if  prog-if_name   <-- two tabs
        if ( m/^C \s+ ($c_id) \s+ ( $non_space .* ) /x ) {
            $class_id = lc $1;
            $class_name = $2;
            $classes->{$class_id} = { name => $class_name };
            next;
        }

        if ( $class_id and m/^ \t ($c_id) \s+ ( $non_space .* ) /x ) {
            $subclass_id = lc $1;
            $subclass_name = $2;
            $classes->{$class_id}->{'subclasses'} //= {};
            $classes->{$class_id}->{'subclasses'}->{$subclass_id} = { name => $subclass_name };
            next;
        }

        if ( $class_id and $subclass_id and m/^ \t{2} ($c_id) \s+ ( $non_space .* )  /x ) {
            my $prog_if_id = lc $1;
            my $prog_if_name = $2;
            $classes->{$class_id}->{'subclasses'}->{$subclass_id}->{'programming_interfaces'} //= {};
            $classes->{$class_id}->{'subclasses'}->{$subclass_id}->{'programming_interfaces'}->{$prog_if_id} = { name => $prog_if_name };
            next;
        }
    }

    close($fh);

    # Populate subvendor names
    foreach my $vendor_id ( keys %$devices ) {
        my $device_map = $devices->{$vendor_id}->{'devices'};
        foreach my $device_id ( keys %$device_map ) {
            my $subvendor_map = $device_map->{$device_id}->{'subvendor'};
            foreach my $subvendor_id ( keys %$subvendor_map ) {
                $subvendor_map->{$subvendor_id}->{'name'} = $devices->{$subvendor_id}->{'name'} || "";
            }
        }
    }

    return {
        'devices' => $devices,
        'classes' => $classes,
    };
}

# Scan through C code and parse ISA_ROM and PCI_ROM lines
sub build_ipxe_nic_list {
    my ($dir) = @_;
    say STDERR "Building iPXE NIC list from " . ( $dir eq '.' ? 'current directory' : $dir ) . "...";

    # recursively iterate through dir and find .c files
    my @c_files;
    File::Find::find(sub {
        # only process files
        return if -d $_;
        # skip unreadable files
        return unless -r $_;
        # skip all but files with .c extension
        return unless /\.c$/;
        push @c_files, $File::Find::name;
    }, $dir);

    # Look for ISA_ROM or PCI_ROM lines
    my $ipxe_nic_list = [];
    my $hex_id = qr/0 x [[:xdigit:]]{4} /x;
    my $quote = qr/ ['"] /x;
    my $non_space = qr/ [^\s] /x;
    my $rom_line_counter = 0;
    foreach my $c_path ( sort @c_files ) {
        my $legacy = 0;
        open( my $fh, "<", $c_path );
        my $c_file = $c_path;
        $c_file =~ s{^\Q$dir\E/?}{} if -d $dir; # Strip directory from reported filename
        my $ipxe_driver = basename($c_file, '.c');
        while(<$fh>) {
            # Most likely EtherBoot legacy API
            $legacy = 1 if m/struct \s* nic \s*/x;

            # parse ISA|PCI_ROM lines into hashref and append to $ipxe_nic_list
            next unless m/^ \s* (?:ISA|PCI)_ROM /x;
            $rom_line_counter++;
            chomp;
            #say; # for debugging regexp
            if ( m/^ \s* ISA_ROM \s* \( \s* $quote ( .*? ) $quote \s* , \s* $quote ( .*? ) $quote \s* \) /x ) {
                my $image = $1;
                my $name = $2;
                push @$ipxe_nic_list, {
                    file             => $c_file,
                    bus              => 'isa',
                    ipxe_driver      => $ipxe_driver,
                    ipxe_name        => $image,
                    ipxe_description => $name,
                    legacy_api       => ( $legacy ? 'yes' : 'no' ),
                };
                next;
            }
            if ( m/^ \s* PCI_ROM \s* \( \s* ($hex_id) \s* , \s* ($hex_id) \s* , \s* $quote (.*?) $quote \s* , \s* $quote (.*?) $quote /x ) {
                my $vendor_id = lc $1;
                my $device_id = lc $2;
                my $name = $3;
                my $desc = $4;
                push @$ipxe_nic_list, {
                    file             => $c_file,
                    bus              => 'pci',
                    vendor_id        => substr($vendor_id, 2), # strip 0x
                    device_id        => substr($device_id, 2), # strip 0x
                    ipxe_driver      => $ipxe_driver,
                    ipxe_name        => $name,
                    ipxe_description => $desc,
                    legacy_api       => ( $legacy ? 'yes' : 'no' ),
                };
                next;
            }
        }
        close($fh);
    }

    # Verify all ROM lines where parsed properly
    my @isa_roms = grep { $_->{'bus'} eq 'isa' } @$ipxe_nic_list;
    my @pci_roms = grep { $_->{'bus'} eq 'pci' } @$ipxe_nic_list;
    if ( $rom_line_counter != ( @isa_roms + @pci_roms ) ) {
        say STDERR "Found ROM lines: $rom_line_counter";
        say STDERR "Extracted ISA_ROM lines: " . scalar @isa_roms;
        say STDERR "Extracted PCI_ROM lines: " . scalar @pci_roms;
        die("Mismatch between number of ISA_ROM/PCI_ROM lines and extracted entries. Verify regular expressions.\n");
    }

    return $ipxe_nic_list;
}

# merge vendor/product name from $pci_id_map into $ipxe_nic_list
sub update_ipxe_nic_names {
    my ($ipxe_nic_list, $pci_id_map) = @_;
    say STDERR "Merging 'official' vendor/device names...";

    foreach my $nic ( @$ipxe_nic_list ) {
        next unless $nic->{'bus'} eq 'pci';
        $nic->{'vendor_name'} = $pci_id_map->{'devices'}->{ $nic->{'vendor_id'} }->{'name'} || "";
        $nic->{'device_name'} = $pci_id_map->{'devices'}->{ $nic->{'vendor_id'} }->{'devices'}->{ $nic->{'device_id'} }->{'name'} || "";
    }
    return $ipxe_nic_list; # Redundant, as we're mutating the input list, useful for chaining calls
}

# Sort entries in NIC list according to sort criteria
sub sort_ipxe_nic_list {
    my ($ipxe_nic_list, $sort_column_names) = @_;
    my @sort_column_names = @{ parse_columns_param($sort_column_names) };
    say STDERR "Sorting NIC list by: " . join(", ", @sort_column_names );
    # Start at the end of the list and resort until list is exhausted
    my @sorted_list = @{ $ipxe_nic_list };
    while(@sort_column_names) {
        my $column_name = pop @sort_column_names;
        @sorted_list = sort { ( $a->{$column_name} || "" ) cmp ( $b->{$column_name} || "" ) }
                       @sorted_list;
    }
    return \@sorted_list;
}

# Parse comma-separated values into array
sub parse_columns_param {
    my ($columns) = @_;
    return [
        grep { is_valid_column($_) } # only include valid entries
        map  { s/\s//g; $_; }        # filter whitespace
        split( /,/, $columns )       # split on comma
    ];
}

# Return true if the input column name is valid
sub is_valid_column {
    my ($name) = @_;
    my $valid_column_map = {
        map { $_ => 1 }
        qw(
           bus file legacy_api
           ipxe_driver ipxe_name ipxe_description
           vendor_id device_id vendor_name device_name
        )
    };
    return unless $name;
    return unless $valid_column_map->{$name};
    return 1;
}

# Output NIC list in plain text
sub format_nic_list_text {
    my ($nic_list, $column_names) = @_;
    return join("\n",
        map { format_nic_text($_, $column_names) }
        @$nic_list
    );
}

# Format one ipxe_nic_list entry for display
# Column order not supported by text format
sub format_nic_text {
    my ($nic, $column_names) = @_;
    my $labels = {
        bus              => 'Bus:             ',
        ipxe_driver      => 'iPXE driver:     ',
        ipxe_name        => 'iPXE name:       ',
        ipxe_description => 'iPXE description:',
        file             => 'Source file:     ',
        legacy_api       => 'Using legacy API:',
        vendor_id        => 'PCI vendor ID:   ',
        device_id        => 'PCI device ID:   ',
        vendor_name      => 'Vendor name:     ',
        device_name      => 'Device name:     ',
    };
    my $pci_only = {
        vendor_id   => 1,
        device_id   => 1,
        vendor_name => 1,
        device_name => 1,
    };
    my $output = "";
    foreach my $column ( @$column_names ) {
        next if $nic->{'bus'} eq 'isa' and $pci_only->{$column};
        $output .= $labels->{$column}
                .  " "
                . ( $nic->{$column} || "" )
                . "\n";
    }
    return $output;
}

# Output NIC list in JSON
sub format_nic_list_json {
    my ($nic_list, $column_names) = @_;

    # Filter columns not mentioned
    my @nics;
    foreach my $nic ( @$nic_list ) {
        my $filtered_nic = {};
        foreach my $key ( @$column_names ) {
            $filtered_nic->{$key} = $nic->{$key};
        }
        push @nics, $filtered_nic;
    }

    return JSON->new->pretty->utf8->encode(\@nics);
}

# Output NIC list in CSV
sub format_nic_list_csv {
    my ($nic_list, $column_names) = @_;
    my @output;

    # Output CSV header
    my $csv = Text::CSV->new();
    if ( $csv->combine( @$column_names ) ) {
        push @output, $csv->string();
    }

    # Output CSV lines
    foreach my $nic ( @$nic_list ) {
        my @columns = @{ $nic }{ @$column_names };
        if ( $csv->combine( @columns ) ) {
            push @output, $csv->string();
        }
    }
    return join("\n", @output) . "\n";
}

# Output NIC list in HTML
sub format_nic_list_html {
    my ($nic_list, $column_names) = @_;
    my @output;

    push @output, <<'EOM';
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Network cards supported by iPXE</title>
<style>
table.tablesorter {
 border: thin solid black;
}

table.tablesorter thead {
 background-color: #EEE;
}

table.tablesorter thead th {
 font-weight: bold;
}

table.tablesorter tbody td {
 vertical-align: top;
 padding-left: 0.25em;
 padding-right: 0.25em;
 padding-bottom: 0.125em;
 white-space: nowrap;
}

table.tablesorter tbody tr.even {
 background-color: #eee;
}

table.tablesorter tbody tr.odd {
 background-color: #fff;
}
</style>
</head>
<body>
<h1>Network cards supported by iPXE</h1>
<table class="tablesorter">
<thead>
EOM

    # Output HTML header
    push @output, "<tr>"
                . join("",
                    map { "<th>" . HTML::Entities::encode($_) . "</th>" }
                    @$column_names
                  )
                . "</tr>";

    push @output, <<"EOM";
</thead>
<tbody>
EOM
    # Output HTML lines
    my $counter = 0;
    foreach my $nic ( @$nic_list ) {
        my @columns = @{ $nic }{ @$column_names }; # array slice from hashref, see perldoc perldata if confusing
        push @output, q!<tr class="! . ( $counter % 2 ? 'even' : 'odd' ) . q!">!
                    . join("",
                        map { "<td>" . HTML::Entities::encode( $_ || "" ) . "</td>" }
                        @columns
                      )
                    . "</tr>";
        $counter++;
    }

    push @output, <<'EOM';
</tbody>
</table>
<script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
<script>
/*
 *
 * TableSorter 2.0 - Client-side table sorting with ease!
 * Version 2.0.5b
 * @requires jQuery v1.2.3
 * From http://tablesorter.com/
 *
 * Copyright (c) 2007 Christian Bach
 * Examples and docs at: http://tablesorter.com
 * Dual licensed under the MIT and GPL licenses:
 * http://www.opensource.org/licenses/mit-license.php
 * http://www.gnu.org/licenses/gpl.html
 *
 */
(function($){$.extend({tablesorter:new
function(){var parsers=[],widgets=[];this.defaults={cssHeader:"header",cssAsc:"headerSortUp",cssDesc:"headerSortDown",cssChildRow:"expand-child",sortInitialOrder:"asc",sortMultiSortKey:"shiftKey",sortForce:null,sortAppend:null,sortLocaleCompare:true,textExtraction:"simple",parsers:{},widgets:[],widgetZebra:{css:["even","odd"]},headers:{},widthFixed:false,cancelSelection:true,sortList:[],headerList:[],dateFormat:"us",decimal:'/\.|\,/g',onRenderHeader:null,selectorHeaders:'thead th',debug:false};function benchmark(s,d){log(s+","+(new Date().getTime()-d.getTime())+"ms");}this.benchmark=benchmark;function log(s){if(typeof console!="undefined"&&typeof console.debug!="undefined"){console.log(s);}else{alert(s);}}function buildParserCache(table,$headers){if(table.config.debug){var parsersDebug="";}if(table.tBodies.length==0)return;var rows=table.tBodies[0].rows;if(rows[0]){var list=[],cells=rows[0].cells,l=cells.length;for(var i=0;i<l;i++){var p=false;if($.metadata&&($($headers[i]).metadata()&&$($headers[i]).metadata().sorter)){p=getParserById($($headers[i]).metadata().sorter);}else if((table.config.headers[i]&&table.config.headers[i].sorter)){p=getParserById(table.config.headers[i].sorter);}if(!p){p=detectParserForColumn(table,rows,-1,i);}if(table.config.debug){parsersDebug+="column:"+i+" parser:"+p.id+"\n";}list.push(p);}}if(table.config.debug){log(parsersDebug);}return list;};function detectParserForColumn(table,rows,rowIndex,cellIndex){var l=parsers.length,node=false,nodeValue=false,keepLooking=true;while(nodeValue==''&&keepLooking){rowIndex++;if(rows[rowIndex]){node=getNodeFromRowAndCellIndex(rows,rowIndex,cellIndex);nodeValue=trimAndGetNodeText(table.config,node);if(table.config.debug){log('Checking if value was empty on row:'+rowIndex);}}else{keepLooking=false;}}for(var i=1;i<l;i++){if(parsers[i].is(nodeValue,table,node)){return parsers[i];}}return parsers[0];}function getNodeFromRowAndCellIndex(rows,rowIndex,cellIndex){return rows[rowIndex].cells[cellIndex];}function trimAndGetNodeText(config,node){return $.trim(getElementText(config,node));}function getParserById(name){var l=parsers.length;for(var i=0;i<l;i++){if(parsers[i].id.toLowerCase()==name.toLowerCase()){return parsers[i];}}return false;}function buildCache(table){if(table.config.debug){var cacheTime=new Date();}var totalRows=(table.tBodies[0]&&table.tBodies[0].rows.length)||0,totalCells=(table.tBodies[0].rows[0]&&table.tBodies[0].rows[0].cells.length)||0,parsers=table.config.parsers,cache={row:[],normalized:[]};for(var i=0;i<totalRows;++i){var c=$(table.tBodies[0].rows[i]),cols=[];if(c.hasClass(table.config.cssChildRow)){cache.row[cache.row.length-1]=cache.row[cache.row.length-1].add(c);continue;}cache.row.push(c);for(var j=0;j<totalCells;++j){cols.push(parsers[j].format(getElementText(table.config,c[0].cells[j]),table,c[0].cells[j]));}cols.push(cache.normalized.length);cache.normalized.push(cols);cols=null;};if(table.config.debug){benchmark("Building cache for "+totalRows+" rows:",cacheTime);}return cache;};function getElementText(config,node){var text="";if(!node)return"";if(!config.supportsTextContent)config.supportsTextContent=node.textContent||false;if(config.textExtraction=="simple"){if(config.supportsTextContent){text=node.textContent;}else{if(node.childNodes[0]&&node.childNodes[0].hasChildNodes()){text=node.childNodes[0].innerHTML;}else{text=node.innerHTML;}}}else{if(typeof(config.textExtraction)=="function"){text=config.textExtraction(node);}else{text=$(node).text();}}return text;}function appendToTable(table,cache){if(table.config.debug){var appendTime=new Date()}var c=cache,r=c.row,n=c.normalized,totalRows=n.length,checkCell=(n[0].length-1),tableBody=$(table.tBodies[0]),rows=[];for(var i=0;i<totalRows;i++){var pos=n[i][checkCell];rows.push(r[pos]);if(!table.config.appender){var l=r[pos].length;for(var j=0;j<l;j++){tableBody[0].appendChild(r[pos][j]);}}}if(table.config.appender){table.config.appender(table,rows);}rows=null;if(table.config.debug){benchmark("Rebuilt table:",appendTime);}applyWidget(table);setTimeout(function(){$(table).trigger("sortEnd");},0);};function buildHeaders(table){if(table.config.debug){var time=new Date();}var meta=($.metadata)?true:false;var header_index=computeTableHeaderCellIndexes(table);$tableHeaders=$(table.config.selectorHeaders,table).each(function(index){this.column=header_index[this.parentNode.rowIndex+"-"+this.cellIndex];this.order=formatSortingOrder(table.config.sortInitialOrder);this.count=this.order;if(checkHeaderMetadata(this)||checkHeaderOptions(table,index))this.sortDisabled=true;if(checkHeaderOptionsSortingLocked(table,index))this.order=this.lockedOrder=checkHeaderOptionsSortingLocked(table,index);if(!this.sortDisabled){var $th=$(this).addClass(table.config.cssHeader);if(table.config.onRenderHeader)table.config.onRenderHeader.apply($th);}table.config.headerList[index]=this;});if(table.config.debug){benchmark("Built headers:",time);log($tableHeaders);}return $tableHeaders;};function computeTableHeaderCellIndexes(t){var matrix=[];var lookup={};var thead=t.getElementsByTagName('THEAD')[0];var trs=thead.getElementsByTagName('TR');for(var i=0;i<trs.length;i++){var cells=trs[i].cells;for(var j=0;j<cells.length;j++){var c=cells[j];var rowIndex=c.parentNode.rowIndex;var cellId=rowIndex+"-"+c.cellIndex;var rowSpan=c.rowSpan||1;var colSpan=c.colSpan||1
var firstAvailCol;if(typeof(matrix[rowIndex])=="undefined"){matrix[rowIndex]=[];}for(var k=0;k<matrix[rowIndex].length+1;k++){if(typeof(matrix[rowIndex][k])=="undefined"){firstAvailCol=k;break;}}lookup[cellId]=firstAvailCol;for(var k=rowIndex;k<rowIndex+rowSpan;k++){if(typeof(matrix[k])=="undefined"){matrix[k]=[];}var matrixrow=matrix[k];for(var l=firstAvailCol;l<firstAvailCol+colSpan;l++){matrixrow[l]="x";}}}}return lookup;}function checkCellColSpan(table,rows,row){var arr=[],r=table.tHead.rows,c=r[row].cells;for(var i=0;i<c.length;i++){var cell=c[i];if(cell.colSpan>1){arr=arr.concat(checkCellColSpan(table,headerArr,row++));}else{if(table.tHead.length==1||(cell.rowSpan>1||!r[row+1])){arr.push(cell);}}}return arr;};function checkHeaderMetadata(cell){if(($.metadata)&&($(cell).metadata().sorter===false)){return true;};return false;}function checkHeaderOptions(table,i){if((table.config.headers[i])&&(table.config.headers[i].sorter===false)){return true;};return false;}function checkHeaderOptionsSortingLocked(table,i){if((table.config.headers[i])&&(table.config.headers[i].lockedOrder))return table.config.headers[i].lockedOrder;return false;}function applyWidget(table){var c=table.config.widgets;var l=c.length;for(var i=0;i<l;i++){getWidgetById(c[i]).format(table);}}function getWidgetById(name){var l=widgets.length;for(var i=0;i<l;i++){if(widgets[i].id.toLowerCase()==name.toLowerCase()){return widgets[i];}}};function formatSortingOrder(v){if(typeof(v)!="Number"){return(v.toLowerCase()=="desc")?1:0;}else{return(v==1)?1:0;}}function isValueInArray(v,a){var l=a.length;for(var i=0;i<l;i++){if(a[i][0]==v){return true;}}return false;}function setHeadersCss(table,$headers,list,css){$headers.removeClass(css[0]).removeClass(css[1]);var h=[];$headers.each(function(offset){if(!this.sortDisabled){h[this.column]=$(this);}});var l=list.length;for(var i=0;i<l;i++){h[list[i][0]].addClass(css[list[i][1]]);}}function fixColumnWidth(table,$headers){var c=table.config;if(c.widthFixed){var colgroup=$('<colgroup>');$("tr:first td",table.tBodies[0]).each(function(){colgroup.append($('<col>').css('width',$(this).width()));});$(table).prepend(colgroup);};}function updateHeaderSortCount(table,sortList){var c=table.config,l=sortList.length;for(var i=0;i<l;i++){var s=sortList[i],o=c.headerList[s[0]];o.count=s[1];o.count++;}}function multisort(table,sortList,cache){if(table.config.debug){var sortTime=new Date();}var dynamicExp="var sortWrapper = function(a,b) {",l=sortList.length;for(var i=0;i<l;i++){var c=sortList[i][0];var order=sortList[i][1];var s=(table.config.parsers[c].type=="text")?((order==0)?makeSortFunction("text","asc",c):makeSortFunction("text","desc",c)):((order==0)?makeSortFunction("numeric","asc",c):makeSortFunction("numeric","desc",c));var e="e"+i;dynamicExp+="var "+e+" = "+s;dynamicExp+="if("+e+") { return "+e+"; } ";dynamicExp+="else { ";}var orgOrderCol=cache.normalized[0].length-1;dynamicExp+="return a["+orgOrderCol+"]-b["+orgOrderCol+"];";for(var i=0;i<l;i++){dynamicExp+="}; ";}dynamicExp+="return 0; ";dynamicExp+="}; ";if(table.config.debug){benchmark("Evaling expression:"+dynamicExp,new Date());}eval(dynamicExp);cache.normalized.sort(sortWrapper);if(table.config.debug){benchmark("Sorting on "+sortList.toString()+" and dir "+order+" time:",sortTime);}return cache;};function makeSortFunction(type,direction,index){var a="a["+index+"]",b="b["+index+"]";if(type=='text'&&direction=='asc'){return"("+a+" == "+b+" ? 0 : ("+a+" === null ? Number.POSITIVE_INFINITY : ("+b+" === null ? Number.NEGATIVE_INFINITY : ("+a+" < "+b+") ? -1 : 1 )));";}else if(type=='text'&&direction=='desc'){return"("+a+" == "+b+" ? 0 : ("+a+" === null ? Number.POSITIVE_INFINITY : ("+b+" === null ? Number.NEGATIVE_INFINITY : ("+b+" < "+a+") ? -1 : 1 )));";}else if(type=='numeric'&&direction=='asc'){return"("+a+" === null && "+b+" === null) ? 0 :("+a+" === null ? Number.POSITIVE_INFINITY : ("+b+" === null ? Number.NEGATIVE_INFINITY : "+a+" - "+b+"));";}else if(type=='numeric'&&direction=='desc'){return"("+a+" === null && "+b+" === null) ? 0 :("+a+" === null ? Number.POSITIVE_INFINITY : ("+b+" === null ? Number.NEGATIVE_INFINITY : "+b+" - "+a+"));";}};function makeSortText(i){return"((a["+i+"] < b["+i+"]) ? -1 : ((a["+i+"] > b["+i+"]) ? 1 : 0));";};function makeSortTextDesc(i){return"((b["+i+"] < a["+i+"]) ? -1 : ((b["+i+"] > a["+i+"]) ? 1 : 0));";};function makeSortNumeric(i){return"a["+i+"]-b["+i+"];";};function makeSortNumericDesc(i){return"b["+i+"]-a["+i+"];";};function sortText(a,b){if(table.config.sortLocaleCompare)return a.localeCompare(b);return((a<b)?-1:((a>b)?1:0));};function sortTextDesc(a,b){if(table.config.sortLocaleCompare)return b.localeCompare(a);return((b<a)?-1:((b>a)?1:0));};function sortNumeric(a,b){return a-b;};function sortNumericDesc(a,b){return b-a;};function getCachedSortType(parsers,i){return parsers[i].type;};this.construct=function(settings){return this.each(function(){if(!this.tHead||!this.tBodies)return;var $this,$document,$headers,cache,config,shiftDown=0,sortOrder;this.config={};config=$.extend(this.config,$.tablesorter.defaults,settings);$this=$(this);$.data(this,"tablesorter",config);$headers=buildHeaders(this);this.config.parsers=buildParserCache(this,$headers);cache=buildCache(this);var sortCSS=[config.cssDesc,config.cssAsc];fixColumnWidth(this);$headers.click(function(e){var totalRows=($this[0].tBodies[0]&&$this[0].tBodies[0].rows.length)||0;if(!this.sortDisabled&&totalRows>0){$this.trigger("sortStart");var $cell=$(this);var i=this.column;this.order=this.count++%2;if(this.lockedOrder)this.order=this.lockedOrder;if(!e[config.sortMultiSortKey]){config.sortList=[];if(config.sortForce!=null){var a=config.sortForce;for(var j=0;j<a.length;j++){if(a[j][0]!=i){config.sortList.push(a[j]);}}}config.sortList.push([i,this.order]);}else{if(isValueInArray(i,config.sortList)){for(var j=0;j<config.sortList.length;j++){var s=config.sortList[j],o=config.headerList[s[0]];if(s[0]==i){o.count=s[1];o.count++;s[1]=o.count%2;}}}else{config.sortList.push([i,this.order]);}};setTimeout(function(){setHeadersCss($this[0],$headers,config.sortList,sortCSS);appendToTable($this[0],multisort($this[0],config.sortList,cache));},1);return false;}}).mousedown(function(){if(config.cancelSelection){this.onselectstart=function(){return false};return false;}});$this.bind("update",function(){var me=this;setTimeout(function(){me.config.parsers=buildParserCache(me,$headers);cache=buildCache(me);},1);}).bind("updateCell",function(e,cell){var config=this.config;var pos=[(cell.parentNode.rowIndex-1),cell.cellIndex];cache.normalized[pos[0]][pos[1]]=config.parsers[pos[1]].format(getElementText(config,cell),cell);}).bind("sorton",function(e,list){$(this).trigger("sortStart");config.sortList=list;var sortList=config.sortList;updateHeaderSortCount(this,sortList);setHeadersCss(this,$headers,sortList,sortCSS);appendToTable(this,multisort(this,sortList,cache));}).bind("appendCache",function(){appendToTable(this,cache);}).bind("applyWidgetId",function(e,id){getWidgetById(id).format(this);}).bind("applyWidgets",function(){applyWidget(this);});if($.metadata&&($(this).metadata()&&$(this).metadata().sortlist)){config.sortList=$(this).metadata().sortlist;}if(config.sortList.length>0){$this.trigger("sorton",[config.sortList]);}applyWidget(this);});};this.addParser=function(parser){var l=parsers.length,a=true;for(var i=0;i<l;i++){if(parsers[i].id.toLowerCase()==parser.id.toLowerCase()){a=false;}}if(a){parsers.push(parser);};};this.addWidget=function(widget){widgets.push(widget);};this.formatFloat=function(s){var i=parseFloat(s);return(isNaN(i))?0:i;};this.formatInt=function(s){var i=parseInt(s);return(isNaN(i))?0:i;};this.isDigit=function(s,config){return/^[-+]?\d*$/.test($.trim(s.replace(/[,.']/g,'')));};this.clearTableBody=function(table){if($.browser.msie){function empty(){while(this.firstChild)this.removeChild(this.firstChild);}empty.apply(table.tBodies[0]);}else{table.tBodies[0].innerHTML="";}};}});$.fn.extend({tablesorter:$.tablesorter.construct});var ts=$.tablesorter;ts.addParser({id:"text",is:function(s){return true;},format:function(s){return $.trim(s.toLocaleLowerCase());},type:"text"});ts.addParser({id:"digit",is:function(s,table){var c=table.config;return $.tablesorter.isDigit(s,c);},format:function(s){return $.tablesorter.formatFloat(s);},type:"numeric"});ts.addParser({id:"currency",is:function(s){return/^[£$€?.]/.test(s);},format:function(s){return $.tablesorter.formatFloat(s.replace(new RegExp(/[£$€]/g),""));},type:"numeric"});ts.addParser({id:"ipAddress",is:function(s){return/^\d{2,3}[\.]\d{2,3}[\.]\d{2,3}[\.]\d{2,3}$/.test(s);},format:function(s){var a=s.split("."),r="",l=a.length;for(var i=0;i<l;i++){var item=a[i];if(item.length==2){r+="0"+item;}else{r+=item;}}return $.tablesorter.formatFloat(r);},type:"numeric"});ts.addParser({id:"url",is:function(s){return/^(https?|ftp|file):\/\/$/.test(s);},format:function(s){return jQuery.trim(s.replace(new RegExp(/(https?|ftp|file):\/\//),''));},type:"text"});ts.addParser({id:"isoDate",is:function(s){return/^\d{4}[\/-]\d{1,2}[\/-]\d{1,2}$/.test(s);},format:function(s){return $.tablesorter.formatFloat((s!="")?new Date(s.replace(new RegExp(/-/g),"/")).getTime():"0");},type:"numeric"});ts.addParser({id:"percent",is:function(s){return/\%$/.test($.trim(s));},format:function(s){return $.tablesorter.formatFloat(s.replace(new RegExp(/%/g),""));},type:"numeric"});ts.addParser({id:"usLongDate",is:function(s){return s.match(new RegExp(/^[A-Za-z]{3,10}\.? [0-9]{1,2}, ([0-9]{4}|'?[0-9]{2}) (([0-2]?[0-9]:[0-5][0-9])|([0-1]?[0-9]:[0-5][0-9]\s(AM|PM)))$/));},format:function(s){return $.tablesorter.formatFloat(new Date(s).getTime());},type:"numeric"});ts.addParser({id:"shortDate",is:function(s){return/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/.test(s);},format:function(s,table){var c=table.config;s=s.replace(/\-/g,"/");if(c.dateFormat=="us"){s=s.replace(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/,"$3/$1/$2");}else if(c.dateFormat=="uk"){s=s.replace(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/,"$3/$2/$1");}else if(c.dateFormat=="dd/mm/yy"||c.dateFormat=="dd-mm-yy"){s=s.replace(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2})/,"$1/$2/$3");}return $.tablesorter.formatFloat(new Date(s).getTime());},type:"numeric"});ts.addParser({id:"time",is:function(s){return/^(([0-2]?[0-9]:[0-5][0-9])|([0-1]?[0-9]:[0-5][0-9]\s(am|pm)))$/.test(s);},format:function(s){return $.tablesorter.formatFloat(new Date("2000/01/01 "+s).getTime());},type:"numeric"});ts.addParser({id:"metadata",is:function(s){return false;},format:function(s,table,cell){var c=table.config,p=(!c.parserMetadataName)?'sortValue':c.parserMetadataName;return $(cell).metadata()[p];},type:"numeric"});ts.addWidget({id:"zebra",format:function(table){if(table.config.debug){var time=new Date();}var $tr,row=-1,odd;$("tr:visible",table.tBodies[0]).each(function(i){$tr=$(this);if(!$tr.hasClass(table.config.cssChildRow))row++;odd=(row%2==0);$tr.removeClass(table.config.widgetZebra.css[odd?0:1]).addClass(table.config.widgetZebra.css[odd?1:0])});if(table.config.debug){$.tablesorter.benchmark("Applying Zebra widget",time);}}});})(jQuery);
</script>
<script type="text/javascript">
$(document).ready(function() {
    $("table.tablesorter").tablesorter();
});
</script>
</body>
</html>
EOM
    return join("\n", @output);
}

# Output NIC list in DokuWiki format (for http://ipxe.org)
sub format_nic_list_dokuwiki {
    my ($nic_list, $column_names) = @_;
    my @output;

    push @output, <<'EOM';
EOM

    # Output DokuWiki table header
    push @output, "^"
                . join("^",
                    map { $_ || "" }
                    @$column_names
                  )
                . "^";

    # Output DokuWiki table entries
    foreach my $nic ( @$nic_list ) {
        my @columns = @{ $nic }{ @$column_names }; # array slice from hashref, see perldoc perldata if confusing
        push @output, '|'
                    . join('|',
                        map { $_ || "" }
                        @columns
                      )
                    . '|';
    }

    return join("\n", @output);
}
