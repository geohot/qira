open Core_kernel.Std
open Or_error
open Dwarf

module Buffer = Dwarf_data.Buffer
(*
let fb bin =
  let tmp_file = Filename.temp_file bin ".tmp" in
  let command =
    Printf.sprintf
      "arm-linux-gnueabi-objdump -t %s | grep \"F .text\" | \
       gawk `{ \
         start=strtonum(\"0x\"$1); \
         size=strtonum(\"0x\"$5); \
         printf(\"%%x %%x\\n\", start, start+size)}` | sort -u > %s"
      bin tmp_file
  in
  let () = Sys.command command in
  read_fb tmp_file
*)

let read_fs filename =
  let lines = In_channel.read_lines filename in
  List.map lines ~f: (fun line ->
      let addr_int = int_of_string (Printf.sprintf "0x%s" line) in
      Bitvector.lit addr_int 32
    )

let fs bin =
  let tmp_file = Filename.temp_file (Filename.basename bin) ".tmp" in
  let command =
    Printf.sprintf
      "arm-linux-gnueabi-objdump -t %s | grep \"F .text\" | \
       awk '{print $1}' | sort -u > %s"
      bin tmp_file
  in
  (* Printf.printf "%s%!" command; *)
  let _ = Sys.command command in
  read_fs tmp_file
(*
let fs_dwarf filename =
  let filedata = In_channel.read_all filename in
  match Elf.parse filedata with
  | None -> (*errorf "%s is not an elf file\n" filename *) []
  | Some elf ->
    let open Elf in
    let endian = match elf.e_data with
      | ELFDATA2LSB -> LittleEndian
      | ELFDATA2MSB -> BigEndian in
    let create name s = Some (name, Buffer.create s.sh_data) in
    let sections = List.filter_map elf.e_sections ~f:(fun s ->
        match s.sh_name with
        | ".debug_info"   -> create Section.Info s
        | ".debug_abbrev" -> create Section.Abbrev s
        | ".debug_str"    -> create Section.Str s
        | _ -> None) in
    match Dwarf_data.create endian sections with
      | Ok data ->
        (match Dff.create data with
        | Ok dff ->
          let seq = Sequence.map (Dff.functions dff) ~f:(fun (_, fn) ->
            match Dff.Fn.pc_lo fn with
            | Dwarf.Addr.Int64 x -> Bitvector.litz (Z.of_int64 x) 64
            | Dwarf.Addr.Int32 x -> Bitvector.litz (Z.of_int32 x) 32
          ) in
          Sequence.to_list seq
        | Error err -> (* eprintf "error" @@ Error.to_string_hum err; *) [])
      | _ -> []
*)

let dwarf_to_bitvector = function
  | Dwarf.Addr.Int64 x -> Bitvector.litz (Z.of_int64 x) 64
  | Dwarf.Addr.Int32 x -> Bitvector.litz (Z.of_int32 x) 32

let fs_dwarf filename =
  let filedata = In_channel.read_all filename in
  let res =
    match Elf.parse filedata with
    | None -> errorf "%s is not an elf file\n" filename
    | Some elf ->
      let open Elf in
      let endian = match elf.e_data with
        | ELFDATA2LSB -> LittleEndian
        | ELFDATA2MSB -> BigEndian in
      let create name s = Some (name, Buffer.create s.sh_data) in
      let sections = List.filter_map elf.e_sections ~f:(fun s ->
          match s.sh_name with
          | ".debug_info"   -> create Section.Info s
          | ".debug_abbrev" -> create Section.Abbrev s
          | ".debug_str"    -> create Section.Str s
          | _ -> None) in
      Dwarf_data.create endian sections >>= fun data ->
      Dff.create data >>| fun dff ->
      let seq = Sequence.map (Dff.functions dff) ~f:(fun (_, fn) ->
          dwarf_to_bitvector (Dff.Fn.pc_lo fn)
        ) in
      Sequence.to_list seq
  in match res with
  | Ok x ->
    (*
        let gt = Filename.concat "gt_dwarf" (Filename.basename filename) in
        Out_channel.write_lines gt (List.map x ~f:Bitvector.to_hex);
        *)
    x
  | Error err -> Printf.printf "dwarf error %s: %s\n" filename
                   (Error.to_string_hum err); []
