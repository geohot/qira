exception No_Dism
module Instr = struct
  type t = string
  let equal i j = i = j
  let hash = Hashtbl.hash
end

module M = struct
  module D = Hashtbl.Make(Instr)
  include D
  let format a = a
end

module Trie = Trie.Make(M)

let sep = ";"

(* read_from_ic : in_channel -> string list * float *)
let read_from_ic ic =
  let to_dism_score line =
    let words = Str.split (Str.regexp "->") line in
    match words with
    | [disms_str; counts] ->
      let disms = Str.split (Str.regexp ";") disms_str in
      let p, n =
        let p_n = Str.split (Str.regexp ",") counts in
        match p_n with
        | [p;n] -> float_of_string p, float_of_string n
        | _ -> failwith "WPT File Format error"
      in
      disms, (p /. (p +. n))
    | _ -> failwith "WPT File Format error"
  in
  let sigs = ref [] in
  try
    while true; do
      let line = input_line ic in
      let disms, score = to_dism_score line in
      sigs := (disms, score) :: !sigs
    done;
    []
  with End_of_file ->
    close_in ic;
    !sigs

let load file =
  let ic = open_in file in
  (* sigs : string list * float *)
  let sigs = read_from_ic ic in
  let trie = Trie.init 0.0 in
  List.iter (fun (k, v) ->
      Trie.add trie k v
    ) sigs;
  trie

let get_disasm container addr =
  let module ARM = Arch_arm.ARM in
  (* Printf.printf "%s\n" (Bitvector.to_hex addr); *)
  let _, _, fallthrough, dism =
    ARM.disasm ARM.init_state (fun addr ->
        String.get
          (Exec_container.Reader.get_bytes container addr (Bitvector.incr addr)) 0
      ) addr
  in
  match dism with
  | None -> raise No_Dism
  | Some d -> d, fallthrough


(* consecutive: addr -> addr -> int -> Container.exec_container -> asm list *)
let consecutive addr end_addr len container =
  let rec rec_consecutive addr i disms =
    if (i >= len) || (Bitvector.bool_of (Bitvector.lt end_addr addr)) then
      List.rev disms
    else try (
      let dism, fallthrough = get_disasm container addr in
      rec_consecutive fallthrough (i + 1) (Normalize.normalize dism :: disms)
    )
      with _ -> List.rev disms
  in
  rec_consecutive addr 0 []


let get_container bin =
  let ic = open_in_bin bin in
  let buf = String.create (in_channel_length ic) in
  let () = really_input ic buf 0 (String.length buf) in
  let () = close_in ic in
  Elf_container.load_executable buf


let generate_keys disms =
  let rec rec_g res prefix = function
    | [] -> res
    | hd :: tl ->
      let new_key =
        if prefix = "" then hd
        else Printf.sprintf "%s%s%s" prefix sep hd
      in
      rec_g (new_key :: res) new_key tl
  in
  rec_g [] "" disms

