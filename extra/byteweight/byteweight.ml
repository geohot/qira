(* TODO: convert to Core_list? *)
module DismTrie = Dism.Trie
let usage = "./match [binary file]"
let k = 10

let g_wpt = Filename.concat (Filename.dirname Sys.executable_name) "signatures/sig_arm"

let threshold = ref 0.5
let d_bin = ref None
let d_out = ref None
let bin = ref None
let out = ref stdout
let f_wpt = ref g_wpt
(* let arch = ref None *)

let arg_specs =
  ("-wpt", Arg.String(fun s -> f_wpt := s), "weighted prefix tree file")
  :: ("-bin-dir", Arg.String(fun s -> d_bin := Some s), "test binary directory")
  (* :: ("-bin", Arg.String(fun s -> bin := Some s), "test binary") *)
  :: ("-o-dir", Arg.String(fun s -> d_out := Some s; try Unix.mkdir s 0o755 with _ -> ()), "output directory")
  :: ("-o", Arg.String(fun s -> out := open_out s), "output file")
  :: ("-t", Arg.Float(fun f -> threshold := f), "threshold")
  (* Question: can BAP infer architecture from binaries? *)
  :: []

let anon_fun s = bin := Some s


(* fsi_container : Trie.t -> Container.exec_container -> addr list -> addr list *)
let fsi_container trie container codes =
  let fs_sec = List.map (fun (start_addr, end_addr) ->
      (* score : Trie.t -> addr -> float *)
      let score addr =
        let disms = Dism.consecutive addr end_addr k container in
        DismTrie.find trie disms
      in

      let rec rec_score addr fs =
        if (Bitvector.bool_of (Bitvector.lt end_addr addr)) then fs
        else
          let s = score addr in
          if s > !threshold then
            rec_score (Bitvector.incr addr) (addr :: fs)
          else
            rec_score (Bitvector.incr addr) fs
      in

      rec_score start_addr []
    ) codes in
  (* List.concat fs_sec *)
  (* List.concat is not tail-recursive, so I use List.fold_left instead *)
  List.sort
    Bitvector.compare
    (List.fold_left (fun res l -> List.rev_append (List.rev res) l) [] fs_sec)


(* output: out_channel -> addr list -> unit *)
let output oc fsi =
  List.iter (fun addr ->
      Printf.fprintf oc "%s\n" (Bitvector.to_hex addr)
    ) fsi;
  close_out oc

let get_code_segments container =
  let sections = Exec_container.Reader.get_sections container in
  List.fold_left (
    fun res {Exec_container.start_addr=start_addr;
             Exec_container.end_addr=end_addr;
             Exec_container.permissions=permissions} ->
      if List.mem Exec_container.X permissions then
        (start_addr, end_addr) :: res
      else
        res
  ) [] sections

(* fsi_bin : string -> Trie.t -> addr list *)
let fsi_bin bin trie =
  let exec_container = Dism.get_container bin in
  match exec_container with
  | None -> failwith (Printf.sprintf "Binary Load Error %s" bin)
  | Some container ->
    (* codes: (addr * addr) list *)
    let codes = get_code_segments container in
    (* List.iter (fun (st, en) -> Printf.printf "%s %s\n%!"
       (Bitvector.to_hex st) (Bitvector.to_hex en)) codes; *)
    fsi_container trie container codes


(* main *)
let () =
  let () = Arg.parse arg_specs anon_fun usage in
  match !bin, !d_bin with
  | None, Some d_i -> (
      match !d_out with
      | None ->
        let err =
          Printf.sprintf "Output directory is required.\n" ^ usage
        in
        raise (Arg.Bad err)
      | Some d_o ->
        let trie = Dism.load !f_wpt in
        let bins = List.map
            (Filename.concat d_i)
            (Array.to_list (Sys.readdir d_i))
        in
        List.iter (fun bin ->
            let fs = fsi_bin bin trie in
            let oc =
              let bin_out = Filename.concat d_o (Filename.basename bin) in
              open_out bin_out
            in
            output oc fs
          ) bins
    )
  | Some i, None ->
    let trie = Dism.load !f_wpt in
    let fs = fsi_bin i trie in
    output !out fs
  | _ -> raise (Arg.Bad usage)


(* get_functions: exec_container -> addr list *)
let get_functions container =
  let trie = Dism.load g_wpt in
  let codes = get_code_segments container in
  fsi_container trie container codes
