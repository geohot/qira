module I = Dism.Instr
module Sigs = Hashtbl.Make(I)
let usage = "Train: ./train -bin-dir [test binary directory] -sig [output signature file]"
let d_bin = ref None
let sig_out = ref None
let k = 20

let arg_specs =
  ("-bin-dir", Arg.String(fun s -> d_bin := Some s), "train binary directory")
  :: ("-sig", Arg.String(fun s -> sig_out := Some s), "output signature file")
  :: []

let anon_fun _ = raise (Arg.Bad usage)

let parse_command =
  Arg.parse arg_specs anon_fun usage;
  match !d_bin, !sig_out with
  | Some d, Some out -> d, out
  | _ -> raise (Arg.Bad usage)

(* build_sigs : (addr list * Container.exec_container) list -> string Hashtbl.t *)
let build_sigs info =
  let sigs = Sigs.create 1000 in
  List.iter (fun (fs, sections, container) ->
      List.iter (fun addr ->
          let keys =
            let sec_end =
              let rec rec_sec_end addr = function
                | (st, nd) :: tl ->
                  if (Bitvector.bool_of (Bitvector.le addr nd))
                  && (Bitvector.bool_of (Bitvector.le st addr))
                  then nd
                  else rec_sec_end addr tl
                | [] ->
                  failwith (
                    Printf.sprintf "Function %s is not in executable segment"
                      (Bitvector.to_hex addr))
              in
              rec_sec_end addr sections
            in
            (* let disms = Dism.consecutive addr sec_end k container in
            Dism.generate_keys disms *)
            let bytes = Byte.consecutive addr sec_end k container in
            Byte.generate_keys bytes
          in
          List.iter (fun key ->
              try
                (* Printf.printf "%s\n%!" key; *)
                let (p, n) = Sigs.find sigs key in
                Sigs.replace sigs key (p + 1, n)
              with Not_found ->
                Sigs.add sigs key (1, 0)
            ) keys
        ) fs
    ) info;
  sigs

(* update_sigs :
 * string Hashtbl.t -> (addr list * Container.section) list -> unit
*)
let update_sigs sigs info =
  List.iter (fun (fs, sections, container) ->
      List.iter (fun (start_addr, end_addr) ->
          let rec rec_update addr =
            if addr > end_addr then ()
            else if List.mem addr fs then
              rec_update (Bitvector.incr addr)
            else (
              let keys =
                (* let disms = Dism.consecutive addr end_addr k container in
                Dism.generate_keys disms *)
                let bytes = Byte.consecutive addr end_addr k container in
                Byte.generate_keys bytes
              in
              List.iter (fun key ->
                  try
                    let (p, n) = Sigs.find sigs key in
                    Sigs.replace sigs key (p, n + 1)
                  with Not_found -> ()
                ) keys;
              rec_update (Bitvector.incr addr)
            )
          in
          rec_update start_addr
        ) sections
    ) info

let train d =
  let bins =
    List.map (Filename.concat d) (Array.to_list (Sys.readdir d))
  in
  let info = List.rev_map (fun bin ->
      Printf.printf "%s\n%!" bin;
      let exec_container = Dism.get_container bin in
      match exec_container with
      | None -> failwith "Binary Load Error"
      | Some container ->
        (* let fs = Mock.fs bin *)
        let fs = Mock.fs_dwarf bin
        and codes =
          (* TODO: currently they are segments, not sections
           * What we really want is sections *)
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
        in
      (*
      List.iter (fun (st, en) ->
        Printf.printf "%s %s\n%!" (Bitvector.to_hex st) (Bitvector.to_hex en))
      codes;
      List.iter (fun addr ->
        Printf.printf "%s\n%!" (Bitvector.to_hex addr)
      ) fs; *)
        fs, codes, container
    ) bins in
  let sigs = build_sigs info in
  update_sigs sigs info;
  sigs

let output sigs file =
  let oc = open_out_bin file in
  Sigs.iter (fun k (p, n) ->
      Printf.fprintf oc "%s->%d,%d\n" k p n
    ) sigs;
  close_out oc

let () =
  let d, out = parse_command in
  let sigs = train d in
  output sigs out
