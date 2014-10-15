module type M = sig
  type 'a t
  type key
  val create : int -> 'a t
  val iter : (key -> 'a -> unit) -> 'a t -> unit
  val add : 'a t -> key -> 'a -> unit
  val replace : 'a t -> key -> 'a -> unit
  val find : 'a t -> key -> 'a
  val format : key -> string
end

module type TRIE = sig
  type 'a t
  type key
  val init : 'a -> 'a t
  val add : 'a t -> key -> 'a -> unit
  val find : 'a t -> key -> 'a
  val output : 'a t -> string -> ('a -> string) -> unit
end


module Make (M : M) : (TRIE with type key = M.key list) = struct
  type key = M.key list
  type 'a t = Node of 'a * 'a t M.t

  let init v = Node (v, M.create 10)

  (* add : 'a t -> key -> 'a -> unit *)
  let rec add trie k v = match k with
    | [] -> ()
    | hd :: [] -> (
        match trie with
        | Node (_, m) ->
          try
            match (M.find m hd) with
            | Node (_, sub) -> M.replace m hd (Node (v, sub))
          with Not_found ->
            (* If this is a new node, add to its father node's map *)
            let subtrie_init = init v in
            M.add m hd subtrie_init
      )
    | hd :: tl ->
      match trie with
      | Node (_, m) ->
        let subtrie =
          try
            M.find m hd
          with Not_found -> (
              (* If this is a new node, add to its father node's map *)
              let subtrie_init = init v in
              M.add m hd subtrie_init;
              subtrie_init
            )
        in
        add subtrie tl v

  (* find : 'a t -> key -> 'a -> 'a *)
  (* find : return the longest match *)
  let find trie k =
    let rec rec_find trie k t_v = match k with
      | [] -> t_v
      | hd :: tl ->
        match trie with
        | Node (_, m) ->
          try
            (* let subtrie = M.find m hd in
               match subtrie with *)
            match M.find m hd with
            | Node (v, _) as subtrie ->
              rec_find subtrie tl v
          (* Not_found means reach the longest match, so return t_v *)
          with Not_found ->
            t_v
    in
    let root_v = match trie with
      | Node (v, _) -> v
    in
    rec_find trie k root_v

  (* output : 'a t -> string -> ('a -> string) -> unit *)
  let output trie file format_v =
    let oc = open_out file in
    let rec rec_output prefix = function
      | Node (v, m) ->
        Printf.fprintf oc "%s->%s\n" (String.concat ";" (List.rev prefix)) (format_v v);
        M.iter (fun k v ->
            rec_output (M.format k :: prefix) v
          ) m
    in
    rec_output [] trie;
    close_out oc
end

(*
module type DISM = sig
  type t
  val equal : t -> t -> bool
  val hash : t -> int
end

module Dism : DISM = struct
  type t = string
  let equal i j = i = j
  let hash = Hashtbl.hash
end

module M = struct
  module D = Hashtbl.Make(Dism)
  include D
  let format a = a
end

module DismTrie = Make(M) *)
