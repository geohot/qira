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

module Make (M : M) : (TRIE with type key = M.key list)
