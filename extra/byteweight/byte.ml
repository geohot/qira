
let generate_keys bytes =
  let rec rec_g res bytes =
    let len = String.length bytes in
    if len == 0 then res
    else
      let tl_bytes = 
        String.sub bytes 0 (len-1)
      in
      rec_g (bytes :: res) tl_bytes
  in
  rec_g [] bytes

(*consecutive : addr -> addr -> int -> Exec_container.t -> string *)
let consecutive addr end_addr len container =
  let real_end =
    let max_addr = Bitvector.plus addr (Bitvector.lit len 32) in
    if Bitvector.bool_of (Bitvector.lt end_addr max_addr) then end_addr
    else max_addr
  in
  Exec_container.Reader.get_bytes container addr real_end
