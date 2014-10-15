type t_arch =
  | Arm
  | X86
  | X86_64


let replace_patt str patt =
  Str.global_replace (Str.regexp patt) patt str

let normalize ?(arch=None) s =
  let s_trimmed = String.trim s in
  let s_normalized =
    match arch with
    | None | Some Arm ->
      let norm_const =
        let neg = "#-[1-9a-f][0-9a-f]*"
        and pos = "#[1-9a-f][0-9a-f]*"
        and zero = "#0+" in
        List.fold_left replace_patt s_trimmed [neg;pos;zero]
      in
      let norm_branch =
        let bl = "^b\\(l\\)?[ \t]+[1-9a-f]+" in
        replace_patt norm_const bl
      in
      norm_branch
    | Some X86
    | Some X86_64 ->
      let norm_const =
        let neg = "-\\(\\$\\)?\\(0x\\)?[0-9a-f]+"
        and pos = "\\(\\$\\)?\\(0x\\)?[0-9a-f]+"
        and zero = "\\(\\$\\)?\\(0x\\)?0+" in
        List.fold_left replace_patt s_trimmed [neg;pos;zero]
      in
      let norm_branch =
        let jump = "^j[a-z]+[ \t]+\\(\\*\\)?[0-9a-f]+"
        and call = "^call[a-z]+[ \t]+\\(\\*\\)?[0-9a-f]+" in
        List.fold_left replace_patt norm_const [jump;call]
      in
      norm_branch
  in
  let s_stripped =
    let s_splitted = Str.split (Str.regexp "[ \t]+") s_normalized in
    String.concat "" s_splitted
  in
  (* Printf.printf "====\n%s\n%s\n====\n%!" s s_stripped; *)
  s_stripped
