if !has('python')
  echo "vim must be compiled with +python"
  finish
endif

" highlight the line
" hi CursorLine cterm=NONE ctermbg=darkblue
set cursorline

function! Bob()

python << EOF

import vim

print dir(vim.current)
#print vim.current.line_num

#vim.current.buffer.append('bobobbb')
#print dir(vim)

EOF

" autocmd CursorMoved * :call Bob()

endfunction

