package handler

import (
	"net/http"
)

const VerbotenText =`VERBOTEN`
const VerbotenAscii =`
                        X8X888888X8X
                   88tttttttttttttttttt@8
                8tttttttttttttttttttttttttt8
             8%tttttttttttttttttttttttttttttt%8
           8%ttttttttttttS8X8888X8StttttttttttttX
         @%ttttttttt%@                X%ttttttttt%@
        8ttttttttt8                      @ttttttttt8
       SttttttttttS                        8%tttttttS
      %ttttttttttttt8                        8ttttttt%
     %ttttttttttttttttX                       @ttttttt%
    @ttttttt@ 8ttttttttS                        tttttttX
   @ttttttt@    Stttttttt8                      Xttttttt8
   %tttttt8      XtttttttttX                     8ttttttt
   ttttttt         8ttttttttS                     ttttttt@
  8tttttt8           Stttttttt8                   8tttttt8
  %tttttt@            XtttttttttX                 Xttttttt
  ttttttt               8ttttttttS                 ttttttt
  ttttttt                 Stttttttt8               ttttttt
  %tttttt@                 XtttttttttX             ttttttt
  8tttttt8                   8ttttttttS           8tttttt8
   ttttttt                     Stttttttt8         ttttttt@
   %tttttt8                     XtttttttttX      8ttttttt
   @ttttttt@                      8ttttttttS     ttttttt8
    @ttttttt                        Stttttttt8  tttttttX
     %ttttttt@                       Xtttttttttttttttt%
      %ttttttt8                        8ttttttttttttt%
       SttttttttX                        Stttttttttt%
        8tttttttttX                      8ttttttttt@
         @%ttttttttt%X                XSttttttttt%@
           XtttttttttttttS8X8888X8Sttttttttttttt@
             X%tttttttttttttttttttttttttttttttX
                8tttttttttttttttttttttttttt8
                   8XttttttttttttttttttX8
                        @888@@@@88X@
`

var Verboten = mummify(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(`connection`, `close`)
	http.Error(w, VerbotenText + "\r\n" + VerbotenAscii, http.StatusMethodNotAllowed)
})
