package handler

import (
	"net/http"
)

const ManusText = `Clean gloves hide dirty hands and mine are dirtier than most.`
const ManusAscii = `
                             .:
                            8: 88
                            :   8 S@%
                       888@ :   8X. .%
                      X.   8:   8t   :
                      8    %:   8t   :;@t S
                      8    %:   8t   :8   X
                      8    %:   8t   :8   ;
                      8    %:   8t   :8   ;
                      8    %:   8t   :8   ;
                      8    %:   8t   :8   ;
                      8    S.   .8   8;   ;
                      8                   ;
               %@S%;  8                   ;
               8   X. 8                   ;
               8     SS                   ;
                :S                        ;
                 S:                       ;
                   S.                     S
                    88                    %
                     t                    :
                       :;               .%
                        %@;            :8
                          :. @;   .8 S@
                               :t;
`

var Manus = mummify(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(`connection`, `close`)
	http.Error(w, ManusText+"\r\n"+ManusAscii, http.StatusMethodNotAllowed)
})
