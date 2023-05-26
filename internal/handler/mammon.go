package handler

import (
	"net/http"
)

const MammonText =`Filthy Lucre`
const MammonAscii =`
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣦⣤⣤⣤⣿⣿⣶⣤⣤⣶⣿⡿⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠧⣜⢿⣿⠉⢻⣿⢿⣿⣿⡇⢠⣭⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⢿⣿⡄⣺⣿⣤⣿⣿⣿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣻⣿⣿⣛⣿⣿⣾⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣟⣿⣿⣟⣻⣿⣿⣾⣿⣿⣃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⢿⠿⠟⠿⣿⢿⡉⠉⢽⡗⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠞⠋⢉⠟⠀⠀⠀⠀⠀⠈⠀⠙⢄⠀⠉⢿⣇⠏⡵⢦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡶⣿⣦⠖⠀⠀⠀⠀⠀⢰⣶⣤⡄⠀⠀⠀⠀⠀⠀⠉⠺⢷⠎⣸⣻⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣾⣷⣿⡟⠁⠀⢀⣴⣾⣯⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡡⢊⡼⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣴⢏⢗⢸⠟⠃⠀⠀⢠⣾⣿⣿⡿⢿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠸⡗⣩⠞⡔⣹⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣠⠞⣷⢸⡸⠈⠀⠀⠀⠀⢸⣿⣿⡏⠀⣸⣿⣿⡏⠙⢿⡿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠨⠵⣪⠜⡡⣻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⡾⢡⣶⡟⠋⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣶⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⣡⢞⡕⢡⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⡞⠀⠈⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡵⢋⠔⡿⢡⣿⡀⠀⠀⠀⠀⠀⠀⠀
⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⣣⠞⣴⣻⣿⡇⠀⠀⠀⠀⠀⠀⠀
⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣴⣧⡀⠀⣿⣿⣿⠀⠹⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡔⣡⣾⢟⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣷⣤⣿⣿⣿⣀⣠⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣬⣾⢟⣵⣿⡿⣻⡇⠀⠀⠀⠀⠀⠀⠀
⢳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢞⣥⣿⣿⢟⡕⣹⠁⠀⠀⠀⠀⠀⠀⠀
⠈⣆⢻⣠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⣿⣿⣿⠛⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⢟⡻⢟⣽⡿⣋⢴⡟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠸⡌⢿⣧⡄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣇⡠⠊⡠⢊⠔⡻⢫⠞⣡⣿⣤⣤⣤⣀⠀⠀⠀⠀⠀
⠀⠀⠹⣄⠛⣷⣷⣤⣄⠀⠀⠀⠀⠀⢀⣄⡴⣢⢖⡰⢂⠔⣠⠖⣰⣦⢆⣴⣲⣿⢞⣶⠞⡴⢡⢞⠔⣡⣏⣾⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄
⠀⠀⠀⠈⠳⣌⠙⢿⣿⢸⣿⣷⣶⣿⣿⡾⡿⣵⢋⠔⠵⢊⡵⢮⠟⡵⣯⢞⡵⣣⡿⢃⠞⡴⡱⢋⣾⣟⣯⣭⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿
⠀⠀⠀⠀⠀⠿⢷⣦⣭⣭⣭⣥⣭⣤⣤⣤⣤⣤⣤⣤⣶⣞⡒⠒⠲⠃⠌⣹⢿⡿⣷⣣⣞⣴⣟⣛⣒⣺⣿⣿⣿⣟⣷⣶⣶⠦⠤⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⠹⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣤⣤⣼⣿⡟⠛⠛⠳⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⡭⠿⠿⢿⣿⣶⣶⣞⣃⣀⣀⣀⡚⠛⠛⠛⠉⠉⠉⠉⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
`
var Mammon = mummify(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(`connection`, `close`)
	// FIXME: include location to payment gateway
	//w.Header().Set(`location`, `fixme`)
	http.Error(w, MammonText + "\r\n" + MammonAscii, http.StatusPaymentRequired)
})
