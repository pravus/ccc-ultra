package volatile

import (
	"io"
	"net/http"
	"os"
	"strings"

	"ultra/internal/model"
)

const defaultMimeType = `text/plain`

var mimeTypes = map[string]string{
	`7z`:    `application/x-7z-compressed`,
	`aac`:   `audio/aac`,
	`avi`:   `video/x-msvideo`,
	`bin`:   `application/octet-stream`,
	`bmp`:   `image/bmp`,
	`bz`:    `application/x-bzip`,
	`bz2`:   `application/x-bzip2`,
	`css`:   `text/css`,
	`csv`:   `text/csv`,
	`flac`:  `audio/flac`,
	`gif`:   `image/gif`,
	`gz`:    `application/gzip`,
	`htm`:   `text/html`,
	`html`:  `text/html`,
	`jpeg`:  `image/jpeg`,
	`jpg`:   `image/jpeg`,
	`js`:    `text/javascript`,
	`json`:  `application/json`,
	`md`:    `text/markdown`,
	`mkv`:   `video/x-matroska`,
	`mp3`:   `audio/mpeg`,
	`mp4`:   `video/mp4`,
	`mpeg`:  `video/mpeg`,
	`opus`:  `audio/opus`,
	`pdf`:   `application/pdf`,
	`png`:   `image/png`,
	`rar`:   `application/vnd.rar`,
	`svg`:   `image/svg+xml`,
	`tar`:   `application/x-tar`,
	`tif`:   `image/tiff`,
	`tiff`:  `image/tiff`,
	`ttf`:   `font/ttf`,
	`txt`:   `text/plain`,
	`wav`:   `audio/wav`,
	`weba`:  `audio/webm`,
	`webm`:  `video/webm`,
	`webp`:  `image/webp`,
	`woff`:  `font/woff`,
	`woff2`: `font/woff2`,
	`xhtml`: `application/xhtml+xml`,
	`xml`:   `application/xml`,
	`zip`:   `application/zip`,
}

type FsWand struct {
}

var _ model.FsWand = (*FsWand)(nil)

func Magic() FsWand {
	return FsWand{}
}

func (wand FsWand) Zap(name string) string {
	if index := strings.LastIndex(name, `.`); index >= 0 && index < len(name)-1 {
		if mimeType, ok := mimeTypes[name[index+1:]]; ok {
			return mimeType
		}
	}
	file, err := os.Open(name)
	if err != nil {
		return defaultMimeType
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 512))
	if err != nil {
		return defaultMimeType
	}
	return http.DetectContentType(data)
}
