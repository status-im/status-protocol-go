package identicon

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

func renderBase64(id Identicon) (string, error) {
	img := image.NewRGBA(image.Rect(0, 0, 50, 50))
	var buff bytes.Buffer

	setBackgroundWhite(img)

	for i, v := range id.bitmap {
		if v == 1 {
			drawRect(img, i, id.color)
		}
	}

	if err := png.Encode(&buff, img); err != nil {
		return "", err
	}

	encodedString := base64.StdEncoding.EncodeToString(buff.Bytes())
	image := "data:image/png;base64," + encodedString
	return image, nil
}

func setBackgroundWhite(img *image.RGBA) {
	draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.ZP, draw.Src)
}

func drawRect(rgba *image.RGBA, i int, c color.Color) {
	sizeSquare := 6
	maxRow := 5

	r := image.Rect(
		10+(i%maxRow)*sizeSquare,
		10+(i/maxRow)*sizeSquare,
		10+(i%maxRow)*sizeSquare+sizeSquare,
		10+(i/maxRow)*sizeSquare+sizeSquare,
	)

	draw.Draw(rgba, r, &image.Uniform{c}, image.ZP, draw.Src)
}

// GenerateBase64 generates an identicon in base64 png format given a string
func GenerateBase64(id string) (string, error) {
	i := generate(id)
	return renderBase64(i)
}
