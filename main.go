package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func encryptImageWith(img []byte, encryptMethod func(src []byte) []byte, newName string) error {
	newImg := encryptMethod(img)
	if len(newImg) == 0 {
		return fmt.Errorf("encrypt image error")
	}

	// 复制图片文件头，防止图像编辑器无法识别加密后的图片，100bytes包含了文件头信息
	for i := 0; i < 100; i++ {
		newImg[i] = img[i]
	}

	return ioutil.WriteFile(newName, newImg, os.ModePerm)
}

func main() {
	img, err := ioutil.ReadFile("origin/img.bmp")
	if err != nil || len(img) == 0 {
		fmt.Printf("read origin image error %v", err)
		return
	}

	// ECB 模式加密
	if err := encryptImageWith(img, Encrypt, "after/img_ecb.bmp"); err != nil {
		fmt.Printf("read origin image error %v", err)
		return
	}
	// CBC 模式加密
	if err := encryptImageWith(img, NewEncrypt, "after/img_cbc.bmp"); err != nil {
		fmt.Printf("read origin image error %v", err)
		return
	}
}
