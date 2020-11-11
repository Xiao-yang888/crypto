package utils

import "bytes"

/**
 *该函数将明文进行尾部填充，采用PKCS5方式
 */
func PKCS5EndPadding(text []byte, size int) []byte {
	paddingSize := size - len(text) % size
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(text, paddingText...)
}

/**
 *该函数用于将明文进行尾部填充，采用Zeros方式
 */
func ZerosEndPadding(text []byte, size int) []byte {
	paddingSize := size - len(text) % size
	paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(text, paddingText...)
}
