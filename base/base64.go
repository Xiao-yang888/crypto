package base

import "encoding/base64"

/**
 *使用base64进行编码
 */
func Base64Encode(data []byte) string {
	//base64.NewEncoder(base64.NewEncoding(base64.encodingStd))
	encoding := base64.StdEncoding
	dst := make([]byte, 0)
	encoding.Encode(dst , data)
	return string(dst)
}

/**
 *使用Base64进行解码
 */
func Base64Decode(data string) string {
	encoding := base64.StdEncoding
	dst := make([]byte, 0)
	encoding.Decode(dst, []byte(data))
	return string(dst)
}

