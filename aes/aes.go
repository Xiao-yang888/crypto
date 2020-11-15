package aes

import (
	"11_11/utils"
	"crypto/aes"
	"crypto/cipher"
)

/*
 *使用AES算法对明文进行加密
 */
func AESEnCrypt(origin []byte, key []byte) ([]byte, error) {
	//三元素：key。data，mode
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil ,err
	}
	//2,对明文数据进行尾部填充
	cryptData := utils.PKCS5EndPadding(origin, block.BlockSize())
    //3,实例化一个加密mode
    blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
    //4,加密
    cipherData := make([]byte, len(cryptData))
    blockMode.CryptBlocks(cipherData, cryptData)
    return cipherData, nil
}

/**
 *使用AES算法对密文进行解密
 */
func AESDeCrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	originalText := make([]byte, len(data))
	blockMode.CryptBlocks(originalText,data)
	//去尾部填充
	originalText = utils.ClearPKCS5Padding(originalText, block.BlockSize())
	return originalText, nil
}