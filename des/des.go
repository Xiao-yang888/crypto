package des


import (
	"11_11/utils"
	"crypto/cipher"
	"crypto/des"
)

/**
 *使用DES算法对明文进行加密，使用密钥key
 */
func DESEnCrypt(data []byte, key []byte) ([]byte, error) {
	//三要素：key，data， mode
	block, err := des.NewCipher(key)
	if err != nil {
		return  nil, err
	}
	//尾部填充
	originData := utils.PKCS5EndPadding(data, block.BlockSize())
	//mode
	blockMode := cipher.NewCBCEncrypter(block, key)
	cipherData := make([]byte, len(originData))
	blockMode.CryptBlocks(cipherData, originData)
	return cipherData, nil
}

/**
 *使用DES算法对密文进行解密，使用key作为密钥
 */
func DESDeCrypt(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	originData := make([]byte, len(data))
	blockMode.CryptBlocks(originData, data)
	originData = utils.ClearPKCS5Padding(originData, block.BlockSize())
	return originData, nil
}
