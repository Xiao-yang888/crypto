package main

import (
	"11_11/3des"
	"11_11/aes"
	"11_11/des"
	"bytes"
	"fmt"
)

func main() {
	//des：块加密
	//des:key,data,mode
	/**
	 *key: 密钥
	 *data：明文，即将加密的明文
	 *mode：两种模式，加密和解密
	 */
	//key := []byte("c1906041")
	//data := "憨憨华华大憨憨"
	//加密：crypto
	//	block, err := des.NewCipher(key)
	//	if err != nil {
	//		panic("初始化密码错误，请重试！")
	//	}
	//	//dst, src
	//	dst := make([]byte, len([]byte(data)))
	//	//加密过程
	//	block.Encrypt(dst, []byte(data))
	//	fmt.Println("加密后的内容：", dst)
	//
	//	//解密过程
	//	deBlock, err := des.NewCipher(key)
	//	if err != nil {
	//		panic("初始化密码错误，请重试！")
	//	}
	//	deData := make([]byte, len(dst))
	//	deBlock.Decrypt(deData, dst)
	//	fmt.Println(deData)
	//}

	//一，对数据进行加密   DES的密钥长度为8字节3DES密钥长度为24字节
	//key := []byte("c1906041")
	//data := "憨憨华华大憨憨哦，傻不拉几的哈哈哈"

	//	//1,得到cipher
	//	block, err := des.NewCipher(key)
	//	if err != nil {
	//		fmt.Println(err.Error())
	//		return
	//	}
	//
	//	//2,对数据明文进行尾部填充
	//	paddingData := utils.PKCS5EndPadding([]byte(data), block.BlockSize())
	//
	//	//3,选择模式
	//	mode := cipher.NewCBCEncrypter(block, key)
	//
	//	//4,加密
	//	dstData := make([]byte, len(paddingData))
	//	mode.CryptBlocks(dstData, paddingData)
	//
	//	fmt.Println("加密后的内容：", dstData)
	//
	//	//二，对数据进行解密
	//	//DES三元素，key，data，mode
	//	key1 := []byte("c1906041")
	//	data1 := dstData //待解密的数据
	//	block1, err := des.NewCipher(key1)
	//	if err != nil {
	//		panic(err.Error())
	//	}
	//	deMode := cipher.NewCBCDecrypter(block1, key1)
	//	originalData := make([]byte, len(data1))
	//	//分组解密
	//	deMode.CryptBlocks(originalData, data1)
	//	originData := utils.ClearPKCS5Padding(originalData, block1.BlockSize())
	//	fmt.Println("解密后的内容：", string(originData))
	//
	//}
	//


	//一，使用DES进行加解密
	key := []byte("20201112")//密钥长度8字节
	data := "窗含西岭千秋雪，门泊东吴万里船。"
	cipherText, err := des.DESEnCrypt([]byte(data), key)
    if err != nil {
    	fmt.Println(err.Error())
		return
	}
	originText, err := des.DESDeCrypt(cipherText, key)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("DES解密后的内容：", string(originText))

	//二：3DES加解密
	key1 := []byte("202011122020111220201112")//3des的密钥长度为24字节
    data1 := "穷在闹市无人问，富在深山有远亲。"
    cipherText1, err := _des.TripleDESEncrypt([]byte(data1), key1)
    if err != nil {
    	fmt.Println("3DES加密失败:",err.Error())
		return
	}
	originalText1, err := _des.TripleDESDecrypt(cipherText1, key1)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("3DES解密后的内容：", string(originalText1))

	//三，AES算法
	key2 := []byte("202011122020111220201112")//8
	data2 := ("人生在世不称意，明诏散发弄汴州。")
	cipherText2, err := aes.AESEnCrypt([]byte(data2), key2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	originText2, err := aes.AESDeCrypt(cipherText2, key2)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("AES解密后的内容：", string(originText2))
}

/**
 *明文数据尾部填充
 */
func PKCS5Padding(text []byte, blocksize int) []byte {
	paddingSize := blocksize - len(text) % blocksize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(text, paddingText...)

}