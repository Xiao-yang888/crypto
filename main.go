package main

import (
	"11_11/3des"
	"11_11/aes"
	"11_11/des"
	"11_11/ecc"
	"11_11/rsa"
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
	fmt.Println("DES算法:")
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
	fmt.Println("3DES算法：")
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
	fmt.Println("AES算法：")
	key2 := []byte("202011122020111220201112")//8
	data2 := "人生在世不称意，明诏散发弄汴州。"
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

	//四，RSA算法的使用
	//fmt.Println("RSA算法：")
	//data3 := "把我的悲伤留给自己。"
	////生成密钥对
	//priv, err := rsa.CreatePairKeys()
	//if err != nil {
	//	fmt.Println("生成密钥对出错：", err.Error())
	//	return
	//}
	//
	////对数据进行加密
	//cipherText3, err := rsa.RSAEncrypt(priv.PublicKey, []byte(data3))
	//if err != nil {
	//	fmt.Println("rsa算法加密失败：", err.Error())
	//	return
	//}
	//originalText3, err:= rsa.RSADecrypt(priv, cipherText3)
	//if err != nil {
	//	fmt.Println("rsa算法解密失败：", err.Error())
	//	return
	//}
	//fmt.Println("rsa解密成功，结果是：", string(originalText3))
	////对原文数据进行签名
	//SignText3, err := rsa.RSASign(priv, []byte(data3))
	//if err != nil {
	//	fmt.Println("rsa算法签名失败：", err.Error())
	//	return
	//}
	////对签名数据进行验证
	//VerfityResult, err := rsa.RSAVerify(priv.PublicKey, []byte(data3), SignText3)
	//if err != nil {
	//	fmt.Println("rsa算法签名真正失败：", err.Error())
	//}
	//if VerfityResult{
	//	fmt.Println("rsa签名验证成功")
	//}else {
	//	fmt.Println("rsa签名认证失败")
	//}
	//
	//五，生成私钥公钥证书文件
	//将生成的私钥保存到硬盘上一个pem文件中，进行持久化存储下来
	//_, err = rsa.GenerateKeys("zeng")
	//if err != nil {
	//	fmt.Println("生成私钥证书失败：", err.Error())
	//}

	//五。五，从pem文件中读取私钥与公钥
	priKey, err := rsa.ReadPemPriKeys("rsa_pri_zeng.pem")
	if err != nil {
		fmt.Println("读取私钥文件出现错误：", err.Error())
		return
	}
	pubKey, err := rsa.ReadPemPubKey("rsa_pub_zeng.pem")
	if err != nil {
		fmt.Println("读取公钥文件出现错误：", err.Error())
		return
	}

	//用读取到的公钥文件进行加密
	data5_5 := "风流快活"
	cipherText5_5, err := rsa.RSAEncrypt(*pubKey, []byte(data5_5))
	//用读取到的私钥进行解密
	originalText5_5, err := rsa.RSADecrypt(priKey, cipherText5_5)
	fmt.Println("解密后的原文是：", string(originalText5_5))

	//六，椭圆曲线数字签名算法
	fmt.Println("========椭圆曲线数字签名算法======")

	//生成密钥
	pri, err := ecc.GenerateECDSAKey()
	if err != nil {
		fmt.Println("生成ECDSA密钥对失败：", err.Error())
		return
	}

	//准备数据
	data6 := "永不失联的爱"

	//数字签名
	r, s, err := ecc.ECDSASign(pri, []byte(data6))
	fmt.Printf("%x\n",r)
	fmt.Printf("%x\n",s)
    fmt.Println(r)
	fmt.Println(s)
	//der格式：

	//数字签名验证
	verifyResult := ecc.ECDSAVerify(pri.PublicKey, []byte(data6), r, s)
	if verifyResult{
		fmt.Println("ECDSA数字签名验证成功")
	}else{
		fmt.Println("ECDSA数字签名验证失败")
	}
	fmt.Println("签名验证结果:", verifyResult)
}

/**
 *明文数据尾部填充
 */
func PKCS5Padding(text []byte, blocksize int) []byte {
	paddingSize := blocksize - len(text) % blocksize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(text, paddingText...)

}
