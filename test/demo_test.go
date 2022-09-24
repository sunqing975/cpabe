package test

import (
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"testing"
)

func TestDemo(t *testing.T) {

	inst := abe.NewFAME()
	instJson, _ := json.Marshal(inst)
	//fmt.Println("instJson", instJson)

	var new_inst abe.FAME
	err := json.Unmarshal(instJson, &new_inst)
	if err != nil {
		return
	}
	// 生成主密钥 和 公共密钥
	pubKey, secKey, err := new_inst.GenerateMasterKeys()
	if err != nil {
		panic(err)
	}
	pubKeyJson, err := json.Marshal(pubKey)
	secKeyJson, err := json.Marshal(secKey)
	var newPubkey abe.FAMEPubKey
	err = json.Unmarshal(pubKeyJson, &newPubkey)
	var newSeckey abe.FAMESecKey
	err = json.Unmarshal(secKeyJson, &newSeckey)

	// 明神数据信息
	msg := "baidu.com"

	// 构造策略信息
	// "((0 AND 1) OR (2 AND 3)) AND 5",
	msp, err := abe.BooleanToMSP("((清华 AND 计算机) OR (北大 AND 数学))", false)
	if err != nil {
		panic(err)
	}

	// 生成密文数据
	cipher, err := new_inst.Encrypt(msg, msp, &newPubkey)
	if err != nil {
		panic(err)
	}
	cipherJson, err := json.Marshal(cipher)
	var newCipher abe.FAMECipher
	err = json.Unmarshal(cipherJson, &newCipher)
	// 解密时构造 属性
	gamma := []string{"清华", "计算机"}

	keys, err := new_inst.GenerateAttribKeys(gamma, &newSeckey)
	if err != nil {
		panic(err)
	}
	keysJson, err := json.Marshal(keys)
	var newKeys abe.FAMEAttribKeys
	err = json.Unmarshal(keysJson, &newKeys)
	if err != nil {
		return
	}
	//解密
	msgCheck, err := new_inst.Decrypt(&newCipher, &newKeys, &newPubkey)
	if err != nil {
		panic(err)
	}
	fmt.Println(msgCheck)
}
