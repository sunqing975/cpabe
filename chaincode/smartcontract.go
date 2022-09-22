package chaincode

import (
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"strings"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

func (s *SmartContract) GenerateMasterKeys(ctx contractapi.TransactionContextInterface) error {
	inst := abe.NewFAME()
	pubKey, secKey, err := inst.GenerateMasterKeys()
	instJson, err := json.Marshal(inst)
	pubKeyJson, err := json.Marshal(pubKey)
	secKeyJson, err := json.Marshal(secKey)

	err = ctx.GetStub().PutState("inst", instJson)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState("pubKey", pubKeyJson)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState("secKey", secKeyJson)
	if err != nil {
		return err
	}
	return nil
}

// Encrypt encryption
func (s *SmartContract) Encrypt(ctx contractapi.TransactionContextInterface, msg string, boolExp string) {
	inst, _ := s.ReadInst(ctx)
	pubKey, _ := s.ReadPub(ctx)
	// 构造策略信息
	// "((0 AND 1) OR (2 AND 3)) AND 5",
	//"((清华 AND 计算机) OR (北大 AND 数学))"
	msp, err := abe.BooleanToMSP(boolExp, false)
	if err != nil {
		panic(err)
	}
	// 生成密文数据
	cipher, err := inst.Encrypt(msg, msp, pubKey)
	if err != nil {
		panic(err)
	}
	cipherJson, err := json.Marshal(cipher)
	err = ctx.GetStub().PutState("cipher", cipherJson)
}

func (s *SmartContract) GenerateAttribKeys(ctx contractapi.TransactionContextInterface, gammaStr string) {
	inst, _ := s.ReadInst(ctx)
	secKey, err := s.ReadSec(ctx)
	gamma := strings.Split(gammaStr, ",")
	keys, err := inst.GenerateAttribKeys(gamma, secKey)
	if err != nil {
		panic(err)
	}
	keysJson, err := json.Marshal(keys)
	err = ctx.GetStub().PutState("keys", keysJson)
	if err != nil {
		return
	}
}

func (s *SmartContract) Decrypt(ctx contractapi.TransactionContextInterface) {
	inst, _ := s.ReadInst(ctx)
	pubKey, _ := s.ReadPub(ctx)
	cipher, _ := s.ReadCipher(ctx)
	keys, _ := s.ReadKeys(ctx)
	//解密
	msgCheck, err := inst.Decrypt(cipher, keys, pubKey)
	if err != nil {
		panic(err)
	}
	msg, err := json.Marshal(msgCheck)
	fmt.Println(msg)
}

func (s *SmartContract) ReadKeys(ctx contractapi.TransactionContextInterface) (*abe.FAMEAttribKeys, error) {
	keysJson, err := ctx.GetStub().GetState("keys")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if keysJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var keys abe.FAMEAttribKeys
	err = json.Unmarshal(keysJson, &keys)
	return &keys, err
}

func (s *SmartContract) ReadCipher(ctx contractapi.TransactionContextInterface) (*abe.FAMECipher, error) {
	cipherJson, err := ctx.GetStub().GetState("cipher")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if cipherJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var cipher abe.FAMECipher
	err = json.Unmarshal(cipherJson, &cipher)
	return &cipher, err
}

// ReadInst  returns the asset stored in the world state with given id.
func (s *SmartContract) ReadInst(ctx contractapi.TransactionContextInterface) (*abe.FAME, error) {
	instJson, err := ctx.GetStub().GetState("inst")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if instJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var inst abe.FAME
	err = json.Unmarshal(instJson, &inst)

	if err != nil {
		return nil, err
	}

	return &inst, nil
}

// ReadPub returns the asset stored in the world state with given id.
func (s *SmartContract) ReadPub(ctx contractapi.TransactionContextInterface) (*abe.FAMEPubKey, error) {
	pubKeyJson, err := ctx.GetStub().GetState("pubKey")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if pubKeyJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var pubKey abe.FAMEPubKey
	err = json.Unmarshal(pubKeyJson, &pubKey)

	if err != nil {
		return nil, err
	}

	return &pubKey, nil
}

func (s *SmartContract) ReadSec(ctx contractapi.TransactionContextInterface) (*abe.FAMESecKey, error) {
	secKeyJson, err := ctx.GetStub().GetState("secKey")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if secKeyJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var secKey abe.FAMESecKey
	err = json.Unmarshal(secKeyJson, &secKey)
	if err != nil {
		return nil, err
	}
	return &secKey, nil
}
