package chaincode

import (
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"strings"
)

type Asset struct {
	Inst   *abe.FAME           `json:"cpabe_inst"`
	PubKey *abe.FAMEPubKey     `json:"pubKey"`
	SecKey *abe.FAMESecKey     `json:"secKey"`
	Cipher *abe.FAMECipher     `json:"cipher"`
	Keys   *abe.FAMEAttribKeys `json:"keys"`
}

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
func (s *SmartContract) Encrypt(ctx contractapi.TransactionContextInterface, msg string, boolExp string) error {
	readInst, _ := s.ReadInst(ctx)
	readPub, _ := s.ReadPub(ctx)

	// 构造策略信息
	// "((0 AND 1) OR (2 AND 3)) AND 5",
	//"((清华 AND 计算机) OR (北大 AND 数学))"
	msp, err := abe.BooleanToMSP(boolExp, false)
	if err != nil {
		return err
	}
	// 生成密文数据
	cipher, err := readInst.Inst.Encrypt(msg, msp, readPub.PubKey)
	if err != nil {
		return nil
	}
	cipherJson, err := json.Marshal(cipher)
	err = ctx.GetStub().PutState("cipher", cipherJson)
	return nil
}

func (s *SmartContract) GenerateAttribKeys(ctx contractapi.TransactionContextInterface, gammaStr string) error {
	readInst, _ := s.ReadInst(ctx)
	readSec, _ := s.ReadSec(ctx)

	gamma := strings.Split(gammaStr, ",")
	keys, err := readInst.Inst.GenerateAttribKeys(gamma, readSec.SecKey)
	if err != nil {
		return err
	}
	keysJson, err := json.Marshal(keys)
	err = ctx.GetStub().PutState("keys", keysJson)
	if err != nil {
		return err
	}
	return nil
}

func (s *SmartContract) Decrypt(ctx contractapi.TransactionContextInterface) error {

	readInst, _ := s.ReadInst(ctx)
	readPub, _ := s.ReadPub(ctx)
	readCipher, _ := s.ReadCipher(ctx)
	readKeys, _ := s.ReadKeys(ctx)
	//解密
	msgCheck, err := readInst.Inst.Decrypt(readCipher.Cipher, readKeys.Keys, readPub.PubKey)
	if err != nil {
		return err
	}
	msg, err := json.Marshal(msgCheck)
	fmt.Println(msg)
	return nil
}

func (s *SmartContract) ReadKeys(ctx contractapi.TransactionContextInterface) (*Asset, error) {
	keysJson, err := ctx.GetStub().GetState("keys")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if keysJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}

	var asset Asset
	//var keys abe.FAMEAttribKeys
	err = json.Unmarshal(keysJson, asset.Keys)
	return &asset, err
}

func (s *SmartContract) ReadCipher(ctx contractapi.TransactionContextInterface) (*Asset, error) {
	cipherJson, err := ctx.GetStub().GetState("cipher")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if cipherJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var asset Asset
	//var cipher abe.FAMECipher
	err = json.Unmarshal(cipherJson, asset.Cipher)
	return &asset, err
}

// ReadInst  returns the asset stored in the world state with given id.
func (s *SmartContract) ReadInst(ctx contractapi.TransactionContextInterface) (*Asset, error) {
	instJson, err := ctx.GetStub().GetState("inst")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if instJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var asset Asset
	//var inst abe.FAME
	err = json.Unmarshal(instJson, asset.Inst)

	if err != nil {
		return nil, err
	}

	return &asset, nil
}

// ReadPub returns the asset stored in the world state with given id.
func (s *SmartContract) ReadPub(ctx contractapi.TransactionContextInterface) (*Asset, error) {
	pubKeyJson, err := ctx.GetStub().GetState("pubKey")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if pubKeyJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var asset Asset
	//var pubKey abe.FAMEPubKey
	err = json.Unmarshal(pubKeyJson, asset.PubKey)

	if err != nil {
		return nil, err
	}

	return &asset, nil
}

func (s *SmartContract) ReadSec(ctx contractapi.TransactionContextInterface) (*Asset, error) {
	secKeyJson, err := ctx.GetStub().GetState("secKey")
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if secKeyJson == nil {
		return nil, fmt.Errorf("the inst does not exist")
	}
	var asset Asset
	//var secKey abe.FAMESecKey
	err = json.Unmarshal(secKeyJson, asset.SecKey)
	if err != nil {
		return nil, err
	}
	return &asset, nil
}
