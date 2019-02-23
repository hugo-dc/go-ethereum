// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package runtime

import (
	"math/big"
	"strings"
	"testing"
	"fmt"
	
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

func TestDefaults(t *testing.T) {
	cfg := new(Config)
	setDefaults(cfg)

	if cfg.Difficulty == nil {
		t.Error("expected difficulty to be non nil")
	}

	if cfg.Time == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.GasLimit == 0 {
		t.Error("didn't expect gaslimit to be zero")
	}
	if cfg.GasPrice == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.Value == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.GetHashFn == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.BlockNumber == nil {
		t.Error("expected block number to be non nil")
	}
}

func TestEVM(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("crashed with: %v", r)
		}
	}()

	Execute([]byte{
		byte(vm.DIFFICULTY),
		byte(vm.TIMESTAMP),
		byte(vm.GASLIMIT),
		byte(vm.PUSH1),
		byte(vm.ORIGIN),
		byte(vm.BLOCKHASH),
		byte(vm.COINBASE),
	}, nil, nil)
}

func TestExecute(t *testing.T) {
	ret, _, err := Execute([]byte{
		byte(vm.PUSH1), 10,
		byte(vm.PUSH1), 0,
		byte(vm.MSTORE),
		byte(vm.PUSH1), 32,
		byte(vm.PUSH1), 0,
		byte(vm.RETURN),
	}, nil, nil)
	if err != nil {
		t.Fatal("didn't expect error", err)
	}

	num := new(big.Int).SetBytes(ret)
	if num.Cmp(big.NewInt(10)) != 0 {
		t.Error("Expected 10, got", num)
	}
}

func TestCall(t *testing.T) {
	state, _ := state.New(common.Hash{}, state.NewDatabase(ethdb.NewMemDatabase()))
	address := common.HexToAddress("0x0a")
	state.SetCode(address, []byte{
		byte(vm.PUSH1), 10,
		byte(vm.PUSH1), 0,
		byte(vm.MSTORE),
		byte(vm.PUSH1), 32,
		byte(vm.PUSH1), 0,
		byte(vm.RETURN),
	})

	ret, _, err := Call(address, nil, &Config{State: state})
	if err != nil {
		t.Fatal("didn't expect error", err)
	}

	num := new(big.Int).SetBytes(ret)
	if num.Cmp(big.NewInt(10)) != 0 {
		t.Error("Expected 10, got", num)
	}
}

func BenchmarkCall(b *testing.B) {
	var definition = `[{"constant":true,"inputs":[],"name":"seller","outputs":[{"name":"","type":"address"}],"type":"function"},{"constant":false,"inputs":[],"name":"abort","outputs":[],"type":"function"},{"constant":true,"inputs":[],"name":"value","outputs":[{"name":"","type":"uint256"}],"type":"function"},{"constant":false,"inputs":[],"name":"refund","outputs":[],"type":"function"},{"constant":true,"inputs":[],"name":"buyer","outputs":[{"name":"","type":"address"}],"type":"function"},{"constant":false,"inputs":[],"name":"confirmReceived","outputs":[],"type":"function"},{"constant":true,"inputs":[],"name":"state","outputs":[{"name":"","type":"uint8"}],"type":"function"},{"constant":false,"inputs":[],"name":"confirmPurchase","outputs":[],"type":"function"},{"inputs":[],"type":"constructor"},{"anonymous":false,"inputs":[],"name":"Aborted","type":"event"},{"anonymous":false,"inputs":[],"name":"PurchaseConfirmed","type":"event"},{"anonymous":false,"inputs":[],"name":"ItemReceived","type":"event"},{"anonymous":false,"inputs":[],"name":"Refunded","type":"event"}]`

	var code = common.Hex2Bytes("6060604052361561006c5760e060020a600035046308551a53811461007457806335a063b4146100865780633fa4f245146100a6578063590e1ae3146100af5780637150d8ae146100cf57806373fac6f0146100e1578063c19d93fb146100fe578063d696069714610112575b610131610002565b610133600154600160a060020a031681565b610131600154600160a060020a0390811633919091161461015057610002565b61014660005481565b610131600154600160a060020a039081163391909116146102d557610002565b610133600254600160a060020a031681565b610131600254600160a060020a0333811691161461023757610002565b61014660025460ff60a060020a9091041681565b61013160025460009060ff60a060020a9091041681146101cc57610002565b005b600160a060020a03166060908152602090f35b6060908152602090f35b60025460009060a060020a900460ff16811461016b57610002565b600154600160a060020a03908116908290301631606082818181858883f150506002805460a060020a60ff02191660a160020a179055506040517f72c874aeff0b183a56e2b79c71b46e1aed4dee5e09862134b8821ba2fddbf8bf9250a150565b80546002023414806101dd57610002565b6002805460a060020a60ff021973ffffffffffffffffffffffffffffffffffffffff1990911633171660a060020a1790557fd5d55c8a68912e9a110618df8d5e2e83b8d83211c57a8ddd1203df92885dc881826060a15050565b60025460019060a060020a900460ff16811461025257610002565b60025460008054600160a060020a0390921691606082818181858883f150508354604051600160a060020a0391821694503090911631915082818181858883f150506002805460a060020a60ff02191660a160020a179055506040517fe89152acd703c9d8c7d28829d443260b411454d45394e7995815140c8cbcbcf79250a150565b60025460019060a060020a900460ff1681146102f057610002565b6002805460008054600160a060020a0390921692909102606082818181858883f150508354604051600160a060020a0391821694503090911631915082818181858883f150506002805460a060020a60ff02191660a160020a179055506040517f8616bbbbad963e4e65b1366f1d75dfb63f9e9704bbbf91fb01bec70849906cf79250a15056")

	abi, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		b.Fatal(err)
	}

	cpurchase, err := abi.Pack("confirmPurchase")
	if err != nil {
		b.Fatal(err)
	}
	creceived, err := abi.Pack("confirmReceived")
	if err != nil {
		b.Fatal(err)
	}
	refund, err := abi.Pack("refund")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 400; j++ {
			Execute(code, cpurchase, nil)
			Execute(code, creceived, nil)
			Execute(code, refund, nil)
		}
	}
}
func benchmarkEVM_Create(bench *testing.B, code string) {
	var (
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(ethdb.NewMemDatabase()))
		sender     = common.BytesToAddress([]byte("sender"))
		receiver   = common.BytesToAddress([]byte("receiver"))
	)

	statedb.CreateAccount(sender)
	statedb.SetCode(receiver, common.FromHex(code))
	runtimeConfig := Config{
		Origin:      sender,
		State:       statedb,
		GasLimit:    10000000,
		Difficulty:  big.NewInt(0x200000),
		Time:        new(big.Int).SetUint64(0),
		Coinbase:    common.Address{},
		BlockNumber: new(big.Int).SetUint64(1),
		ChainConfig: &params.ChainConfig{
			ChainID:             big.NewInt(1),
			HomesteadBlock:      new(big.Int),
			ByzantiumBlock:      new(big.Int),
			ConstantinopleBlock: new(big.Int),
			DAOForkBlock:        new(big.Int),
			DAOForkSupport:      false,
			EIP150Block:         new(big.Int),
			EIP155Block:         new(big.Int),
			EIP158Block:         new(big.Int),
		},
		EVMConfig: vm.Config{},
	}
	// Warm up the intpools and stuff
	bench.ResetTimer()
	for i := 0; i < bench.N; i++ {
		Call(receiver, []byte{}, &runtimeConfig)
	}
	bench.StopTimer()
}

func BenchmarkEVM_CREATE_500(bench *testing.B) {
	// initcode size 500K, repeatedly calls CREATE and then modifies the mem contents
	benchmarkEVM_Create(bench, "5b6207a120600080f0600152600056")
}
func BenchmarkEVM_CREATE2_500(bench *testing.B) {
	// initcode size 500K, repeatedly calls CREATE2 and then modifies the mem contents
	benchmarkEVM_Create(bench, "5b586207a120600080f5600152600056")
}
func BenchmarkEVM_CREATE_1200(bench *testing.B) {
	// initcode size 1200K, repeatedly calls CREATE and then modifies the mem contents
	benchmarkEVM_Create(bench, "5b62124f80600080f0600152600056")
}
func BenchmarkEVM_CREATE2_1200(bench *testing.B) {
	// initcode size 1200K, repeatedly calls CREATE2 and then modifies the mem contents
	benchmarkEVM_Create(bench, "5b5862124f80600080f5600152600056")
}



func BenchmarkSHA1(b *testing.B) {
	fmt.Println("BenchmarkSHA1.")
	// https://etherscan.io/address/0x4e89a683dade995736457bde623e75f5840c2d34#code
	var definition = `[{"constant":true,"inputs":[{"name":"data","type":"bytes"},{"name":"hash","type":"bytes"}],"name":"verify","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"pure","type":"function"}]`

	var code = common.Hex2Bytes("6080604052600436106100405763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663f7e83aee8114610045575b600080fd5b34801561005157600080fd5b506100716024600480358281019290820135918135918201910135610085565b604080519115158252519081900360200190f35b60008060006100ce600086868080601f01602080910402602001604051908101604052809392919081815260200183838082843750949594505063ffffffff6101351692505050565b6bffffffffffffffffffffffff1916915061011887878080601f01602080910402602001604051908101604052809392919081815260200183838082843750610161945050505050565b6bffffffffffffffffffffffff1916919091149695505050505050565b815160009060148301111561014957600080fd5b5001602001516bffffffffffffffffffffffff191690565b60006040518251602084019350604067ffffffffffffffc06001830116016009828203106001811461019257610199565b6040820191505b50776745230100efcdab890098badcfe001032547600c3d2e1f06101ec565b6000838310156101e5575080820151928290039260208410156101e55760001960208590036101000a0119165b9392505050565b60005b828110156105b2576102028482896101b8565b85526102128460208301896101b8565b60208601526040818503106001811461022a57610233565b60808286038701535b506040830381146001811461024757610255565b602086018051600887021790525b5060405b60808110156102dd57858101603f19810151603719820151601f19830151600b198401516002911891909218189081027ffffffffefffffffefffffffefffffffefffffffefffffffefffffffefffffffe1663800000009091047c010000000100000001000000010000000100000001000000010000000116179052600c01610259565b5060805b61014081101561036657858101607f19810151606f19820151603f198301516017198401516004911891909218189081027ffffffffcfffffffcfffffffcfffffffcfffffffcfffffffcfffffffcfffffffc1663400000009091047c0300000003000000030000000300000003000000030000000300000003161790526018016102e1565b508160008060005b60508110156105885760148104801561039e57600181146103da5760028114610414576003811461045357610489565b6501000000000085046a0100000000000000000000860481186f01000000000000000000000000000000870416189350635a8279999250610489565b6501000000000085046f0100000000000000000000000000000086046a0100000000000000000000870418189350636ed9eba19250610489565b6a010000000000000000000085046f010000000000000000000000000000008604818117650100000000008804169116179350638f1bbcdc9250610489565b6501000000000085046f0100000000000000000000000000000086046a010000000000000000000087041818935063ca62c1d692505b50601f770800000000000000000000000000000000000000000000008504168063ffffffe073080000000000000000000000000000000000000087041617905080840190508063ffffffff86160190508083019050807c0100000000000000000000000000000000000000000000000000000000600484028c0151040190507401000000000000000000000000000000000000000081026501000000000086041794506a0100000000000000000000633fffffff6a040000000000000000000087041663c00000006604000000000000880416170277ffffffff00ffffffff000000000000ffffffff00ffffffff86161794505060018101905061036e565b5050509190910177ffffffff00ffffffff00ffffffff00ffffffff00ffffffff16906040016101ef565b506c0100000000000000000000000063ffffffff821667ffffffff000000006101008404166bffffffff0000000000000000620100008504166fffffffff000000000000000000000000630100000086041673ffffffff0000000000000000000000000000000064010000000087041617171717029450505050509190505600a165627a7a723058205141ef912fb4560d9fda28a7c91dcf4da60e01ba569d15ae1b3dae2455f0c8600029")

	abi, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		b.Fatal(err)
	}
	
	//input := common.Hex2Bytes("616263")
	//expected := common.Hex2Bytes("a9993e364706816aba3e25717850c26c9cd0d89d")
	// this is wrong hash.  should fail
	//expected := common.Hex2Bytes("a9993e364706816aba3e25717850c26c9cd0d89e")

	// sha1 test vectors from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs
	// FIPS 180-4 "SHA Test Vectors for Hashing Byte-Oriented Messages"

	// input := common.Hex2Bytes("6cb70d19c096200f9249d2dbc04299b0085eb068257560be3a307dbd741a3378ebfa03fcca610883b07f7fea563a866571822472dade8a0bec4b98202d47a344312976a7bcb3964427eacb5b0525db22066599b81be41e5adaf157d925fac04b06eb6e01deb753babf33be16162b214e8db017212fafa512cdc8c0d0a15c10f632e8f4f47792c64d3f026004d173df50cf0aa7976066a79a8d78deeeec951dab7cc90f68d16f786671feba0b7d269d92941c4f02f432aa5ce2aab6194dcc6fd3ae36c8433274ef6b1bd0d314636be47ba38d1948343a38bf9406523a0b2a8cd78ed6266ee3c9b5c60620b308cc6b3a73c6060d5268a7d82b6a33b93a6fd6fe1de55231d12c97")
	// expected := common.Hex2Bytes("4a75a406f4de5f9e1132069d66717fc424376388")
	
	
	input := common.Hex2Bytes("54ad09ead61540366364b6f311e3d9e3736c71c31bda3b695cbed40f5554d9ef2ab54d10954d3b5f9e909c01a6e97ae8aaf356a4c6ecc87cf86765be2740e55364d586966f73ab677d0fc97a383783f50848143b91e0ee027d96a0ac7be9fdd487777b276d70d97588490507d0b53c3414d1732f839ef62371b54f825836699a1d02f569952a0db248a71750754bedcb56f73b29a40f28065e2b38e7c70f70ccaedebc04f18a8f45448fc9fc2fe1dde2562233d0fd19cbd4cb602484ce5c5c92c07298a18978a657046ae1b4065f55a29dbb24cd95a529b441bcda0178057315dd2851e863dd9b1011a1281f03ad9d32b228d6c7759c88cf47a72405caf3fe7d8c67ae80899fb697f29a66e62db3fdbb1dd31167a3e4314d6589c838ce0c44f25698781203a83f152fbf63b08d5abd6567229d5529676c5523ca8f438b398f9bc1217745d7de7eb15177e62629882457177f41380f0b800f0ad241ce096325a0576b73c20f2bbb94df29b9f00b267bbab551c6b85bbab7a4a109a68051704f2aa0de3430b3763de5613fa2b53b1d0ab5c900f57e175b573c70d885026a4a556123e28138c9a74dcd60206a1dbf531971dcf494324ad6a9fe00a5a8fb5cd77f6c68e024825ba533746334d9d2a1b2f01675946b7cfd13f513d8d9d51430011573f73ee3b5705a3701f2e3b679e921d7cb1d4a440237f983a381ddd5f5edae5ea05966877911ada19d9595cbbd9d8715b85b7ee56f00729ad5811870459bc8a31915bed8784586b86fd5b2de43c7cef306b7961769606683d162f16dad43362c06b3b09d5714cdc5a039a2b8b66eddb9ddb9fba29860bb87c0abd296d4ebe04190bba3a0c1866a10574acd21bc9b9caf64ea154ea6075aeccae522b1639eae2adfb6ffa75ca446e1bd8e9ce0fd55f31cc4d14ce3385e2bfa169748870161882e1a2c2b7bd0754780fa8f75bf23a4ca4a24f70928f96b16fbcd49aee0573e569769a391e4c601563435d5c184d390097fade2b2e68e3804351684bb840c3c00abf5a598a9e6515c4796e6e9f8b7229804871cb1e5a2cddbf11aced73ac9636eb3e6b9a894d76c3fff464c53e377615f21d92d6ceddb30857700b26acb36bc89f66468296b425ae9a56d8f690dbb56471dcb9b4dc6e16be80ff1b5dc00fa4e37be963883f7ce2440803235923d2a07364287f0ba375d86ee011561969fbe226151a4b31f0024d12edabec8353d6c7e15d632b31d0af7877e94933dfe70293ef0f8b761634eeb699af939d0bcd32ac3cd22f76ddd0556787f1294d17d3de4accafbf7c9b8a8ccf56b26cad38ec80cdc446efca562f12360dbc13fa67ccc9674d9a28b7387d76f7c8ba9995b13e3b9d3640269e31495054879eabd4361e6e89c03359be736a47b06e1cacfefb3eedab0142567b05bbba53741d435309553822e32fb51ae2fd4999c55d19418d6af16793b201e929f29aa351bc9d0f681db0b314d3dd34fd8327044cf050f5ce4f01638c33bb51348a8bd4bef0fb61c8c462cae3c4349529b85a90837b06946457781f493be54bbbe00867fa5ef0e2a1d5b8cace755dc40df94ebf07518c95b610c00b693f1251169f9acdb25b100a99ee3d43336bbb39f0b28df0372855825a1793b85ab1c4d9db25bd867579db62076a7ab4c11bcf8fa89092c4914413e2b6b85d969c386f7e7ffedb12a24fb55170d6cbafd60a2d0d6c0ff7bca4493a2f528f7836ac3784978b978e02c72120816cbfda8500bb365bd18d2748febc2ac0c4198e091933a6bd749c40c752b2bf5a618211e4dfa38df36f949be9fef1786f71c3099e51c14868c1599de0e358e444e5c9fc4fb157866cacb2e02023ada553e2387556e444ec22087bffefe7a831e97ff40416245bd20fff647e7c1b253446abd64bd35f42f461a06fd134de052ab0869cc3e8a704d3860e25d16e341c978025190784115003b02f91dc50351421229020b627c7f71d472f8373670ce861c8e49d42f9b8d0ac861cae5be29b49c7c8233c4563f5b711dbf9e9ff07140d056960cf68a49469216bde01ea3c7f0a9109c62c1c1dbea953ace3d5beced81f04ea302be305526e34da1a3901fe3efaef7fef9c84c59162553273e34d1ec782e2e3c93f6cac6174494927b02d88798f658305ea29fc0c668925307f248760dd11bea2764ffa500fc131ad03d76bad3c85cbbfb176118e2a71dd9025df89428233f3426d278f9c854f3c00a0aa285886b2a2636ee3a69512a1c41963c8a4db16ac2a2f806ddca59945c0c912f04ee9f28ecf979f1d4bcfd39b8142a59a5aa90efccbc05c8d5219a047587ce7443000147c7bd2be6d418cd1c18d8287af2b1aefa830bb6e2080573eb67b827a307c09410e5f9b396e586a91a6618f768186cf1d21216711a1f7ecc9359280582fa3841ca6e357bc9ad0d797dc759ffebc0e342c19f659f3ac2948d42745dd1dbc26ff1bf8af9ea46d4b5258b6525a8ca921d8a0d5381a90898509f41e0e1f174076d8a355fce68d70386968d68035acf3522afff55f1f54d4ab9e8d8c43ccf15723bf575183b5d42e289b2caf87c7dc052fa9bdfce3dedd07fd7514e48f4d188aae01bc7dbc9315018c5628c3b17796690ae34f5e5eef85be0b3c2ed969361945864e372d0fe4dc94e428f195c5cb68998446488c38b7db4155424fbd3a1e60024d034c0216517752b091fbb81d39df111c711e28f9ce6a4c5c35dc12aa4c895b52bf8f7f383f81c5821fcb7d3059465a43c254972aa9af398065787c1266e1bb47d166071e259857c920c58797904aff9ad8706943c01693827f895c0ae425ac8ce7643c009a079406539e59bb75695b7211f611cda83ce4a2d2a3250c5ab199a2700e80b8037c04ca169a56348f0e087a1d5a1320c88e97921d4a799f11122d28f9c9678d08422474e86e1f7b33c5810349110005b78836a0ade3dc2bddc3b170f32972f80f167d97577e27f80a0c4fbe23bf4ab4ebb64c8f02f39f3ae752d11aeaa315918e456ab1d24ed243886edefb3bb965e6eb95439dcb1e6564e42bf6974ecad1e20c7b8654e754d0d62559c95b0f93e3f41db1b65d44b8b1024acbbc769e053a5210155af1052486486759795e0de3476518780f6e3e56f4cb81ce7d2966f6a17a3faf52f6ca3284e2c4ea6964c50bf2c26264d910e68db3093f80d33027f3c9b2c1a6090695033f5dd489340fa382889462148e05fba17e43ca9f392b5f90f5a46c95d781041b28120cb253cf47fb8b43bde3a8bddc46b913b986295b8c62c7c786fb690685fec1a7e3f2332420bb4d68dc7ea3a906e1f5f192c21e712ccdb284a74317f79902be67e0c56c9eac66716c243229481a17a755dccfa2ecbf56386454097ed4bbdb510a89a86aaf697189d64b9a841b743c5fc8fe2b313ec280ebff03baf84e7cfd4be84517a7d6d650e92fb9345ea3a3d491b38d5153d7c4d22fbd4ce43e954accd199b9afce9581a921e0d38c13713784bfbdf0de855834be861775f19c79a3eeb4874dbd296be9dec692410e4cf49db16c30cf2f4020a0ca81a6358fbc4c26b7573977dc52da7d6649ac783765be44df19c47ec00ed1777aa4d201faf88d21db2c48de99d561cad42da7ff93e82edb823ae1963d6bdb5743523341efdbcd53beb61dd8622b8230acd50d2da05ed6b03f52009bf3c1be9eb92c429bbaf08d0ad69720fbb1cfcc7d54e254a8e93436616af1ba068fbafbdc40a5787608b13cd5b7120acf252c90df60d806f7db02de7d999c664c6db2038e7e305d4745b86d32d4e923b928dc8ff55528ac8102453f434fa4adf41a317623d65f59a5fe508eb0b46f2440395a1a4db656addadb65c980f1cce99")
	expected := common.Hex2Bytes("0f5176527280b8e3fa69a6c14ce1f759d6e9c67c")

	verifyinput, err := abi.Pack("verify", input, expected)

	if err != nil {
		b.Fatal(err)
	}
	
	fmt.Sprintf("verifyinput:  %v", verifyinput)


	var cfg = new(Config)
	setDefaults(cfg)
	cfg.State, _ = state.New(common.Hash{}, state.NewDatabase(ethdb.NewMemDatabase()))

	var (
		address = common.BytesToAddress([]byte("contract"))
		vmenv   = NewEnv(cfg)
		sender  = vm.AccountRef(cfg.Origin)
	)

	cfg.State.CreateAccount(address)
	cfg.State.SetCode(address, code)

	var (
		ret  []byte
		exec_err  error
		leftOverGas uint64
		//cfg_state *state.StateDB
		//data = make([]byte, len(verifyinput))
	)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ret, leftOverGas, exec_err = vmenv.Call(sender, address, verifyinput, cfg.GasLimit, cfg.Value)
		//res, _, exec_err = Execute(code, verifyinput, nil)
	}
	b.StopTimer()

	gasUsed := cfg.GasLimit - leftOverGas

	if exec_err != nil {
		b.Error(exec_err)
		return
	}
	if common.Bytes2Hex(ret) != "0000000000000000000000000000000000000000000000000000000000000001" {
		b.Error(fmt.Sprintf("Expected %v, got %v", expected, common.Bytes2Hex(ret)))
		return
	}
	fmt.Println("gasUsed:", gasUsed)

}
