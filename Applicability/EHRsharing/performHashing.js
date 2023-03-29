const ethers = require("ethers") // npm i ethers@4.0.49

const abi = ethers.utils.defaultAbiCoder;

hashOne = ethers.utils.keccak256(abi.encode(["string"], ["CHN345"]))
console.log('First Digest:', hashOne) // 0x6814531d1fec7c42b86b534ba8c335cb96b7b6030e410027da6bfca30fa8df8f

hashTwo = ethers.utils.keccak256(abi.encode([ "bytes32", "address" ], [ "0x6814531d1fec7c42b86b534ba8c335cb96b7b6030e410027da6bfca30fa8df8f", "0x136f79926505f76c3252a921937dd5ab18ded515" ]))
// This matches the solidity smart contract code => keccak256(abi.encode("Hello", "world!"))
console.log('Second Digest:', hashTwo)