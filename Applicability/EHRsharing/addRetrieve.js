import * as IPFS from 'ipfs-core' // npm i ipfs-core
// Go to package.json and add "type" : "module" to be able to import modules.
// No local instance of IPFS running needed.

const ipfs = await IPFS.create()
const patientData = {"Ts": 124, "E_AP": "0x12345", "E_EHR": "g834859"}
const dataBuffer =   Buffer.from(patientData.toString())
const { cid } = await ipfs.add(dataBuffer)
console.log("IPFS hash: ",cid.toString())