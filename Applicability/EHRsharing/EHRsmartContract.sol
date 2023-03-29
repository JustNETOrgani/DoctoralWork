// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
// A Smart Contract to to be deployed by MoH.
// Contract begins. 
contract EHRsharingSC {
    // Structs to be used in the contract.
    struct registeredHF{
        string nameOfHF; // Name of the HF.
        address addrOfHF; // Blockchain address of the HF.
        string pubKey; // Sample public key of HF.
		stateOfHF hfState; // State of the HF.
    }

    struct patient{
        bytes32 PatientPHID; // Dynamic identifier of patient. Based on H(HashedID||addrOfHF)
        string PatientIPFShash; // IPFS pointer.
		bytes RingSig; // Ring signature....POC.
        bytes32 hashedEncEHR; // Hash of encrypted EHR.
        uint256 timestamp; // Timestamp.
    }

    string[] pubKeysOfHFs; // Public keys of HFs.
    address[] addrOfHFs; // Blockchain address of HFs.
	
	enum stateOfHF {Registered, Unregistered} // States that HFs could be. 
 
    address MoHaddr; // Contract deployer = MoH.
    uint256 numOfHFsRegistered; // Total registered HFs.
    
    // Mappings.
    mapping (address => registeredHF)  public healthFacility; // Mapping for registered HFs.
    mapping (bytes32 => patient)  public patientData; // Mapping for registered HFs.
	
	// Public states.
    stateOfHF public stateOfTheHF;
	
    // Events begin.
    event MoHscDeployment(string deployMsg);
    event HFRegistered(address HFAddr, string HFname);
    event HFtransactionDone(string message);
    
    // Constructor for the contract.
    constructor() {
        MoHaddr = msg.sender;
		stateOfTheHF = stateOfHF.Unregistered;
		numOfHFsRegistered = 0;
		emit MoHscDeployment("MoH SC deployed");
    }
    
    // Creating an access modifier for contractDeployer
    modifier MoH {
     require(msg.sender == MoHaddr);
     _;
     }
    
    // Access modifier for HF only.
    modifier RegisteredHFOnly {
     require(healthFacility[msg.sender].addrOfHF != address(0), "Unregistered HF"); // Access is restricted to registered HF only.
     _;
     }
     
    // Function to authenticate MoH login via MetaMask.
    function checkMoHaddr() public view returns (bool) {
        if (msg.sender == MoHaddr) {
            return true;
        }
        else {
            return false;
        }
    }

    // Function to register an HF.
    function registerHF(string memory _nameOfHF,address _addrOfHF, string memory _pubKey) MoH public returns (bool){
        healthFacility[_addrOfHF] = registeredHF(_nameOfHF, _addrOfHF, _pubKey, stateOfHF.Registered);
        pubKeysOfHFs.push(_pubKey);
        addrOfHFs.push(_addrOfHF);
        numOfHFsRegistered +=1;
        emit HFRegistered(_addrOfHF, _nameOfHF); // Emit event on registeration of an HF. 
        return true;
    }
    
    // Function to get total number of HFs registered.
    function totalRegisteredHFs() public view returns (uint256) {
        return numOfHFsRegistered;
    }
    
    // Function to get HF details. Only registered HFs can call.
    function getHFInfo() RegisteredHFOnly public view returns (string memory, address, stateOfHF) {
        return (healthFacility[msg.sender].nameOfHF, healthFacility[msg.sender].addrOfHF, healthFacility[msg.sender].hfState);
    }

    // Function to get HF details. Only registered HFs can call.
    function releasePubKeys(uint256 numReq) RegisteredHFOnly public view returns (string[] memory releasedPubs) {
        require(numReq <= pubKeysOfHFs.length, "Insufficent Public keys");
        string[] memory pubs = new string[](numReq); // Create and init temp array.
        for(uint256 i = 0; i < pubKeysOfHFs.length; i++){ 
            pubs[i]=pubKeysOfHFs[i];
            if(i==numReq-1){
                return pubs;
            }
        }
    }

    // HF transaction.
    function transactHF(bytes32 _PHID,string memory _IPFShash,bytes memory _RingSig,bytes32 _hEncEHR, uint256 timestamp) RegisteredHFOnly public returns (bool){
        patientData[_PHID] = patient(_PHID, _IPFShash, _RingSig, _hEncEHR,timestamp);
        emit HFtransactionDone("HF transaction done"); // Emit event on HF transaction sucess. 
        return true;
    }

    // Retrieve patient records....Patient finder function
    function patientFinder(bytes32 hashedID) public view returns (bytes32 PHID, string memory IPFShash,bytes memory RingSig){
        bytes32[] memory computedPHIDs = computePHIDs(hashedID);
        uint256[] memory timestamps = new uint256[](computedPHIDs.length);
        for(uint256 i = 0; i < computedPHIDs.length; i++){ 
            timestamps[i] = patientData[computedPHIDs[i]].timestamp;
        }
        // Get current timestamp
        uint256 pos = maxTimestamp(timestamps);
        // Use current timestamp to get patient data.
        string memory ipfsHash = patientData[computedPHIDs[pos]].PatientIPFShash;
        bytes memory RS = patientData[computedPHIDs[pos]].RingSig;
        bytes32 pID = patientData[computedPHIDs[pos]].PatientPHID;
        return (pID,ipfsHash,RS); // Sig verification can later be done at frontend app.
    }

    // Helper functions
    function computePHIDs(bytes32 hashedID) internal view returns (bytes32[] memory computedPHIDs){
        bytes32[] memory tempPHIDs = new bytes32[](addrOfHFs.length);
        for(uint256 i = 0; i < addrOfHFs.length; i++){ 
            tempPHIDs[i] = keccak256(abi.encode(hashedID,addrOfHFs[i])); // abi.encode instead of abi.encodePacked prevents possible collision.
        }
        return tempPHIDs;
    }

    // Get position of largest timestamp....mimick current timestamp.
    function maxTimestamp(uint256[] memory arr) internal pure returns(uint256 ithPos){
        uint256 maxVal = 0;
        uint256 pos = 0; 
        for(uint256 i = 0; i < arr.length; i++){
            if(arr[i] > maxVal) {
                maxVal = arr[i];
                pos = i; 
            } 
        }
        return pos;
    }
}