// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
// A Smart Contract to to be deployed by the Trusted Party.
// Contract begins. 
contract keyIssuance {
    // Structs to be used in the contract.
    struct KGCpublicParams{
        uint256 X; // Public key of trusted party (KGC).
        address KGCaddr; // Blockchain addres of KGC.
        uint T_M;  // Epoch or time-bound.
        string BilinearPairing; // Pairing name....SuperSingular
        string HashFuncs; // Cryptographic hash functions.
    }

    struct UserPublicParam{
        string userID; // ID of user.
        uint256 Yval; // Part of user public key.
		uint256 QID; // QID of the user.
    }

    struct UserEmbeddedData{
        uint s; // Check value.
        uint256 YID; // User-embedded private key.
    }
 
    address addrOfTrustedParty; // Contract deployer = KGC.
    
    // Mappings.
    mapping (address => KGCpublicParams)  public trustedParty; // Mapping for public params.
    mapping (string => UserPublicParam)  public systemUsers; // Mapping for users.
    mapping (uint => UserEmbeddedData)  public embeddedKeys; // Mapping for embedded keys.
	
    // Events begin.
    event BlockchainBasedSCFDeployment(string deployMsg);
    event PublicParamsPublished(string publishedParamsMsg);
    event NewUserRegistered(string registMsg);
    event PublishUserEmbeddedData(string embeddedKeyPubMsg);
    
    // Constructor for the contract.
    constructor() {
        addrOfTrustedParty = msg.sender;
		emit BlockchainBasedSCFDeployment("Key issuance smart contract deployed");
    }
    
    // Creating an access modifier for contractDeployer
    modifier TP {
     require(msg.sender == addrOfTrustedParty);
     _;
     }
    
    // Function to publish params.
    function publishParams(uint256 _X, address _KGCaddr, uint _T_M, string memory _BilinearPairing, string memory _HashFuncs) TP public returns (bool){
        trustedParty[_KGCaddr] = KGCpublicParams(_X, _KGCaddr, _T_M, _BilinearPairing, _HashFuncs);
        emit PublicParamsPublished("Public params published"); // Emit event on publication of params. 
        return true;
    }

    // Function for users to publish their data.
    function keyRequest(string memory _userID, uint256 _Yval, uint256 _QID) public returns (bool){
        systemUsers[_userID] = UserPublicParam(_userID, _Yval, _QID);
        emit NewUserRegistered("Key request executed"); // Emit event on key request success. 
        return true;
    }

    // Functon to publish user embedded data on-chain.
    function issueKey(uint _s, uint256 _YID) TP public returns (bool){
        embeddedKeys[_s] = UserEmbeddedData(_s, _YID);
        emit PublishUserEmbeddedData("Key issueing success: User-embedded key published"); // Emit event on key issuance success. 
        return true;
    }
}