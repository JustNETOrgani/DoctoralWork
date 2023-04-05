// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;
// A Smart Contract to to be deployed by WHO.
// Contract begins. 
contract WHOsc {
    // Structs to be used in the contract.
    struct registeredCountry{
        string nameOfCountry; // Name of the Country.
        string bcType; // Blockchain type in use by the country.
        address addrOfCountry; // Blockchain address of the Country.
        address addrOfSC; // Address of SC deployed by Country.
        string tcIPFShash; // IPFS hash of Country's TCs.
		stateOfCountry cState; // State of the country.
    }
	
	enum stateOfCountry {Holding, Activated, Revoked} // States that countries can be. 
 
    address WHOdir; // Contract deployer = WHO.
    uint256 numOfCountriesRegistered; // Total registered countries.
    
    // Mappings.
    mapping (address => registeredCountry)  public country; // Mapping for registered countries.
	
	// Public states.
    stateOfCountry public stateOfTheCountry;
	
    // Events begin.
    event WHOscDeployment(string deployMsg);
    event countryRegistered(address countryAddr, string countryName);
    event countryTCsUpdated(address countryAddr);
    event countryRevoked(address indexed countryAddr, string reason);
    event countryReActivated(address indexed countryAddr, string reason);
    
    // Constructor for the contract.
    constructor() {
        WHOdir = msg.sender;
		stateOfTheCountry = stateOfCountry.Holding;
		numOfCountriesRegistered = 0;
		emit WHOscDeployment("WHO SC deployed");
    }
    
    // Creating an access modifier for contractDeployer
    modifier WHO {
     require(msg.sender == WHOdir);
     _;
     }
    
    // Access modifier for Country only.
    modifier RegisteredCountryOnly {
     require(country[msg.sender].addrOfCountry != address(0), "Unregistered country"); // A registered country cannot access another country's data.
     _;
     }
     
    // Function to authenticate WHO login via MetaMask.
    function checkWHOaddr() public view returns (bool) {
        if (msg.sender == WHOdir) {
            return true;
        }
        else {
            return false;
        }
    }

    // Function to register a country.
    function registerCountry(string memory _bcType, string memory _nameOfCountry,address _addrOfCountry, address _addrOfSC, string memory _tcIPFShash) WHO public returns (bool){
        country[_addrOfCountry] = registeredCountry(_nameOfCountry, _bcType, _addrOfCountry, _addrOfSC, _tcIPFShash, stateOfCountry.Activated);
        numOfCountriesRegistered +=1;
        emit countryRegistered(_addrOfCountry, _nameOfCountry); // Emit event on registeration of a country. 
        return true;
    }
  
    // Function to revoke a country's status.
    function revokeCountry(string memory _nameOfCountry,address _addrOfCountry, string memory reason) WHO public returns (bool){
		require (country[_addrOfCountry].addrOfCountry == _addrOfCountry, "Address of country mismatch");
		require (keccak256(abi.encodePacked(country[_addrOfCountry].nameOfCountry)) == keccak256(abi.encodePacked(_nameOfCountry)), "Name of country mismatch");
        country[_addrOfCountry].cState = stateOfCountry.Revoked;
        emit countryRevoked(_addrOfCountry, reason); // Emit event on revoke of country. 
        return true;
    }
    
    // Function to re-activate a country's status.
    function reactivateCountry(string memory _nameOfCountry,address _addrOfCountry, string memory reason) WHO public returns (bool){
		require (country[_addrOfCountry].addrOfCountry == _addrOfCountry, "Address of country mismatch");
		require (keccak256(abi.encodePacked(country[_addrOfCountry].nameOfCountry)) == keccak256(abi.encodePacked(_nameOfCountry)), "Name of country mismatch");
        country[_addrOfCountry].cState = stateOfCountry.Activated;
        emit countryReActivated(_addrOfCountry, reason); // Emit event on revoke of country. 
        return true;
    }
    
     // Function for country verification at Patient verification time.
    function verificationTime(address _addrOfCountry) public view returns (string memory) {
        require (country[_addrOfCountry].cState == stateOfCountry.Activated, "Country either not listed or revoked");
        return country[_addrOfCountry].tcIPFShash;
    }
    
    // Function to get total number of countries registered.
    function totalRegisteredCountries() public view returns (uint256) {
        return numOfCountriesRegistered;
    }
    
    // Functions that registered countries can interact with.
    // Function to authenticate WHO login via MetaMask.
    function checkLoginAddr() public view returns (bool) {
        if (country[msg.sender].addrOfCountry != address(0)) {
            return true;
        }
        else {
            return false;
        }
    }
        
    // Function to update IPFS hash containing country's TCs.
    function updateTChash(string memory _newTcIPFShash) RegisteredCountryOnly public returns (bool result){
        require (keccak256(abi.encodePacked(country[msg.sender].tcIPFShash)) != keccak256(abi.encodePacked(_newTcIPFShash)), "IPFS hash already exist");
        country[msg.sender].tcIPFShash = _newTcIPFShash;
        emit countryTCsUpdated(msg.sender);
        return true;
    }
    
    // Function to get country details. Only registered countries can call due to msg.sender usage.
    function getCountryInfo() RegisteredCountryOnly public view returns (string memory, string memory, stateOfCountry) {
        return (country[msg.sender].nameOfCountry, country[msg.sender].tcIPFShash, country[msg.sender].cState);
    }
}