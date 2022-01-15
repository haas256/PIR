var Coordinator = artifacts.require("SimpleCoordinator");

module.exports = function(deployer) {
  // deployment steps
  deployer.deploy(Coordinator);
  // deployer.deploy(Coordinator,1002, 25,30,40,1001,1002,1);
};