// SPDX-License-Identifier: GPL-3.0
/*
 * @title Collusion-resistant multi-server PIR manager
 * @author Anonym <@gmail.com>
 *
 * @dev Implements a contract managing multi-server PIR services and collusion accusation resolution
 */
pragma solidity >=0.7.0;

import { BytesLib } from "./BytesLib.sol";
import "./ECDSA.sol";
// import "@chainlink/contracts/src/v0.7/ChainlinkClient.sol";
// contract ZKCoordinator is ChainlinkClient

contract ZKCoordinator {
    uint defaultMinDeposit = 100000; //vI
    uint defaultThresAccusationFee = 100; // vA
    uint defaultReward = 10; // vR-vA
    uint defaultFines = 100000; // vI
    uint defaultServiceFee = 2; // vS
    uint feeLockDays = 6; // ~5760 = 24*6*40 blocks
    uint complainLock = 2;
    address private owner = msg.sender;
    // address scheduler;
    /**  for oracle api calls on chainlink
     address private oracle; // address of Oracle contract on Kovan network
     bytes32 private jobId; // job id on Kovan network
     uint256 private fee = 1 * 10 ** 18; // depends
    */

    constructor() {}
    
    uint trackBalance;
    bool private failSafeActivated = false;
    
    struct Server {
        uint deposit; // deposit amount
        bool active; // if true, deposit satisfys minimum amount
        uint accusationfee; // accusation fee amount
        mapping(uint => bool) fined;
        bool isSet; 
    }
    mapping(address => Server) public servers;

    // mapping(uint => mapping(address => uint[])) keys;
    
    // bookkeeping the queries 
    struct Journal {
        uint timestamp; // to schedule transaction fee payments
        uint jid; // journal id
        address client; // client address
        uint fee; // service fee amount 
        address[] serverList; // list of addresses of queried servers 
        mapping(address => bytes32) q_comms; // query commitments
        mapping(address => bytes) q_sigs; // query signatures
        mapping(address => bytes32) r_comms; // response commitments
        mapping(address => bytes) r_sigs; // response signatures
        uint8 rcnt; //response count
        bool[] responded; // indicate response received from each server in serverList
        bool active; 
        bool isSet;
    }
    mapping(uint => Journal) public journals;

    // accusation data structure
    struct Proposal {
        address reporter;
        address f; // circuit address
        uint pid; // proposal id
        uint jid; // journal id
        uint e_type; // evidence type
        // 1 - query; 2 - response; 3 - Type 2 with input being query ; 4 - Type 2 with input being response
        bytes ed; // evidence
        bytes m; // zk verifier payload
        uint gasLimit; // the maximum has to be attached for Type 2 function evaluation
        bool isSet;
    }
    mapping(uint => Proposal) public proposals;
    uint jcounter = 0;
    uint pcounter = 0;
    uint pactive = 0;

    // ************************************************************************
    // Events
    
    event Deposited(address indexed payee, uint weiAmount);
    event Withdrawn(address indexed payee, uint weiAmount);
    event Query(address indexed user, uint weiAmount);
    event Response(uint jid, bytes32 response, bytes signature);
    event NewAccusation(uint jid, uint pid);
    event EvidenceCollected(uint pid);
    event EvidenceVerification(Proposal p);
    event CallOracle(uint pid);
    event OracleResponse(uint pid);

    // ************************************************************************
    // Security specific to smart contracts

    modifier isAdmin() {
        require(msg.sender == owner);
        _;
    }

    // fail-safe
    function toggleContractActive() isAdmin public {
        failSafeActivated = !failSafeActivated;
    }

    modifier stopInEmergency { if (!failSafeActivated) _; }
    // modifier onlyInEmergency { if (failSafeActivated) _; }
    
    // ************************************************************************
    // Service

    /** 
     * @dev servers make deposits
     * 
     */
    function deposit() stopInEmergency public payable {
        servers[msg.sender].deposit += msg.value;
        servers[msg.sender].isSet = true;
        trackBalance += msg.value;
        if (servers[msg.sender].active != true && servers[msg.sender].deposit >= defaultMinDeposit) {
            servers[msg.sender].active = true;
        }
        emit Deposited(msg.sender, msg.value);
    }

    /** 
     * @dev check if a server is active
     * 
     */
    function checkActive(address server) public view returns (bool) {
        //require(servers[server].isSet);
        return servers[server].active;
    }

    /** 
     * @dev check deposit amount of an address
     * 
     */
    function checkDeposit(address server) public view returns (uint) {
        //require(servers[server].isSet);
        return servers[server].deposit;
    }
    
    /** 
     * @dev withdraw deposits
     */
    function withdraw() stopInEmergency public {
        // claimServiceFees();
        if (servers[msg.sender].active == true && pactive == 0) {
            uint balance = servers[msg.sender].deposit;
            require(balance>0);
            servers[msg.sender].deposit = 0;
            servers[msg.sender].active = false;
            servers[msg.sender].isSet = false;
            trackBalance -= balance;
            payable(msg.sender).transfer(balance);
            emit Withdrawn(msg.sender, balance);
        }
    }

    /**
    /// @dev update IBE key
    function updateKey(uint[] memory epk) public {
        // require(epk != servers[msg.sender].eph_key);
        servers[msg.sender].eph_key = epk;
    }

    /// @dev obtain public key from address
    function getPk(address server_addr) public view returns (uint[] memory) {
        return servers[server_addr].eph_key;
    }

    /// @dev obtain public key from addresses
    function getPks(address[] memory server_addrs) public view returns (uint[] memory) {
        uint8 num = uint8(server_addrs.length);
        require(num>0);
        uint[] memory eph_keys;
        for (uint8 i=0; i<num; i++) {
            eph_keys[3*i] = servers[server_addrs[i]].eph_key[0];
            eph_keys[3*i+1] = servers[server_addrs[i]].eph_key[1];
            eph_keys[3*i+2] = servers[server_addrs[i]].eph_key[2];
        }
        return eph_keys;
    }
    */

    /// @dev post queries: for convenience, we let query vector and addresses correspond to each other (ordered) but this is not a must, we can have indicator string prepended to each query byte string
    function postRequests(address[] memory s, bytes32[] memory comms, bytes[] memory sigs) public payable {
        require(msg.value > 0); // require positive service fees
        require(s.length > 1); // require querying more than 1 server
        
        journals[jcounter].timestamp = block.timestamp;
        journals[jcounter].jid = jcounter;
        journals[jcounter].client = msg.sender;
        journals[jcounter].serverList = s;
        journals[jcounter].fee = msg.value;
        journals[jcounter].active = true;
        journals[jcounter].isSet = true;
        journals[jcounter].rcnt = 0;
        trackBalance += msg.value;
        for (uint8 i=0; i<s.length; i++) {
            journals[jcounter].q_comms[s[i]] = comms[i];
            journals[jcounter].q_sigs[s[i]] = sigs[i];
            journals[jcounter].responded.push(false);
        }
        jcounter++; 
        emit Query(msg.sender, msg.value);
        // uint targetBlock = 34560 + block.number; // 6 days
        // bytes4 sig = bytes4(keccak256("claimServiceFees(uint)"));
        // bytes4 scheduleCallSig = bytes4(keccak256("scheduleCall(bytes4,uint)"));
        // scheduler.call(scheduleCallSig, sig, targetBlock);
    }

    /// @dev submit response: 
    /// avoided repeated submissions
    /// does not check answer
    function submitResponse(bytes32 r_comm, bytes memory r_sig, uint jid) public {
        for (uint8 i=0; i<journals[jid].serverList.length; i++) {
            if (journals[jid].serverList[i] == msg.sender) {
                require(journals[jid].active == true);
                if (journals[jid].responded[i] == false) {
                    journals[jid].responded[i] = true;
                    journals[jid].rcnt++;
                }
                journals[jid].r_comms[msg.sender] = r_comm;
                journals[jid].r_sigs[msg.sender] = r_sig;
                if (journals[jid].rcnt == journals[jid].serverList.length) {
                    journals[jid].timestamp = block.timestamp; // the timestamp used to schedule payment
                    // schedule transaction fee transfer to the servers: can be troublesome since no guarantee on who is submitting solutions
                    journals[jid].active = false;
                }
                break;
            }
        }
        servers[msg.sender].active = false; 
        emit Response(jid, r_comm, r_sig);
    }

    /** 
     * @dev server retrieves service fees actively; or scheduler calls
     * 
     */
    function claimServiceFees(uint jid) public {
        require(journals[jid].isSet);
        require(journals[jid].rcnt == journals[jid].serverList.length);
        if (journals[jid].timestamp + feeLockDays*1 days <= block.timestamp ) {
            // transfer money to servers
            uint feeShare = journals[jid].fee/journals[jid].serverList.length;
            require(feeShare > 0);
            trackBalance -= journals[jid].fee;
            journals[jid].fee = 0;
            address payable addr;
            address addr1;
            for (uint j=0; j<journals[jid].serverList.length;j++) {
                addr1 = journals[jid].serverList[j];
                addr = payable(addr1);
                addr.transfer(feeShare);
            }
        }
    }

    /** 
     * @dev accuse with evidence 
     * 
     */
    function accuse(uint8 etype, uint jid, bytes memory evidence, address cAdress, uint gas) public payable {
        require(msg.value >= gas);
        servers[msg.sender].deposit += msg.value;
        trackBalance += msg.value;
        // check the well-formedness of evidence
        require(journals[jid].isSet); // journals not deleted
        proposals[pcounter].reporter = msg.sender;
        proposals[pcounter].pid = pcounter;
        proposals[pcounter].jid = jid;
        proposals[pcounter].e_type = etype;
        proposals[pcounter].ed = evidence;
        proposals[pcounter].isSet = true;
        proposals[pcounter].f = cAdress;
        proposals[pcounter].gasLimit = gas;
        trackBalance += msg.value;
        pcounter++; 
        pactive++;
        emit NewAccusation(jid, pcounter-1);
    }

    /** 
     * @dev submit zk proof for Type 1 evidence (-query or -response)
     * @param pid proposal id
     * @param etype evidence type
     * @param cAddr verifier address
     * @param pi zk proof
     */
    function submitNewInfo1(uint pid, uint8 etype, address cAddr, bytes memory m, bytes memory pi) public {
        // make sure the proposal exists and the evidence type matches
        require(proposals[pid].isSet);
        require(proposals[pid].e_type == etype);
        require (etype < 3);
        uint jid = proposals[pid].jid;
        require(!servers[msg.sender].fined[jid]); // check if the server is already fined
        // bytes32 comm;
        bool valid = false;

        for (uint8 i = 0; i < journals[jid].serverList.length; i++) {
            if (journals[jid].serverList[i] == msg.sender) {
                // calling vereifier at address 
                bytes memory payload = abi.encodeWithSignature("verifier()", m);
                address accuser = proposals[pid].reporter;
                // uint gasLimit = proposals[pid].gasLimit;
                servers[accuser].deposit -= proposals[pid].gasLimit;
                trackBalance -= proposals[pid].gasLimit;
                (bool success, bytes memory fOutput) = address(cAddr).staticcall{gas: proposals[pid].gasLimit}(payload);
                require(success);
                valid = BytesLib.equalStorage(proposals[pid].ed, fOutput);
                
                if ((BytesLib.equalStorage(proposals[pid].ed,pi) && valid) || (!valid)) {
                    // execute payments: (1) pay the accuser; (2) fine the accused
                    trackBalance -= defaultFines; //servers[sv].deposit;
                    servers[msg.sender].deposit -= defaultFines; 
                    if (servers[msg.sender].deposit < defaultMinDeposit) {
                        servers[msg.sender].active = false;
                    }
                    payable(accuser).transfer(defaultReward); 
                    servers[msg.sender].fined[jid] = true;
                } else {
                    // (1) fine the false accuser 
                    trackBalance -= servers[accuser].deposit;
                    // address sv = proposals[pid].reporter;
                    servers[accuser].deposit -= defaultFines;
                    if (servers[accuser].deposit < defaultMinDeposit) {
                        servers[accuser].active = false;
                    }
                }
                break;
            }
        }
        // sucessful accusation - delete journal?
        delete proposals[pid];
        pactive--;
    }

    /** 
     * @dev submit auxiliary information for Type 2 evidence
     */
    function submitNewInfo2(uint pid, uint8 etype, address cAddr, bytes memory m, bytes memory pi) public {
        // make sure the proposal exists and the evidence type matches
        require(proposals[pid].isSet);
        require(proposals[pid].e_type == etype);
        require(etype == 3 || etype == 4);

        uint jid = proposals[pid].jid;

        emit EvidenceCollected(pid);
        verify(pid, jid, pi, m, cAddr, proposals[pid].gasLimit);
    }

    /** 
     * @dev report trivial circuits for Type 2 accusation
     */
    function reportTrivial(uint pid, bool trivial) public {
        require(proposals[pid].isSet);
        require(trivial);

        // check non-triviality
        if (trivial) {
            // verify triviality through Tainted Analysis Oracle
            /** create an API request
            Chainlink.Request memory request = buildChainlinkRequest(jobId, address(this), this.fulfill.selector);
            request.add("get", proposals[pid].f);
            sendChainlinkRequestTo(oracle, request, fee);
             */ 
            emit CallOracle(pid);
        }

    }

    /** 
     * @dev report unmatching circuits for accusations
     */
    function reportMismatch(uint pid, bool mismatch) public {
        require(proposals[pid].isSet);
        require(mismatch);

        // check mismatch
        if (mismatch) {
            // verify mismatch through Oracle
            /** create an API request
            Chainlink.Request memory request = buildChainlinkRequest(jobId, address(this), this.fulfill.selector);
            request.add("get", proposals[pid].f);
            sendChainlinkRequestTo(oracle, request, fee);
             */ 
            emit CallOracle(pid);
        }

    }

    /** 
     * @dev Substitute with an actual Oracle contract after deployment on ChainLink
     fulfill(bytes32 _requestId, bool trivial)
     */
    function fullfilTriviality(uint pid, bool trivial) public {
        // require(msg.sender == oracle);
        if (trivial) {
            // punish the accuser and terminate the proposal
            trackBalance -= servers[proposals[pid].reporter].deposit;
            servers[proposals[pid].reporter].deposit -= defaultFines;
            if (servers[proposals[pid].reporter].deposit < defaultMinDeposit) {
                servers[proposals[pid].reporter].active = false;
            }
            delete proposals[pid];
            pactive--;
            return;
        } 
    }

    /** 
     * @dev Substitute with an actual Oracle contract after deployment on ChainLink
     fulfill(bytes32 _requestId, bool trivial)
     */
    function fullfilMismatch(uint pid, bool mismatch) public {
        // require(msg.sender == oracle);
        if (mismatch) {
            uint jid = proposals[pid].jid;
            address sv;
            // punish the accused
            for (uint8 j = 0; j<journals[jid].serverList.length; j++) {
                sv = journals[jid].serverList[j];
                if (!servers[sv].fined[jid] && sv != proposals[pid].reporter) {
                    trackBalance -= servers[sv].deposit;
                    servers[sv].deposit -= defaultFines; 
                    if (servers[sv].deposit < defaultMinDeposit) {
                        servers[sv].active = false;
                    }
                    servers[sv].fined[jid] = true;
                    payable(proposals[pid].reporter).transfer(defaultReward); 
                }
            }
            // sucessful accusation - delete journal?
            delete proposals[pid];
            pactive--;
        } 
    }

    /** 
     * @dev Verify accusation with zk verifier
     * @param cAddr address of zk verifier contract
     */
    function verify(uint pid, uint jid, bytes memory pi, bytes memory m, address cAddr, uint gasLimit) internal {
        // make sure the proposal exists and the evidence type matches
        require(proposals[pid].isSet);
        // evidence all collected
        require(proposals[pid].m.length == journals[jid].serverList.length);

        address sv;
        bool valid = false;
        
        // static call to the zk verifier
        bytes memory payload = abi.encodeWithSignature("verifier()", m);
        address accuser = proposals[pid].reporter;
        servers[accuser].deposit -= gasLimit;
        trackBalance -= servers[accuser].deposit;
        (bool success, bytes memory fOutput) = address(cAddr).staticcall{gas: gasLimit}(payload);
        require(success);
        valid = BytesLib.equalStorage(proposals[pid].ed, fOutput);
        
        if (valid) {
            // execute payments: (1) pay the accuser; (2) fine the accused
            for (uint8 j = 0; j<journals[jid].serverList.length; j++) {
                sv = journals[jid].serverList[j];
                if (!servers[sv].fined[jid] && sv != accuser) {
                    trackBalance -= servers[sv].deposit;
                    servers[sv].deposit -= defaultFines; 
                    if (servers[sv].deposit < defaultMinDeposit) {
                        servers[sv].active = false;
                    }
                    servers[sv].fined[jid] = true;
                    payable(accuser).transfer(defaultReward); 
                }
            }
        } else {
            // (1) fine the false accuser 
            trackBalance -= servers[accuser].deposit;
            servers[accuser].deposit -= defaultFines;
            if (servers[accuser].deposit < defaultMinDeposit) {
                servers[accuser].active = false;
            }
        }

        // sucessful accusation - delete journal?
        delete proposals[pid];
        pactive--;
    }

}