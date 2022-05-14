# Coordinator for mitigating collusion in multi-server PIR

## Cost in Berlin EVM

| operation                         | cost in gas |
| --------------------------------- | ----------- |
| deployment                        | 4697299     |  
| deposit                           | 105436      | Average(116836 99736 99736)
| post requests                     | 405657      | 
| submit response                   | 97400       | Average(114558 83308 94334)
| claim service fees                | 33103       |
| accuse                            | 223766      | Average(240013 225713 205573 224998)
| verify type 1                     | 61822       | 
| check triviality                  | 66991 + Chainlink costs| Sum(25439 41552)
| verify type 2                     | 275279      | Sum(82649 68375 124255)

## Example requests
### Setup
>> Addresses of queried servers:
Server 1: 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2
Server 2: 0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db
Server 3: 0x78731D3Ca6b7E34aC0F824c42a7cC18A495cabaB

>> Address of example user: 0x617F2E2fD72FD9D5503197092aC168c91465E7f2

>> Signature scheme: ECDSA (using the curve secp256k1 + SHA3-256)
Private key: 0x79afbf7147841fca72b45a1978dd7669470ba67abbe5c220062924380c9c364b 
Public key: (0x3804a19f2437f7bba4fcfbc194379e43e514aa98073db3528ccdbdb642e240, 0x6b22d833b9a502b0e10e58aac485aa357bccd1df6ec0fa4d398908c1ac1920bc)

>> Commitment scheme: SHA-3 hash

### Three queries:
Query 1: "0x8AA4", with commitment / hash "0x97b76ac95098db47598c9262dc539a7438402f1272d37226c9433dc4cb394d08"
Query 2: "0x8A24", "0x7e3af5120fde202ac27cab61b9ce3fe66ca03350a6ebd1357206b7470170ec77"
Query 3: "0x8A26", "0x33e3348b6b3c6765442204236f167c1d019df61bd1c15eed19f7f18f349a087d"

s = ["0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2", "0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db", "0x78731D3Ca6b7E34aC0F824c42a7cC18A495cabaB"]
comms = ["0x97b76ac95098db47598c9262dc539a7438402f1272d37226c9433dc4cb394d08", "0x7e3af5120fde202ac27cab61b9ce3fe66ca03350a6ebd1357206b7470170ec77", "0x33e3348b6b3c6765442204236f167c1d019df61bd1c15eed19f7f18f349a087d"]


### Three (fake) responses:
 - server 1
@0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2
resp = 35492 0x8AA4
r-comm = "0x97b76ac95098db47598c9262dc539a7438402f1272d37226c9433dc4cb394d08"

 - server 2
@0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db
resp = 35364 0x8A24
r-comm = "0x7e3af5120fde202ac27cab61b9ce3fe66ca03350a6ebd1357206b7470170ec77"

 - server 3
@0x78731D3Ca6b7E34aC0F824c42a7cC18A495cabaB
resp = 35366 0x8A26
r-comm = "0x33e3348b6b3c6765442204236f167c1d019df61bd1c15eed19f7f18f349a087d"
         
### Accuse
- Type 1
Since either query or response works, we can accuse with an exchanged query. 
eType = 1 (eType is the categories in the implementation; different from the type characterization in the paper)
evidence = "0x8AA4"

- Type 2
eType = 3 
evidence = "0x8AA6" or "0x0000000000000000000000000000000000000000000000000000000000008AA6"

"0x0000000000000000000000000000000000000000000000000000000000008AA4"
"0x0000000000000000000000000000000000000000000000000000000000008A24"
"0x0000000000000000000000000000000000000000000000000000000000008A26"
address(0) "0x0000000000000000000000000000000000000000"