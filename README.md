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
| Plonk Verifier                    | 2286423     | 1989563 (deploy) + 296860 (execution)
| Goth16 Verifier                   | 2360902     | 2079665 (deploy) + 281237 (execution)
