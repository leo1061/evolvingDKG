# zk promtp

For each new party you have to get to create a zk proof (see the TODO comment to know where). To do that you have to garther the following things that have been computed before:

- its el gamal sk
- its el gamal pk and Split it into coordinates, let's call them pk.x and pk.y
- all its encrypted shares (let N be the number of them)
- its commitment Y and Split it into coordinates, let's call them Y.x and Y.y
- create a json file similar to scripts/testdata_even_4.json, call it scripts/R1L_i.json where i is the party number
- run this (you must `cd` into script, the command line parameters are the variables you got before):
  `node test_R1Lpot20.js sk pk.x pk.y N R1L_i.json Y.x Y.y`
