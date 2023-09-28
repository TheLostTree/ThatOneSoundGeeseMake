import bruteforce from './bruteforce';



let testbuffer = Buffer.from('09E397AD', 'hex');
// testbuffer[0] ^= 0x45;
// testbuffer[1] ^= 0x67;
bruteforce(BigInt('1662278651305'), BigInt('7086588313692556774'), testbuffer);


/*
KeyPrefix: [0x0B, 0xB9]
SentTime: 1658814410247
serverSeed: 4502709363913224634
bf result: 
time: 1658814410242
seed: 12912619839419543994
*/



// import Random from './csrandom';

// let x = new Random(1);
// for(let i = 0; i < 10; i++){
//     console.log(x.NextSafeUint64().toString());
// }


