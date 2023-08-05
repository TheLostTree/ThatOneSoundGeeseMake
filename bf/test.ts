import Random from './csrandom';
import MTKey from './mtkey';

const const2pow16 = 1 << 16;
const const2pow32 = 4294967296n; // 4294967296



let testbuffer = Buffer.from('09E397AD', 'hex');
testbuffer[0] ^= 0x45;
testbuffer[1] ^= 0x67;
bruteforce(BigInt('1662278651305'), BigInt('7086588313692556774'), testbuffer);


function CSLongToInt(number: bigint) {
    return Number(number % const2pow32);
}
/*
KeyPrefix: [0x0B, 0xB9]
SentTime: 1658814410247
serverSeed: 4502709363913224634
bf result: 
time: 1658814410242
seed: 12912619839419543994
*/

function bruteforce(senttime: bigint, serverSeed: bigint, keyprefix: Buffer) {
    // report all vars
    console.log('KeyPrefix:', keyprefix);
    console.log('SentTime:', senttime);
    console.log('serverSeed:', serverSeed);

    console.log('\nbrute force started');
    for (let i = 0; i < 1000; i++) {
        let offset = BigInt(i % 2 == 0 ? i / 2 : -(i - 1) / 2);

        var rand = new Random(CSLongToInt(senttime + offset));

        let clientSeed = rand.NextSafeUint64();
        let seed = clientSeed ^ serverSeed;
        //todo: partial key
        let key = MTKey.getFirstBytes(seed);
        if (key[0] == keyprefix[0] && key[1] == keyprefix[1]) {
            console.log('found seed!');
            console.log(`time: ${senttime + offset}`);
            console.log(`seed: ${seed}`);
            return key;
        }
    }
    console.log('sadge');
    return undefined;
}