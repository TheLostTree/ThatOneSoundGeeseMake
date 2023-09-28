import Random from './csrandom';
import MTKey from './mtkey';

const const2pow16 = 1 << 16;
const const2pow32 = 4294967296n; // 4294967296

function CSLongToInt(number: bigint) {
    return Number(number % const2pow32);
}
function bruteforce(senttime: bigint, serverSeed: bigint, testbuf: Buffer) {
    // report all vars

    let keyprefix = [testbuf[0]^0x45, testbuf[1] ^ 0x67];
    console.log('KeyPrefix:', keyprefix);
    console.log('SentTime:', senttime);
    console.log('serverSeed:', serverSeed);

    console.log('\nbrute force started');
    for (let i = 0; i < 1000; i++) {
        let offset = BigInt(i % 2 == 0 ? i / 2 : -(i - 1) / 2);

        var rand = new Random(CSLongToInt(senttime + offset));

        let clientSeed = rand.NextSafeUint64();
        console.log(clientSeed)
        let seed = clientSeed ^ serverSeed;
        let key = MTKey.getFirstBytes(seed);
        if (key[0] == keyprefix[0] && key[1] == keyprefix[1]) {
            key = MTKey.fromSeed(seed).keybytes;
            //test the last 2 bytes


            console.log('found seed!');
            console.log(`time: ${senttime + offset}`);
            console.log(`seed: ${seed}`);
            return key;
        }
    }
    console.log('sadge');
    return undefined;
}

export default bruteforce;