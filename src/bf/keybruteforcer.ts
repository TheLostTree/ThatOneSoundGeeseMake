import * as fs from 'fs';
import Random from './csrandom';
import MTKey from './mtkey';

const const2pow32 = 4294967296n; // 4294967296

function CSLongToInt(number: bigint|number) {
    let buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(number));
    //dot dot dot...
    return buf.readInt32BE(4);
}

class KeyBruteforcer {
    prevSeeds: bigint[] = [];
    storeOldSeeds() {
        fs.writeFileSync('./OLDSEEDS.txt', this.prevSeeds.join('\n'));
    }
    loadOldSeeds() {
        if(!fs.existsSync('./OLDSEEDS.txt')){
            fs.writeFileSync('./OLDSEEDS.txt', '');
            this.prevSeeds = [];
            return;
        };
        let oldseeds = fs.readFileSync('./OLDSEEDS.txt', 'utf-8').split('\n').map(x => BigInt(x));
        this.prevSeeds = oldseeds;
    }
    constructor() {
        this.loadOldSeeds();
    }
    public bruteforce(request: Buffer, sendTime: bigint, serverKey:bigint){
        // Check against already guessed seeds
        for (let oldSeed of this.prevSeeds) {
            let key = this.guess(request, Number(oldSeed), serverKey, 5);
            if (key != null) {
                return key;
            }
        }
        // Check against our arguments with timeStamp offset
        // Effective range of the loop is -1499..1499
        // erm if your ping is above 1 second you're having larger issues lmao
        for (let count = 0; count < 3000; count++) {
            // Special case: 1 would result in 0 again, which we already checked for count = 0
            if (count == 1)
                continue;
            // Alternate between negative and positive offset
            let i = count;
            let offset = BigInt(i % 2 == 0 ? i / 2 : -(i - 1) / 2);


            let guess = CSLongToInt(sendTime + offset);
            // this gives us a hard limit of 50 relogs, but its also nice to cap the maximum bruteforces to 3000 * 50
            let key = this.guess(request, guess, serverKey, 5);
            if (key == null)
                continue;
            // Save found seed
            this.prevSeeds.push(sendTime + offset);
            this.storeOldSeeds();
            return key;
        }
        // If we didn't find the correct key
        return null;
    }


    guess(request: Buffer, timeStamp: number, serverKey: bigint, depth: number) {
        let keyPrefix = [request[0] ^ 0x45, request[1] ^ 0x67];
        let keyPostfix = [request[request.length - 2] ^ 0x89, request[request.length - 1] ^ 0xAB];
        // Check up to depth since static random in client is reused on exiting coop and re-login to server
        timeStamp = CSLongToInt(timeStamp)

        let rand = new Random(timeStamp);
        for (let i = 0; i < depth; i++) {
            let clientSeed = rand.NextSafeUint64();
            let seed = clientSeed ^ serverKey;

            // Check data prefix
            let key = MTKey.getFirstBytes(seed);
            if (key[0] != keyPrefix[0] || key[1] != keyPrefix[1]){
                continue;
            }
                
            // Check data suffix
            let full = MTKey.fromSeed(seed).keybytes;
            if (full[(request.length - 2) % 4096] != keyPostfix[0] ||
                full[(request.length - 1) % 4096] != keyPostfix[1])
                continue;
            // Return key for found seed
            return full;
        }
    }
}


export default KeyBruteforcer;