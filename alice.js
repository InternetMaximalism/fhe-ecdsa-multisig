import {EC} from './lib/makek.js';
import BN from 'bn.js';
import {LWEencrypt,LWEsetup,decryptMatrixToBN} from 'nodeseal-bn';
import { randomBytes } from 'crypto';

var ec = new EC('secp256k1');

export async function step1(aliceKey,message){

    var alicek = ec.makeK(message,ec);
    var setup = await LWEsetup();
    var challengeMsg = _generateRandomBN();

    var alicekInsKey = ec.keyFromPrivate(alicek.k.toJSON(), 'hex');
    var aliceKSig = alicekInsKey.sign(challengeMsg,ec);
    var aliceInsPubKey = ec.keyFromPublic(alicekInsKey.getPublic(), 'hex');

    var decryptor = setup.decryptor;

    var setupWithoutDecryptor = setup;
    setupWithoutDecryptor.decryptor = false;//erase the decryptor(private key)

    var encPriv = LWEencrypt(setup.encryptor,aliceKey.getPrivate(),setup.encoder);
    var aliceKSig = ec.sign(challengeMsg,alicekInsKey);
    var forBob  = {
        setup: setupWithoutDecryptor,
        alicekPubKey: aliceInsPubKey,
        aliceKSig: aliceKSig,
        encPriv:encPriv,
        message:message,
        challengeMsg:challengeMsg
    };

    return {setup: setup, k:alicek, forBob:forBob, decryptor:decryptor}
}

export function step3(fromBob,step1Data,multiAddressPoint){

    var det = _verifyMultiK(fromBob,step1Data.forBob,step1Data.k);
    if(!det){console.log("here");return false};
    var data  = _recoverEncyptedMultSig(step1Data,fromBob.cipherTextMatrix, step1Data.k, step1Data.forBob.message,fromBob.multiK,multiAddressPoint);
    return data
}

function _generateRandomBN(){
    const value = randomBytes(32);
    const bn = new BN(value.toString('hex'), 16);
    return bn;
}

function _verifyMultiK(fromBob,forBob,alicek){

    if(ec.verify(forBob.challengeMsg,fromBob.signature,fromBob.bobKPubKey)){
        if(fromBob.multiK.getX().toString()===fromBob.bobKPubKey.getPublic().mul(alicek.k).getX().toString()){
            return true;
        } 
    }
    return false;
}

function _recoverEncyptedMultSig(step1Data,cipherTextMatrix,alicek,message,multiK,multiP){

    var s_ = decryptMatrixToBN(step1Data.decryptor,cipherTextMatrix.contents,step1Data.setup.encoder);
    var s = s_.mul(new BN(alicek.kinv)).umod(alicek.n);
    var sinv = s.invm(alicek.n);

    var u1 = sinv.mul(message).umod(alicek.n);
    var u2 = sinv.mul(multiK.getX()).umod(alicek.n);
    var p;
    p = ec.g.mul(u1);
    var p2 = multiP.mul(u2);
    p = p.add(p2);

    if(p.x.toString()===multiK.getX().toString()){return true}
    else{return false};

}