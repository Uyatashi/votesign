import elliptic from 'elliptic';
import Hasher from './hasher';
import Prng from './prng';
import PrivateKey from './private-key';
import BN from 'bn.js';
import keccakHash from 'keccak';

export function setupParameters() {
  //Setup (Needs to be the same for everyone)
  const ECurve = new elliptic.eddsa('ed25519'); // Elliptic Curve
  const G = [ECurve.g.x,ECurve.g.y]; //Base point
  const hasher  = new Hasher();
  const prng = new Prng();

  return [ECurve, G, hasher, prng];
};

//Hash function
export function H(input){
  return keccakHash('keccak256').update(input).digest('hex');
};

export function generateKeyPair(secret, params) {
  const ec = params[0];
  const KeyPair = ec.keyFromSecret(secret); //Constructing key pairs this way might not be the best way

  const privateKey = new PrivateKey(KeyPair.priv(), params[2]);
  return [privateKey, privateKey.public_key];
};

export function ecPointToString(ecPoint) {
  return (ecPoint.x.toString() + ecPoint.y.toString() + ecPoint.z.toString())
};

//Vote for candidate
//candidateKeyPairs = [[a,A],[b,B]]
//***B should be derived from the candidate's name(string)
export function voteForCandidate(candidateKeyPairs, params) {
  const ec = params[0];
  const G = params[1];

  //Voter computes a random key
  const randomKeyPair = generateKeyPair('voterrandomsecret', params); //Must introduce randomness here
  //console.log(randomKeyPair[0].value);

  //Voter computes the Stealth Address of the candidate
  const SA = ec.g.mul(new BN(H(candidateKeyPairs[0][1].point.mul(randomKeyPair[0].value).encode('hex')))).add(candidateKeyPairs[1][1].point).encode('hex');
  //console.log(SA);

  //The vote before signing
  const vote = [SA, randomKeyPair[1]] // (SA,R)
  return vote;
};

//Just for testing purposes
export function generateVoterList(numberOfVoters) {
  const prng = new Prng();
  const hasher = new Hasher();
  const voterList = [];

  for (let i=0; i < numberOfVoters; i++) {
    voterList.push(new PrivateKey(prng.random,hasher).public_key);
  }
  return voterList;
};

//Returns JUST the signature
export function signVote(vote, voterPrivateKey, voterListPublicKeys) {
  //Concatenate SA and R before signing
  const msg = vote[0] + ecPointToString(vote[1].point);
  const signature = voterPrivateKey.sign(msg, voterListPublicKeys);
  return signature;
};
