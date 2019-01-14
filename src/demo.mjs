import Hasher from './lib/hasher';
import PrivateKey from './lib/private-key';
import PublicKey from './lib/public-key';
import Prng from './lib/prng';
import Signature from './lib/signature';
import BN from 'bn.js';
import {setupParameters, generateKeyPair, voteForCandidate, signVote, ecPointToString, H} from './lib/voterLib';

//PARAMETERS - SET YOUR OWN
const voterCount = 10;

//Setup
const params = setupParameters();
//console.log(params);

//Generate the key pair of each candidate
//The second key pair should be identity-based!
const candidateAKeyPairs = [generateKeyPair('candidateasecreta', params), generateKeyPair('candidateasecretb', params)];
const candidateBKeyPairs = [generateKeyPair('candidatebsecreta', params), generateKeyPair('candidatebsecretb', params)];
//console.log(candidateAKeyPairs);

//Generate the key pairs for the voters
const voterKeyPairs = [];
const voterListPublicKeys = [];
let keyPair;
for (let i=0; i<voterCount; i++) {
  keyPair = generateKeyPair(params[3].random, params);
  voterKeyPairs.push(keyPair);
  voterListPublicKeys.push(keyPair[1]);
};
// console.log(voterKeyPairs);
// console.log(voterListPublicKeys);

//construct votes for candidates
let voteA = voteForCandidate(candidateAKeyPairs, params);
let voteB = voteForCandidate(candidateBKeyPairs, params);
// console.log(voteA);

//Votes will be gathered in this list
const allVotes = [];

//Sign the vote using voter's private key and Voter list (Everyone, except one, will vote for A)
for (let i=1; i<voterCount; i++) {
  allVotes.push([voteA, signVote(voteA, voterKeyPairs[i][0], voterListPublicKeys)]);
}
allVotes.push([voteB, signVote(voteB, voterKeyPairs[0][0], voterListPublicKeys)]);
//console.log(allVotes[0]);

//Vote tallying
const keyImages = new Set();
let ecPoint;
let sum_c;
let votesForCandidateA = 0;
let votesForCandidateB = 0;
for (let i=0; i<allVotes.length; i++) {
  ecPoint = ecPointToString(allVotes[i][1].key_image);

  //Check if key image has voted already
  if (keyImages.has(ecPoint)) {
    continue;
  }
  keyImages.add(ecPoint);

  //Verify 2nd
  sum_c = 0;
  for (let j=0; j<allVotes[i][1].c_array.length; j++) {
    sum_c += allVotes[i][1].c_array[j];
  }
  //console.log(sum_c);

  // console.log(allVotes[i][1]);
  // //H(m, )
  // break;
  //console.log(candidateAKeyPairs[0][0].value);
  //break;
  //const _P = ec.g.mul(new BN(H(R.mul(a).encode('hex')))).add(B).encode('hex');


  //Verify 3rd
  let candA_collect = params[0].g.mul(new BN(H(allVotes[i][0][1].point.mul(candidateAKeyPairs[0][0].value).encode('hex')))).add(candidateAKeyPairs[1][1].point).encode('hex');

  if (candA_collect === allVotes[i][0][0]) {
    votesForCandidateA++;
    continue;
  }

  let candB_collect = params[0].g.mul(new BN(H(allVotes[i][0][1].point.mul(candidateBKeyPairs[0][0].value).encode('hex')))).add(candidateBKeyPairs[1][1].point).encode('hex');

  if (candB_collect === allVotes[i][0][0]) {
    votesForCandidateB++;
  }

};

console.log(`Votes for candidate A: ${votesForCandidateA}`);
console.log(`Votes for candidate B: ${votesForCandidateB}`);
