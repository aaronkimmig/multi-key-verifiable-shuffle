(* ::Package:: *)

(* ::Title:: *)
(*Schnorr Primes*)


(* ::Section:: *)
(*Meta*)


(* ::Text:: *)
(*Description: Generating Primes, Schnorr Primes and Generators of Schnorr Groups*)
(*Author: Aaron Kimmig <kimmiga@informatik.uni-freiburg.de>*)
(*Package Version: 1.2.0*)
(*Last Edited: 2023-02-20*)


BeginPackage["SchnorrPrimes`"];


ParallelRandomPrime::usage = "Generates a random prime p using multiple threads";
FindRandomSchnorrGroup::usage = "Finds a random Schnorr Group with a cofactor from a predefined set";
ParallelFindRandomSchnorrGroup::usage = "Finds a random Schnorr Group with a cofactor from a predefined set using multiple threads";
RandomSchnorrGroupGenerator::usage = "Finds a random generator for the Schnorr Group with specified modulus p and cofactor";
RandomSchnorrGroupGenerators::usage = "Finds n distinct random generators for the Schnorr Group with specified modulus p and cofactor";


Begin["`Private`"];


(* ::Section:: *)
(*Generate Random Prime (Parallel)*)


ParallelRandomPrimeHalfRange[halfRange_,batchSize_: 256]:=Module[{candidates,candidateTests,primeIndices,tests},
	candidates={};
	primeIndices={};
	tests=0;
	While[Length[primeIndices]==0,
		candidates=RandomInteger[halfRange,batchSize]*2+1;
		candidateTests=ParallelMap[PrimeQ,candidates];
		tests=tests+batchSize;
		primeIndices=Position[candidateTests,True];
	];
	{candidates[[primeIndices[[1]][[1]]]],tests}
]
ParallelRandomPrime[bits_Integer,batchSize_:256]:=ParallelRandomPrimeHalfRange[{2^(bits-1),2^bits-1},batchSize]


(* ::Section:: *)
(*Generate Candidate q for Order of Schnorr Group*)


RandomSchnorrGroupOrderHalfRange[halfRange_]:=Module[{q,tests},
	q=RandomInteger[halfRange]*2+1;
	tests=1;
	While[!PrimeQ[q],
		q=RandomInteger[halfRange]*2+1;
		tests++
	];
	{q,tests}
]
RandomSchnorrGroupOrder[bits_Integer]:=RandomSchnorrGroupOrderHalfRange[{2^(bits-1),2^bits-1}]


(* ::Section:: *)
(*Try to Combine Cofactors with Candidate q to get Prime Modulus p*)


TryToFindSchnorrGroupModulus[q_Integer,cofactors:{__Integer}]:=Module[{cofactor,p,foundSchnorrPrime,testIndex},
	foundSchnorrPrime=False;
	testIndex=1;
	p=0;
	cofactor=0;
	While[testIndex<=Length[cofactors]&&!foundSchnorrPrime,
		cofactor=cofactors[[testIndex]];
		p=q*cofactor+1;
		foundSchnorrPrime=PrimeQ[p];
		testIndex++;
	];
	If[foundSchnorrPrime,
		{p,cofactor,testIndex-1},
		{0,0,testIndex-1}
	]
]


(* ::Section:: *)
(*Find Schnorr Group: Generate new Candidate q until it can be Combined to a Prime Modulus p with one of the Cofactors (Sequential & Parallel)*)


FindRandomSchnorrGroup[groupOrderBits_Integer,cofactors:{__Integer}]:=Module[{halfRange,cofactor,tests,q,qRes,p,pRes},
	cofactor=0;
	tests=0;
	halfRange={2^(groupOrderBits-1),2^groupOrderBits-1};
	While[cofactor==0,
		qRes=RandomSchnorrGroupOrderHalfRange[halfRange];
		q=qRes[[1]];
		tests+=qRes[[2]];
		pRes=TryToFindSchnorrGroupModulus[q,cofactors];
		p=pRes[[1]];
		cofactor=pRes[[2]];
		tests+=pRes[[3]];
	];
	{p,q,cofactor,tests}
]
ParallelFindRandomSchnorrGroup[groupOrderBits_Integer,cofactors:{__Integer},batchSize_:64]:=Module[{lock,stop,halfRange,cofactor,tests,batchTests,result,q,qRes,p,pRes,i},
	SetSharedVariable[stop];
	SetSharedVariable[tests];
	SetSharedVariable[result];
	tests=0;
	halfRange={2^(groupOrderBits-1),2^groupOrderBits-1};
	stop=False;
	result={0,0,0};
	ParallelDo[
		If[stop,Break[]];
		cofactor=0;
		batchTests=0;
		For[i=1,i<=batchSize&&cofactor==0,i++,
			qRes=RandomSchnorrGroupOrderHalfRange[halfRange];
			q=qRes[[1]];
			pRes=TryToFindSchnorrGroupModulus[q,cofactors];
			p=pRes[[1]];
			cofactor=pRes[[2]];
			batchTests+=qRes[[2]]+pRes[[3]];
		];
		CriticalSection[lock,
			tests+=batchTests;
			If[cofactor!=0,
				result={p,q,cofactor};
				stop=True;
			]
		],
		(*maximum number of iterations of loop (practically iterate as long as possible)*)
		{i,2^32},
		Method->"CoarsestGrained",
		DistributedContexts->"SchnorrPrimes`"
	];
	Append[result,tests]
]


(* ::Section:: *)
(*Find Pseudorandom Generator(s) of Schnorr Group*)


RandomSchnorrGroupGenerator[p_Integer,cofactor_Integer]:=Module[{base,generator},
	base=1;
	generator=1;
	While[generator==1,
		base=RandomInteger[{2,p-1}];
		generator=PowerMod[base,cofactor,p];
	];
	{generator,base}
]
RandomSchnorrGroupGenerators[p_Integer,cofactor_Integer,n_Integer]:=Module[{base,generator,bases,generators,i},
	base=1;
	generator=1;
	bases={};
	generators={};
	For[i=1,i<=n,i++,
		While[generator==1&&!ContainsAny[generators,{generator}],
			base=RandomInteger[{2,p-1}];
			generator=PowerMod[base,cofactor,p];
		];
		AppendTo[generators,generator];
		AppendTo[bases,base];
	];
	{generators,bases}
]


End[];


EndPackage[];
