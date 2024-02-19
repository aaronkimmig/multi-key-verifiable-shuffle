(* ::Package:: *)

(* ::Title:: *)
(*Fiat-Shamir Transform*)


(* ::Section:: *)
(*Meta*)


(* ::Text:: *)
(*Description: Utility functions for Fiat-Shamir transform*)
(*Author: Aaron Kimmig <kimmiga@informatik.uni-freiburg.de>*)
(*Package Version: 0.1.1*)
(*Last Edited: 2023-04-26*)


BeginPackage["FiatShamir`"];


NumbersToHexString::usage = "Convert Array of Integers to Hex String With Configurable Minimum Output Bits";
SHA256Multi::usage = "SHA256-Based Hash Function With Configurable Minimum Output Bits";


Begin["`Private`"];


(* ::Section:: *)
(*SHA256-Based Hash Function With Configurable Minimum Output Bits*)


NumbersToHexString[numbers: {__Integer}, minOutputBits_Integer, minBitsPerNumber_: {}] := Module[
	{allBits,i,number,minBits,bits,minHexDigits},
	If[minBitsPerNumber=={},
		allBits=Flatten[Map[IntegerDigits[#,2]&,numbers]];
	(*Else*),
		If[Total[minBitsPerNumber]<minOutputBits,
			Print["Error: Not enough entropy guaranteed to output "<>ToString[minOutputBits]<>" bits (only total of "<>ToString[Total[minBitsPerNumber]]<>")."];
			Return[""]
		];
		allBits={};
		For[i=1,i<=Length[numbers],i++,
			number=numbers[[i]];
			minBits=minBitsPerNumber[[i]];
			bits=IntegerDigits[number,2];
			If[Length[bits]<=minBits,
				allBits=Join[allBits,ConstantArray[0,minBits-Length[bits]]];
			];
			allBits=Join[allBits,bits];
		];
	];
	IntegerString[FromDigits[allBits],16]
]
SHA256Multi[inputHexString_String, minOutputBits_Integer, minInputBits_:0, doubleOutputBits_:True, verbose_:0] := Module[
	{minInputBitsValue,hashOutputHexDigits,hashOutputBits,hashChunks,srcStringHexDigitsPerChunk,compositeHashValue,factor,hexDigitsIndex},
	If[verbose>=2,Print["SHA256Multi: Input Hex String: "<>inputHexString]];
	minInputBitsValue = If[minInputBits == 0, minOutputBits, minInputBits];
	If[minInputBitsValue > StringLength[inputHexString] * 4,
		Print["Security Assertion Failure: minInputBitsValue <= StringLength[srcString] * 4. Not enough entropy! Continuation could leave your crypto system with a vulnerability!"]
	];
	hashOutputHexDigits = 64;
	hashOutputBits = hashOutputHexDigits * 4;
	hashChunks = Ceiling[minOutputBits * If[doubleOutputBits, 2, 1] / hashOutputBits];
	srcStringHexDigitsPerChunk = Ceiling[StringLength[inputHexString] / hashChunks];
	compositeHashValue = 0;
	factor = 1;
	hexDigitsIndex = 0;
	For[i = 1, i <= hashChunks-1, i++,
		compositeHashValue += Interpreter["HexInteger"][Hash[StringTake[inputHexString,{hexDigitsIndex+1,hexDigitsIndex+srcStringHexDigitsPerChunk}],"SHA256","HexString"]] * factor;
		factor *= 2^hashOutputBits;
		hexDigitsIndex += srcStringHexDigitsPerChunk;
	];
	If[hexDigitsIndex <= StringLength[inputHexString],
		compositeHashValue += Interpreter["HexInteger"][Hash[StringTake[inputHexString,{hexDigitsIndex+1,StringLength[inputHexString]}],"SHA256","HexString"]] * factor,
		Print["Assertion Failure for: hexDigitsIndex <= StringLength[inputHexString]"]
	];
	compositeHashValue
]
SHA256Multi[inputNumbers: {__Integer}, minOutputBits_Integer, minBitsPerNumber_: {}, doubleOutputBits_: True, verbose_: 0] := SHA256Multi[NumbersToHexString[inputNumbers, minOutputBits, minBitsPerNumber], minOutputBits, Total[minBitsPerNumber], doubleOutputBits, verbose]


End[];


EndPackage[];
