(* ::Package:: *)

(*(* :Context: Bulletproofs` *)*)
(**)
(*(* :Title: Sigma Protocol utility Functions Version 2*)*)
(**)
(*(* :Author: Aaron Kimmig *)*)
(**)
(*(* :Version: Mathematica 13.2 *)*)
(**)
(*(* :Package Version: 0.2.0 *)*)
(**)
(*(* :Keywords:*)
(*    sigma protocols, bulletproofs, network*)
(**)*)
(**)
(*(* :History:*)
(* Version 0.1.0 by Aaron Kimmig, March 2023 *)
(* Version 0.1.1, May 2023*)
(* Version 0.2.0, June 2023 - Breaking Changes*)
(**)*)
(**)
(*(* :Copyright: Copyright 2023 - Aaron Kimmig*)*)
(**)
(*(* :Summary:*)
(*This package implements network functions needed for Schnorr and Bulletproofs network demo implementations.*)
(**)*)
(**)


BeginPackage["SigmaTools`"];


Needs["ECOverloaded`"];
Needs["FiatShamir`"];


(*Utility Functions*)
StringToInteger::usage = "";
IntegerToString::usage = "";
ToShortString::usage = "";
EscapeString::usage = "";
EscapeColons::usage = "";
EscapeAts::usage = "";
EscapeColonsAndAts::usage = "";
ParseSplitEscapedString::usage = "";
CustomTypeParserECPoint::usage = "";
ToDenestedAssoc::usage = "";
(*Message Format*)
SetMyRole::usage = "";
GetMyRole::usage = "";
SetMyId::usage = "";
GetMyId::usage = "";
SetRoom::usage = "";
GetRoom::usage = "";
(*Entropy*)
SetScalarEntropy::usage = "";
SetGroupElementEntropy::usage = "";
(*State Machine*)
(*RNG*)
SetFixedRandomSeeds::usage = "";
SetRNGMethod::usage = "";
BPRandomInteger::usage = "";
BPRandomIntegerVector::usage = "";
BPRandomPermutation::usage = "";
RandomNumberFromDevRandom::usage = "";
(*Verbosity*)
SetStateMachineVerbosity::usage = "";
(*Unread Variables*)
UnreadVariablesPrint::usage = "";
UnreadVariablesGrid::usage = "";
(*EnqueueAsUnreadVariablesFromTo::usage = "";*)
EnqueueAsUnreadVariables::usage = "";
UnreadVariablesReset::usage = "";
UnreadVariablesClear::usage = "";
UnreadVariablesAddScalars::usage = "";
UnreadVariablesAddGroupElements::usage = "";
UnreadVariablesSave::usage = "";
UnreadVariablesRestore::usage = "";
(*Fiat-Shamir*)
FiatShamirReset::usage = "";
FiatShamirClear::usage = "";
FiatShamirSave::usage = "";
FiatShamirRestore::usage = "";
(*Communication Cost*)
SetCostSpecification::usage = "";
CommunicationCostPrint::usage = "";
CommunicationCostGrid::usage = "";
CommunicationCostReset::usage = "";
CommunicationCostClear::usage = "";
CommunicationCostAddScalars::usage = "";
CommunicationCostAddGroupElements::usage = "";
CommunicationCostAddOther::usage = "";
CommunicationCostAdd::usage = "";
CommunicationCostSave::usage = "";
CommunicationCostRestore::usage = "";
(*State Machine*)
StateMachinePrint::usage = "";
StateMachineGrid::usage = "";
StateMachineReset::usage = "";
StateMachineClear::usage = "";
StateMachineSave::usage = "";
StateMachineRestore::usage = "";
GetState::usage = "";(*Uncomment for d\[Florin]sebugging*)
(*Fiat-Shamir switch*)
EnableFiatShamir::usage = "";
DisableFiatShamir::usage = "";
(*Network*)
AddrFromConfig::usage = "";
HostFromConfig::usage = "";
(*Message Handling*)
SetEventHandler::usage = "";
ClearEventHandler::usage = "";
EventHandlerGeneric::usage = "";
ResetEventHandlers::usage = "";
SetCustomTypeParser::usage = "";
ClearCustomTypeParser::usage = "";
ResetCustomTypeParsers::usage = "";
ParseMessage::usage = "";
ProcessIncomingMessages::usage = "";
ProcessNewMessages::usage = "";
FlushMessages::usage = "";
(*Connection between Broker, Verifier and Prover*)
ConnectToRouter::usage = "";
DisconnectFromRouter::usage = "";
TellVerifier::usage = "";
TellProver::usage = "";
SendVariables::usage = "";
SendRandomChallengeTo::usage = "";
SendRandomChallenge::usage = "";
WaitForVariable::usage = "";
WaitForMessageWithVariable::usage = "";
WaitForVariables::usage = "";
WaitForMessagesWithVariables::usage = "";
WaitForProversVariable::usage = "";
WaitForRandomChallenge::usage = "";
SendVerificationSucceeded::usage = "";
SendVerificationFailed::usage = "";
SendInspectionSucceeded::usage = "";
SendInspectionFailed::usage = "";
SendCRS::usage = "";
JoinRoom::usage = "";
JoinRoomAndWaitUntilComplete::usage = "";
SetInspection::usage = "";
GiveInsight::usage = "";
(*Fiat-Shamir*)
SetFiatShamirVerbosity::usage = "";
SetFiatShamirMinimumOutputBits::usage = "";
FiatShamirAdd::usage = "";
FiatShamirGet::usage = "";
FiatShamirGrid::usage = "";


Begin["`Private`"]


(*Utility Functions*)
StringToInteger[s_String] := Module[{},
	Fold[#1*256 + #2 &, 0, Normal[StringToByteArray[s]]]
]
IntegerToString[i_Integer] := Module[{n=i,a,c},
	a={};
	While[n>0,
		c=Mod[n,256];
		AppendTo[a,c];
		n=(n-c)/256;
	];
	ByteArrayToString[ByteArray[Reverse[a]]]
]
ToShortString[value_]:=Module[{},
	If[ListQ[value],
		"{Length:"<>ToString[Length[value]]<>"}",
	(*Else*)If[AssociationQ[value],
		"<|Length:"<>ToString[Length[value]]<>"|>",
	(*Else*)If[IntegerQ[value],
		"Integer[Bits:"<>ToString[Length[IntegerDigits[value,2]]]<>"]",
	(*Else*)
		value
	]]]
]
EscapeString[s_String,toBeEscaped_String,escapeCharacter_:"\\"]:=StringReplace[s,toBeEscaped->escapeCharacter<>toBeEscaped]
EscapeColons[s_String,escapeCharacter_:"\\"]:=EscapeString[s,":",escapeCharacter]
EscapeAts[s_String,escapeCharacter_:"\\"]:=EscapeString[s,"@",escapeCharacter]
EscapeColonsAndAts[s_String,escapeCharacter_:"\\"]:=EscapeColons[EscapeAts[s,escapeCharacter],escapeCharacter]
ParseSplitEscapedString[s_String,splitCharacter_String,escapeCharacter_String,maxParts_:0,additionalEscapedCharacters_:{}]:=Module[
	{parts,part,partStart,i,curChar,nextChar},
	parts={};
	part="";
	partStart=1;
	i=1;
	While[i<=StringLength[s],
		curChar=StringTake[s,{i}];
		If[curChar==escapeCharacter&&i+1<=StringLength[s],
			nextChar=StringTake[s,{i+1}];
			If[(nextChar==escapeCharacter||nextChar==splitCharacter||MemberQ[additionalEscapedCharacters,nextChar]),
				part=part<>StringTake[s,{partStart,i-1}];
				partStart=i+1;
				i+=2;
				Continue[]
			];
		];
		(*Else If*)
		If[curChar==splitCharacter,
			part=part<>StringTake[s,{partStart,i-1}];
			AppendTo[parts,part];
			part="";
			partStart=i+1;
			If[maxParts>0&&Length[parts]==maxParts-1,
				Break[]
			];
			i+=1;
			Continue[]
		];
		(*Else*)
		i+=1;
	];
	part=part<>StringTake[s,{partStart,-1}];
	AppendTo[parts,part];
	parts
]
CustomTypeParserECPoint[obj_]:=Module[{},
	If[!KeyExistsQ[obj,"x"]||!KeyExistsQ[obj,"y"],
		Print["Parse Error for type ECPoint: Expected integer coordinates x and y in "<>ToString[obj]];
		Return[Null];
	];
	If[!IntegerQ[obj["x"]]||!IntegerQ[obj["y"]],
		Print["Parse Error for type ECPoint: Expected integer coordinates x and y in "<>ToString[obj]];
		Return[Null];
	];
	ecPnt[obj["x"],obj["y"]]
]
ToDenestedAssoc[obj_,existingResObj_:<||>,prefix_:""]:=Module[{resObj=existingResObj},
	If[ListQ[obj],
		Scan[
			(resObj=ToDenestedAssoc[obj[[#]],resObj,prefix<>"."<>ToString[#]])&,
			Range[1, Length[obj]]
		];
		Return[resObj]
	];
	If[AssociationQ[obj],
		Scan[
			(resObj=ToDenestedAssoc[obj[#],resObj,If[prefix=="",ToString[#],prefix<>"."<>ToString[#]]])&,
			Keys[obj]
		];
		Return[resObj]
	];
	resObj[prefix]=obj;
	resObj
]


(*Message Format*)
(*<sender_role>@<sender_id>:<receiver_role|Public|CRS>@<receiver_id>:<room>:<data_format>:<DATA>*)
myRole="";
myId="";
myRoleAtIdEscaped="";
room="";
roomEscaped="";
dataFormat="json";
(*Sender Role and Id*)
SetMyRole[role_String]:=Module[{},
	myRole=role;
	myRoleAtIdEscaped=EscapeColonsAndAts[myRole]<>If[myId=="","","@"<>EscapeColonsAndAts[myId]];
	myRole
]
GetMyRole[]:=myRole
SetMyId[id_String]:=Module[{},
	myId=id;
	myRoleAtIdEscaped=EscapeColonsAndAts[myRole]<>If[myId=="","","@"<>EscapeColonsAndAts[myId]];
	myId
]
GetMyId[]:=myId
(*Room*)
SetRoom[roomName_String]:=Module[{},
	room=roomName;
	roomEscaped=EscapeColons[room];
	room
]
GetRoom[]:=room


(*Entropy*)
scalarEntropy=0;
groupElementEntropy=0;
SetScalarEntropy[bits_Integer]:=scalarEntropy=bits
SetGroupElementEntropy[bits_Integer]:=groupElementEntropy=bits


(*State Machine - Random Number Generators*)
fixedRandomSeeds=False;
SetFixedRandomSeeds[fixed_?(BooleanQ[#]&)]:=fixedRandomSeeds=fixed
bpRNGMethod="OpenSSL";
SetRNGMethod[method_String]:=bpRNGMethod=method
randState=Null;
BPRandomInteger[min_Integer,max_Integer]:=Module[{val},
	If[!fixedRandomSeeds||randState===Null,
		Return[RandomInteger[{min,max}]]
	];
	SeedRandom[randState];
	val=RandomInteger[{min,max}];
	randState=$RandomGeneratorState;
	val
]
BPRandomIntegerVector[min_Integer,max_Integer,size_Integer]:=Module[{val},
	If[!fixedRandomSeeds||randState===Null,
		Return[Array[RandomInteger[{min,max}]&,size]];
	];
	SeedRandom[randState];
	val=Array[RandomInteger[{min,max}]&,size];
	randState=$RandomGeneratorState;
	val
]
BPRandomPermutation[size_Integer]:=Module[{permutation,i,j,tmp},
	permutation = Range[size];
	If[fixedRandomSeeds&&randState=!=Null,
		SeedRandom[randState];
	];
	For[i=1,i<=size-1,i++,
		j=RandomInteger[{i,size}];
		tmp=permutation[[i]];
		permutation[[i]]=permutation[[j]];
		permutation[[j]]=tmp;
	];
	If[fixedRandomSeeds&&randState=!=Null,
		randState=$RandomGeneratorState;
	];
	permutation
]
RandomNumberFromDevRandom[max_Integer]:=Module[{numberOfRandomBytes},
	(*avoid rejection sampling: use double the number of random bytes than needed
	to represent the maximum value (but at least 256 bits) to avoid bias by
	a potentially predictable overflow resulting from applying the modulus function*)
	numberOfRandomBytes=Ceiling[Max[BitLength[max], 256]/8]*2;
	Mod[Normal[ReadByteArray["!dd if=/dev/random count=1 bs="<>ToString[numberOfRandomBytes]]] . (256^Range[0,numberOfRandomBytes-1]),max+1]
]


(*State machine - verbosity*)
stateMachineVerbosity=1;
SetStateMachineVerbosity[verbosity_]:=stateMachineVerbosity=verbosity


(*State machine - Unread Variables*)
unreadVariables=<||>;
UnreadVariablesPrint[]:=Print["Unread variables at the moment: "<>ToString[Length[unreadVariables]]<>"\n  "<>ToString[Keys[unreadVariables]]];
UnreadVariablesGrid[]:=Module[
	{name,roleAtId,value},
	Grid[Join[
		{
			{Style["Unread Variables",Bold],SpanFromLeft,SpanFromLeft},
			{
				Style["Name",Bold],
				Style["Sender",Bold],
				Style["Value",Bold]
			}
		},
		Map[Function[{name},
			Flatten[Map[Function[{roleAtId},
				value=unreadVariables[name][roleAtId][name];
				{
					name,
					roleAtId,
					ToShortString[value]
				}],
				Keys[unreadVariables[name]]
			], 1]],
			Keys[unreadVariables]
		]
	], Alignment->{{Left,Left,Left}},Frame->All]
]
EnqueueAsUnreadVariables[variables_,includeVariablesToProofRole_:True,ignoreReceiverSpecification_:False,verbose_:1]:=Module[
	{cost,keyParts,name,receiverRoleAtId,receiverParts,receiverRole,receiverId,msgSenderRoleAtId,msgSenderParts,senderRole,senderId,msgConstructed},
	cost=If[KeyExistsQ[variables,"_cost"],variables["_cost"],Null];
	Scan[
		(keyParts=ParseSplitEscapedString[#,":","\\"];
		If[Length[keyParts]<2&&Length[keyParts]>3,If[verbose>=1,Print["Error: expected key of format name:role@id in "<>#]];Return[]];
		name=keyParts[[1]];
		receiverRole="";
		receiverId="";
		If[Length[keyParts]>2,
			(*check if receiver matches own role@id*)
			receiverRoleAtId=keyParts[[3]];
			receiverParts=ParseSplitEscapedString[receiverRoleAtId,"@","\\"];
			If[Length[receiverParts]>2||Length[receiverParts]==0,If[verbose>=1,Print["Error: expecting receiver key part of form role@id): "<>receiverRoleAtId<>" in "<>#]];Return[]];
			receiverRole=receiverParts[[1]];
			If[!ignoreReceiverSpecification&&receiverRole!=""&&receiverRole!=myRole&&!(receiverRole=="Proof"&&includeVariablesToProofRole),
				(*specified receiver does not match own role*)
				Return[]
			];
			If[Length[receiverParts]==2,
				receiverId=receiverParts[[2]];
				If[!ignoreReceiverSpecification&&receiverId!=""&&receiverId!=myId,(*specified receiver does not match own id*)Return[]];
			];
		];
		msgSenderRoleAtId=keyParts[[2]];
		msgSenderParts=ParseSplitEscapedString[msgSenderRoleAtId,"@","\\"];
		If[Length[msgSenderParts]>2||Length[msgSenderParts]==0,If[verbose>=1,Print["Error: expecting sender key part of form role@id): "<>msgSenderRoleAtId<>" in "<>#]];Return[]];
		senderRole=msgSenderParts[[1]];
		If[Length[msgSenderParts]==2,
			senderId=msgSenderParts[[2]];
		(*Else: Length[msgSenderParts]==1*),
			senderId="";
		];
		msgConstructed=<|
			name->variables[#],
			"_Valid"->True,
			"_SenderRole"->senderRole,
			"_SenderId"->senderId,
			"_SenderRoleAtId"->msgSenderRoleAtId,
			"_ReceiverRole"->receiverRole,
			"_ReceiverId"->receiverId,
			"_ReceiverRoleAtId"->receiverRoleAtId,
			"_UniqueKey"->EscapeColons[msgSenderRoleAtId]<>":"<>EscapeColons[receiverRoleAtId]
		|>;
		If[cost=!=Null,msgConstructed["_cost"]=cost];
		If[KeyExistsQ[unreadVariables,name],
			If[verbose>=2&&KeyExistsQ[unreadVariables[name],msgSenderRoleAtId],
				Print["Info: EnqueueAsUnreadVariables: overriding previously received variable "<>#]
			];
			unreadVariables[name][msgSenderRoleAtId]=msgConstructed;
		(*Else*),
			unreadVariables[name]=<|msgSenderRoleAtId->msgConstructed|>
		])&,
		Select[Keys[variables],!StringStartsQ[#,"_"]&]
	]
]
unreadVariablesSaved=<||>;(*<|
	stateKey-><|
		"variable name"->msgParsed,
		...
	|>,
	...
|>*)
UnreadVariablesReset[]:=unreadVariables=<||>
UnreadVariablesClear[]:=Module[{},
	UnreadVariablesReset[];
	unreadVariablesSaved=<||>;
]
UnreadVariablesSave[(stateKey_Integer|stateKey_String)]:=Module[{state},
	If[stateMachineVerbosity>=2,Print["Unread variables saved states:\n"<>ToString[unreadVariablesSaved]]];
	state=Map[#&,unreadVariables];
	unreadVariablesSaved[stateKey]=state;
	If[stateMachineVerbosity>=1,Print["Unread variables: Saving "<>ToString[state]<>" to "<>ToString[stateKey]]];
	state
]
UnreadVariablesRestore[(stateKey_Integer|stateKey_String)]:=Module[{state},
	If[stateMachineVerbosity>=2,Print["Unread variables saved states:\n"<>TextString[unreadVariablesSaved]]];
	If[KeyExistsQ[unreadVariablesSaved,stateKey],
		state=unreadVariablesSaved[stateKey];
		If[stateMachineVerbosity>=1,Print["Unread variables: Restoring "<>ToString[state]]];
		unreadVariables=Map[#&,state];
		state
	]
]


(*State machine - Fiat-Shamir*)
fiatShamirImplicitVariableNames={};
fiatShamirExplicitVariables={};
fiatShamirExplicitEntropy={};
fiatShamirSaved=<||>;(*<|
	stateKey-><|
		"string"->string,
		"implicit"->{"<implicit variable name>",...},
		"explicit"->{"<explicit variable name>" -> <value>,...},
		"explicitEntropy"->{<bits>,...}
	|>,
	...
|>*)
FiatShamirReset[]:=Module[{},
	fiatShamirImplicitVariableNames={};
	fiatShamirExplicitVariables={};
	fiatShamirExplicitEntropy={};
]
FiatShamirClear[]:=Module[{},
	FiatShamirReset[];
	fiatShamirSaved=<||>;
]
FiatShamirSave[(stateKey_Integer|stateKey_String)]:=Module[{state},
	If[stateMachineVerbosity>=2,Print["Fiat-Shamir saved states:\n"<>TextString[fiatShamirSaved]]];
	state=<|
		"implicit"->Map[#&,fiatShamirImplicitVariableNames],
		"explicit"->Map[#&,fiatShamirExplicitVariables],
		"explicitEntropy"->Map[#&,fiatShamirExplicitEntropy]
	|>;
	fiatShamirSaved[stateKey]=state;
	If[stateMachineVerbosity>=1,Print["Fiat-Shamir: Saving "<>TextString[state]<>" to "<>ToString[stateKey]]];
	state
]
FiatShamirRestore[(stateKey_Integer|stateKey_String)]:=Module[{state},
	If[stateMachineVerbosity>=2,Print["Fiat-Shamir saved states:\n"<>TextString[fiatShamirSaved]]];
	If[KeyExistsQ[fiatShamirSaved,stateKey],
		state=fiatShamirSaved[stateKey];
		If[stateMachineVerbosity>=1,Print["Fiat-Shamir: Restoring "<>ToString[state]]];
		fiatShamirImplicitVariableNames=state["implicit"];
		fiatShamirExplicitVariables=state["explicit"];
		fiatShamirExplicitEntropy=state["explicitEntropy"];
		state
	]
]


(*State machine - Communication cost*)
(*communicationCostScalars={};
communicationCostGroupElements={};
communicationCostCustom={};*)
costSpecification=<|(*
	"key (scalar|group|...)"->bits,
	...
*)|>;
SetCostSpecification[spec_]:=costSpecification=spec
communicationCostGrouped=<|(*
	"key (scalar|group|...)"->{var name, ...},
	...
*)|>;
communicationCostOther={(*
	"var name"->bits,
	...
*)};
CommunicationCostPrint[]:=Print["Communication cost so far:\n  Grouped: ("<>ToString[communicationCostGrouped]<>"\n  Other: "<>ToString[communicationCostOther]<>"\n  Entropy specification: "<>ToString[costSpecification]]
CommunicationCostGrid[]:=Module[
	{ccOther,ccTotal,ccOtherTotal},
	ccOther=If[Length[communicationCostOther]==0,Null,{
		Style["other",Italic],
		Length[communicationCostOther],
		StringRiffle[Map[#[[1]]<>":"<>ToString[#[[2]]]&,communicationCostOther],", "],
		Total[Map[#[[2]]&,communicationCostOther]]
	}];
	ccTotal={
		Style["total",Italic],
		Total[Map[Length,communicationCostGrouped]] + Length[communicationCostOther],
		"",
		Module[{k1,k2,specified,missing,bits},
			k1=Keys[communicationCostGrouped];
			k2=Keys[costSpecification];
			specified=Intersection[k1,k2];
			missing={};
			If[Length[specified]<Length[k1],missing=UniqueElements[{k1,k2}][[1]]];
			bits=Total[Map[Length[communicationCostGrouped[#]]*costSpecification[#]&,specified]];
			If[Length[missing]==0,
				bits,
				ToString[bits]<>"\n(excluding "<>ToString[Total[Map[Length[communicationCostGrouped[#]]&,missing]]]<>" variable(s) with unknown entropy)"
			]
		]
	};
	ccOtherTotal=If[ccOther===Null,{ccTotal},{ccOther,ccTotal}];
	Grid[Join[{
		{Style["Total Communication Cost",Bold],SpanFromLeft,SpanFromLeft,SpanFromLeft},
		{Style["Type",Bold],Style["Count",Bold],Style["Names",Bold],Style["Bits",Bold]}
	}, Map[
		{
			#,
			Length[communicationCostGrouped[#]],
			StringRiffle[communicationCostGrouped[#],", "],
			If[KeyExistsQ[costSpecification,#],
				costSpecification[#]*Length[communicationCostGrouped[#]],
				""
			]
		}&,
		Keys[communicationCostGrouped]
	], ccOtherTotal], Alignment->{{Left,Left,Left,Left}},Frame->All]
]
communicationCostSaved=<||>;(*<|
	stateKey-><|
		"grouped"->value,
		"other"->value
	|>,
	...
|>*)
CommunicationCostReset[]:=Module[{},
	communicationCostGrouped=<||>;
	communicationCostOther={};
]
CommunicationCostClear[]:=Module[{},
	CommunicationCostReset[];
	communicationCostSaved=<||>;
]
CommunicationCostAddScalars[scalars:{__String}]:=communicationCostGrouped["scalar"]=If[KeyExistsQ[communicationCostGrouped,"scalar"],Join[communicationCostGrouped["scalar"],scalars],scalars]
CommunicationCostAddGroupElements[groupElements:{__String}]:=communicationCostGrouped["group"]=If[KeyExistsQ[communicationCostGrouped,"group"],Join[communicationCostGrouped["group"],groupElements],groupElements]
CommunicationCostAddOther[variables:{__String},bits_Integer]:=communicationCostOther=Join[communicationCostOther,Map[#->bits&,variables]]
CommunicationCostAdd[variables_,selectedNames_:{}]:=Module[
	{cost,denestedVariables,uniqueVarKey,varCost},
	If[!KeyExistsQ[variables,"_cost"],Return[]];
	cost=variables["_cost"];
	denestedVariables=ToDenestedAssoc[KeySelect[
		variables,
		If[Length[selectedNames]==0,
			!StringStartsQ[#,"_"]&,
			MemberQ[selectedNames,#]&
		]
	]];
	If[stateMachineVerbosity>=2,Print["Communication Cost: adding selected variables "<>ToString[selectedNames]<>" from "<>ToString[variables]]];
	If[StringQ[cost],
		communicationCostGrouped[cost]=If[KeyExistsQ[communicationCostGrouped,cost],
			Join[communicationCostGrouped[cost],Keys[denestedVariables]],
			Keys[denestedVariables]
		];
		Return[];
	];
	(*Else*)If[IntegerQ[cost],
		CommunicationCostAddOther[cost,Keys[denestedVariables]];
		Return[];
	];
	(*Else*)If[ListQ[cost],
		cost=Association[cost];
	];
	(*Else*)If[!AssociationQ[cost],
		(*Error*)
		If[stateMachineVerbosity>=1,Print["Error: general communincation cost type needs to be on of String, Integer, List of rules or Association. But it is "<>ToString[cost]];Return[]];
	];
	(*Else - Association*)
	Scan[Function[{varKey},
		If[KeyExistsQ[cost,varKey],
			varCost=cost[varKey];
		(*Else*),
			uniqueVarKey=varKey<>":"<>variables["_UniqueKey"];
			If[KeyExistsQ[cost,uniqueVarKey],
				varCost=cost[uniqueVarKey];
			(*Else*),
				If[verbose>=1,Print["CommunicationCostAdd: Warning: variable "<>varKey<>" with "<>uniqueVarKey<>" not in cost assoc"]];
				Return[];
			];
		];
		If[StringQ[varCost],
			communicationCostGrouped[varCost]=If[KeyExistsQ[communicationCostGrouped,varCost],
				Join[communicationCostGrouped[varCost],{varKey}],
				{varKey}
			];
			Return[];
		];
		(*Else*)If[IntegerQ[varCost],
			CommunicationCostAddOther[varCost,{varKey}];
			Return[];
		];
		(*Else*)
		If[stateMachineVerbosity>=1,Print["Error: type of communication cost "<>ToString[varCost]<>" for "<>varKey<>" needs to be one of String or Integer. Ignoring"]];
	], Keys[denestedVariables]];
]
CommunicationCostSave[(stateKey_Integer|stateKey_String)]:=Module[{state},
	If[stateMachineVerbosity>=2,Print["Communication cost saved states:\n"<>TextString[communicationCostSaved]]];
	state=<|
		"grouped"->Join[communicationCostGrouped],
		"other"->Join[communicationCostOther]
	|>;
	communicationCostSaved[stateKey]=state;
	If[stateMachineVerbosity>=1,Print["Communication cost: Saving "<>ToString[state]<>" to "<>ToString[stateKey]]];
	state
]
CommunicationCostRestore[(stateKey_Integer|stateKey_String)]:=Module[{state},
	If[stateMachineVerbosity>=2,Print["Communication cost saved states:\n"<>ToString[communicationCostSaved]]];
	If[KeyExistsQ[communicationCostSaved,stateKey],
		state=communicationCostSaved[stateKey];
		If[stateMachineVerbosity>=1,Print["Communication cost: Restoring "<>ToString[state]]];
		communicationCostGrouped=state["grouped"];
		communicationCostOther=state["other"];
		state
	]
]


(*State machine*)
StateMachinePrint[]:=Module[{},
	UnreadVariablesPrint[];
	FiatShamirPrint[];
	CommunicationCostPrint[];
]
StateMachineGrid[]:=Module[{},
	UnreadVariablesGrid[];
	FiatShamirGrid[];
	CommunicationCostGrid[];
]
StateMachineReset[]:=Module[{},
	UnreadVariablesReset[];
	FiatShamirReset[];
	CommunicationCostReset[];
]
StateMachineClear[]:=Module[{},
	UnreadVariablesClear[];
	FiatShamirClear[];
	CommunicationCostClear[];
]
StateMachineSave[(stateKey_Integer|stateKey_String)]:=Module[{state},
	UnreadVariablesSave[stateKey];
	FiatShamirSave[stateKey];
	CommunicationCostSave[stateKey];
]
StateMachineRestore[(stateKey_Integer|stateKey_String)]:=Module[{state},
	UnreadVariablesRestore[stateKey];
	FiatShamirRestore[stateKey];
	CommunicationCostRestore[stateKey];
	If[fixedRandomSeeds,
		SeedRandom[
			If[StringQ[stateKey],StringToInteger[stateKey],stateKey],
			Method->"ExtendedCA"
		];
		randState=$RandomGeneratorState;
	];
]
(*Only for Debugging*)
GetState[]:=<|
	"unreadVariablesSaved"->unreadVariablesSaved,
	"unreadVariables"->unreadVariables,
	"fiatShamirSaved"->fiatShamirSaved,
	"communicationCostSaved"->communicationCostSaved
|>


(*Fiat-Shamir switch*)
fiatShamir=False;
EnableFiatShamir[]:=fiatShamir=True
DisableFiatShamir[]:=fiatShamir=False


(*Network*)
(*Socket Configuration*)
AddrFromConfig[config_Association]:=config["Host"]<>":"<>ToString[config["Port"]]
HostFromConfig[config_Association]:=HostLookup[config["Host"],"IPv4Addresses"][[1]];


(*Event handlers*)
eventHandlers=<||>;
SetEventHandler[key_String,handler_]:=eventHandlers[key]=handler
ClearEventHandler[key_String]:=KeyDropFrom[eventHandlers,key]
EventHandlerStatus[msgParsed_]:=Module[{status},
	status=msgParsed["__status__"];
	If[KeyExistsQ[msgParsed,"msg"],
		Print[status<>": "<>msgParsed["msg"]<>". Detail:\n  "<>ToString[msgParsed]],
	(*Else*)
		Print[status<>": "<>ToString[msgParsed]]
	]
]
EventHandlerMsg[msgParsed_]:=Print["Message from "<>msgParsed["_SenderRole"]<>"@"<>msgParsed["_SenderId"]<>":\n  "<>msgParsed["__msg__"]]
EventHandlerGeneric[msgParsed_,eventKey_String,eventFunction_:(Null&)]:=Module[{status},
	eventFunction[msgParsed];
	status=If[KeyExistsQ[msgParsed,"status"],
		msgParsed["status"],
	(*Else*)
		"success"
	];
	Print[
		"Handling Event: "<>status<>": "<>eventKey<>" ("<>msgParsed["_SenderRoleAtId"]<>
		If[KeyExistsQ[msgParsed,"msg"],
			"): "<>msgParsed["msg"],
		(*Else*)
			"):\n  Event Data: "<>ToShortString[msgParsed[eventKey]]<>"\n  Keys: "<>ToString[Keys[msgParsed]]
		]
	];
	msgParsed[eventKey]
]
DefaultEventHandlerLeaveRoom[msgParsed_]:=Print["Received __leave_room__ event. TODO: Register handler function. "<>ToString[msgParsed]]
DefaultEventHandlerInspectionRequest[msgParsed_]:=Print["Received _inspection_request_ event. TODO: Register handler function. "<>ToString[msgParsed]]
ResetEventHandlers[]:=Module[{},
	eventHandlers=<||>;
	eventHandlers["__status__"]=EventHandlerStatus;
	eventHandlers["__msg__"]=EventHandlerMsg;
	eventHandlers["__leave_room__"]=DefaultEventHandlerLeaveRoom;
	eventHandlers["_inspection_request_"]=DefaultEventHandlerInspectionRequest;
]
ResetEventHandlers[];
(*Parsers for custom types*)
customTypeParsers=<||>;
SetCustomTypeParser[key_String,parser_]:=customTypeParsers[key]=parser
ClearCustomTypeParser[key_String]:=KeyDropFrom[customTypeParsers,key]
ResetCustomTypeParsers[]:=Module[{},
	customTypeParsers=<||>;
	customTypeParsers["ECPoint"]=CustomTypeParserECPoint;
]
ResetCustomTypeParsers[];
ToJsonConvertible[obj_]:=ToJsonConvertibleIter[ResourceFunction["ToAssociations"][obj]]
ToJsonConvertibleIter[obj_]:=Module[{i},
	If[ListQ[obj]||AssociationQ[obj],
		Return[Map[ToJsonConvertibleIter,obj]]
	];
	If[Head@obj==ecPnt,
		Return[{
			"__type"->"ECPoint",
			"x"->obj[[1]],
			"y"->obj[[2]]
		}]
	];
	If[StringQ[obj]||NumberQ[obj]||BooleanQ[obj]||obj===Null,
		obj,
	(*Else*)
		ToString[obj]
	]
]
ParseCustomTypes[obj_,baseObj_]:=Module[{i,customType,parsedObj},
	If[ListQ[obj],
		Return[Map[ParseCustomTypes[#,baseObj]&,obj]]
	];
	If[!AssociationQ[obj],
		Return[obj]
	];
	If[!KeyExistsQ[obj,"__type"],
		Return[Map[ParseCustomTypes[#,baseObj]&,obj]]
	];
	customType=obj["__type"];
	If[!StringQ[customType],
		baseObj["_Error"]="Parsing failed: Value of special key '__type' has to be a String";
		Return[Null]
	];
	If[!KeyExistsQ[customTypeParsers,customType],
		Print["Warning: Unhandled custom type "<>customType<>" in object "<>ToString[obj]];
		Return[obj]
	];
	parsedObj=customTypeParsers[customType][obj];
	If[parsedObj===Null,
		baseObj["_Error"]="Parsing object as type "<>customType<>" failed with "<>ToString[obj];
		Return[Null]
	];
	parsedObj
];
(*Parse Message String*)
ParseMessage[msg_String]:=Module[
	{parsed,msgParts,senderParts,senderRole,senderId,receiverParts,receiverRole,receiverId,room,dataFormat,msgData,parsedData,assocIntersection,underscoreVars1,underscoreVars2},
	parsed=<|
		"_Message"->msg,
		"_Valid"->False
	|>;
	(*5 parts: senderRole@senderId, receiverRole@receiverId, room, data_format, data*)
	msgParts=ParseSplitEscapedString[msg,":","\\",5];
	If[Length[msgParts]!=5,
		Print["Error: Received malformed message (expecting 5 parts separated by ':'): "<>StringTrim[msg]<>"\n"<>ToString[msgParts]];
		parsed["_Error"]="Parsing failed: Expecting 5 parts separated by ':'";
		Return[parsed]
	];
	(*senderRole@senderId*)
	senderParts=ParseSplitEscapedString[msgParts[[1]],"@","\\"];
	If[Length[senderParts]>2,
		Print["Error: Received malformed message (expecting 2 sender parts separated by '@'): "<>msg];
		parsed["_Error"]="Parsing failed: Expecting 2 sender parts separated by '@'";
		Return[parsed]
	];
	senderRole=senderParts[[1]];
	If[Length[senderParts]==2,
		senderId=senderParts[[2]],
	(*Else if*)
	If[Length[senderParts]==1,
		senderId="",
	(*Else*)
		Print["Assertion failure: Length[senderParts] > 0: senderParts="<>ToString[senderParts]];
		parsed["_Error"]="Parsing failed: Assertion failure";
		Return[parsed]
	]];
	parsed["_SenderRoleAtId"]=msgParts[[1]];
	parsed["_SenderRole"]=senderRole;
	parsed["_SenderId"]=senderId;
	(*receiverRole@receiverId*)
	receiverParts=ParseSplitEscapedString[msgParts[[2]],"@","\\"];
	If[Length[receiverParts]>2,
		Print["Error: Received malformed message from "<>msgParts[[1]]<>" (expecting 2 receiver parts separated by '@'): "<>msg];
		parsed["_Error"]="Parsing failed: Expecting 2 receiver parts separated by '@'";
		Return[parsed]
	];
	If[Length[receiverParts]==2,
		receiverRole=receiverParts[[1]];
		receiverId=receiverParts[[2]],
	(*Else if*)
	If[Length[receiverParts]==1,
		receiverRole=receiverParts[[1]];
		receiverId="",
	(*Else*)
		Print["Assertion failure: Length[receiverParts] > 0: receiverParts="<>ToString[receiverParts]];
		parsed["_Error"]="Parsing failed: Assertion failure";
		Return[parsed]
	]];
	parsed["_ReceiverRoleAtId"]=msgParts[[2]];
	parsed["_ReceiverRole"]=receiverRole;
	parsed["_ReceiverId"]=receiverId;
	parsed["_UniqueKey"]=EscapeColons[msgParts[[1]]]<>":"<>EscapeColons[msgParts[[2]]];
	(*Room*)
	room=msgParts[[3]];
	parsed["_Room"]=room;
	(*DataFormat*)
	dataFormat=msgParts[[4]];
	parsed["_DataFormat"]=dataFormat;
	(*Data*)
	msgData=msgParts[[5]];
	parsed["_Data"]=msgData;
	(*Parse Data*)
	If[dataFormat=="json",
		parsedData=Check[ImportString[msgData,"RawJSON"],Null];
		If[parsedData===Null,
			parsed["_Error"]="Parsing failed: data is no valid JSON: "<>msgData;
			Return[parsed]
		];
		If[AssociationQ[parsedData],
			assocIntersection=KeyIntersection[{parsed,parsedData}];
			If[Length[assocIntersection[[1]]]>0,
				parsed["_Error"]="Parsing failed: Collision with internal key names: "<>ToString[Keys[assocIntersection]];
				Print[parsed["_Error"]<>": "<>msg<>"\n"<>ToString[parsed]<>"\n"<>ToString[assoc]];
				Return[parsed]
			];
			parsedData=ParseCustomTypes[parsedData,parsed];
			parsed=Join[parsedData,parsed];
		(*Else*),
			parsed["variable"]=ParseCustomTypes[parsedData,parsed]
		];
		If[KeyExistsQ[parsed,"_Error"],
			Return[parsed]
		];
		(*variables of form '_*_'*)
		underscoreVars1=KeySelect[parsed,StringTake[#,{1}]=="_"&&StringTake[#,{2}]!="_"&&StringTake[#,{-2}]!="_"&&StringTake[#,{-1}]=="_"&];
		parsed["_UnderscoreVars1"]=underscoreVars1;
		(*variables of form '__*__'*)
		underscoreVars2=KeySelect[parsed,StringStartsQ[#,"__"]&&StringEndsQ[#,"__"]&];
		parsed["_UnderscoreVars2"]=underscoreVars2;
		If[senderRole!="Router"&&senderRole!="Inspector"&&Length[underscoreVars2]>0,
			Print["Only roles 'Router' and 'Inspector' are allowed to send variables starting and ending with '__'. Ignoring message with keys:\n"<>ToString[Keys[parsed]]];
			Return[parsed];
		];
	(*Else: unknown dataFormat*),
		parsed["_Error"]="Parsing failed: Unknown data format '"<>dataFormat<>"'";
		Print["Parsing failed: Unknown data format '"<>dataFormat<>"' (only known format is 'json'): "<>msg];
		Return[parsed]
	];
	(*Valid*)
	parsed["_Valid"]=True;
	(*Return*)
	parsed
]
CheckRoleAndId[msgParsed_,idsAccepted_,rolesAccepted_]:=Module[
	{senderId,senderRole},
	senderId=msgParsed["_SenderId"];
	If[Length[idsAccepted]>=1&&!MemberQ[idsAccepted,senderId],
		Return[False]
	];
	senderRole=msgParsed["_SenderRole"];
	If[
		Length[rolesAccepted]>=1&&
		senderRole!=""&&
		senderRole!="Router"&&
		senderRole!="Inspector"&&
		!MemberQ[rolesAccepted,senderRole],
		Return[False]
	];
	True
]
(*Helper functions*)
ProcessIncomingMessages[socket_,names_:{},rolesAccepted_:{},idsAccepted_:{},finishedAfterFirstVariable_:False,returnParsedMessage_:False,verbose_:1]:=Module[
	{fullMsg,variables,finished,varName,senderRole,senderId,senderRoleAtId,found,unreadVariableMsgs,unreadMsg,msg,msgParsed,newlines,completeMsg,i,prevIndex,newUnreadVariables,status},
	(*Parse all unprocessed messages*)
	fullMsg="";
	variables=<||>;
	finished=False;
	Scan[Function[{varName},
		If[KeyExistsQ[unreadVariables,varName],
			unreadVariableMsgs=unreadVariables[varName];
			found=False;
			Scan[Function[{roleAtId},
				unreadMsg=unreadVariableMsgs[roleAtId];
				If[CheckRoleAndId[unreadMsg,idsAccepted,rolesAccepted],
					If[found,Print["ProcessIncomingMessages: Warning: already found variable "<>varName<>". Overriding. Specify accepted sender id to avoid overriding previous values."]];
					found=True;
					variables[varName]=If[returnParsedMessage,unreadMsg,unreadMsg[varName]];
					CommunicationCostAdd[unreadMsg,{varName}];
					KeyDropFrom[unreadVariableMsgs,roleAtId];
					If[finishedAfterFirstVariable,
						finished=True;
					];
				];
			], Keys[unreadVariables[varName]]];
			If[Length[unreadVariableMsgs]==0,
				KeyDropFrom[unreadVariables,varName];
			];
		]],
		names
	];
	If[verbose>=2,
		Print["ProcessIncomingMessages: read previously received variables with requested names "<>ToString[variables]];
		Print["ProcessIncomingMessages: variables that still have not been read: "<>ToString[unreadVariables]];
	];
	If[Length[variables]==Length[names],
		(*Already received all variables*)
		finished=True;
	];
	While[True,
		If[finished&&!SocketReadyQ[socket],
			If[verbose>=2,Print["All variables received: "<>names]];
			Return[variables]
		];
		SocketWaitNext[socket];
		msg=ByteArrayToString[SocketReadMessage[socket]];
		If[verbose>=3,Print["Received message part: "<>msg]];
		fullMsg=fullMsg<>msg;
		newlines=StringPosition[fullMsg,"\n"];
		prevIndex=1;
		For[i=1,i<=Length[newlines],i++,
			(*Improvement: Allow escaping \n-characters*)
			completeMsg=StringTake[fullMsg,{prevIndex,newlines[[i]][[1]]-1}];
			prevIndex=newlines[[i]][[2]]+1;
			If[verbose>=2,Print["Debug: parsing and processing message "<>msg<> " ..."]];
			msgParsed=ParseMessage[completeMsg];
			If[!msgParsed["_Valid"],Continue[]];
			newUnreadVariables={};
			If[CheckRoleAndId[msgParsed,idsAccepted,rolesAccepted],
				Scan[
					If[KeyExistsQ[msgParsed,#],
						variables[#]=If[returnParsedMessage,msgParsed,msgParsed[#]];
						If[!StringStartsQ[#,"_"],
							(*only add regular non-underscore variables to communication cost*)
							CommunicationCostAdd[msgParsed,{#}];
						];
						If[Length[variables]==Length[names]||finishedAfterFirstVariable,
							finished=True;
						];
					]&,
					names
				];
				newUnreadVariables=Select[Keys[msgParsed],!MemberQ[names,#]&];
			(*Else*),
				newUnreadVariables=Select[Keys[msgParsed]];
			];
			senderRole=msgParsed["_SenderRole"];
			senderId=msgParsed["_SenderId"];
			senderRoleAtId=msgParsed["_SenderRoleAtId"];
			If[senderRole=="Router"||senderRole=="Inspector",
				(*Only handle '__*__' variables*)
				Scan[
					If[KeyExistsQ[eventHandlers,#],
						eventHandlers[#][msgParsed]
					(*Else*),
						EventHandlerGeneric[msgParsed,#]
					]&,
					Keys[msgParsed["_UnderscoreVars2"]](*variables of form __*__ *)
				];
			(*Else*),
				(*Save unread ordinary variables*)
				Scan[Function[{varName},
					If[KeyExistsQ[unreadVariables,varName],
						unreadVariables[varName][senderRoleAtId]=msgParsed;
					(*Else*),
						unreadVariables[varName]=<|senderRoleAtId->msgParsed|>;
					]],
					newUnreadVariables
				];
				(*Handle _*_ variables*)
				Scan[
					If[KeyExistsQ[eventHandlers,#],
						eventHandlers[#][msgParsed]
					(*Else*),
						EventHandlerGeneric[msgParsed,#]
					]&,
					Keys[msgParsed["_UnderscoreVars1"]](*variables of form _*_ *)
				];
			];
		];
		If[prevIndex>StringLength[fullMsg],
			fullMsg="",
			fullMsg=StringTake[fullMsg,{prevIndex,StringLength[fullMsg]}]
		];
		(*If there is still data to be read from the socket continue to process the data:*)
		If[SocketReadyQ[socket],Continue[]];
		(*If there is an incomplete message wait for data on the socket and continue to process it*)
		If[StringLength[fullMsg]>=1,
			If[verbose>=1,Print["Waiting for message to be completed ..."]];
			Continue[]
		];
		(*If the desired variable has not yet been received wait for more data*)
		If[!finished,
			If[verbose>=2,Print["ProcessIncomingMessages: Waiting to receive all of the variables "<>ToString[names]]];
			Continue[]
		];
	];
]
ProcessNewMessages[]:=ProcessIncomingMessages[router]
FlushMessages[socket_,verbose:1]:=Module[
	{socketDropCount,unreadDropCount},
	If[socket=!=Null,
		If[verbose>=1,Print["Flushing messages from "<>ToString[socket]<>" ..."]];
		socketDropCount=0;
		While[SocketReadyQ[socket],
			SocketReadMessage[socket];
			socketDropCount+=1;
		];
		If[verbose>=1,Print["Dropped data of "<>ToString[socketDropCount]<>" read operation(s)."]];
	];
	If[verbose>=1,Print["Flushing all unread variables ..."]];
	unreadDropCount=Total[Map[Length[unreadVariables[#]]&,Keys[unreadVariables]]];
	ResetUnreadVariables[];
	If[verbose>=1,Print["Dropped "<>ToString[unreadDropCount]<>" unread variable(s). Done."]];
]


(*Connection between Router, Verifier and Prover*)
(*Sending values / Router*)
router=Null;
SendVariables[to_String,variables_,verbose_:0]:=Module[
	{msg,cost,maxChars,msgPart},
	If[router===Null,Print["Error: not connected to router"];Return[]];
	If[to!="CRS",
		CommunicationCostAdd[Association[variables]];
	];
	msg=myRoleAtIdEscaped<>":"<>EscapeColons[to]<>":"<>roomEscaped<>":json:"<>
		ExportString[ToJsonConvertible[variables],"JSON",{"Compact"->True}];
	If[verbose>=1,Print["Sending message:\n"<>msg]];
	msg=msg<>"\n";
	maxChars = 1024;
	While[StringLength[msg]>maxChars,
		msgPart=StringTake[msg,{1,maxChars}];
		WriteString[router,msgPart];
		msg=StringTake[msg,{maxChars+1,StringLength[msg]}];
	];
	WriteString[router,msg]
]
ConnectToRouter[config_,reconnect_:False,forceAuthorization_:False]:=Module[{prevRouter,addr},
	If[reconnect,
		prevRouter=router;
		router=Null,
	(*Else*)
		prevRouter=Null
	];
	If[router===Null,
		addr=AddrFromConfig[config];
		router=SocketConnect[addr]
	(*Else*),
		If[!forceAuthorization,
			Return[router]
		]
	];
	SendVariables["Router",{
		"__authorize__"->{
			"router_password"->config["Password"],
			"connection_password"->config["ConnectionPassword"]
		}
	}];
	Print["Network connection to router:"];
	Print[router];
	Print["Authorizing, waiting for confirmation ..."];
	WaitForVariable["__authorize__"];
	If[prevRouter=!=Null,Close[prevRouter]];
	router
]
DisconnectFromRouter[]:=If[router=!=Null,Close[router];router=Null]
TellVerifier[variables_,verbose_:0]:=SendVariables[
	If[fiatShamir,
		(*Save variables in the proof statement which later can be read by a verifier*)
		"Proof",
	(*Else: interactive*)
		(*Send to interactive verifier; will also be added to the proof statement*)
		"InteractiveVerifier"
	],
	variables,
	verbose
]
TellProver[variables_,verbose_:0]:=SendVariables["Prover",variables,verbose]
SendRandomChallengeTo[to_String,name_String,min_Integer,max_Integer,entropy_:"scalar",verbose_:1]:=Module[
	{value},
	value=BPRandomInteger[min,max];
	If[verbose>=1,Print["Generated random challenge\n  "<>name<>" = "<>IntegerString[value]]];
	SendVariables[to,If[entropy=="",{name->value},{name->value,"_cost"->"scalar"}],verbose-1];
	value
]
SendRandomChallenge[name_String,min_Integer,max_Integer,entropy_:"scalar",verbose_:1]:=SendRandomChallengeTo["Prover",name,min,max,entropy,verbose]
(*Waiting for and receiving values*)
WaitForVariablesImpl[names_:{},fromRole_:"",idsAccepted_:{},finishedAfterFirstVariable_:False,returnParsedMessages_:False,verbose_:1]:=Module[
	{rolesAccepted},
	If[router===Null,Print["Error: not connected to router"];Return[]];
	rolesAccepted=If[fromRole=="",{},{fromRole}];
	If[verbose>=1,Print[
		"Waiting to receive "<>StringRiffle[names,", "]<>
		If[fromRole=="",""," from "<>fromRole]<>
		" ..."
	]];
	ProcessIncomingMessages[router,names,rolesAccepted,idsAccepted,finishedAfterFirstVariable,returnParsedMessages,verbose]
]
WaitForVariable[name_String,fromRole_:"",idsAccepted_:{},verbose_:1]:=WaitForVariablesImpl[{name},fromRole,idsAccepted,False,False,verbose][name]
WaitForMessageWithVariable[name_String,fromRole_:"",idsAccepted_:{},verbose_:1]:=WaitForVariablesImpl[{name},fromRole,idsAccepted,False,True,verbose][name]
WaitForVariables[names_:{},fromRole_:"",idsAccepted_:{},finishedAfterFirstVariable_:False,verbose_:1]:=WaitForVariablesImpl[names,fromRole,idsAccepted,finishedAfterFirstVariable,False,verbose]
WaitForMessagesWithVariables[names_:{},fromRole_:"",idsAccepted_:{},finishedAfterFirstVariable_:False,verbose_:1]:=WaitForVariablesImpl[names,fromRole,idsAccepted,finishedAfterFirstVariable,True,verbose]
WaitForProversVariable[name_String,verbose_:1]:=WaitForVariable[name,"Prover",{},verbose]
WaitForRandomChallenge[name_String,verbose_:1]:=WaitForVariable[name,"InteractiveVerifier",{},verbose]
(*Verification of Proof*)
SendVerificationSucceeded[proverId_:"",verbose_:0]:=SendVariables["Prover"<>If[proverId=="","","@"<>EscapeAts[proverId]],{"_verification_result_"->{"status"->"success"}},verbose]
SendVerificationFailed[reason_String,proverId_:"",verbose_:0]:=SendVariables["Prover"<>If[proverId=="","","@"<>EscapeAts[proverId]],{"_verification_result_"->{"status"->"fail","msg"->reason}},verbose]
(*Inspection of Commitments*)
SendInspectionSucceeded[proverId_:"",verbose_:0]:=SendVariables["Prover"<>If[proverId=="","","@"<>EscapeAts[proverId]],{"_inspection_result_"->{"status"->"success"}},verbose]
SendInspectionFailed[reason_String,proverId_:"",verbose_:0]:=SendVariables["Prover"<>If[proverId=="","","@"<>EscapeAts[proverId]],{"_inspection_result_"->{"status"->"fail","msg"->reason}},verbose]
(*CRS*)
SendCRS[variables_,verbose_:0]:=SendVariables["CRS",variables,verbose]
(*Room*)
JoinRoom[roomOptions_:{},verbose_:0]:=SendVariables["Router",{"__join_room__"->roomOptions},verbose]
JoinRoomAndWaitUntilComplete[roomOptions_:{},verbose_:1]:=Module[{},
	JoinRoom[roomOptions,verbose];
	If[verbose>=1,Print["Joining room '"<>room<>"'. Waiting for confirmation and for all members to have joined to room ..."]];
	roomInfos=WaitForVariables[{"__join_room__","__room_complete__"}];
	roomInfo=Merge[{roomInfos[[2]],roomInfos[[1]]},#[[1]]&];
	roomInfo
]
(*Inspection*)
inspectionEnabled=True;
SetInspection[inspectionEnabledParam_:True]:=Module[{},inspectionEnabled=inspectionEnabledParam]
GiveInsight[variables_,verbose_:0]:=Module[{},
	If[inspectionEnabled && !(fiatShamir && myRole == "Verifier"),
		SendVariables["Inspector",variables,verbose]
	]
]


(*Fiat-Shamir*)
fiatShamirVerbosity=0;
SetFiatShamirVerbosity[verbosity_]:=fiatShamirVerbosity=verbosity
fiatShamirMinimumOutputBits=256;
SetFiatShamirMinimumOutputBits[bits_Integer]:=fiatShamirMinimumOutputBits=bits
FiatShamirAdd[name_String, value_Integer, minBitsOfValue_: 0]:=Module[{},
	If[MemberQ[fiatShamirExplicitVariables,name]||MemberQ[fiatShamirImplicitVariableNames,name],
		Print["Fiat-Shamir transform: Warning: Variable "<>name<>" already added. Adding again."];
	];
	AppendTo[fiatShamirExplicitVariables,name->value];
	AppendTo[fiatShamirExplicitEntropy,minBitsOfValue];
	If[fiatShamirVerbosity>=1,Print["Current variables for next Fiat-Shamir transform are "<>ToString[fiatShamirExplicitVariables]<>" with entropies "<>ToString[fiatShamirExplicitEntropy]]];
	value
]
FiatShamirGet[name_String, q_Integer, qBits_:0]:=Module[{challengeValue},
	If[qBits==0,qBits=Length[IntegerDigits[q,2]]];
	challengeValue=SHA256Multi[
		Values[fiatShamirExplicitVariables],
		Max[qBits,fiatShamirMinimumOutputBits](*output bits*),
		fiatShamirExplicitEntropy(*input entropy*),
		True(*double output bits*),
		fiatShamirVerbosity
	];
	(*Bringing challenge value into the range of [1,q-1] (avoid neutral element 0)*)
	(*Avoid rejection sampling by previously having sampled a challenge value with double the bits*)
	challengeValue=Mod[challengeValue,q-1]+1;
	If[fiatShamirVerbosity>=2,
		Print["Applying Fiat-Shamir transform to get challenge value "<>name<>".\n"<>
			"  The Fiat-Shamir transform will bind "<>name<>" explicitly to "<>StringRiffle[fiatShamirExplicitVariables,", "]<>" and implicitly to "<>TextString[fiatShamirImplicitVariableNames]<>":\n"<>
			"  "<>name<>" = "<>IntegerString[challengeValue]<>"\n"<>
			"  Required output bits are "<>ToString[Max[qBits,fiatShamirMinimumOutputBits]]<>"\n"<>
			"  Input entropy is "<>ToString[fiatShamirExplicitEntropy]<>" bits\n"<>
			"  Doubling output bits: "<>ToString[True]],
	(*Else*)If[fiatShamirVerbosity==1,
		Print["Fiat-Shamir transform yields\n"<>
		"  "<>name<>" = "<>IntegerString[challengeValue]]
	]];
	fiatShamirImplicitVariableNames=Join[fiatShamirImplicitVariableNames,Map[#[[1]]&,fiatShamirExplicitVariables]];
	fiatShamirExplicitVariables={};
	fiatShamirExplicitEntropy={};
	FiatShamirAdd[name,challengeValue,qBits];
	challengeValue
]
FiatShamirGrid[]:=Grid[{
	{Style["Fiat-Shamir state",Bold],SpanFromLeft,SpanFromLeft},
	{"Implicit Variables",Length[fiatShamirImplicitVariableNames],StringRiffle[fiatShamirImplicitVariableNames,", "]},
	{"Explicit Variables",Length[fiatShamirExplicitVariables],StringRiffle[Map[#[[1]]&,fiatShamirExplicitVariables],", "]}
}, Alignment->{{Left,Left,Left}},Frame->All]


End[]


EndPackage[]
