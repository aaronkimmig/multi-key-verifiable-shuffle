(* ::Package:: *)

(*(* :Context: EllipticCurves` *)*)
(**)
(*(* :Title: Elliptic Curves *)*)
(**)
(*(* :Author: John McGee, Changes by: Aaron Kimmig *)*)
(**)
(*(* :Version: Mathematica 10.1 *)*)
(**)
(*(* :Package Version: 2.0 *)*)
(**)
(*(* :Keywords:*)
(*    elliptic curve, number theory, cryptology*)
(**)*)
(**)
(*(* :History:*)
(* Version 1.0 by John McGee, October 2015 *)
(* Version 2.0 by Aaron Kimmig, December 2022 *)
(**)*)
(**)
(*(* :Copyright: Copyright 2015 - Wolfram Research *)*)
(*(* :Copyright: Copyright 2022 - Aaron Kimmig*)*)
(**)
(*(* :Requirements: *)*)
(**)
(*(* :Warnings:*)
(**)
(* *)
(*	The algorithms in this package are based largely on *)
(*	"Elliptic Curves" - by Lawrence Washington *)
(**)
(*    Adds functionality to the following functions:*)
(*    Plus, Minus, Times*)
(**)
(*    In this version of the package, the elliptic curves must be in*)
(*	Weierstrass short form y^2 = x^3 + a x + b over one of the following*)
(*	fields: \[DoubleStruckCapitalQ], \[DoubleStruckCapitalR], \[DoubleStruckCapitalC], Subscript[\[DoubleStruckCapitalF], p], Subscript[\[DoubleStruckCapitalF], p^k]*)
(**)
(**)*)
(**)
(*(* :Sources: *)
(*	"Elliptic Curves - Number Theory and Cryptography" - by Lawrence Washington*)
(*	"Rational Points on Elliptic Curves" - by Silverman and Tate*)
(**)*)
(**)
(*(* :Summary:*)
(*This package implements elliptic curve point arithmetic with applications.*)
(**)*)
(**)


BeginPackage["ECOverloaded`"];


If[Not@ValueQ[\[ScriptCapitalO]::usage],\[ScriptCapitalO]::usage="\[ScriptCapitalO] = ecPnt[\[Infinity],\[Infinity]] is the identity for elliptic curve point addition"];


If[Not@ValueQ[ecCurve::usage],ecCurve::usage=" is the head for elliptic curve definition ecCurve[a,b,f]"];


If[Not@ValueQ[setEC::usage],setEC::usage =
        "setEC[ec_ecCurve] establishes the current elliptic curve\
	where ec has the form ecCurve[a,b,f] for the curve
 \!\(\*SuperscriptBox[\(y\), \(2\)]\) = \!\(\*SuperscriptBox[\(x\), \(3\)]\) + a x + b\
	and F is one of the field symbols \[DoubleStruckCapitalR], \[DoubleStruckCapitalC] or {p,1} for \!\(\*SubscriptBox[\(\[DoubleStruckCapitalF]\), \(p\)]\), or {p, n} for \!\(\*SubscriptBox[\(\[DoubleStruckCapitalF]\), SuperscriptBox[\(p\), \(n\)]]\)"];


If[Not@ValueQ[currentEC::usage],currentEC::usage="returns the current elliptic curve"];


If[Not@ValueQ[ecPnt::usage],ecPnt::usage="is the head for an elliptic curve point ecpnt[x0,y0]"];


If[Not@ValueQ[isECQ::usage],isECQ::usage=
"IsECQ[ec_ecCurve] returns true if the given curve is nonsingular"];


If[Not@ValueQ[isECPointQ::usage],isECPointQ::usage=
"isECPointQ[pnt_ecPnt] returns True if the point (x,y)\[Element]\!\(\*SuperscriptBox[\(F\), \(2\)]\) is on the current elliptic curve"];


If[Not@ValueQ[CirclePlus::usage],CirclePlus::usage="P \[CirclePlus] Q gives the sum of the points P, Q using elliptic curve point addition
 on the current curve"];


If[Not@ValueQ[CircleTimes::usage],CircleTimes::usage="n \[CircleTimes] P computes the sum of n copies of the point P using elliptic
 curve point addition on the current curve"];


If[Not@ValueQ[jInvariant::usage],jInvariant::usage="jInvariant[ec_ecCurve] computes the j-invariant of the given elliptic curve"];


If[Not@ValueQ[ecPointOrder::usage],ecPointOrder::usage="ecPointOrder[p_ecPnt] determines the smallest positive integer n such that nP = \[ScriptCapitalO]"];


If[Not@ValueQ[randomECPoint::usage],randomECPoint::usage="randomECPoint[m_Integer] - generates a random point (x,y) with -m<=x<=m"];


If[Not@ValueQ[findECPoint::usage],findECPoint::usage="findEcPoint[x0], returns a point on the curve with x-coordinate close to x0"];


If[Not@ValueQ[ecHasseBounds::usage],ecHasseBounds::usage="determines limits of the group order"];


If[Not@ValueQ[ecGroupOrder::usage],ecGroupOrder::usage="determine the order of the current elliptic curve group"];


If[Not@ValueQ[ecGroupOrder::usage],ecRandomGenerators::usage="ecRandomGenerators[m_Integer, cofactor_Integer, size_Integer] generates a list of distinct random generator points with x-coordinate -m<=x<=m"];


Begin["`Private`"]


(* ::Text:: *)
(*The private symbol $curEC holds the current elliptic curve definition of the form:*)
(*	{A,B,\[DoubleStruckCapitalR]}  for the curve y^2=x^3+A x+B over \[DoubleStruckCapitalR]*)
(*	{A,B,\[DoubleStruckCapitalC]}  for the curve y^2=x^3+A x+B over \[DoubleStruckCapitalC]*)
(*	{A,B,{p,1}}  for the curve y^2=x^3+A x+B over Subscript[\[DoubleStruckCapitalF], p]*)
(*	{A,B,{p,n}} for the curve y^2=x^3+A x+B over the finite field Subscript[\[DoubleStruckCapitalF], p^n]*)


Needs["FiniteFields`"];  (* provide support for arithmetic in Subscript[\[DoubleStruckCapitalF], p^n] *)


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*$curEC holds the currently active elliptic curve parameters*)
(*The identity \[ScriptCapitalO] for point addition is the point at infinity in \[DoubleStruckCapitalP]^2 [0:1:0]*)
(*We use ecPnt is the head for elliptic curve points.*)


$ecFld=\[DoubleStruckCapitalR];$curEC={-3,1,\[DoubleStruckCapitalR]};\[ScriptCapitalO]=ecPnt[\[Infinity],\[Infinity]];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Method to set the current elliptic curve type and parameters*)


setEC[ec_ecCurve]:=Module[{f},
$curEC=ec;
f=Last[ec];
If[MatchQ[f,{_Integer,_Integer}],
If[Last[f]>1,
$ecFld=GF@@f;
];
];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*jInvariantL gives the j-Invariant for the long Weirstrass form*)
(*	x^3+Subscript[a, 2] x^2+Subscript[a, 4]x+Subscript[a, 6]-y^2-Subscript[a, 1] x y-Subscript[a, 3]y=0*)


jInvariantL[ec_ecCurve]:=Module[{a1,a2,a3,a4,a6,b2,b4,b6,b8,cl,c4,c6,del,j},
cl=CoefficientList[ec,{x,y}];
a1=-cl[[2,2]];a2=cl[[3,1]];a3=-cl[[1,2]];a4=cl[[2,1]];a6=cl[[1,1]];b2=a1^2+4 a2;b4=a1 a3+2 a4;b6=a3^2+4 a6;b8=a1^2 a6-a1 a3 a4+a2 a3^2+4 a2 a6-a4^2;
c4=b2^2-24 b4;c6=-b2^3+36 b2 b4-216 b6;
del=-b2^2b8+9b2 b4 b6-8 b4^3-27 b6^2;
j=c4^3/del;
Return[j];
];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*x^3+a x+b-y^2=0 represents a non-singular curve only if its discriminant 4a^3+27b^2 is nonzero*)


isECQF[{a_,b_},_]:=4 a^3+27 b^2!=0;


isECQF[{a_,b_},{p_,1}]:=Mod[4 a^3+27 b^2,p]!=0;


isECQ[ec_ecCurve]:=isECQF[List@@ec[[1;;2]],Last[ec]];


currentEC[]:=Return[$curEC];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent methods to support EC j-Invariant computation*)


jInvariantF[{a_,b_},\[DoubleStruckCapitalR]]:=(6912 a^3)/(4 a^3+27b^2);


jInvariantF[{a_,b_},{p_,1}]:=Module[{a3,b2,n,d,di,j},
a3=PowerMod[a,3,p];
b2=PowerMod[b,2,p];
(* denominator is 4a^3+27b^3 *)
d=Mod[4*a3+27*b2,p];
(* d^-1 (mod p) exists because Subscript[\[DoubleStruckCapitalF], p] is a field and d \[NotEqual] 0 for an elliptic curve *)
di=PowerMod[d,-1,p];
(* j = 1728 (4a^3)/(4 a^3+27 b^2) *)
j=Mod[1728*4*a3*di,p];
Return[j];
];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*jInvariant gives the j-Invariant for the short Weierstrass form*)
(*	x^3+a x+b-y^2=0   j=1728 (4 a^3)/(4 a^3+27 b^2)*)


jInvariant[ec_ecCurve]:=Module[{a,b,f},
{a,b,f}=List@@ec;
Return[jInvariantF[{a,b},f]];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*(x,y) is a point on the elliptic curve if it is a zero of the elliptic curve polynomial p(x,y)*)


isECPointQF[{x_,y_},_]:=(x^3+a*x+b-y^2==0)/.{a->$curEC[[1]],b->$curEC[[2]]};


isECPointQF[{x_,y_},{p_,1}]:=(Mod[x^3+a*x+b-y^2,p]==0)/.{a->$curEC[[1]],b->$curEC[[2]]};


isECPointQ[pnt_ecPnt]:=isECPointQF[List@@pnt,Last[$curEC]]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Generate a random point (x,y) on the current curve with -m<=x<=m*)


quadraticResidueQ[a_,p_]:=PowerMod[a,(p-1)/2,p]==1;


randomECPointFp[a_,b_,p_]:=Module[{x1,y1,y2},
While[True,
x1=RandomInteger[{0,p-1}];
y2=Mod[x1^3+a*x1+b,p];
If[quadraticResidueQ[y2,p],
y1=PowerMod[y2,1/2,p];
Break[];
];
];
If[RandomChoice[{True,False}],y1=Mod[p-y1,p]];
Return[ecPnt[x1,y1]];
]


randomECPoint[m_]:=Module[{a,b,f,x1,y1},
{a,b,f}=List@@$curEC;
If[MatchQ[f,{_,1}],Return[randomECPointFp[a,b,First@f]]];
While[True,
x1=RandomInteger[{-m,m}];
y1=Sqrt[x1^3+a*x1+b];
If[IntegerQ[y1],Break[]];
];
If[RandomChoice[{True,False}],y1*=-1];
Return[ecPnt[x1,y1]];
]


findEcPointFp[a_,b_,p_,x0_]:=Module[{x1,y1,x2,y2},
x1=x0;x2=x0+100;
While[x1<x2,
y2=x1^3+a*x1+b;
If[quadraticResidueQ[y2,p],
y1=PowerMod[y2,1/2,p];
Return[ecPnt[x1,y1]];
];
++x1;
];
Return[{}];
]


findECPoint[x0_]:=Module[{a,b,f,y1,x1=x0},
{a,b,f}=List@@$curEC;
If[MatchQ[f,{_,1}],Return[findEcPointFp[a,b,First[f],x0]]];
y1=Sqrt[x1^3+a*x1+b];
Return[ecPnt[x1,y1]];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Determine the equation of the elliptic curve of the form y^2=x^3+a x +b through the given points*)
(*	use a least-square fit if no exact solution is availible	*)


makeEC3Point[pnts_]:=Module[{m,u,sol,a,b},
m={#[[1]],1}&/@pnts;
u={#[[2]]^2-#[[1]]^3}&/@pnts;
sol=RowReduce[Join[m\[Transpose] . m,m\[Transpose] . u,2]];
{a,b}=sol[[All,3]];
Return[{a,b}];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent method to support EC point negation  \!\(TraditionalForm\`\((\[DoubleStruckCapitalQ], \[DoubleStruckCapitalR], \[DoubleStruckCapitalC], *)
(*\*SubscriptBox[\(\[DoubleStruckCapitalF]\), *)
(*SuperscriptBox[\(p\), \(n\)]]\)\))*)


ecNegateF[{x1_,y1_},_]:=ecPnt[x1,-y1];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent method to support EC point negation  \!\(TraditionalForm\`\(( *)
(*\*SubscriptBox[\(\[DoubleStruckCapitalF]\), \(p\)])\)\)*)


ecNegateF[{x1_,y1_},{p_,1}]:=ecPnt[x1,Mod[p-y1,p]];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Return the additive inverse of the point P*)


ecNegate[p_ecPnt]:=ecNegateF[List@@p,Last[$curEC]];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent method to support EC point doubling (\[DoubleStruckCapitalQ],\[DoubleStruckCapitalR],\[DoubleStruckCapitalC],Subscript[\[DoubleStruckCapitalF], p^n])*)


ecDoubleF[{x1_,y1_},_]:=Module[{a,\[Lambda],x3,y3},
a=First[$curEC];
(* Compute the slope of the tangent line using implicit differentiation *)
\[Lambda]=(3 x1^2+a)/(2 y1);
(* 2P is the negative of the third point of intersection *)
x3=\[Lambda]^2-2 x1;
y3=\[Lambda](x1-x3)-y1;
Return[{x3,y3}];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent method to support EC point doubling (Subscript[\[DoubleStruckCapitalF], p])*)


ecDoubleF[{x1_,y1_},{p_,1}]:=Module[{a,\[Lambda],x3,y3},
a=First[$curEC];
(* Compute the slope of the tangent line using formal implicit differentiation *)
\[Lambda]=Mod[(3 x1^2+a) PowerMod[2 y1,-1,p],p];
(* 2P is the negative of the third point of intersection *)
x3=Mod[\[Lambda]^2-2 x1,p];
y3=Mod[\[Lambda](x1-x3)-y1,p];
Return[{x3,y3}];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Method to compute 2 P on the curve y^2=x^3+A x+B over \[DoubleStruckCapitalF]*)


ecDouble[p_ecPnt]:=Module[{x1,y1,a,b,\[Lambda],x3,y3},
(* 2 \[ScriptCapitalO] = \[ScriptCapitalO]*)
If[p==\[ScriptCapitalO],Return[p]];
{x1,y1}=List@@p;
(* Check for vertical tangent - gives \[ScriptCapitalO] *)
If[y1==0,Return[\[ScriptCapitalO]]];
{x3,y3}=ecDoubleF[{x1,y1},Last@$curEC];
Return[ecPnt[x3,y3]];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent method to support EC point addition (\[DoubleStruckCapitalQ],\[DoubleStruckCapitalR],\[DoubleStruckCapitalC],Subscript[\[DoubleStruckCapitalF], p^n])*)


ecAddF[{x1_,y1_},{x2_,y2_},_]:=Module[{\[Lambda],x3,y3},
\[Lambda]=(y2-y1)/(x2-x1);
(* P \[CirclePlus] Q is the negative of the third point of intersection *)
x3=\[Lambda]^2-x1-x2;
y3=\[Lambda](x1-x3)-y1;
Return[{x3,y3}];
];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Low level field-dependent method to support EC point addition (Subscript[\[DoubleStruckCapitalF], p])*)


ecAddF[{x1_,y1_},{x2_,y2_},{p_,1}]:=Module[{\[Lambda],x3,y3},
\[Lambda]=Mod[(y2-y1) PowerMod[x2-x1,-1,p],p];
x3=Mod[\[Lambda]^2-x1-x2,p];
y3=Mod[\[Lambda] (x1-x3)-y1,p];
Return[{x3,y3}];
];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Method to add to points on the curve y^2=x^3+A x+B over \[DoubleStruckCapitalR]*)
(*	uses \[ScriptCapitalO]  to represent the "point at infinity", the identity*)


ecAdd[p_ecPnt,q_ecPnt]:=Module[{x1,y1,x2,y2,\[Lambda],x3,y3},
(* first check if one of the points is the identity *)
If[p===\[ScriptCapitalO],Return[q]];
If[q===\[ScriptCapitalO],Return[p]];
If[p==q,Return[ecDouble[p]]];
{x1,y1}=List@@p;{x2,y2}=List@@q;
(* check for vertical line between the points *)
If[x1==x2,Return[\[ScriptCapitalO]]];
{x3,y3}=ecAddF[{x1,y1},{x2,y2},Last@$curEC];
Return[ecPnt[x3,y3]];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Compute n P for the point P by efficient addition using the binary representation of n  (\[DoubleStruckCapitalQ],\[DoubleStruckCapitalR],\[DoubleStruckCapitalC],Subscript[\[DoubleStruckCapitalF], p],Subscript[\[DoubleStruckCapitalF], p^n])*)


ecTimes[n_Integer,p_ecPnt]:=Module[{k,q,r},
k=n; 
(* handle the special cases 0*P, 1*P, 2*P, 3*P *)
If[k==0,Return[\[ScriptCapitalO]]];
If[k==1,Return[p]];
If[k==2,Return[ecDouble[p]]];
If[k==3,Return[ecAdd[p,ecDouble[p]]]];
q=\[ScriptCapitalO];r=p;
While[k!=0,
If[OddQ[k],
--k;
q=ecAdd[q,r];
,
k=BitShiftRight[k];
r=ecDouble[r];
];
];
Return[q];
];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Compute n P for n<0 as (-n)(-P)*)


ecTimes[n_Integer/;n<0,p_ecPnt]:=Module[{q,r},
q=ecNegate[p];
r=ecTimes[-n,q];
Return[r];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Compute P n = n P*)


ecTimes[p_ecPnt,n_Integer]:=ecTimes[n,p];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Plus is a binary operator on two ecPnt's P,Q giving*)
(*	P+Q in the algebraic group formed using 'chord and tangent' point addition*)


Unprotect[Plus]
ecPnt /: Plus[p_ecPnt,q_ecPnt]:=ecAdd[p,q];
(*Plus[p:{__ecPnt},q:{__ecPnt}]:=Thread[ecAdd[p,q]];*)
Protect[Plus]
Unprotect[Minus]
ecPnt /: Minus[p_ecPnt]:=ecNegate[p];
(*Minus[p:{__ecPnt}]:=Thread[Minus[p]];*)
Protect[Minus]
Unprotect[Subtract]
ecPnt /: Subtract[p_ecPnt,q_ecPnt]:=ecAdd[p,ecNegate[q]];
(*Subtract[p:{__ecPnt},q:{__ecPnt}]:=Thread[ecAdd[p,ecNegate[q]]];*)
Protect[Subtract]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*multiple n P of the ecPnt P where*)
(*	n*P = P+P+ ... +P (n copies)*)


Unprotect[Times]
ecPnt /: Times[n_Integer,p_ecPnt]:=ecTimes[n,p];
(*Times[n:{__Integer},p:{__ecPnt}]:=Thread[ecTimes[n,p]];*)


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Support P*n*)


ecPnt /: Times[p_ecPnt,n_Integer]:=ecTimes[n,p];
(*Times[p:{__ecPnt},n:{__Integer}]:=Thread[ecTimes[n,p]];*)
Protect[Times]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Support equality test with ==*)


Unprotect[Equal]
Equal[a_ecPnt,b_ecPnt]:=a[[1]]==b[[1]]&&a[[2]]==b[[2]]
Protect[Equal]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Array of distinct random generator points*)


ecRandomGenerators[p_Integer, cofactor_Integer, size_Integer]:=Module[{generators,i,generatorOk,generator,j},
	generators = {};
	For[i = 1, i <= size, i++,
		generatorOk = True;
		generator = randomECPoint[p]*cofactor;
		For[j = 1, j <= i-1, j++,
			If[generator[[1]]==generators[[j]][[1]],
				generatorOk = False;
				Break[];
			];
		];
		If[generatorOk,
			AppendTo[generators, generator],
			i--
		]
	];
	generators
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Attempt to find the order of a point by computing k P for k=1 to m looking for k P=\[ScriptCapitalO]*)
(*	return 0 if |P| > m   (\[DoubleStruckCapitalQ],\[DoubleStruckCapitalR],\[DoubleStruckCapitalC],Subscript[\[DoubleStruckCapitalF], p],Subscript[\[DoubleStruckCapitalF], p^n])*)


ecPointOrderF[q_ecPnt,m_Integer]:=Module[{a,b,k,q2},
(* Test for special case orders 1,2 *)
If[q==\[ScriptCapitalO],Return[1]];
q2=ecDouble[q];
If[q2===\[ScriptCapitalO],Return[2]];
k=2;
(* while (k)Q \[NotEqual] \[ScriptCapitalO] *)
While[\[Not](q2===\[ScriptCapitalO])\[And]k<=m,
(* kQ = Q + (k-1)Q *)
q2=ecAdd[q2,q];
++k;
];
(* did not find a solution \[LessEqual] m, return 0 *)
If[k>m,Return[0]];
(* return the order of P = k *)
Return[k];
]


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Use the BabyStep-GiantStep method to find order of the point Q, that is*)
(*	find m\[Element]Subscript[\[DoubleStruckCapitalZ], p]\[SuchThat]m Q=\[ScriptCapitalO]  on the elliptic curve E:y^2=x^3+a x+b.  Only for (Subscript[\[DoubleStruckCapitalF], p])*)
(*	This method, described in Washington[7] \[Section] 4.3 is based on the so-called birthday paradox*)


ecPointOrderBabyGiant[q_ecPnt]:=Module[{r,k,m,iptbl,t1,a,b,f,p,rp2kmq,rm2kmq,rq,qp2m,qn,qn2m,qm3,p2,m1,f1,b1,x1},
{a,b,f}=List@@$curEC;
If[\[Not]MatchQ[f,{_Integer,1}],
Print["ERROR - ecPointOrderBabyGiant only works for F = \!\(\*SubscriptBox[\(\[DoubleStruckCapitalF]\), \(p\)]\)"];Return[0]];
p=First[f];
(* Compute R = (p+1)Q *)
r=ecTimes[p+1,q];
(* Table size m = \[LeftCeiling]Power[p, (4)^-1]\[RightCeiling] *)
m=Ceiling[Power[p,1/4]];
(* Create table of jQ for j=1,m *)
iptbl=NestList[ecAdd[#,q]&,q,m];
t1=First/@iptbl; (* the x-coordinates *)
(* Walk through table of R \[PlusMinus] 2kmQ for k=1,...,m *)
rp2kmq=r;rm2kmq=r;
qp2m=ecTimes[2*m,q];
(* Compute -Q, -2mQ *)
qn=ecNegate[q];
qn2m=ecTimes[2*m,qn];
k=0;
(* Compute for k=\[PlusMinus]1,\[PlusMinus]2,... *)
While[True&&k<10^4,
(* Until R + 2kmQ = \[PlusMinus]jQ or ... *)
If[MemberQ[t1,First[rp2kmq]],
rq=rp2kmq;
Break[];
];
(* Until R - 2kmQ = \[PlusMinus]jQ *)
If[MemberQ[t1,First[rm2kmq]],
k=-k;
rq=rm2kmq;
Break[];
];
(* Compute next R \[PlusMinus] 2kmQ for next k *)
rp2kmq=ecAdd[rp2kmq,qp2m];
rm2kmq=ecAdd[rm2kmq,qn2m];
++k;
];
(* Here we have Q \[PlusMinus] 2kmP = \[PlusMinus]jP, figure out j *)
j=First@Flatten@Position[t1,First[rq]];
(* Determine which \[PlusMinus]j *)
p2=iptbl[[j]];
If[Last[rq]!=Last[p2] ,
If[Last[rq]==Mod[p-Last[p2],p],
j=-j;
,
Print["ERROR: Q + kmP \[NotEqual] \[PlusMinus]jP"];
Return[0];
];
];
(* Compute M \[SuchThat] Order(P) | M *)
m1=p+1+2*m*k-j;
(* TBD - This fails if m1 = 0 => j = p + 1 + 2*m*k *)
If[m1 == 0, Print["ERROR: M == 0"];Return[0]];
(* If M is prime, it must be the order of P *)
If[PrimeQ[m1], Return[m1]];
(* Factor can be VERY hard if no small factors *)
f1=FactorInteger[m1];
b1=True;
While[b1,
b1=False;
For[i=1,i<=Length[f1],++i,
(* Divide out a prime factor *)
x1=m1/First[f1[[i]]];
(* If x Q(mod p) = Q then M = x *)
qm3=ecTimes[x1-1,q];
If[qm3==qn,
m1=x1;
b1=True;
(* This looks wrong - delete f1?? Break exist the loop, should it be Continue? *)
If[--f1[[i,2]] <= 0, f1=Delete[f1,i]];
Break[];
];
];
];
Return[m1];
];


(* ::Text::RGBColor[0.6, 0.4, 0.2]:: *)
(*Determine the order of the point Q on the current elliptic curve,*)
(*	that is, the smallest positive integer n, such that n Q=\[ScriptCapitalO]*)


ecPointOrder[q_ecPnt]:=Module[{a,b,f,p,n},
{a,b,f}=List@@$curEC;
(* for finite fields *)
If[MatchQ[f,{_Integer,1}],
p=First@f;
n=ecPointOrderF[q,Min[250,2*p]];
If[n>0,Return[n]];
n=ecPointOrderBabyGiant[q];
Return[n];
,
(* note if the field is \[DoubleStruckCapitalR] or \[DoubleStruckCapitalQ], this can only work for exact arithmetic *)
n=ecPointOrderF[q,1000];
Return[n];
];
]


(* ::Subsubsection:: *)
(*Determine the limits on the order of the group over Subscript[\[DoubleStruckCapitalF], q]*)
(*   according to Hasse bounds q+1\[PlusMinus]2\[LeftFloor]Sqrt[q]\[RightFloor]*)


ecHasseBounds[]:=Module[{a,b,f,p,k,q},
{a,b,f}=List@@$curEC;
If[\[Not]MatchQ[f,{_Integer,_Integer}],Return[{}]];
{p,k}=f;
q=p^k;
s=Floor[2 Sqrt[q]];
Return[{q+1-s,q+1+s}];
]


ecGroupOrderFp[a_,b_,p_]:=Module[{h0,h1,p1,p2,k1,k2,or1,or3,t,k},
{h0,h1}=ecHasseBounds[];
or1=0;
t={};
While[True,
(* Generate a random point on E(Subscript[\[DoubleStruckCapitalF], p]) *)
p1=randomECPointFp[a,b,p];
(* Determine |p1| *)
k1=ecPointOrder[p1];
If[k1 != 0,
t=Union[t,{k1}];
(* Compute the LCM of all orders found *)
or1=Apply[LCM,t];
(* There is a solution if p + 1 - 2Sqrt[p] \[LessEqual] LCM \[LessEqual] p + 1 +2Sqrt[p] *)
If[h0 <= or1 && or1 <= h1, Return[or1]];
(* Determine # of multiples of the LCM within Hasse's bounds *)
k2=Quotient[h1,or1]-Quotient[h0,or1];
(* If there is only one multiple of the LCM within Hasse's bounds, it must be the order of the group *)
If[k2 == 1,
or3=Quotient[h0,or1]*or1;
If[or3 < h0, or3+=or1];
Return[or3];
];
];
];
Return[{}];
];


ecGroupOrder[]:=Module[{a,b,f,p},
{a,b,f}=List@@$curEC;
If[\[Not]MatchQ[f,{_Integer,1}],Return[0]];
p=First@f;
Return[ecGroupOrderFp[a,b,p]];
]


End[ ]


EndPackage[ ]
